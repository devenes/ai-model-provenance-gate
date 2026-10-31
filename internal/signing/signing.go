// Package signing implements standard PKIX key loading, fingerprint calculation,
// DSSE v1.0 Pre-Authentication Encoding (PAE) signing, and Sigstore v0.3 bundle packaging
// using only the Go standard library cryptographic primitives.
package signing

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/devenes/ai-model-provenance-gate/internal/digest"
)

const (
	// InTotoPayloadType is the standard DSSE payload media type for in-toto statements.
	InTotoPayloadType = "application/vnd.in-toto+json"
	// InTotoStatementV1Type is the standard in-toto Statement v1 URI.
	InTotoStatementV1Type = "https://in-toto.io/Statement/v1"
	// SigstoreBundleV03MediaType is the media type for Sigstore v0.3 JSON bundles.
	SigstoreBundleV03MediaType = "application/vnd.dev.sigstore.bundle.v0.3+json"
)

var (
	// ErrInvalidKeyMaterial is returned when PEM private or public key data cannot be parsed.
	ErrInvalidKeyMaterial = errors.New("invalid PEM cryptographic key material")
	// ErrInvalidDSSEEnvelope is returned when a DSSE envelope or Sigstore bundle is malformed.
	ErrInvalidDSSEEnvelope = errors.New("invalid DSSE envelope")
	// ErrInvalidSignature is returned when a signature or certificate fails verification.
	ErrInvalidSignature = errors.New("invalid cryptographic signature")
)

// DSSESignature represents a single signature entry inside a DSSE v1.0 envelope.
type DSSESignature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

// DSSEEnvelope represents a standard Dead Simple Signing Envelope (DSSE v1.0).
type DSSEEnvelope struct {
	PayloadType string          `json:"payloadType"`
	Payload     string          `json:"payload"`
	Signatures  []DSSESignature `json:"signatures"`
}

// SigstoreBundlePublicKey identifies a public key hint (or legacy rawBytes) inside a Sigstore bundle.
type SigstoreBundlePublicKey struct {
	Hint       string `json:"hint,omitempty"`
	RawBytes   string `json:"rawBytes,omitempty"`
	KeyDetails string `json:"keyDetails,omitempty"`
}

// SigstoreVerificationMaterial holds verification material metadata in a Sigstore bundle.
type SigstoreVerificationMaterial struct {
	PublicKey                 *SigstoreBundlePublicKey      `json:"publicKey,omitempty"`
	X509CertificateChain      *X509CertificateChainMaterial `json:"x509CertificateChain,omitempty"`
	Certificate               *CertificateMaterial          `json:"certificate,omitempty"`
	TlogEntries               []RekorTlogEntry              `json:"tlogEntries,omitempty"`
	TimestampVerificationData json.RawMessage               `json:"timestampVerificationData,omitempty"`
}

// SigstoreBundle represents a Sigstore v0.2/v0.3 JSON bundle wrapping a DSSE envelope.
type SigstoreBundle struct {
	MediaType            string                        `json:"mediaType"`
	VerificationMaterial *SigstoreVerificationMaterial `json:"verificationMaterial,omitempty"`
	DSSEEnvelope         *DSSEEnvelope                 `json:"dsseEnvelope"`
}

// ResourceDescriptor represents an in-toto v1 subject resource descriptor.
type ResourceDescriptor struct {
	Name        string            `json:"name"`
	Digest      map[string]string `json:"digest"`
	Annotations map[string]any    `json:"annotations,omitempty"`
}

// InTotoStatement represents an in-toto Attestation Statement v1.
type InTotoStatement struct {
	Type          string               `json:"_type"`
	Subject       []ResourceDescriptor `json:"subject"`
	PredicateType string               `json:"predicateType"`
	Predicate     json.RawMessage      `json:"predicate"`
}

// PrivateKey wraps a standard library asymmetric private key and its PKIX public key fingerprint.
type PrivateKey struct {
	KeyID       string
	Fingerprint string
	Algorithm   string
	Signer      crypto.Signer
	PublicKey   crypto.PublicKey
}

// PublicKey wraps a standard library asymmetric public key and its PKIX SHA-256 fingerprint.
type PublicKey struct {
	KeyID       string
	Name        string
	Fingerprint string
	Algorithm   string
	Pub         crypto.PublicKey
}

// DSSEPAE constructs the exact DSSE v1.0 Pre-Authentication Encoding byte sequence:
// "DSSEv1 " + len(payloadType) + " " + payloadType + " " + len(payload) + " " + payload
func DSSEPAE(payloadType string, rawPayload []byte) []byte {
	header := fmt.Sprintf("DSSEv1 %d %s %d ", len(payloadType), payloadType, len(rawPayload))
	out := make([]byte, len(header)+len(rawPayload))
	copy(out, header)
	copy(out[len(header):], rawPayload)
	return out
}

// GenerateEd25519KeyPairPEM generates a fresh Ed25519 key pair in standard PKCS#8 / PKIX PEM format.
func GenerateEd25519KeyPairPEM() (privPEM []byte, pubPEM []byte, fingerprint string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, "", fmt.Errorf("generate ed25519 key: %w", err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, "", fmt.Errorf("marshal pkcs8 private key: %w", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, nil, "", fmt.Errorf("marshal pkix public key: %w", err)
	}
	privBuf := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	pubBuf := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	fp := digest.ComputeBytes(pubDER)
	return privBuf, pubBuf, fp, nil
}

// LoadPrivateKeyFile loads a PEM-encoded PKCS#8, EC, or RSA private key from disk.
func LoadPrivateKeyFile(path string, keyID string) (*PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read private key %q: %w", path, err)
	}
	return ParsePrivateKeyPEM(raw, keyID)
}

// ParsePrivateKeyPEM parses a PEM-encoded PKCS#8, EC, or RSA private key.
func ParsePrivateKeyPEM(rawPEM []byte, keyID string) (*PrivateKey, error) {
	block, _ := pem.Decode(rawPEM)
	if block == nil {
		return nil, fmt.Errorf("%w: no PEM block found", ErrInvalidKeyMaterial)
	}

	var parsed any
	var err error
	switch block.Type {
	case "PRIVATE KEY":
		parsed, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		parsed, err = x509.ParseECPrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		parsed, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("%w: unsupported PEM block type %q", ErrInvalidKeyMaterial, block.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidKeyMaterial, err)
	}

	signer, ok := parsed.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("%w: key type %T does not implement crypto.Signer", ErrInvalidKeyMaterial, parsed)
	}

	pub := signer.Public()
	fp, alg, err := PublicKeyFingerprintAndAlg(pub)
	if err != nil {
		return nil, err
	}

	if strings.TrimSpace(keyID) == "" {
		// Default keyid to first 16 hex chars of PKIX SHA-256 fingerprint
		hexFP, _ := digest.TrimPrefix(fp)
		keyID = hexFP[:16]
	}

	return &PrivateKey{
		KeyID:       keyID,
		Fingerprint: fp,
		Algorithm:   alg,
		Signer:      signer,
		PublicKey:   pub,
	}, nil
}

// LoadPublicKeyFile loads a PEM-encoded PKIX public key from disk.
func LoadPublicKeyFile(path string, keyID string, name string) (*PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read public key %q: %w", path, err)
	}
	return ParsePublicKeyPEM(raw, keyID, name)
}

// ParsePublicKeyPEM parses a PEM-encoded PKIX public key.
func ParsePublicKeyPEM(rawPEM []byte, keyID string, name string) (*PublicKey, error) {
	block, _ := pem.Decode(rawPEM)
	if block == nil {
		return nil, fmt.Errorf("%w: no PEM block found", ErrInvalidKeyMaterial)
	}

	var pub any
	var err error
	switch block.Type {
	case "PUBLIC KEY":
		pub, err = x509.ParsePKIXPublicKey(block.Bytes)
	case "RSA PUBLIC KEY":
		pub, err = x509.ParsePKCS1PublicKey(block.Bytes)
	default:
		return nil, fmt.Errorf("%w: unsupported public key PEM block type %q", ErrInvalidKeyMaterial, block.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidKeyMaterial, err)
	}

	fp, alg, err := PublicKeyFingerprintAndAlg(pub)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(keyID) == "" {
		hexFP, _ := digest.TrimPrefix(fp)
		keyID = hexFP[:16]
	}

	return &PublicKey{
		KeyID:       keyID,
		Name:        name,
		Fingerprint: fp,
		Algorithm:   alg,
		Pub:         pub,
	}, nil
}

// PublicKeyFingerprintAndAlg returns the "sha256:<64-hex>" fingerprint of the PKIX DER public key and its algorithm name.
func PublicKeyFingerprintAndAlg(pub crypto.PublicKey) (string, string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", "", fmt.Errorf("%w: marshal PKIX public key: %v", ErrInvalidKeyMaterial, err)
	}
	sum := sha256.Sum256(der)
	fp := digest.Prefix + hex.EncodeToString(sum[:])

	switch k := pub.(type) {
	case ed25519.PublicKey:
		return fp, "ed25519", nil
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256():
			return fp, "ecdsa-p256-sha256", nil
		case elliptic.P384():
			return fp, "ecdsa-p384-sha384", nil
		case elliptic.P521():
			return fp, "ecdsa-p521-sha512", nil
		default:
			return "", "", fmt.Errorf("%w: unsupported ECDSA curve %v", ErrInvalidKeyMaterial, k.Curve.Params().Name)
		}
	case *rsa.PublicKey:
		return fp, "rsa-sha256", nil
	default:
		return "", "", fmt.Errorf("%w: unsupported public key algorithm %T", ErrInvalidKeyMaterial, pub)
	}
}

func ecdsaHashPayload(curve elliptic.Curve, pae []byte) ([]byte, error) {
	switch curve {
	case elliptic.P256():
		h := sha256.Sum256(pae)
		return h[:], nil
	case elliptic.P384():
		h := sha512.Sum384(pae)
		return h[:], nil
	case elliptic.P521():
		h := sha512.Sum512(pae)
		return h[:], nil
	default:
		return nil, fmt.Errorf("%w: unsupported ECDSA curve", ErrInvalidKeyMaterial)
	}
}

// SignDSSE signs rawPayload inside a DSSE v1.0 envelope with payloadType using priv.
func SignDSSE(payloadType string, rawPayload []byte, priv *PrivateKey) (DSSEEnvelope, error) {
	if priv == nil || priv.Signer == nil {
		return DSSEEnvelope{}, fmt.Errorf("%w: nil private key", ErrInvalidKeyMaterial)
	}
	pae := DSSEPAE(payloadType, rawPayload)
	var sigBytes []byte
	var err error

	switch k := priv.Signer.(type) {
	case ed25519.PrivateKey:
		sigBytes = ed25519.Sign(k, pae)
	case *ecdsa.PrivateKey:
		digestBytes, hErr := ecdsaHashPayload(k.Curve, pae)
		if hErr != nil {
			return DSSEEnvelope{}, hErr
		}
		sigBytes, err = ecdsa.SignASN1(rand.Reader, k, digestBytes)
	case *rsa.PrivateKey:
		h := sha256.Sum256(pae)
		sigBytes, err = rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, h[:])
	default:
		return DSSEEnvelope{}, fmt.Errorf("%w: unsupported signer type %T", ErrInvalidKeyMaterial, priv.Signer)
	}
	if err != nil {
		return DSSEEnvelope{}, fmt.Errorf("sign DSSE PAE: %w", err)
	}

	return DSSEEnvelope{
		PayloadType: payloadType,
		Payload:     base64.StdEncoding.EncodeToString(rawPayload),
		Signatures: []DSSESignature{
			{
				KeyID: priv.KeyID,
				Sig:   base64.StdEncoding.EncodeToString(sigBytes),
			},
		},
	}, nil
}

// VerifyPAESignature verifies sigBytes over pae using pub.
func VerifyPAESignature(pae []byte, sigBytes []byte, pub *PublicKey) error {
	if pub == nil || pub.Pub == nil {
		return fmt.Errorf("%w: nil public key", ErrInvalidKeyMaterial)
	}
	switch k := pub.Pub.(type) {
	case ed25519.PublicKey:
		if !ed25519.Verify(k, pae, sigBytes) {
			return fmt.Errorf("%w: ed25519 signature verification failed", ErrInvalidSignature)
		}
		return nil
	case *ecdsa.PublicKey:
		digestBytes, err := ecdsaHashPayload(k.Curve, pae)
		if err != nil {
			return err
		}
		if !ecdsa.VerifyASN1(k, digestBytes, sigBytes) {
			return fmt.Errorf("%w: ecdsa signature verification failed", ErrInvalidSignature)
		}
		return nil
	case *rsa.PublicKey:
		h256 := sha256.Sum256(pae)
		if err := rsa.VerifyPKCS1v15(k, crypto.SHA256, h256[:], sigBytes); err == nil {
			return nil
		}
		if err := rsa.VerifyPSS(k, crypto.SHA256, h256[:], sigBytes, nil); err == nil {
			return nil
		}
		h384 := sha512.Sum384(pae)
		if err := rsa.VerifyPKCS1v15(k, crypto.SHA384, h384[:], sigBytes); err == nil {
			return nil
		}
		if err := rsa.VerifyPSS(k, crypto.SHA384, h384[:], sigBytes, nil); err == nil {
			return nil
		}
		h512 := sha512.Sum512(pae)
		if err := rsa.VerifyPKCS1v15(k, crypto.SHA512, h512[:], sigBytes); err == nil {
			return nil
		}
		if err := rsa.VerifyPSS(k, crypto.SHA512, h512[:], sigBytes, nil); err == nil {
			return nil
		}
		return fmt.Errorf("%w: rsa signature verification failed", ErrInvalidSignature)
	default:
		return fmt.Errorf("%w: unsupported public key type %T", ErrInvalidKeyMaterial, pub.Pub)
	}
}

// WrapInSigstoreBundle wraps a DSSEEnvelope in a Sigstore v0.3 JSON Bundle with a public key hint.
func WrapInSigstoreBundle(env DSSEEnvelope, keyHint string) SigstoreBundle {
	return SigstoreBundle{
		MediaType: SigstoreBundleV03MediaType,
		VerificationMaterial: &SigstoreVerificationMaterial{
			PublicKey: &SigstoreBundlePublicKey{
				Hint: keyHint,
			},
		},
		DSSEEnvelope: &env,
	}
}

// WrapInSigstoreCertificateBundle wraps a DSSEEnvelope and X.509 certificate chain in a Sigstore v0.3 JSON Bundle.
func WrapInSigstoreCertificateBundle(env DSSEEnvelope, certs []*x509.Certificate) (SigstoreBundle, error) {
	if len(certs) == 0 {
		return SigstoreBundle{}, fmt.Errorf("%w: at least one certificate is required", ErrInvalidKeyMaterial)
	}
	items := make([]CertificateMaterial, 0, len(certs))
	for _, c := range certs {
		items = append(items, CertificateMaterial{
			RawBytes: base64.StdEncoding.EncodeToString(c.Raw),
		})
	}
	return SigstoreBundle{
		MediaType: SigstoreBundleV03MediaType,
		VerificationMaterial: &SigstoreVerificationMaterial{
			X509CertificateChain: &X509CertificateChainMaterial{
				Certificates: items,
			},
		},
		DSSEEnvelope: &env,
	}, nil
}

// ParseSigstoreBundle parses a full SigstoreBundle and validates its top-level mediaType and DSSE envelope.
func ParseSigstoreBundle(rawJSON []byte) (SigstoreBundle, error) {
	if len(bytes.TrimSpace(rawJSON)) == 0 {
		return SigstoreBundle{}, fmt.Errorf("%w: empty bundle", ErrInvalidDSSEEnvelope)
	}
	var bundle SigstoreBundle
	if err := json.Unmarshal(rawJSON, &bundle); err != nil {
		return SigstoreBundle{}, fmt.Errorf("%w: decode Sigstore bundle: %v", ErrInvalidDSSEEnvelope, err)
	}
	if !strings.HasPrefix(bundle.MediaType, "application/vnd.dev.sigstore.bundle") {
		return SigstoreBundle{}, fmt.Errorf("%w: invalid Sigstore bundle mediaType %q", ErrInvalidDSSEEnvelope, bundle.MediaType)
	}
	if bundle.VerificationMaterial == nil {
		return SigstoreBundle{}, fmt.Errorf("%w: missing verificationMaterial in Sigstore bundle", ErrInvalidDSSEEnvelope)
	}
	if bundle.DSSEEnvelope == nil {
		return SigstoreBundle{}, fmt.Errorf("%w: missing dsseEnvelope in Sigstore bundle", ErrInvalidDSSEEnvelope)
	}
	if err := validateEnvelope(*bundle.DSSEEnvelope); err != nil {
		return SigstoreBundle{}, err
	}
	if bundle.DSSEEnvelope.PayloadType != InTotoPayloadType {
		return SigstoreBundle{}, fmt.Errorf("%w: unexpected DSSE payloadType %q, expected %q", ErrInvalidDSSEEnvelope, bundle.DSSEEnvelope.PayloadType, InTotoPayloadType)
	}
	return bundle, nil
}

// ParseDSSEOrSigstoreBundle extracts a DSSEEnvelope from either a raw DSSE JSON envelope or a Sigstore Bundle JSON.
func ParseDSSEOrSigstoreBundle(rawJSON []byte) (DSSEEnvelope, bool, error) {
	if len(bytes.TrimSpace(rawJSON)) == 0 {
		return DSSEEnvelope{}, false, fmt.Errorf("%w: empty input", ErrInvalidDSSEEnvelope)
	}
	var probe struct {
		MediaType            string                        `json:"mediaType"`
		VerificationMaterial *SigstoreVerificationMaterial `json:"verificationMaterial"`
		DSSEEnvelope         *DSSEEnvelope                 `json:"dsseEnvelope"`
		PayloadType          string                        `json:"payloadType"`
		Payload              string                        `json:"payload"`
		Signatures           []DSSESignature               `json:"signatures"`
	}
	dec := json.NewDecoder(bytes.NewReader(rawJSON))
	if err := dec.Decode(&probe); err != nil {
		return DSSEEnvelope{}, false, fmt.Errorf("%w: decode JSON: %v", ErrInvalidDSSEEnvelope, err)
	}

	if probe.MediaType != "" || probe.VerificationMaterial != nil || probe.DSSEEnvelope != nil {
		bundle, err := ParseSigstoreBundle(rawJSON)
		if err != nil {
			return DSSEEnvelope{}, true, err
		}
		return *bundle.DSSEEnvelope, true, nil
	}

	env := DSSEEnvelope{
		PayloadType: probe.PayloadType,
		Payload:     probe.Payload,
		Signatures:  probe.Signatures,
	}
	if err := validateEnvelope(env); err != nil {
		return DSSEEnvelope{}, false, err
	}
	return env, false, nil
}

func validateEnvelope(env DSSEEnvelope) error {
	if strings.TrimSpace(env.PayloadType) == "" {
		return fmt.Errorf("%w: missing payloadType", ErrInvalidDSSEEnvelope)
	}
	if strings.TrimSpace(env.Payload) == "" {
		return fmt.Errorf("%w: missing base64 payload", ErrInvalidDSSEEnvelope)
	}
	if len(env.Signatures) == 0 {
		return fmt.Errorf("%w: signatures array is empty", ErrInvalidDSSEEnvelope)
	}
	for i, s := range env.Signatures {
		if strings.TrimSpace(s.Sig) == "" {
			return fmt.Errorf("%w: signature[%d] has empty sig", ErrInvalidDSSEEnvelope, i)
		}
	}
	return nil
}
