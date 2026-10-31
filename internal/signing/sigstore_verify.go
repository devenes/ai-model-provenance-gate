package signing

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strconv"
	"strings"
	"time"
)

//go:embed sigstore_trusted_root.json
var embeddedSigstoreTrustedRoot []byte

var (
	oidExtKeyUsageCodeSigning = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 3}
	oidFulcioIssuerV1         = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1}
	oidFulcioIssuerV2         = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 8}
)

// X509CertificateChainMaterial holds base64-encoded DER certificates in a Sigstore Bundle.
type X509CertificateChainMaterial struct {
	Certificates []CertificateMaterial `json:"certificates"`
}

// CertificateMaterial holds a single base64-encoded DER certificate in a Sigstore Bundle.
type CertificateMaterial struct {
	RawBytes string `json:"rawBytes"`
}

// RekorTlogEntry represents a transparency log entry in a Sigstore Bundle v0.3.
type RekorTlogEntry struct {
	LogIndex          any                  `json:"logIndex"`
	LogID             RekorLogID           `json:"logId"`
	KindVersion       RekorKindVersion     `json:"kindVersion"`
	IntegratedTime    any                  `json:"integratedTime"`
	InclusionPromise  *RekorInclusionProm  `json:"inclusionPromise,omitempty"`
	InclusionProof    *RekorInclusionProof `json:"inclusionProof,omitempty"`
	CanonicalizedBody string               `json:"canonicalizedBody"`
}

// RekorLogID holds the base64 keyId of a Rekor log.
type RekorLogID struct {
	KeyID string `json:"keyId"`
}

// RekorKindVersion identifies the Rekor entry type and version.
type RekorKindVersion struct {
	Kind    string `json:"kind"`
	Version string `json:"version"`
}

// RekorInclusionProm holds the signed entry timestamp (SET).
type RekorInclusionProm struct {
	SignedEntryTimestamp string `json:"signedEntryTimestamp"`
}

// RekorInclusionProof holds the RFC 6962 Merkle inclusion proof and checkpoint.
type RekorInclusionProof struct {
	LogIndex   any              `json:"logIndex"`
	RootHash   string           `json:"rootHash"`
	TreeSize   any              `json:"treeSize"`
	Hashes     []string         `json:"hashes"`
	Checkpoint *RekorCheckpoint `json:"checkpoint,omitempty"`
}

// RekorCheckpoint holds the signed transparency log checkpoint note.
type RekorCheckpoint struct {
	Envelope string `json:"envelope"`
}

// ParseCertificatesPEM parses one or more X.509 certificates from PEM-encoded bytes.
func ParseCertificatesPEM(pemBytes []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("%w: expected CERTIFICATE PEM block, got %q", ErrInvalidKeyMaterial, block.Type)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: parse X.509 certificate: %v", ErrInvalidKeyMaterial, err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("%w: no CERTIFICATE PEM block found", ErrInvalidKeyMaterial)
	}
	return certs, nil
}

// HasCodeSigningEKU checks whether the certificate includes id-kp-codeSigning (1.3.6.1.5.5.7.3.3).
func HasCodeSigningEKU(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}
	for _, u := range cert.ExtKeyUsage {
		if u == x509.ExtKeyUsageCodeSigning {
			return true
		}
	}
	for _, oid := range cert.UnknownExtKeyUsage {
		if oid.Equal(oidExtKeyUsageCodeSigning) {
			return true
		}
	}
	return false
}

func isSelfSignedCertificate(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}
	return bytes.Equal(cert.RawSubject, cert.RawIssuer) && cert.CheckSignatureFrom(cert) == nil
}

// ValidateSigningCertificate validates a leaf signing certificate and optional intermediate chain
// against the private key and current timestamp prior to OMS certificate-based signing.
func ValidateSigningCertificate(signingCert *x509.Certificate, chainCerts []*x509.Certificate, privKey *PrivateKey, now time.Time) ([]*x509.Certificate, error) {
	if signingCert == nil {
		return nil, fmt.Errorf("%w: signing certificate is required", ErrInvalidKeyMaterial)
	}
	if privKey == nil || privKey.PublicKey == nil {
		return nil, fmt.Errorf("%w: private key is required", ErrInvalidKeyMaterial)
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if now.Before(signingCert.NotBefore) || now.After(signingCert.NotAfter) {
		return nil, fmt.Errorf("%w: signing certificate is outside validity window [%s, %s]", ErrInvalidSignature, signingCert.NotBefore.Format(time.RFC3339), signingCert.NotAfter.Format(time.RFC3339))
	}
	if !HasCodeSigningEKU(signingCert) {
		return nil, fmt.Errorf("%w: signing certificate is missing required codeSigning ExtendedKeyUsage", ErrInvalidSignature)
	}

	leafSPKI, err := x509.MarshalPKIXPublicKey(signingCert.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal signing certificate public key: %w", err)
	}
	privSPKI, err := x509.MarshalPKIXPublicKey(privKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal private key public key: %w", err)
	}
	if !bytes.Equal(leafSPKI, privSPKI) {
		return nil, fmt.Errorf("%w: signing certificate public key does not match private key", ErrInvalidSignature)
	}

	bundleCerts := []*x509.Certificate{signingCert}
	for _, c := range chainCerts {
		if now.Before(c.NotBefore) || now.After(c.NotAfter) {
			return nil, fmt.Errorf("%w: chain certificate %q is outside validity window [%s, %s]", ErrInvalidSignature, c.Subject.String(), c.NotBefore.Format(time.RFC3339), c.NotAfter.Format(time.RFC3339))
		}
		if bytes.Equal(c.Raw, signingCert.Raw) {
			continue
		}
		if isSelfSignedCertificate(c) {
			// Self-signed root CAs are trust anchors and are not duplicated in x509CertificateChain when signing a leaf.
			continue
		}
		bundleCerts = append(bundleCerts, c)
	}
	return bundleCerts, nil
}

// VerifyCertificateBundle verifies an X.509 certificate-signed Sigstore Bundle v0.3 against trust anchor certificates
// and returns the verified DSSEEnvelope, decoded payload bytes, and leaf signer PublicKey.
func VerifyCertificateBundle(rawJSON []byte, trustAnchorCerts []*x509.Certificate, now time.Time) (DSSEEnvelope, []byte, *PublicKey, error) {
	bundle, err := ParseSigstoreBundle(rawJSON)
	if err != nil {
		return DSSEEnvelope{}, nil, nil, err
	}
	if bundle.VerificationMaterial.PublicKey != nil || bundle.VerificationMaterial.Certificate != nil {
		return DSSEEnvelope{}, nil, nil, fmt.Errorf("%w: bundle is not a certificate-chain signed bundle", ErrInvalidDSSEEnvelope)
	}
	if bundle.VerificationMaterial.X509CertificateChain == nil || len(bundle.VerificationMaterial.X509CertificateChain.Certificates) == 0 {
		return DSSEEnvelope{}, nil, nil, fmt.Errorf("%w: missing x509CertificateChain in verificationMaterial", ErrInvalidDSSEEnvelope)
	}
	if len(trustAnchorCerts) == 0 {
		return DSSEEnvelope{}, nil, nil, fmt.Errorf("%w: no trust anchor certificates provided for certificate verification", ErrInvalidKeyMaterial)
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}

	var bundleCerts []*x509.Certificate
	for i, cm := range bundle.VerificationMaterial.X509CertificateChain.Certificates {
		if strings.TrimSpace(cm.RawBytes) == "" {
			return DSSEEnvelope{}, nil, nil, fmt.Errorf("%w: empty certificate rawBytes at index %d", ErrInvalidDSSEEnvelope, i)
		}
		derBytes, err := base64.StdEncoding.DecodeString(cm.RawBytes)
		if err != nil {
			return DSSEEnvelope{}, nil, nil, fmt.Errorf("%w: decode base64 certificate at index %d: %v", ErrInvalidDSSEEnvelope, i, err)
		}
		cert, err := x509.ParseCertificate(derBytes)
		if err != nil {
			return DSSEEnvelope{}, nil, nil, fmt.Errorf("%w: parse DER certificate at index %d: %v", ErrInvalidDSSEEnvelope, i, err)
		}
		if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
			return DSSEEnvelope{}, nil, nil, fmt.Errorf("%w: bundle certificate %q is outside validity window [%s, %s]", ErrInvalidSignature, cert.Subject.String(), cert.NotBefore.Format(time.RFC3339), cert.NotAfter.Format(time.RFC3339))
		}
		bundleCerts = append(bundleCerts, cert)
	}

	leaf := bundleCerts[0]
	if !HasCodeSigningEKU(leaf) {
		return DSSEEnvelope{}, nil, nil, fmt.Errorf("%w: leaf certificate is missing codeSigning ExtendedKeyUsage", ErrInvalidSignature)
	}

	roots := x509.NewCertPool()
	intermediates := x509.NewCertPool()
	hasRoot := false
	for _, c := range bundleCerts[1:] {
		intermediates.AddCert(c)
	}
	for _, tc := range trustAnchorCerts {
		if now.Before(tc.NotBefore) || now.After(tc.NotAfter) {
			return DSSEEnvelope{}, nil, nil, fmt.Errorf("%w: trust certificate %q is outside validity window [%s, %s]", ErrInvalidSignature, tc.Subject.String(), tc.NotBefore.Format(time.RFC3339), tc.NotAfter.Format(time.RFC3339))
		}
		if isSelfSignedCertificate(tc) {
			roots.AddCert(tc)
			hasRoot = true
		} else {
			intermediates.AddCert(tc)
		}
	}
	if !hasRoot {
		for _, tc := range trustAnchorCerts {
			roots.AddCert(tc)
		}
	}

	verifyOpts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}
	if _, err := leaf.Verify(verifyOpts); err != nil {
		return DSSEEnvelope{}, nil, nil, fmt.Errorf("%w: X.509 certificate chain verification failed: %v", ErrInvalidSignature, err)
	}

	leafPubKey, err := PublicKeyFromX509Cert(leaf)
	if err != nil {
		return DSSEEnvelope{}, nil, nil, err
	}
	rawPayload, err := verifyEnvelopeWithSingleKey(*bundle.DSSEEnvelope, leafPubKey)
	if err != nil {
		return DSSEEnvelope{}, nil, nil, err
	}
	return *bundle.DSSEEnvelope, rawPayload, leafPubKey, nil
}

type sigstoreTrustedRootDoc struct {
	CertificateAuthorities []struct {
		CertChain struct {
			Certificates []CertificateMaterial `json:"certificates"`
		} `json:"certChain"`
	} `json:"certificateAuthorities"`
	Tlogs []struct {
		BaseURL   string `json:"baseUrl"`
		PublicKey struct {
			RawBytes   string `json:"rawBytes"`
			KeyDetails string `json:"keyDetails"`
		} `json:"publicKey"`
	} `json:"tlogs"`
}

// VerifySigstoreBundle verifies a keyless Sigstore Bundle v0.3:
// 1. Validates Fulcio leaf certificate chain against Sigstore Trusted Root CAs at Rekor integratedTime.
// 2. Validates leaf certificate codeSigning EKU, Subject Alternative Name (--certificate-identity), and Fulcio OIDC Issuer (--certificate-oidc-issuer).
// 3. Validates Rekor transparency log entry (canonicalizedBody payloadHash, SET or RFC 6962 Merkle inclusionProof + signed checkpoint).
// 4. Validates DSSE PAE signature using the Fulcio leaf certificate's public key.
func VerifySigstoreBundle(rawJSON []byte, expectedIdentity, expectedOIDCIssuer string, customTrustedRootJSON []byte) (DSSEEnvelope, []byte, *PublicKey, error) {
	bundle, err := ParseSigstoreBundle(rawJSON)
	if err != nil {
		return DSSEEnvelope{}, nil, nil, err
	}
	if bundle.VerificationMaterial.PublicKey != nil || bundle.VerificationMaterial.X509CertificateChain != nil {
		return DSSEEnvelope{}, nil, nil, fmt.Errorf("%w: bundle is not a keyless Sigstore bundle (contains publicKey or x509CertificateChain)", ErrInvalidDSSEEnvelope)
	}
	if bundle.VerificationMaterial.Certificate == nil || strings.TrimSpace(bundle.VerificationMaterial.Certificate.RawBytes) == "" {
		return DSSEEnvelope{}, nil, nil, fmt.Errorf("%w: keyless Sigstore bundle requires verificationMaterial.certificate.rawBytes", ErrInvalidDSSEEnvelope)
	}
	if len(bundle.VerificationMaterial.TlogEntries) == 0 {
		return DSSEEnvelope{}, nil, nil, fmt.Errorf("%w: keyless Sigstore bundle requires at least one Rekor tlogEntry", ErrInvalidDSSEEnvelope)
	}

	leafDER, err := base64.StdEncoding.DecodeString(bundle.VerificationMaterial.Certificate.RawBytes)
	if err != nil {
		return DSSEEnvelope{}, nil, nil, fmt.Errorf("%w: decode Fulcio certificate: %v", ErrInvalidDSSEEnvelope, err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return DSSEEnvelope{}, nil, nil, fmt.Errorf("%w: parse Fulcio certificate: %v", ErrInvalidDSSEEnvelope, err)
	}
	if !HasCodeSigningEKU(leaf) {
		return DSSEEnvelope{}, nil, nil, fmt.Errorf("%w: Fulcio certificate missing codeSigning ExtendedKeyUsage", ErrInvalidSignature)
	}

	// Verify SAN identity (--certificate-identity)
	if strings.TrimSpace(expectedIdentity) == "" {
		return DSSEEnvelope{}, nil, nil, fmt.Errorf("%w: expected certificate identity is required for Sigstore verification", ErrInvalidSignature)
	}
	if !matchCertificateSAN(leaf, expectedIdentity) {
		return DSSEEnvelope{}, nil, nil, fmt.Errorf("%w: Fulcio certificate SAN %v does not match expected identity %q", ErrInvalidSignature, extractAllSANs(leaf), expectedIdentity)
	}

	// Verify Fulcio OIDC Issuer (--certificate-oidc-issuer)
	if strings.TrimSpace(expectedOIDCIssuer) == "" {
		return DSSEEnvelope{}, nil, nil, fmt.Errorf("%w: expected OIDC issuer is required for Sigstore verification", ErrInvalidSignature)
	}
	gotIssuer := extractFulcioOIDCIssuer(leaf)
	if gotIssuer != expectedOIDCIssuer {
		return DSSEEnvelope{}, nil, nil, fmt.Errorf("%w: Fulcio OIDC issuer %q does not match expected issuer %q", ErrInvalidSignature, gotIssuer, expectedOIDCIssuer)
	}

	// Parse Trusted Root
	trRaw := embeddedSigstoreTrustedRoot
	if len(customTrustedRootJSON) > 0 {
		trRaw = customTrustedRootJSON
	}
	var tr sigstoreTrustedRootDoc
	if err := json.Unmarshal(trRaw, &tr); err != nil {
		return DSSEEnvelope{}, nil, nil, fmt.Errorf("parse Sigstore trusted_root.json: %w", err)
	}

	roots := x509.NewCertPool()
	intermediates := x509.NewCertPool()
	for _, ca := range tr.CertificateAuthorities {
		for _, cm := range ca.CertChain.Certificates {
			der, err := base64.StdEncoding.DecodeString(cm.RawBytes)
			if err != nil {
				continue
			}
			c, err := x509.ParseCertificate(der)
			if err != nil {
				continue
			}
			if isSelfSignedCertificate(c) {
				roots.AddCert(c)
			} else {
				intermediates.AddCert(c)
			}
		}
	}

	rekorKeys := make(map[string]crypto.PublicKey)
	rekorKeyHexIDs := make(map[string]string)
	for _, tl := range tr.Tlogs {
		der, err := base64.StdEncoding.DecodeString(tl.PublicKey.RawBytes)
		if err != nil {
			continue
		}
		pub, err := x509.ParsePKIXPublicKey(der)
		if err != nil {
			continue
		}
		sum := sha256.Sum256(der)
		b64KeyID := base64.StdEncoding.EncodeToString(sum[:])
		rekorKeys[b64KeyID] = pub
		rekorKeyHexIDs[b64KeyID] = hex.EncodeToString(sum[:])
	}

	leafPubKey, err := PublicKeyFromX509Cert(leaf)
	if err != nil {
		return DSSEEnvelope{}, nil, nil, err
	}
	rawPayload, err := verifyEnvelopeWithSingleKey(*bundle.DSSEEnvelope, leafPubKey)
	if err != nil {
		return DSSEEnvelope{}, nil, nil, err
	}
	payloadHashSum := sha256.Sum256(rawPayload)
	payloadHashHex := hex.EncodeToString(payloadHashSum[:])

	// Verify Rekor tlogEntry and Fulcio validity at integratedTime
	tlog := bundle.VerificationMaterial.TlogEntries[0]
	integratedUnix, err := parseAnyInt64(tlog.IntegratedTime)
	if err != nil || integratedUnix <= 0 {
		return DSSEEnvelope{}, nil, nil, fmt.Errorf("%w: invalid Rekor integratedTime: %v", ErrInvalidSignature, tlog.IntegratedTime)
	}
	integratedTime := time.Unix(integratedUnix, 0).UTC()
	if integratedTime.Before(leaf.NotBefore) || integratedTime.After(leaf.NotAfter) {
		return DSSEEnvelope{}, nil, nil, fmt.Errorf("%w: Rekor integratedTime %s is outside Fulcio certificate validity [%s, %s]", ErrInvalidSignature, integratedTime.Format(time.RFC3339), leaf.NotBefore.Format(time.RFC3339), leaf.NotAfter.Format(time.RFC3339))
	}

	// Verify Fulcio certificate chain at integratedTime
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   integratedTime,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}); err != nil {
		return DSSEEnvelope{}, nil, nil, fmt.Errorf("%w: Fulcio certificate chain verification failed: %v", ErrInvalidSignature, err)
	}

	// Verify Rekor canonicalizedBody and cryptographic log proof
	if err := verifyRekorEntry(tlog, payloadHashHex, rekorKeys, rekorKeyHexIDs); err != nil {
		return DSSEEnvelope{}, nil, nil, err
	}

	leafPubKey.Name = fmt.Sprintf("sigstore:%s (%s)", expectedIdentity, expectedOIDCIssuer)
	return *bundle.DSSEEnvelope, rawPayload, leafPubKey, nil
}

func verifyEnvelopeWithSingleKey(env DSSEEnvelope, pub *PublicKey) ([]byte, error) {
	rawPayload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, fmt.Errorf("%w: decode base64 payload: %v", ErrInvalidDSSEEnvelope, err)
	}
	pae := DSSEPAE(env.PayloadType, rawPayload)
	for _, sig := range env.Signatures {
		sigBytes, err := base64.StdEncoding.DecodeString(sig.Sig)
		if err != nil {
			continue
		}
		if err := VerifyPAESignature(pae, sigBytes, pub); err == nil {
			return rawPayload, nil
		}
		// Backward-compatibility fallback for legacy OMS v0.2.0 (https://model_signing/Digests/v0.1)
		// per spec/v1.0.md §11 and model_signing._signing.sign_sigstore_pb.pae_compat.
		if bytes.Contains(rawPayload, []byte("https://model_signing/Digests/v0.1")) {
			if ecPub, ok := pub.Pub.(*ecdsa.PublicKey); ok {
				escapedPayload := strings.ReplaceAll(string(rawPayload), "\n", `\n`)
				compatPAE := fmt.Sprintf("DSSEV1 %d %s %d b'%s'", len(env.PayloadType), env.PayloadType, len(rawPayload), escapedPayload)
				sum := sha256.Sum256([]byte(compatPAE))
				if ecdsa.VerifyASN1(ecPub, sum[:], sigBytes) {
					return rawPayload, nil
				}
			}
		}
	}
	return nil, fmt.Errorf("%w: DSSE PAE signature verification failed", ErrInvalidSignature)
}

func verifyRekorEntry(tlog RekorTlogEntry, expectedPayloadSHA256Hex string, rekorKeys map[string]crypto.PublicKey, rekorKeyHexIDs map[string]string) error {
	cbodyBytes, err := base64.StdEncoding.DecodeString(tlog.CanonicalizedBody)
	if err != nil {
		return fmt.Errorf("%w: decode Rekor canonicalizedBody: %v", ErrInvalidSignature, err)
	}
	var cbody struct {
		Kind string `json:"kind"`
		Spec struct {
			PayloadHash struct {
				Algorithm string `json:"algorithm"`
				Value     string `json:"value"`
			} `json:"payloadHash"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(cbodyBytes, &cbody); err != nil {
		return fmt.Errorf("%w: parse Rekor canonicalizedBody: %v", ErrInvalidSignature, err)
	}
	if !strings.EqualFold(cbody.Spec.PayloadHash.Value, expectedPayloadSHA256Hex) {
		return fmt.Errorf("%w: Rekor entry payloadHash %q does not match DSSE payload SHA-256 %q", ErrInvalidSignature, cbody.Spec.PayloadHash.Value, expectedPayloadSHA256Hex)
	}

	rekorPub, ok := rekorKeys[tlog.LogID.KeyID]
	if !ok {
		return fmt.Errorf("%w: untrusted Rekor logId %q", ErrInvalidSignature, tlog.LogID.KeyID)
	}

	verifiedProofOrSET := false

	// 1. Verify SignedEntryTimestamp (SET) if present
	if tlog.InclusionPromise != nil && tlog.InclusionPromise.SignedEntryTimestamp != "" {
		setSig, err := base64.StdEncoding.DecodeString(tlog.InclusionPromise.SignedEntryTimestamp)
		if err != nil {
			return fmt.Errorf("%w: decode Rekor SET: %v", ErrInvalidSignature, err)
		}
		integratedUnix, err := parseAnyInt64(tlog.IntegratedTime)
		if err != nil {
			return fmt.Errorf("%w: invalid integratedTime: %v", ErrInvalidSignature, err)
		}
		logIdx, err := parseAnyInt64(tlog.LogIndex)
		if err != nil {
			return fmt.Errorf("%w: invalid logIndex: %v", ErrInvalidSignature, err)
		}
		logIDHex := rekorKeyHexIDs[tlog.LogID.KeyID]
		// RFC 8785 canonical JSON of {"body":...,"integratedTime":...,"logID":...,"logIndex":...}
		canonicalSET := fmt.Sprintf(
			`{"body":%q,"integratedTime":%d,"logID":%q,"logIndex":%d}`,
			tlog.CanonicalizedBody, integratedUnix, logIDHex, logIdx,
		)
		if err := verifyRawSignature(rekorPub, []byte(canonicalSET), setSig); err != nil {
			return fmt.Errorf("%w: Rekor SignedEntryTimestamp verification failed: %v", ErrInvalidSignature, err)
		}
		verifiedProofOrSET = true
	}

	// 2. Verify RFC 6962 Merkle inclusionProof + checkpoint signature if present
	if tlog.InclusionProof != nil {
		ip := tlog.InclusionProof
		idx, err := parseAnyInt64(ip.LogIndex)
		if err != nil {
			return fmt.Errorf("%w: invalid inclusionProof.logIndex: %v", ErrInvalidSignature, err)
		}
		treeSize, err := parseAnyInt64(ip.TreeSize)
		if err != nil {
			return fmt.Errorf("%w: invalid inclusionProof.treeSize: %v", ErrInvalidSignature, err)
		}
		expectedRoot, err := base64.StdEncoding.DecodeString(ip.RootHash)
		if err != nil {
			return fmt.Errorf("%w: decode inclusionProof.rootHash: %v", ErrInvalidSignature, err)
		}
		leafInput := append([]byte{0x00}, cbodyBytes...)
		leafHash := sha256.Sum256(leafInput)
		if !verifyRFC6962InclusionProof(leafHash[:], idx, treeSize, ip.Hashes, expectedRoot) {
			return fmt.Errorf("%w: Rekor RFC 6962 Merkle inclusion proof verification failed", ErrInvalidSignature)
		}
		if ip.Checkpoint == nil || strings.TrimSpace(ip.Checkpoint.Envelope) == "" {
			return fmt.Errorf("%w: missing Rekor inclusionProof.checkpoint", ErrInvalidSignature)
		}
		if err := verifyRekorCheckpoint(ip.Checkpoint.Envelope, expectedRoot, treeSize, rekorPub); err != nil {
			return err
		}
		verifiedProofOrSET = true
	}

	if !verifiedProofOrSET {
		return fmt.Errorf("%w: Rekor tlogEntry contains neither inclusionPromise nor inclusionProof", ErrInvalidSignature)
	}
	return nil
}

func verifyRFC6962InclusionProof(leafHash []byte, index, treeSize int64, auditPathB64 []string, expectedRoot []byte) bool {
	if index < 0 || index >= treeSize || treeSize <= 0 {
		return false
	}
	fn := index
	sn := treeSize - 1
	r := append([]byte(nil), leafHash...)
	for _, hB64 := range auditPathB64 {
		p, err := base64.StdEncoding.DecodeString(hB64)
		if err != nil {
			return false
		}
		h := sha256.New()
		h.Write([]byte{0x01})
		if fn == sn || (fn&1) == 1 {
			h.Write(p)
			h.Write(r)
			r = h.Sum(nil)
			for (fn&1) == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			h.Write(r)
			h.Write(p)
			r = h.Sum(nil)
		}
		fn >>= 1
		sn >>= 1
	}
	return sn == 0 && bytes.Equal(r, expectedRoot)
}

func verifyRekorCheckpoint(envelope string, expectedRoot []byte, expectedTreeSize int64, rekorPub crypto.PublicKey) error {
	parts := strings.SplitN(envelope, "\n\n", 2)
	if len(parts) != 2 {
		return fmt.Errorf("%w: malformed Rekor checkpoint envelope", ErrInvalidSignature)
	}
	bodyLines := strings.Split(parts[0], "\n")
	if len(bodyLines) < 3 {
		return fmt.Errorf("%w: Rekor checkpoint body has fewer than 3 lines", ErrInvalidSignature)
	}
	cpTreeSize, err := strconv.ParseInt(strings.TrimSpace(bodyLines[1]), 10, 64)
	if err != nil || cpTreeSize != expectedTreeSize {
		return fmt.Errorf("%w: Rekor checkpoint treeSize %q does not match %d", ErrInvalidSignature, bodyLines[1], expectedTreeSize)
	}
	cpRoot, err := base64.StdEncoding.DecodeString(strings.TrimSpace(bodyLines[2]))
	if err != nil || !bytes.Equal(cpRoot, expectedRoot) {
		return fmt.Errorf("%w: Rekor checkpoint rootHash mismatch", ErrInvalidSignature)
	}

	noteMsg := []byte(parts[0] + "\n")
	fields := strings.Fields(parts[1])
	if len(fields) == 0 {
		return fmt.Errorf("%w: Rekor checkpoint missing signature line", ErrInvalidSignature)
	}
	sigB64 := fields[len(fields)-1]
	sigRawWithHint, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil || len(sigRawWithHint) <= 4 {
		return fmt.Errorf("%w: invalid Rekor checkpoint signature encoding", ErrInvalidSignature)
	}
	sigRaw := sigRawWithHint[4:]
	if err := verifyRawSignature(rekorPub, noteMsg, sigRaw); err != nil {
		return fmt.Errorf("%w: Rekor checkpoint signature verification failed: %v", ErrInvalidSignature, err)
	}
	return nil
}

func verifyRawSignature(pub crypto.PublicKey, msg, sig []byte) error {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		sum := sha256.Sum256(msg)
		if !ecdsa.VerifyASN1(k, sum[:], sig) {
			return fmt.Errorf("ECDSA signature invalid")
		}
		return nil
	case ed25519.PublicKey:
		if !ed25519.Verify(k, msg, sig) {
			return fmt.Errorf("Ed25519 signature invalid")
		}
		return nil
	default:
		return fmt.Errorf("unsupported transparency log key type %T", pub)
	}
}

func parseAnyInt64(v any) (int64, error) {
	switch val := v.(type) {
	case float64:
		return int64(val), nil
	case int64:
		return val, nil
	case int:
		return int64(val), nil
	case json.Number:
		return val.Int64()
	case string:
		return strconv.ParseInt(strings.TrimSpace(val), 10, 64)
	default:
		return 0, fmt.Errorf("unsupported integer representation %T", v)
	}
}

func extractAllSANs(cert *x509.Certificate) []string {
	var out []string
	out = append(out, cert.EmailAddresses...)
	for _, u := range cert.URIs {
		out = append(out, u.String())
	}
	out = append(out, cert.DNSNames...)
	return out
}

func matchCertificateSAN(cert *x509.Certificate, expected string) bool {
	for _, s := range extractAllSANs(cert) {
		if s == expected {
			return true
		}
	}
	return false
}

func extractFulcioOIDCIssuer(cert *x509.Certificate) string {
	// Prefer Fulcio v2 OID (1.3.6.1.4.1.57264.1.8) which encodes a DER UTF8String.
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidFulcioIssuerV2) {
			var s string
			if _, err := asn1.Unmarshal(ext.Value, &s); err == nil && s != "" {
				return s
			}
		}
	}
	// Fallback to Fulcio v1 OID (1.3.6.1.4.1.57264.1.1) which stores raw ASCII bytes.
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidFulcioIssuerV1) {
			return string(ext.Value)
		}
	}
	return ""
}

// PublicKeyFromX509Cert extracts a *PublicKey from a parsed X.509 certificate.
func PublicKeyFromX509Cert(cert *x509.Certificate) (*PublicKey, error) {
	fp, alg, err := PublicKeyFingerprintAndAlg(cert.PublicKey)
	if err != nil {
		return nil, err
	}
	fpHex := strings.TrimPrefix(fp, "sha256:")
	return &PublicKey{
		KeyID:       fpHex[:16],
		Name:        cert.Subject.String(),
		Algorithm:   alg,
		Fingerprint: fp,
		Pub:         cert.PublicKey,
	}, nil
}
