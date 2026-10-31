// Package verification verifies DSSE v1.0 envelopes, Sigstore bundles, in-toto v1 statements,
// and signer trust policies without conflating valid cryptography with signer authorization.
package verification

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/devenes/ai-model-provenance-gate/internal/signing"
)

// Status represents the result of cryptographic and signer-trust verification.
type Status string

const (
	// StatusVerified indicates a valid signature from a configured trusted signer.
	StatusVerified Status = "VERIFIED"
	// StatusInvalid indicates a malformed envelope, tampered payload, or failed signature verification.
	StatusInvalid Status = "INVALID"
	// StatusUntrusted indicates a valid signature from a key/signer not in the trusted signers list,
	// or a signature whose keyid/fingerprint conflicts with policy trust roots.
	StatusUntrusted Status = "UNTRUSTED"
	// StatusMissing indicates no signature artifact was provided.
	StatusMissing Status = "MISSING"
	// StatusBlocked indicates verification could not be executed because verification material or a required tool was unavailable.
	StatusBlocked Status = "BLOCKED"
	// StatusNotRun indicates verification was not requested.
	StatusNotRun Status = "NOT_RUN"
)

var (
	// ErrMissingVerificationMaterial is returned when offline verification is requested without any public keys.
	ErrMissingVerificationMaterial = errors.New("missing trusted public key verification material for offline verification")
	// ErrUntrustedSigner is returned when a signature is valid under an untrusted key or does not match trusted signers.
	ErrUntrustedSigner = errors.New("signature was produced by an untrusted signer")
	// ErrInvalidSignature is returned when cryptographic verification or statement validation fails.
	ErrInvalidSignature = errors.New("invalid cryptographic signature or statement")
)

// TrustedSignerRule defines an authorized signer in policy.
type TrustedSignerRule struct {
	ID                       string
	Name                     string
	Role                     string
	AllowOperatorEndorsement bool
	KeyID                    string
	KeyFingerprint           string // optional "sha256:<64-hex>" constraint
	PublicKey                *signing.PublicKey
}

// EnvelopeVerification holds the outcome of verifying a DSSE / Sigstore bundle envelope.
type EnvelopeVerification struct {
	Status                   Status                  `json:"status"`
	IsSigstoreBundle         bool                    `json:"is_sigstore_bundle"`
	VerificationMethod       string                  `json:"verification_method,omitempty"`
	MatchedSignerID          string                  `json:"matched_signer_id,omitempty"`
	MatchedSignerName        string                  `json:"matched_signer_name,omitempty"`
	MatchedSignerRole        string                  `json:"matched_signer_role,omitempty"`
	AllowOperatorEndorsement bool                    `json:"allow_operator_endorsement,omitempty"`
	SignerKeyID              string                  `json:"signer_key_id,omitempty"`
	SignerFingerprint        string                  `json:"signer_fingerprint,omitempty"`
	Algorithm                string                  `json:"algorithm,omitempty"`
	Statement                signing.InTotoStatement `json:"statement"`
	RawPayload               []byte                  `json:"-"`
	Reason                   string                  `json:"reason,omitempty"`
}

func decodeAndValidateInTotoStatement(rawPayload []byte) (signing.InTotoStatement, error) {
	var stmt signing.InTotoStatement
	dec := json.NewDecoder(bytes.NewReader(rawPayload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&stmt); err != nil {
		return signing.InTotoStatement{}, fmt.Errorf("decode in-toto Statement v1: %v", err)
	}
	if stmt.Type != signing.InTotoStatementV1Type {
		return signing.InTotoStatement{}, fmt.Errorf("unexpected in-toto _type %q (expected %q)", stmt.Type, signing.InTotoStatementV1Type)
	}
	if len(stmt.Subject) == 0 {
		return signing.InTotoStatement{}, errors.New("in-toto statement subject array is empty")
	}
	return stmt, nil
}

// VerifyInTotoDSSE parses rawEnvelopeJSON (DSSE or bare-key Sigstore Bundle), verifies the cryptographic signature
// over the DSSE v1.0 PAE against trustedSigners (and optional candidateUntrustedKeys to distinguish UNTRUSTED vs INVALID),
// and decodes the in-toto v1 Statement.
func VerifyInTotoDSSE(
	rawEnvelopeJSON []byte,
	trustedSigners []TrustedSignerRule,
	candidateUntrustedKeys []*signing.PublicKey,
) (EnvelopeVerification, error) {
	if len(trustedSigners) == 0 && len(candidateUntrustedKeys) == 0 {
		return EnvelopeVerification{
			Status: StatusBlocked,
			Reason: ErrMissingVerificationMaterial.Error(),
		}, ErrMissingVerificationMaterial
	}

	env, isBundle, err := signing.ParseDSSEOrSigstoreBundle(rawEnvelopeJSON)
	if err != nil {
		return EnvelopeVerification{
			Status: StatusInvalid,
			Reason: err.Error(),
		}, fmt.Errorf("%w: %v", ErrInvalidSignature, err)
	}

	var bundleKeyHint string
	if isBundle {
		sb, sbErr := signing.ParseSigstoreBundle(rawEnvelopeJSON)
		if sbErr != nil {
			return EnvelopeVerification{
				Status: StatusInvalid,
				Reason: sbErr.Error(),
			}, fmt.Errorf("%w: %v", ErrInvalidSignature, sbErr)
		}
		if sb.VerificationMaterial.X509CertificateChain != nil || sb.VerificationMaterial.Certificate != nil {
			reason := "bundle uses certificate or keyless Sigstore verification material and cannot be verified with bare-key method"
			return EnvelopeVerification{
				Status:           StatusInvalid,
				IsSigstoreBundle: true,
				Reason:           reason,
			}, fmt.Errorf("%w: %s", ErrInvalidSignature, reason)
		}
		if sb.VerificationMaterial.PublicKey == nil {
			reason := "bare-key Sigstore bundle is missing verificationMaterial.publicKey"
			return EnvelopeVerification{
				Status:           StatusInvalid,
				IsSigstoreBundle: true,
				Reason:           reason,
			}, fmt.Errorf("%w: %s", ErrInvalidSignature, reason)
		}
		bundleKeyHint = sb.VerificationMaterial.PublicKey.Hint
	}

	if env.PayloadType != signing.InTotoPayloadType {
		reason := fmt.Sprintf("unexpected DSSE payloadType %q (expected %q)", env.PayloadType, signing.InTotoPayloadType)
		return EnvelopeVerification{
			Status: StatusInvalid,
			Reason: reason,
		}, fmt.Errorf("%w: %s", ErrInvalidSignature, reason)
	}

	rawPayload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		reason := fmt.Sprintf("decode base64 DSSE payload: %v", err)
		return EnvelopeVerification{
			Status: StatusInvalid,
			Reason: reason,
		}, fmt.Errorf("%w: %s", ErrInvalidSignature, reason)
	}

	pae := signing.DSSEPAE(env.PayloadType, rawPayload)

	stmt, err := decodeAndValidateInTotoStatement(rawPayload)
	if err != nil {
		return EnvelopeVerification{
			Status: StatusInvalid,
			Reason: err.Error(),
		}, fmt.Errorf("%w: %s", ErrInvalidSignature, err.Error())
	}

	// Check signatures against trustedSigners first.
	var fingerprintMismatchReason string
	for _, sigEntry := range env.Signatures {
		sigBytes, decErr := base64.StdEncoding.DecodeString(sigEntry.Sig)
		if decErr != nil {
			return EnvelopeVerification{
				Status: StatusInvalid,
				Reason: fmt.Sprintf("decode base64 signature: %v", decErr),
			}, fmt.Errorf("%w: decode base64 signature: %v", ErrInvalidSignature, decErr)
		}

		for _, ts := range trustedSigners {
			if ts.PublicKey == nil {
				continue
			}
			if err := signing.VerifyPAESignature(pae, sigBytes, ts.PublicKey); err == nil {
				// Cryptographic verification succeeded with ts.PublicKey!
				// Now verify policy constraints (expected KeyFingerprint and KeyID if specified).
				if ts.KeyFingerprint != "" && ts.KeyFingerprint != ts.PublicKey.Fingerprint {
					fingerprintMismatchReason = fmt.Sprintf(
						"public key fingerprint %s does not match trusted signer rule fingerprint %s",
						ts.PublicKey.Fingerprint, ts.KeyFingerprint,
					)
					continue
				}
				if ts.KeyID != "" && sigEntry.KeyID != "" && ts.KeyID != sigEntry.KeyID {
					fingerprintMismatchReason = fmt.Sprintf(
						"signature keyid %q does not match trusted signer rule keyid %q",
						sigEntry.KeyID, ts.KeyID,
					)
					continue
				}
				signerID := ts.ID
				if signerID == "" {
					signerID = ts.PublicKey.KeyID
				}
				effectiveKeyID := sigEntry.KeyID
				if effectiveKeyID == "" {
					effectiveKeyID = bundleKeyHint
				}
				return EnvelopeVerification{
					Status:                   StatusVerified,
					IsSigstoreBundle:         isBundle,
					VerificationMethod:       "key",
					MatchedSignerID:          signerID,
					MatchedSignerName:        ts.Name,
					MatchedSignerRole:        ts.Role,
					AllowOperatorEndorsement: ts.AllowOperatorEndorsement,
					SignerKeyID:              effectiveKeyID,
					SignerFingerprint:        ts.PublicKey.Fingerprint,
					Algorithm:                ts.PublicKey.Algorithm,
					Statement:                stmt,
					RawPayload:               rawPayload,
					Reason:                   "cryptographic signature and trusted signer verified",
				}, nil
			}
		}

		// Check if signature is mathematically valid under a known untrusted key (or if trustedSigners was empty).
		for _, uk := range candidateUntrustedKeys {
			if uk == nil {
				continue
			}
			if err := signing.VerifyPAESignature(pae, sigBytes, uk); err == nil {
				reason := fmt.Sprintf(
					"signature is cryptographically valid for key %s (keyid=%q), but signer is not in trusted_signers",
					uk.Fingerprint, sigEntry.KeyID,
				)
				return EnvelopeVerification{
					Status:             StatusUntrusted,
					IsSigstoreBundle:   isBundle,
					VerificationMethod: "key",
					SignerKeyID:        sigEntry.KeyID,
					SignerFingerprint:  uk.Fingerprint,
					Algorithm:          uk.Algorithm,
					Statement:          stmt,
					RawPayload:         rawPayload,
					Reason:             reason,
				}, fmt.Errorf("%w: %s", ErrUntrustedSigner, reason)
			}
		}
	}

	if fingerprintMismatchReason != "" {
		return EnvelopeVerification{
			Status:           StatusUntrusted,
			IsSigstoreBundle: isBundle,
			Statement:        stmt,
			Reason:           fingerprintMismatchReason,
		}, fmt.Errorf("%w: %s", ErrUntrustedSigner, fingerprintMismatchReason)
	}

	// Distinguish a signature whose keyid/hint is completely unknown from a corrupted signature for a known keyid.
	sigKeyID := ""
	if len(env.Signatures) > 0 {
		sigKeyID = env.Signatures[0].KeyID
	}
	if sigKeyID == "" {
		sigKeyID = bundleKeyHint
	}
	if len(trustedSigners) > 0 && sigKeyID != "" {
		keyIDKnown := false
		for _, ts := range trustedSigners {
			fpHex := ""
			if ts.PublicKey != nil {
				fpHex = strings.TrimPrefix(ts.PublicKey.Fingerprint, "sha256:")
			}
			if ts.KeyID == sigKeyID || (ts.PublicKey != nil && ts.PublicKey.KeyID == sigKeyID) || ts.ID == sigKeyID || fpHex == sigKeyID {
				keyIDKnown = true
				break
			}
		}
		if !keyIDKnown {
			reason := fmt.Sprintf("signature keyid/hint %q does not match any configured trusted signer (%d trusted signers checked)", sigKeyID, len(trustedSigners))
			return EnvelopeVerification{
				Status:           StatusUntrusted,
				IsSigstoreBundle: isBundle,
				SignerKeyID:      sigKeyID,
				Statement:        stmt,
				Reason:           reason,
			}, fmt.Errorf("%w: %s", ErrUntrustedSigner, reason)
		}
	}

	var triedIDs []string
	for _, ts := range trustedSigners {
		if ts.PublicKey != nil {
			triedIDs = append(triedIDs, ts.PublicKey.Fingerprint)
		}
	}
	reason := fmt.Sprintf("cryptographic signature verification failed against trusted key(s) [%s]", strings.Join(triedIDs, ", "))
	return EnvelopeVerification{
		Status:           StatusInvalid,
		IsSigstoreBundle: isBundle,
		Statement:        stmt,
		Reason:           reason,
	}, fmt.Errorf("%w: %s", ErrInvalidSignature, reason)
}

// VerifyInTotoCertificateBundle verifies an X.509 certificate-signed Sigstore Bundle and decodes its in-toto Statement v1.
func VerifyInTotoCertificateBundle(
	rawEnvelopeJSON []byte,
	trustAnchorCerts []*x509.Certificate,
	now time.Time,
) (EnvelopeVerification, error) {
	if len(trustAnchorCerts) == 0 {
		return EnvelopeVerification{
			Status: StatusBlocked,
			Reason: "missing X.509 trust anchor certificates for certificate verification",
		}, ErrMissingVerificationMaterial
	}
	_, rawPayload, leafPubKey, err := signing.VerifyCertificateBundle(rawEnvelopeJSON, trustAnchorCerts, now)
	if err != nil {
		return EnvelopeVerification{
			Status:             StatusInvalid,
			IsSigstoreBundle:   true,
			VerificationMethod: "certificate",
			Reason:             err.Error(),
		}, fmt.Errorf("%w: %v", ErrInvalidSignature, err)
	}
	stmt, err := decodeAndValidateInTotoStatement(rawPayload)
	if err != nil {
		return EnvelopeVerification{
			Status:             StatusInvalid,
			IsSigstoreBundle:   true,
			VerificationMethod: "certificate",
			Reason:             err.Error(),
		}, fmt.Errorf("%w: %s", ErrInvalidSignature, err.Error())
	}
	return EnvelopeVerification{
		Status:             StatusVerified,
		IsSigstoreBundle:   true,
		VerificationMethod: "certificate",
		MatchedSignerID:    leafPubKey.KeyID,
		MatchedSignerName:  leafPubKey.Name,
		SignerKeyID:        leafPubKey.KeyID,
		SignerFingerprint:  leafPubKey.Fingerprint,
		Algorithm:          leafPubKey.Algorithm,
		Statement:          stmt,
		RawPayload:         rawPayload,
		Reason:             "X.509 certificate chain and DSSE signature verified",
	}, nil
}

// VerifyInTotoSigstoreBundle verifies a keyless Sigstore Bundle (Fulcio + Rekor + OIDC identity/issuer)
// and decodes its in-toto Statement v1.
func VerifyInTotoSigstoreBundle(
	rawEnvelopeJSON []byte,
	expectedIdentity string,
	expectedOIDCIssuer string,
	customTrustedRootJSON []byte,
) (EnvelopeVerification, error) {
	if strings.TrimSpace(expectedIdentity) == "" || strings.TrimSpace(expectedOIDCIssuer) == "" {
		return EnvelopeVerification{
			Status: StatusBlocked,
			Reason: "missing expected certificate identity or OIDC issuer for Sigstore verification",
		}, ErrMissingVerificationMaterial
	}
	_, rawPayload, leafPubKey, err := signing.VerifySigstoreBundle(rawEnvelopeJSON, expectedIdentity, expectedOIDCIssuer, customTrustedRootJSON)
	if err != nil {
		return EnvelopeVerification{
			Status:             StatusInvalid,
			IsSigstoreBundle:   true,
			VerificationMethod: "sigstore",
			Reason:             err.Error(),
		}, fmt.Errorf("%w: %v", ErrInvalidSignature, err)
	}
	stmt, err := decodeAndValidateInTotoStatement(rawPayload)
	if err != nil {
		return EnvelopeVerification{
			Status:             StatusInvalid,
			IsSigstoreBundle:   true,
			VerificationMethod: "sigstore",
			Reason:             err.Error(),
		}, fmt.Errorf("%w: %s", ErrInvalidSignature, err.Error())
	}
	return EnvelopeVerification{
		Status:             StatusVerified,
		IsSigstoreBundle:   true,
		VerificationMethod: "sigstore",
		MatchedSignerID:    expectedIdentity,
		MatchedSignerName:  leafPubKey.Name,
		SignerKeyID:        leafPubKey.KeyID,
		SignerFingerprint:  leafPubKey.Fingerprint,
		Algorithm:          leafPubKey.Algorithm,
		Statement:          stmt,
		RawPayload:         rawPayload,
		Reason:             "Sigstore Fulcio certificate, OIDC identity/issuer, Rekor log proof, and DSSE signature verified",
	}, nil
}
