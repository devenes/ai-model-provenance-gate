// Package verify exposes the public, disk-I/O-free and network-I/O-free verification API
// for model bundle identity, OpenSSF Model Signing (OMS v1.0), CycloneDX 1.7 AI/ML-BOM,
// LLM Release Gate evaluation attestations, and Release Qualification attestations.
package verify

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/devenes/ai-model-provenance-gate/internal/digest"
	"github.com/devenes/ai-model-provenance-gate/internal/identity"
	"github.com/devenes/ai-model-provenance-gate/internal/signing"
	"github.com/devenes/ai-model-provenance-gate/internal/verification"
	"github.com/devenes/ai-model-provenance-gate/internal/version"
)

// Canonical schema and predicate constants re-exported for downstream consumers.
const (
	BundleIdentitySchemaVersion        = version.BundleIdentitySchemaVersion
	DeploymentCompositionSchemaVersion = version.DeploymentCompositionSchemaVersion
	ReleaseQualificationPredicateType  = version.ReleaseQualificationPredicateType
	EvaluationEvidencePredicateType    = version.EvaluationEvidencePredicateType
	OMSV1PredicateType                 = "https://model_signing/signature/v1.0"
)

// Status represents the deterministic outcome of a cryptographic or policy verification step.
type Status string

const (
	StatusVerified  Status = Status(verification.StatusVerified)
	StatusInvalid   Status = Status(verification.StatusInvalid)
	StatusUntrusted Status = Status(verification.StatusUntrusted)
	StatusMissing   Status = Status(verification.StatusMissing)
	StatusBlocked   Status = Status(verification.StatusBlocked)
	StatusNotRun    Status = Status(verification.StatusNotRun)
)

var (
	// ErrInvalidInventory is returned when OCI descriptor file entries are empty, malformed, or contain path collisions.
	ErrInvalidInventory = errors.New("invalid or unsafe model file descriptor inventory")
	// ErrInvalidBundleManifest is returned when bundle-manifest.json fails schema, JCS digest, or descriptor correspondence checks.
	ErrInvalidBundleManifest = errors.New("invalid or mismatched bundle-manifest.json")
	// ErrInvalidOMSSignature is returned when an OMS signature or resource inventory check fails.
	ErrInvalidOMSSignature = errors.New("invalid OpenSSF Model Signing signature or resource correspondence")
	// ErrInvalidBOM is returned when a CycloneDX AI/ML-BOM fails schema or 1-to-1 inventory correspondence checks.
	ErrInvalidBOM = errors.New("invalid CycloneDX AI/ML-BOM")
	// ErrInvalidEvaluationEvidence is returned when an evaluation report or attestation fails verification.
	ErrInvalidEvaluationEvidence = errors.New("invalid or untrusted evaluation evidence")
	// ErrInvalidReleaseQualification is returned when a release qualification attestation or its cross-evidence bindings fail.
	ErrInvalidReleaseQualification = errors.New("invalid release qualification attestation or cross-evidence binding")
	// ErrUntrustedSigner is returned when a cryptographic signature was produced by an untrusted or cross-domain key.
	ErrUntrustedSigner = verification.ErrUntrustedSigner
	// ErrMissingVerificationMaterial is returned when trusted public keys are empty.
	ErrMissingVerificationMaterial = verification.ErrMissingVerificationMaterial
)

// FileEntry represents a single model bundle file derived from an OCI layer descriptor.
type FileEntry struct {
	Path   string `json:"path"`
	Role   string `json:"role,omitempty"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// TrustedSignerRule defines an authorized public key within a specific trust domain.
type TrustedSignerRule struct {
	ID                       string `json:"id"`
	Name                     string `json:"name,omitempty"`
	Role                     string `json:"role,omitempty"`
	AllowOperatorEndorsement bool   `json:"allow_operator_endorsement,omitempty"`
	KeyID                    string `json:"key_id,omitempty"`
	KeyFingerprint           string `json:"key_fingerprint,omitempty"`
	PublicKeyPEM             []byte `json:"-"`
}

// KeyInfo holds the parsed PKIX metadata and deterministic SHA-256 fingerprint of a public key.
type KeyInfo struct {
	KeyID       string `json:"key_id"`
	Name        string `json:"name,omitempty"`
	Fingerprint string `json:"fingerprint"`
	Algorithm   string `json:"algorithm"`
}

// IdentityResult contains the computed bundle-identity/v1 digest and normalized file entries.
type IdentityResult struct {
	SchemaVersion string      `json:"schema_version"`
	BundleID      string      `json:"bundle_id"`
	FileCount     int         `json:"file_count"`
	TotalBytes    int64       `json:"total_bytes"`
	Files         []FileEntry `json:"files"`
	CanonicalJSON []byte      `json:"-"`
}

// ManifestVerifyOptions configures bundle-manifest.json validation.
type ManifestVerifyOptions struct {
	AllowUnknownFiles    bool
	ExpectedBaseBundleID string
}

// BundleManifest holds the verified bundle-identity/v1 manifest metadata needed for downstream checks.
type BundleManifest struct {
	SchemaVersion           string      `json:"schema_version"`
	BundleID                string      `json:"bundle_id"`
	ManifestDigest          string      `json:"manifest_digest"`
	ConfigBlobDigest        string      `json:"config_blob_digest"`
	FileCount               int         `json:"file_count"`
	TotalBytes              int64       `json:"total_bytes"`
	PrimaryFormat           string      `json:"primary_format"`
	HasLoRAAdapter          bool        `json:"has_lora_adapter"`
	LoRAVerificationStatus  string      `json:"lora_verification_status"`
	VerifiedBaseBundleID    string      `json:"verified_base_bundle_id,omitempty"`
	DeclaredBaseModel       string      `json:"declared_base_model,omitempty"`
	ContainsSymlinks        bool        `json:"contains_symlinks"`
	ContainsUnsafePickle    bool        `json:"contains_unsafe_pickle"`
	ContainsRemoteCodeHooks bool        `json:"contains_remote_code_hooks"`
	UnknownRegularFiles     []string    `json:"unknown_regular_files,omitempty"`
	Files                   []FileEntry `json:"files"`
	RawJSON                 []byte      `json:"-"`
}

// OMSVerifyOptions configures in-memory OpenSSF Model Signing (OMS v1.0) verification.
type OMSVerifyOptions struct {
	TrustedModelSigners []TrustedSignerRule
	UntrustedCandidates []TrustedSignerRule
	IgnoreUnsignedFiles bool
}

// OMSResult captures the outcome of OMS v1.0 verification against OCI descriptors.
type OMSResult struct {
	Status                Status   `json:"status"`
	SignatureDigest       string   `json:"signature_digest"`
	PredicateType         string   `json:"predicate_type,omitempty"`
	RootDigest            string   `json:"root_digest,omitempty"`
	IsSigstoreBundle      bool     `json:"is_sigstore_bundle"`
	SignerID              string   `json:"signer_id,omitempty"`
	SignerKeyID           string   `json:"signer_key_id,omitempty"`
	SignerFingerprint     string   `json:"signer_fingerprint,omitempty"`
	Algorithm             string   `json:"algorithm,omitempty"`
	VerifiedFileCount     int      `json:"verified_file_count"`
	DigestsMatchInventory bool     `json:"digests_match_inventory"`
	MismatchedFiles       []string `json:"mismatched_files,omitempty"`
	MissingSignedFiles    []string `json:"missing_signed_files,omitempty"`
	UnsignedBundleFiles   []string `json:"unsigned_bundle_files,omitempty"`
	Reason                string   `json:"reason"`
}

// BOMResult captures the outcome of CycloneDX 1.6/1.7 AI/ML-BOM verification.
type BOMResult struct {
	Status        Status `json:"status"`
	CanonicalHash string `json:"canonical_hash"`
	RawBlobDigest string `json:"raw_blob_digest"`
	SpecVersion   string `json:"spec_version"`
	SerialNumber  string `json:"serial_number"`
	BundleID      string `json:"bundle_id"`
	Reason        string `json:"reason"`
}

// EvalVerifyOptions configures LLM Release Gate report + evaluation-evidence/v1 attestation verification.
type EvalVerifyOptions struct {
	TrustedEvaluators      []TrustedSignerRule
	UntrustedCandidates    []TrustedSignerRule
	ExpectedBundleID       string
	ExpectedSuiteDigest    string
	ExpectedDatasetDigest  string
	MaxAge                 time.Duration
	RequireArtifactBinding bool
	RequireTrustedEvidence bool
	AllowPostHocBinding    bool
	Now                    time.Time
}

// EvaluationSummary holds the 7 orthogonal evaluation verification guarantees.
type EvaluationSummary struct {
	Status                       Status `json:"status"`
	ReportDigest                 string `json:"report_digest"`
	AttestationDigest            string `json:"attestation_digest"`
	AttestationKind              string `json:"attestation_kind,omitempty"`
	SchemaVersion                string `json:"schema_version"`
	RunID                        string `json:"run_id"`
	Timestamp                    string `json:"timestamp"`
	SuiteDigest                  string `json:"suite_digest"`
	DatasetDigest                string `json:"dataset_digest"`
	ReportedGateStatus           string `json:"reported_gate_status"`
	EffectiveGateStatus          string `json:"effective_gate_status"`
	EvidenceQuality              string `json:"evidence_quality"`
	BindingStatus                string `json:"binding_status"`
	BindingMode                  string `json:"binding_mode"`
	TrustStatus                  string `json:"trust_status"`
	DeclaredBundleID             string `json:"declared_bundle_id,omitempty"`
	AttestedBundleID             string `json:"attested_bundle_id,omitempty"`
	ExpectedBundleID             string `json:"expected_bundle_id"`
	ReportIntegrityVerified      bool   `json:"report_integrity_verified"`
	ReportAuthenticityVerified   bool   `json:"report_authenticity_verified"`
	ProducerIdentityVerified     bool   `json:"producer_identity_verified"`
	ArtifactBindingVerified      bool   `json:"artifact_binding_verified"`
	ExecutionEvidenceVerified    bool   `json:"execution_evidence_verified"`
	SuiteDatasetIdentityVerified bool   `json:"suite_dataset_identity_verified"`
	FreshnessVerified            bool   `json:"freshness_verified"`
	EligibleForRelease           bool   `json:"eligible_for_release"`
	SignerID                     string `json:"signer_id,omitempty"`
	SignerFingerprint            string `json:"signer_fingerprint,omitempty"`
	Reason                       string `json:"reason"`
}

// ReleaseVerifyOptions configures release-qualification/v1 verification and cross-evidence binding checks.
type ReleaseVerifyOptions struct {
	TrustedAuthorities            []TrustedSignerRule
	UntrustedCandidates           []TrustedSignerRule
	ExpectedBundleID              string
	ExpectedManifestDigest        string
	ExpectedBOMDigest             string
	ExpectedOMSSignatureDigest    string
	ExpectedEvalReportDigest      string
	ExpectedEvalAttestationDigest string
	RequireTrustedEvaluator       bool
	RejectPostHocBinding          bool
	MaxAge                        time.Duration
	Now                           time.Time
}

// VerifiedQualification holds the verified release-qualification/v1 result and extracted bindings.
type VerifiedQualification struct {
	Status                  Status `json:"status"`
	AttestationDigest       string `json:"attestation_digest"`
	Timestamp               string `json:"timestamp"`
	SignerID                string `json:"signer_id,omitempty"`
	SignerKeyID             string `json:"signer_key_id,omitempty"`
	SignerFingerprint       string `json:"signer_fingerprint,omitempty"`
	SubjectBundleID         string `json:"subject_bundle_id"`
	ManifestDigest          string `json:"manifest_digest"`
	BOMDigest               string `json:"bom_digest"`
	OMSSignatureDigest      string `json:"oms_signature_digest"`
	OMSSignerFingerprint    string `json:"oms_signer_fingerprint,omitempty"`
	EvalReportDigest        string `json:"eval_report_digest,omitempty"`
	EvalAttestationDigest   string `json:"eval_attestation_digest,omitempty"`
	EvalSuiteDigest         string `json:"eval_suite_digest,omitempty"`
	EvalDatasetDigest       string `json:"eval_dataset_digest,omitempty"`
	EvalSignerFingerprint   string `json:"eval_signer_fingerprint,omitempty"`
	LoRAStatus              string `json:"lora_status"`
	VerifiedBaseBundleID    string `json:"verified_base_bundle_id,omitempty"`
	RuntimeImage            string `json:"runtime_image,omitempty"`
	ServingConfigDigest     string `json:"serving_config_digest,omitempty"`
	QualificationPolicyHash string `json:"qualification_policy_hash"`
	GateStatus              string `json:"gate_status"`
	Reason                  string `json:"reason"`
}

// ParsePublicKeyPEM parses a PEM-encoded PKIX public key and computes its "sha256:<64-hex>" fingerprint.
func ParsePublicKeyPEM(rawPEM []byte, keyID string, name string) (KeyInfo, error) {
	pub, err := signing.ParsePublicKeyPEM(rawPEM, keyID, name)
	if err != nil {
		return KeyInfo{}, err
	}
	return KeyInfo{
		KeyID:       pub.KeyID,
		Name:        pub.Name,
		Fingerprint: pub.Fingerprint,
		Algorithm:   pub.Algorithm,
	}, nil
}

// CanonicalizeStructJCS serializes v to RFC 8785 (JCS) canonical JSON and returns its "sha256:<64-hex>" digest and bytes.
func CanonicalizeStructJCS(v any) (string, []byte, error) {
	canon, err := identity.CanonicalizeStruct(v)
	if err != nil {
		return "", nil, err
	}
	return digest.ComputeBytes(canon), canon, nil
}

// ComputeNormalizedTextDigest computes the "sha256:<64-hex>" digest after normalizing CRLF (\r\n) to LF (\n).
func ComputeNormalizedTextDigest(raw []byte) string {
	return digest.ComputeNormalizedText(raw)
}

// ComputeRawBytesDigest computes the "sha256:<64-hex>" digest over exact raw bytes.
func ComputeRawBytesDigest(raw []byte) string {
	return digest.ComputeBytes(raw)
}

// ValidateDigest checks whether s conforms to "sha256:<64-lowercase-hex>".
func ValidateDigest(s string) error {
	return digest.Validate(s)
}

func resolveSignerRules(rules []TrustedSignerRule) ([]verification.TrustedSignerRule, error) {
	out := make([]verification.TrustedSignerRule, 0, len(rules))
	for _, r := range rules {
		if strings.TrimSpace(r.ID) == "" {
			return nil, fmt.Errorf("trusted signer rule requires non-empty id")
		}
		if len(bytes.TrimSpace(r.PublicKeyPEM)) == 0 {
			return nil, fmt.Errorf("trusted signer %q has empty public key PEM", r.ID)
		}
		pub, err := signing.ParsePublicKeyPEM(r.PublicKeyPEM, r.KeyID, r.Name)
		if err != nil {
			return nil, fmt.Errorf("trusted signer %q: %w", r.ID, err)
		}
		if r.KeyFingerprint != "" {
			if err := digest.Validate(r.KeyFingerprint); err != nil {
				return nil, fmt.Errorf("trusted signer %q invalid key_fingerprint: %w", r.ID, err)
			}
		}
		out = append(out, verification.TrustedSignerRule{
			ID:                       r.ID,
			Name:                     r.Name,
			Role:                     r.Role,
			AllowOperatorEndorsement: r.AllowOperatorEndorsement,
			KeyID:                    r.KeyID,
			KeyFingerprint:           r.KeyFingerprint,
			PublicKey:                pub,
		})
	}
	return out, nil
}

func resolveUntrustedCandidateKeys(trusted []verification.TrustedSignerRule, candidates []TrustedSignerRule) []*signing.PublicKey {
	trustedFPs := make(map[string]bool, len(trusted))
	for _, t := range trusted {
		if t.PublicKey != nil {
			trustedFPs[t.PublicKey.Fingerprint] = true
		}
	}
	var out []*signing.PublicKey
	for _, c := range candidates {
		if len(bytes.TrimSpace(c.PublicKeyPEM)) == 0 {
			continue
		}
		pub, err := signing.ParsePublicKeyPEM(c.PublicKeyPEM, c.KeyID, c.Name)
		if err != nil {
			continue
		}
		if !trustedFPs[pub.Fingerprint] {
			out = append(out, pub)
			trustedFPs[pub.Fingerprint] = true
		}
	}
	return out
}
