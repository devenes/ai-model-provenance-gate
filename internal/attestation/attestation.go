// Package attestation builds, signs, and verifies in-toto Statement v1 Release Qualification Attestations
// (`https://github.com/devenes/ai-model-provenance-gate/attestation/release-qualification/v1`)
// while keeping release qualification strictly separate from SLSA build provenance.
package attestation

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/devenes/ai-model-provenance-gate/internal/bom"
	"github.com/devenes/ai-model-provenance-gate/internal/bundle"
	"github.com/devenes/ai-model-provenance-gate/internal/config"
	"github.com/devenes/ai-model-provenance-gate/internal/digest"
	"github.com/devenes/ai-model-provenance-gate/internal/evaluation/llmreleasegate"
	"github.com/devenes/ai-model-provenance-gate/internal/oms"
	"github.com/devenes/ai-model-provenance-gate/internal/policy"
	"github.com/devenes/ai-model-provenance-gate/internal/provenance"
	"github.com/devenes/ai-model-provenance-gate/internal/scanner"
	"github.com/devenes/ai-model-provenance-gate/internal/signing"
	"github.com/devenes/ai-model-provenance-gate/internal/verification"
	"github.com/devenes/ai-model-provenance-gate/internal/version"
)

const (
	// PredicateSchemaVersion is the schema identifier inside the release qualification predicate.
	PredicateSchemaVersion = "release-qualification/v1"
)

var (
	// ErrInvalidReleaseAttestation is returned when a release qualification attestation is invalid, tampered, or fails verification.
	ErrInvalidReleaseAttestation = errors.New("invalid release qualification attestation")
)

// BundleEvidence summarizes the qualified model bundle inside the attestation predicate.
type BundleEvidence struct {
	BundleID       string `json:"bundle_id"`
	ManifestDigest string `json:"manifest_digest"`
	FileCount      int    `json:"file_count"`
	TotalBytes     int64  `json:"total_bytes"`
	PrimaryFormat  string `json:"primary_format"`
	LoRAStatus     string `json:"lora_status"`
	VerifiedBaseID string `json:"verified_base_bundle_id,omitempty"`
}

// BOMEvidence summarizes the generated CycloneDX BOM inside the attestation predicate.
type BOMEvidence struct {
	Digest      string `json:"digest"`
	SpecVersion string `json:"spec_version"`
}

// OMSEvidence summarizes the OpenSSF Model Signing verification result.
type OMSEvidence struct {
	Status            string `json:"status"`
	PredicateType     string `json:"predicate_type,omitempty"`
	SignerID          string `json:"signer_id,omitempty"`
	SignerKeyID       string `json:"signer_key_id,omitempty"`
	SignerFingerprint string `json:"signer_fingerprint,omitempty"`
	SignatureDigest   string `json:"signature_digest,omitempty"`
}

// EvaluationEvidence summarizes the bound LLM Release Gate evaluation result.
type EvaluationEvidence struct {
	Present           bool   `json:"present"`
	ReportedStatus    string `json:"reported_status,omitempty"`
	EffectiveStatus   string `json:"effective_status,omitempty"`
	EvidenceQuality   string `json:"evidence_quality,omitempty"`
	BindingStatus     string `json:"binding_status,omitempty"`
	TrustStatus       string `json:"trust_status,omitempty"`
	ReportDigest      string `json:"report_digest,omitempty"`
	AttestationDigest string `json:"attestation_digest,omitempty"`
	SuiteDigest       string `json:"suite_digest,omitempty"`
	DatasetDigest     string `json:"dataset_digest,omitempty"`
	RunID             string `json:"run_id,omitempty"`
	SignerFingerprint string `json:"signer_fingerprint,omitempty"`
}

// ScannerEvidence summarizes optional format scanner evidence.
type ScannerEvidence struct {
	Status       string `json:"status"`
	Tool         string `json:"tool,omitempty"`
	ReportDigest string `json:"report_digest,omitempty"`
}

// ProvenanceEvidence summarizes optional upstream SLSA build provenance verification.
type ProvenanceEvidence struct {
	Status            string `json:"status"`
	BuilderID         string `json:"builder_id,omitempty"`
	AttestationDigest string `json:"attestation_digest,omitempty"`
	SLSAClaimNote     string `json:"slsa_claim_note"`
}

// RuntimeEvidence summarizes optional runtime identity bound at qualification time.
type RuntimeEvidence struct {
	RuntimeImage        string `json:"runtime_image,omitempty"`
	ServingConfigDigest string `json:"serving_config_digest,omitempty"`
}

// PolicyEvidence summarizes the policy evaluated to produce the release decision.
type PolicyEvidence struct {
	SchemaVersion     string                   `json:"schema_version"`
	Name              string                   `json:"name,omitempty"`
	Digest            string                   `json:"digest"`
	DecisionMode      string                   `json:"decision_mode"`
	ExceptionsApplied []config.PolicyException `json:"exceptions_applied,omitempty"`
}

// DecisionEvidence summarizes the final gate outcome.
type DecisionEvidence struct {
	GateStatus string                  `json:"gate_status"`
	ExitCode   int                     `json:"exit_code"`
	Reasons    []policy.DecisionReason `json:"reasons"`
}

// ReleaseQualificationPredicate is the structured predicate for release-qualification/v1 attestations.
type ReleaseQualificationPredicate struct {
	SchemaVersion      string             `json:"schema_version"`
	Timestamp          string             `json:"timestamp"`
	Tool               version.Metadata   `json:"tool"`
	Bundle             BundleEvidence     `json:"bundle"`
	BOM                BOMEvidence        `json:"bom"`
	OMSVerification    OMSEvidence        `json:"oms_verification"`
	Evaluation         EvaluationEvidence `json:"evaluation"`
	Scanner            ScannerEvidence    `json:"scanner"`
	UpstreamProvenance ProvenanceEvidence `json:"upstream_provenance"`
	Runtime            *RuntimeEvidence   `json:"runtime,omitempty"`
	Policy             PolicyEvidence     `json:"policy"`
	Decision           DecisionEvidence   `json:"decision"`
}

// BuildInput holds the inputs required to construct a Release Qualification Attestation.
type BuildInput struct {
	Timestamp           string
	SubjectName         string
	Inspection          bundle.InspectionResult
	BOM                 bom.GeneratedBOM
	OMS                 oms.Result
	HasEvaluation       bool
	Evaluation          llmreleasegate.EvaluationSummary
	Scanner             scanner.Result
	Provenance          provenance.Result
	RuntimeImage        string
	ServingConfigDigest string
	Policy              config.Policy
	Decision            policy.Decision
}

// GeneratedAttestation holds the constructed in-toto Statement, optional signed DSSE envelope, and digest.
type GeneratedAttestation struct {
	Statement   signing.InTotoStatement       `json:"statement"`
	Predicate   ReleaseQualificationPredicate `json:"predicate"`
	Signed      bool                          `json:"signed"`
	SignerKeyID string                        `json:"signer_key_id,omitempty"`
	SignerFP    string                        `json:"signer_fingerprint,omitempty"`
	JSONBytes   []byte                        `json:"-"`
	Digest      string                        `json:"digest"`
}

// BuildAndOptionallySign creates an in-toto Statement v1 release qualification attestation
// and signs it in a DSSE v1.0 envelope if priv is non-nil.
func BuildAndOptionallySign(in BuildInput, priv *signing.PrivateKey) (GeneratedAttestation, error) {
	bundleHex, err := digest.TrimPrefix(in.Inspection.BundleID)
	if err != nil {
		return GeneratedAttestation{}, err
	}
	ts := strings.TrimSpace(in.Timestamp)
	if ts == "" {
		ts = time.Now().UTC().Format(time.RFC3339)
	}
	subjName := strings.TrimSpace(in.SubjectName)
	if subjName == "" {
		subjName = "model-bundle:" + bundleHex[:16]
	}

	var rtEv *RuntimeEvidence
	if strings.TrimSpace(in.RuntimeImage) != "" || strings.TrimSpace(in.ServingConfigDigest) != "" {
		rtEv = &RuntimeEvidence{
			RuntimeImage:        in.RuntimeImage,
			ServingConfigDigest: in.ServingConfigDigest,
		}
	}

	slsaNote := "Release qualification attestation only; does NOT claim SLSA build provenance generation."
	if in.Provenance.Status == verification.StatusVerified {
		slsaNote = "Upstream SLSA build provenance verified separately; this predicate records post-build release qualification."
	}

	pred := ReleaseQualificationPredicate{
		SchemaVersion: PredicateSchemaVersion,
		Timestamp:     ts,
		Tool:          version.Get(),
		Bundle: BundleEvidence{
			BundleID:       in.Inspection.BundleID,
			ManifestDigest: in.Inspection.Manifest.ManifestDigest,
			FileCount:      in.Inspection.Manifest.FileCount,
			TotalBytes:     in.Inspection.Manifest.TotalBytes,
			PrimaryFormat:  in.Inspection.Manifest.FormatSummary.PrimaryFormat,
			LoRAStatus:     string(in.Inspection.Manifest.LoRARelationship.VerificationStatus),
			VerifiedBaseID: in.Inspection.Manifest.LoRARelationship.VerifiedBaseBundleID,
		},
		BOM: BOMEvidence{
			Digest:      in.BOM.Digest,
			SpecVersion: in.BOM.Document.SpecVersion,
		},
		OMSVerification: OMSEvidence{
			Status:            string(in.OMS.Status),
			PredicateType:     in.OMS.PredicateType,
			SignerID:          in.OMS.SignerID,
			SignerKeyID:       in.OMS.SignerKeyID,
			SignerFingerprint: in.OMS.SignerFingerprint,
			SignatureDigest:   in.OMS.SignatureDigest,
		},
		Evaluation: EvaluationEvidence{
			Present:           in.HasEvaluation,
			ReportedStatus:    string(in.Evaluation.ReportedGateStatus),
			EffectiveStatus:   string(in.Evaluation.EffectiveGateStatus),
			EvidenceQuality:   string(in.Evaluation.EvidenceQuality),
			BindingStatus:     string(in.Evaluation.BindingStatus),
			TrustStatus:       string(in.Evaluation.TrustStatus),
			ReportDigest:      in.Evaluation.ReportDigest,
			AttestationDigest: in.Evaluation.AttestationDigest,
			SuiteDigest:       in.Evaluation.SuiteDigest,
			DatasetDigest:     in.Evaluation.DatasetDigest,
			RunID:             in.Evaluation.RunID,
			SignerFingerprint: in.Evaluation.SignerFingerprint,
		},
		Scanner: ScannerEvidence{
			Status:       string(in.Scanner.Status),
			Tool:         in.Scanner.Tool,
			ReportDigest: in.Scanner.ReportDigest,
		},
		UpstreamProvenance: ProvenanceEvidence{
			Status:            string(in.Provenance.Status),
			BuilderID:         in.Provenance.BuilderID,
			AttestationDigest: in.Provenance.AttestationDigest,
			SLSAClaimNote:     slsaNote,
		},
		Runtime: rtEv,
		Policy: PolicyEvidence{
			SchemaVersion:     in.Policy.SchemaVersion,
			Name:              in.Policy.Name,
			Digest:            in.Policy.Digest,
			DecisionMode:      in.Policy.Release.DecisionMode,
			ExceptionsApplied: in.Decision.ExceptionsApplied,
		},
		Decision: DecisionEvidence{
			GateStatus: string(in.Decision.GateStatus),
			ExitCode:   in.Decision.ExitCode,
			Reasons:    in.Decision.Reasons,
		},
	}

	predBytes, err := json.Marshal(pred)
	if err != nil {
		return GeneratedAttestation{}, fmt.Errorf("marshal release qualification predicate: %w", err)
	}

	stmt := signing.InTotoStatement{
		Type: signing.InTotoStatementV1Type,
		Subject: []signing.ResourceDescriptor{
			{
				Name: subjName,
				Digest: map[string]string{
					"sha256": bundleHex,
				},
			},
		},
		PredicateType: version.ReleaseQualificationPredicateType,
		Predicate:     predBytes,
	}
	stmtBytes, err := json.Marshal(stmt)
	if err != nil {
		return GeneratedAttestation{}, fmt.Errorf("marshal in-toto statement: %w", err)
	}

	if priv == nil {
		pretty, mErr := json.MarshalIndent(stmt, "", "  ")
		if mErr != nil {
			return GeneratedAttestation{}, mErr
		}
		pretty = append(pretty, '\n')
		return GeneratedAttestation{
			Statement: stmt,
			Predicate: pred,
			Signed:    false,
			JSONBytes: pretty,
			Digest:    digest.ComputeBytes(pretty),
		}, nil
	}

	env, err := signing.SignDSSE(signing.InTotoPayloadType, stmtBytes, priv)
	if err != nil {
		return GeneratedAttestation{}, fmt.Errorf("sign release qualification DSSE: %w", err)
	}
	pretty, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return GeneratedAttestation{}, err
	}
	pretty = append(pretty, '\n')
	return GeneratedAttestation{
		Statement:   stmt,
		Predicate:   pred,
		Signed:      true,
		SignerKeyID: priv.KeyID,
		SignerFP:    priv.Fingerprint,
		JSONBytes:   pretty,
		Digest:      digest.ComputeBytes(pretty),
	}, nil
}

// VerifiedQualification holds the result of verifying a signed Release Qualification DSSE attestation.
type VerifiedQualification struct {
	Status            verification.Status           `json:"status"`
	AttestationPath   string                        `json:"attestation_path"`
	AttestationDigest string                        `json:"attestation_digest"`
	SignerID          string                        `json:"signer_id,omitempty"`
	SignerKeyID       string                        `json:"signer_key_id,omitempty"`
	SignerFingerprint string                        `json:"signer_fingerprint,omitempty"`
	SubjectBundleID   string                        `json:"subject_bundle_id,omitempty"`
	Predicate         ReleaseQualificationPredicate `json:"predicate"`
	Reason            string                        `json:"reason"`
}

// VerifyQualificationFile verifies a signed DSSE Release Qualification Attestation against trusted signers
// and expected bundle identity.
func VerifyQualificationFile(
	path string,
	expectedBundleID string,
	trustedSigners []verification.TrustedSignerRule,
	candidateUntrustedKeys []*signing.PublicKey,
) (VerifiedQualification, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return VerifiedQualification{
			Status: verification.StatusMissing,
			Reason: "no release qualification attestation path provided",
		}, fmt.Errorf("%w: missing attestation path", ErrInvalidReleaseAttestation)
	}

	rawBytes, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return VerifiedQualification{
				Status:          verification.StatusMissing,
				AttestationPath: path,
				Reason:          fmt.Sprintf("release qualification attestation %q does not exist", path),
			}, fmt.Errorf("%w: %v", ErrInvalidReleaseAttestation, err)
		}
		return VerifiedQualification{
			Status:          verification.StatusBlocked,
			AttestationPath: path,
			Reason:          fmt.Sprintf("read release qualification attestation %q: %v", path, err),
		}, err
	}
	res, err := VerifyQualificationBytes(rawBytes, expectedBundleID, trustedSigners, candidateUntrustedKeys)
	res.AttestationPath = path
	return res, err
}

// VerifyQualificationBytes verifies in-memory bytes of a signed DSSE Release Qualification Attestation
// against trusted signers and expected bundle identity without performing any filesystem I/O.
func VerifyQualificationBytes(
	rawBytes []byte,
	expectedBundleID string,
	trustedSigners []verification.TrustedSignerRule,
	candidateUntrustedKeys []*signing.PublicKey,
) (VerifiedQualification, error) {
	if len(strings.TrimSpace(string(rawBytes))) == 0 {
		return VerifiedQualification{
			Status: verification.StatusMissing,
			Reason: "empty release qualification attestation bytes",
		}, fmt.Errorf("%w: empty attestation bytes", ErrInvalidReleaseAttestation)
	}
	attDigest := digest.ComputeBytes(rawBytes)

	envVer, err := verification.VerifyInTotoDSSE(rawBytes, trustedSigners, candidateUntrustedKeys)
	if err != nil {
		return VerifiedQualification{
			Status:            envVer.Status,
			AttestationDigest: attDigest,
			SignerKeyID:       envVer.SignerKeyID,
			SignerFingerprint: envVer.SignerFingerprint,
			Reason:            envVer.Reason,
		}, fmt.Errorf("%w: %v", ErrInvalidReleaseAttestation, err)
	}

	stmt := envVer.Statement
	if stmt.PredicateType != version.ReleaseQualificationPredicateType {
		reason := fmt.Sprintf(
			"unexpected predicateType %q (expected %q)",
			stmt.PredicateType, version.ReleaseQualificationPredicateType,
		)
		return VerifiedQualification{
			Status:            verification.StatusInvalid,
			AttestationDigest: attDigest,
			Reason:            reason,
		}, fmt.Errorf("%w: %s", ErrInvalidReleaseAttestation, reason)
	}

	subjHex := strings.ToLower(strings.TrimSpace(stmt.Subject[0].Digest["sha256"]))
	if err := digest.Validate(digest.Prefix + subjHex); err != nil {
		reason := fmt.Sprintf("invalid subject sha256 digest %q in attestation", subjHex)
		return VerifiedQualification{
			Status:            verification.StatusInvalid,
			AttestationDigest: attDigest,
			Reason:            reason,
		}, fmt.Errorf("%w: %s", ErrInvalidReleaseAttestation, reason)
	}
	subjBundleID := digest.Prefix + subjHex

	var pred ReleaseQualificationPredicate
	if err := json.Unmarshal(stmt.Predicate, &pred); err != nil {
		reason := fmt.Sprintf("decode release qualification predicate: %v", err)
		return VerifiedQualification{
			Status:            verification.StatusInvalid,
			AttestationDigest: attDigest,
			Reason:            reason,
		}, fmt.Errorf("%w: %s", ErrInvalidReleaseAttestation, reason)
	}

	if pred.Bundle.BundleID != subjBundleID {
		reason := fmt.Sprintf(
			"statement subject digest %s conflicts with predicate bundle_id %s (altered attestation)",
			subjBundleID, pred.Bundle.BundleID,
		)
		return VerifiedQualification{
			Status:            verification.StatusInvalid,
			AttestationDigest: attDigest,
			SubjectBundleID:   subjBundleID,
			Predicate:         pred,
			Reason:            reason,
		}, fmt.Errorf("%w: %s", ErrInvalidReleaseAttestation, reason)
	}

	if pred.Decision.GateStatus != string(policy.StatusPass) {
		reason := fmt.Sprintf("release qualification attestation records decision.gate_status=%q (requires PASS)", pred.Decision.GateStatus)
		return VerifiedQualification{
			Status:            verification.StatusInvalid,
			AttestationDigest: attDigest,
			SubjectBundleID:   subjBundleID,
			Predicate:         pred,
			Reason:            reason,
		}, fmt.Errorf("%w: %s", ErrInvalidReleaseAttestation, reason)
	}

	if expectedBundleID != "" && subjBundleID != expectedBundleID {
		reason := fmt.Sprintf(
			"inspected model bundle identity %s does not match attested release subject %s (artifact modified or substituted)",
			expectedBundleID, subjBundleID,
		)
		return VerifiedQualification{
			Status:            verification.StatusInvalid,
			AttestationDigest: attDigest,
			SignerID:          envVer.MatchedSignerID,
			SignerKeyID:       envVer.SignerKeyID,
			SignerFingerprint: envVer.SignerFingerprint,
			SubjectBundleID:   subjBundleID,
			Predicate:         pred,
			Reason:            reason,
		}, fmt.Errorf("%w: %s", ErrInvalidReleaseAttestation, reason)
	}

	return VerifiedQualification{
		Status:            verification.StatusVerified,
		AttestationDigest: attDigest,
		SignerID:          envVer.MatchedSignerID,
		SignerKeyID:       envVer.SignerKeyID,
		SignerFingerprint: envVer.SignerFingerprint,
		SubjectBundleID:   subjBundleID,
		Predicate:         pred,
		Reason:            fmt.Sprintf("verified signed release qualification attestation for bundle %s", subjBundleID),
	}, nil
}
