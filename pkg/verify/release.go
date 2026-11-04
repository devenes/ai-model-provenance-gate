package verify

import (
	"fmt"
	"strings"
	"time"

	"github.com/devenes/ai-model-provenance-gate/internal/attestation"
	"github.com/devenes/ai-model-provenance-gate/internal/evaluation/llmreleasegate"
)

// VerifyReleaseQualificationBytes verifies a signed DSSE Release Qualification Attestation (release-qualification/v1)
// in memory against the releaseAuthorities trust domain AND enforces strict cross-evidence digest binding against
// the verified BundleManifest, BOM, OMS signature, and Evaluation evidence.
func VerifyReleaseQualificationBytes(
	rawAttestation []byte,
	opts ReleaseVerifyOptions,
) (VerifiedQualification, error) {
	trusted, err := resolveSignerRules(opts.TrustedAuthorities)
	if err != nil {
		return VerifiedQualification{
			Status: StatusBlocked,
			Reason: err.Error(),
		}, err
	}
	untrusted := resolveUntrustedCandidateKeys(trusted, opts.UntrustedCandidates)

	qv, err := attestation.VerifyQualificationBytes(rawAttestation, opts.ExpectedBundleID, trusted, untrusted)
	pred := qv.Predicate

	var rtImage, servingCfgDigest string
	if pred.Runtime != nil {
		rtImage = pred.Runtime.RuntimeImage
		servingCfgDigest = pred.Runtime.ServingConfigDigest
	}

	out := VerifiedQualification{
		Status:                  Status(qv.Status),
		AttestationDigest:       qv.AttestationDigest,
		Timestamp:               pred.Timestamp,
		SignerID:                qv.SignerID,
		SignerKeyID:             qv.SignerKeyID,
		SignerFingerprint:       qv.SignerFingerprint,
		SubjectBundleID:         qv.SubjectBundleID,
		ManifestDigest:          pred.Bundle.ManifestDigest,
		BOMDigest:               pred.BOM.Digest,
		OMSSignatureDigest:      pred.OMSVerification.SignatureDigest,
		OMSSignerFingerprint:    pred.OMSVerification.SignerFingerprint,
		EvalReportDigest:        pred.Evaluation.ReportDigest,
		EvalAttestationDigest:   pred.Evaluation.AttestationDigest,
		EvalSuiteDigest:         pred.Evaluation.SuiteDigest,
		EvalDatasetDigest:       pred.Evaluation.DatasetDigest,
		EvalSignerFingerprint:   pred.Evaluation.SignerFingerprint,
		LoRAStatus:              pred.Bundle.LoRAStatus,
		VerifiedBaseBundleID:    pred.Bundle.VerifiedBaseID,
		RuntimeImage:            rtImage,
		ServingConfigDigest:     servingCfgDigest,
		QualificationPolicyHash: pred.Policy.Digest,
		GateStatus:              pred.Decision.GateStatus,
		Reason:                  qv.Reason,
	}

	if err != nil {
		if out.Status == StatusUntrusted {
			return out, fmt.Errorf("%w: %s", ErrUntrustedSigner, out.Reason)
		}
		return out, fmt.Errorf("%w: %v", ErrInvalidReleaseQualification, err)
	}

	// Enforce cross-evidence digest bindings against the sibling OCI referrers verified in the same pass.
	if opts.ExpectedManifestDigest != "" && pred.Bundle.ManifestDigest != opts.ExpectedManifestDigest {
		out.Status = StatusInvalid
		out.Reason = fmt.Sprintf(
			"release qualification bundle.manifest_digest %s does not match verified manifest_digest %s",
			pred.Bundle.ManifestDigest, opts.ExpectedManifestDigest,
		)
		return out, fmt.Errorf("%w: %s", ErrInvalidReleaseQualification, out.Reason)
	}
	if opts.ExpectedBOMDigest != "" && pred.BOM.Digest != opts.ExpectedBOMDigest {
		out.Status = StatusInvalid
		out.Reason = fmt.Sprintf(
			"release qualification bom.digest %s does not match verified BOM canonical hash %s (evidence transplant detected)",
			pred.BOM.Digest, opts.ExpectedBOMDigest,
		)
		return out, fmt.Errorf("%w: %s", ErrInvalidReleaseQualification, out.Reason)
	}
	if opts.ExpectedOMSSignatureDigest != "" && pred.OMSVerification.SignatureDigest != opts.ExpectedOMSSignatureDigest {
		out.Status = StatusInvalid
		out.Reason = fmt.Sprintf(
			"release qualification oms_verification.signature_digest %s does not match verified OMS envelope digest %s (evidence transplant detected)",
			pred.OMSVerification.SignatureDigest, opts.ExpectedOMSSignatureDigest,
		)
		return out, fmt.Errorf("%w: %s", ErrInvalidReleaseQualification, out.Reason)
	}
	if opts.ExpectedEvalReportDigest != "" && pred.Evaluation.ReportDigest != opts.ExpectedEvalReportDigest {
		out.Status = StatusInvalid
		out.Reason = fmt.Sprintf(
			"release qualification evaluation.report_digest %s does not match verified evaluation report digest %s",
			pred.Evaluation.ReportDigest, opts.ExpectedEvalReportDigest,
		)
		return out, fmt.Errorf("%w: %s", ErrInvalidReleaseQualification, out.Reason)
	}
	if opts.ExpectedEvalAttestationDigest != "" && pred.Evaluation.AttestationDigest != opts.ExpectedEvalAttestationDigest {
		out.Status = StatusInvalid
		out.Reason = fmt.Sprintf(
			"release qualification evaluation.attestation_digest %s does not match verified evaluation attestation digest %s (evidence transplant detected)",
			pred.Evaluation.AttestationDigest, opts.ExpectedEvalAttestationDigest,
		)
		return out, fmt.Errorf("%w: %s", ErrInvalidReleaseQualification, out.Reason)
	}

	if opts.RequireTrustedEvaluator {
		if !pred.Evaluation.Present || pred.Evaluation.EffectiveStatus != string(llmreleasegate.GatePass) ||
			pred.Evaluation.TrustStatus != string(llmreleasegate.TrustVerifiedTrusted) ||
			pred.Evaluation.BindingStatus != string(llmreleasegate.BindingMatched) {
			out.Status = StatusInvalid
			out.Reason = fmt.Sprintf(
				"release qualification predicate does not record verified trusted evaluation (present=%v, status=%s, trust=%s, binding=%s)",
				pred.Evaluation.Present, pred.Evaluation.EffectiveStatus, pred.Evaluation.TrustStatus, pred.Evaluation.BindingStatus,
			)
			return out, fmt.Errorf("%w: %s", ErrInvalidReleaseQualification, out.Reason)
		}
	}

	if opts.maxAgeExceeded(pred.Timestamp) {
		out.Status = StatusInvalid
		out.Reason = fmt.Sprintf("release qualification timestamp %q exceeds max age %s or is future-skewed", pred.Timestamp, opts.MaxAge)
		return out, fmt.Errorf("%w: %s", ErrInvalidReleaseQualification, out.Reason)
	}

	return out, nil
}

func (opts ReleaseVerifyOptions) maxAgeExceeded(ts string) bool {
	if opts.MaxAge <= 0 {
		return false
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(ts))
	if err != nil {
		return true
	}
	age := now.Sub(parsed)
	return age > opts.MaxAge || parsed.After(now.Add(5*time.Minute))
}
