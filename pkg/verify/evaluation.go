package verify

import (
	"fmt"
	"math"

	"github.com/devenes/ai-model-provenance-gate/internal/evaluation/llmreleasegate"
)

// VerifyEvaluationBytes verifies an in-memory llm-release-gate report.json and signed evaluation-evidence/v1
// DSSE attestation against the evaluators trust domain and expected model bundle identity.
func VerifyEvaluationBytes(
	rawReport []byte,
	rawAttestation []byte,
	opts EvalVerifyOptions,
) (EvaluationSummary, error) {
	trusted, err := resolveSignerRules(opts.TrustedEvaluators)
	if err != nil {
		return EvaluationSummary{
			Status: StatusBlocked,
			Reason: err.Error(),
		}, err
	}
	untrusted := resolveUntrustedCandidateKeys(trusted, opts.UntrustedCandidates)

	var maxAgeHours int
	if opts.MaxAge > 0 {
		maxAgeHours = int(math.Ceil(opts.MaxAge.Hours()))
		if maxAgeHours < 1 {
			maxAgeHours = 1
		}
	}

	sum, err := llmreleasegate.VerifyBytes(rawReport, rawAttestation, llmreleasegate.VerifyOptions{
		ExpectedBundleID:       opts.ExpectedBundleID,
		TrustedSigners:         trusted,
		CandidateUntrustedKeys: untrusted,
		RequireArtifactBinding: opts.RequireArtifactBinding,
		RequireTrustedEvidence: opts.RequireTrustedEvidence,
		AllowPostHocBinding:    opts.AllowPostHocBinding,
		MaxAgeHours:            maxAgeHours,
		ExpectedSuiteDigest:    opts.ExpectedSuiteDigest,
		ExpectedDatasetDigest:  opts.ExpectedDatasetDigest,
		Now:                    opts.Now,
	})

	status := StatusVerified
	if err != nil || !sum.EligibleForRelease || sum.EffectiveGateStatus != llmreleasegate.GatePass {
		switch sum.TrustStatus {
		case llmreleasegate.TrustUntrustedSigner:
			status = StatusUntrusted
		case llmreleasegate.TrustBlocked:
			status = StatusBlocked
		default:
			if sum.EffectiveGateStatus == llmreleasegate.GateBlocked {
				status = StatusBlocked
			} else {
				status = StatusInvalid
			}
		}
	}

	out := EvaluationSummary{
		Status:                       status,
		ReportDigest:                 sum.ReportDigest,
		AttestationDigest:            sum.AttestationDigest,
		AttestationKind:              sum.AttestationKind,
		SchemaVersion:                sum.SchemaVersion,
		RunID:                        sum.RunID,
		Timestamp:                    sum.Timestamp,
		SuiteDigest:                  sum.SuiteDigest,
		DatasetDigest:                sum.DatasetDigest,
		ReportedGateStatus:           string(sum.ReportedGateStatus),
		EffectiveGateStatus:          string(sum.EffectiveGateStatus),
		EvidenceQuality:              string(sum.EvidenceQuality),
		BindingStatus:                string(sum.BindingStatus),
		BindingMode:                  string(sum.BindingMode),
		TrustStatus:                  string(sum.TrustStatus),
		DeclaredBundleID:             sum.DeclaredBundleID,
		AttestedBundleID:             sum.AttestedBundleID,
		ExpectedBundleID:             sum.ExpectedBundleID,
		ReportIntegrityVerified:      sum.ReportIntegrityVerified,
		ReportAuthenticityVerified:   sum.ReportAuthenticityVerified,
		ProducerIdentityVerified:     sum.ProducerIdentityVerified,
		ArtifactBindingVerified:      sum.ArtifactBindingVerified,
		ExecutionEvidenceVerified:    sum.ExecutionEvidenceVerified,
		SuiteDatasetIdentityVerified: sum.SuiteDatasetIdentityVerified,
		FreshnessVerified:            sum.FreshnessVerified,
		EligibleForRelease:           sum.EligibleForRelease,
		SignerID:                     sum.SignerID,
		SignerFingerprint:            sum.SignerFingerprint,
		Reason:                       sum.Reason,
	}

	if err != nil {
		if status == StatusUntrusted {
			return out, fmt.Errorf("%w: %s", ErrUntrustedSigner, out.Reason)
		}
		return out, fmt.Errorf("%w: %v", ErrInvalidEvaluationEvidence, err)
	}
	return out, nil
}
