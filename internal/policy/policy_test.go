package policy

import (
	"errors"
	"strings"
	"testing"

	"github.com/devenes/ai-model-provenance-gate/internal/bom"
	"github.com/devenes/ai-model-provenance-gate/internal/bundle"
	"github.com/devenes/ai-model-provenance-gate/internal/config"
	"github.com/devenes/ai-model-provenance-gate/internal/evaluation/llmreleasegate"
	"github.com/devenes/ai-model-provenance-gate/internal/formats/peft"
	"github.com/devenes/ai-model-provenance-gate/internal/manifest"
	"github.com/devenes/ai-model-provenance-gate/internal/oms"
	"github.com/devenes/ai-model-provenance-gate/internal/provenance"
	"github.com/devenes/ai-model-provenance-gate/internal/scanner"
	"github.com/devenes/ai-model-provenance-gate/internal/verification"
)

func sampleValidEvalInput() EvaluationInput {
	pol := config.StrictDefaultPolicy()
	return EvaluationInput{
		Policy: pol,
		Inspection: bundle.InspectionResult{
			BundleID: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
			Manifest: manifest.BundleManifest{
				FileCount:  2,
				TotalBytes: 1024,
				FormatSummary: manifest.FormatSummary{
					PrimaryFormat:    "safetensors",
					UnknownFileCount: 0,
				},
				LoRARelationship: peft.AdapterMetadata{
					IsAdapter:          false,
					VerificationStatus: peft.StatusNone,
				},
			},
		},
		BOM: bom.GeneratedBOM{
			Digest: "sha256:2222222222222222222222222222222222222222222222222222222222222222",
		},
		OMS: oms.Result{
			Status:            verification.StatusVerified,
			PredicateType:     "https://model_signing/signature/v1.0",
			SignerID:          "model-signer-1",
			SignerFingerprint: "sha256:3333333333333333333333333333333333333333333333333333333333333333",
		},
		HasEvaluation: true,
		Evaluation: llmreleasegate.EvaluationSummary{
			RunID:                      "run-1",
			ReportedGateStatus:         llmreleasegate.GatePass,
			EffectiveGateStatus:        llmreleasegate.GatePass,
			EvidenceQuality:            llmreleasegate.EvidenceComplete,
			ReportedExitCode:           0,
			BindingStatus:              llmreleasegate.BindingMatched,
			BindingMode:                llmreleasegate.BindingModeNativeEvaluator,
			TrustStatus:                llmreleasegate.TrustVerifiedTrusted,
			ReportIntegrityVerified:    true,
			ReportAuthenticityVerified: true,
			ProducerIdentityVerified:   true,
			ArtifactBindingVerified:    true,
			ExecutionEvidenceVerified:  true,
			EligibleForRelease:         true,
			Reason:                     "verified",
		},
		Scanner:    scanner.Result{Status: scanner.StatusNotRun},
		Provenance: provenance.Result{Status: verification.StatusNotRun},
	}
}

func TestPolicyFailClosedAndExpiredExceptions(t *testing.T) {
	// 1. Strict policy rejects exceptions and allow_post_hoc_binding at config parse time
	strictWithExYAML := `schema_version: "v1"
bundle:
  reject_symlinks: true
  require_deterministic_identity: true
signing:
  require_oms: true
evaluation:
  required_status: PASS
  require_artifact_binding: true
  require_trusted_evidence: true
scanner:
  required: false
deployment:
  require_immutable_image: true
release:
  decision_mode: strict
  exceptions:
    - id: "EX-1"
      rule: "OMS_SIGNATURE_MISSING"
      reason: "test"
      approved_by: "sec"
`
	if _, err := config.ParsePolicyBytes([]byte(strictWithExYAML), ""); !errors.Is(err, config.ErrInvalidPolicy) {
		t.Fatalf("expected strict policy with exceptions to fail validation, got %v", err)
	}

	strictPostHocYAML := `schema_version: "v1"
bundle:
  reject_symlinks: true
  require_deterministic_identity: true
signing:
  require_oms: true
evaluation:
  required_status: PASS
  require_artifact_binding: true
  require_trusted_evidence: true
  allow_post_hoc_binding: true
scanner:
  required: false
deployment:
  require_immutable_image: true
release:
  decision_mode: strict
`
	if _, err := config.ParsePolicyBytes([]byte(strictPostHocYAML), ""); !errors.Is(err, config.ErrInvalidPolicy) {
		t.Fatalf("expected strict policy with allow_post_hoc_binding=true to fail validation, got %v", err)
	}

	// 2. Invalid RFC3339 expires_at rejected
	badExpiresYAML := strings.Replace(strictWithExYAML, "decision_mode: strict", "decision_mode: permissive", 1) + "      expires_at: \"not-a-timestamp\"\n"
	if _, err := config.ParsePolicyBytes([]byte(badExpiresYAML), ""); !errors.Is(err, config.ErrInvalidPolicy) {
		t.Fatalf("expected invalid expires_at to fail validation, got %v", err)
	}

	// 3. Expired exception in permissive mode does NOT override failure
	expiredExYAML := strings.Replace(strictWithExYAML, "decision_mode: strict", "decision_mode: permissive", 1) + "      expires_at: \"2020-01-01T00:00:00Z\"\n"
	polExpired, err := config.ParsePolicyBytes([]byte(expiredExYAML), "")
	if err != nil {
		t.Fatalf("ParsePolicyBytes expiredExYAML: %v", err)
	}
	inExpired := sampleValidEvalInput()
	inExpired.Policy = polExpired
	inExpired.OMS = oms.Result{Status: verification.StatusMissing, Reason: "no signature"}
	decExpired := Evaluate(inExpired)
	if decExpired.GateStatus != StatusBlocked || len(decExpired.ExceptionsApplied) != 0 {
		t.Fatalf("expected expired exception to be rejected and status=BLOCKED, got %+v", decExpired)
	}

	// 4. Active future exception in permissive mode overrides and records in ExceptionsApplied
	activeExYAML := strings.Replace(strictWithExYAML, "decision_mode: strict", "decision_mode: permissive", 1) + "      expires_at: \"2099-01-01T00:00:00Z\"\n"
	polActive, err := config.ParsePolicyBytes([]byte(activeExYAML), "")
	if err != nil {
		t.Fatalf("ParsePolicyBytes activeExYAML: %v", err)
	}
	inActive := sampleValidEvalInput()
	inActive.Policy = polActive
	inActive.OMS = oms.Result{Status: verification.StatusMissing, Reason: "no signature"}
	decActive := Evaluate(inActive)
	if decActive.GateStatus != StatusPass || len(decActive.ExceptionsApplied) != 1 {
		t.Fatalf("expected active exception in permissive mode to apply and record, got %+v", decActive)
	}

	// 5. Post-hoc evaluation binding blocked in strict mode
	inPostHoc := sampleValidEvalInput()
	inPostHoc.Evaluation.BindingMode = llmreleasegate.BindingModePostHocOperator
	inPostHoc.Evaluation.EligibleForRelease = false
	inPostHoc.Evaluation.EffectiveGateStatus = llmreleasegate.GateBlocked
	inPostHoc.Evaluation.Reason = "post-hoc operator binding rejected"
	decPostHoc := Evaluate(inPostHoc)
	if decPostHoc.GateStatus != StatusBlocked || decPostHoc.ExitCode != ExitBlocked {
		t.Fatalf("expected post-hoc binding in strict mode to be BLOCKED, got %+v", decPostHoc)
	}

	// 6. Unverified LoRA base model blocked when RequireVerifiedLoRABase=true
	inLoRA := sampleValidEvalInput()
	inLoRA.Policy.Bundle.RequireVerifiedLoRABase = true
	inLoRA.Inspection.Manifest.LoRARelationship = peft.AdapterMetadata{
		IsAdapter:          true,
		VerificationStatus: peft.StatusDeclaredUnverified,
		VerificationNotes:  "base model declared only",
	}
	decLoRA := Evaluate(inLoRA)
	if decLoRA.GateStatus != StatusBlocked {
		t.Fatalf("expected unverified LoRA base with RequireVerifiedLoRABase=true to be BLOCKED, got %+v", decLoRA)
	}

	// 7. Required scanner not run -> BLOCKED; scanner issues found -> FAIL
	inScanBlocked := sampleValidEvalInput()
	inScanBlocked.Policy.Scanner.Required = true
	inScanBlocked.Scanner = scanner.Result{Status: scanner.StatusNotRun, Reason: "scanner not run"}
	if dec := Evaluate(inScanBlocked); dec.GateStatus != StatusBlocked {
		t.Fatalf("expected required scanner NOT_RUN to be BLOCKED, got %+v", dec)
	}

	inScanFail := sampleValidEvalInput()
	inScanFail.Scanner = scanner.Result{Status: scanner.StatusFail, Reason: "critical deserialization issue"}
	if dec := Evaluate(inScanFail); dec.GateStatus != StatusFail {
		t.Fatalf("expected scanner FAIL to fail gate, got %+v", dec)
	}

	// 8. Audit mode (DecisionModeAudit) rejects exceptions and remains fail-closed
	auditYAML := `schema_version: "v1"
bundle:
  reject_symlinks: true
  require_deterministic_identity: true
signing:
  require_oms: true
evaluation:
  required_status: PASS
  require_artifact_binding: true
  require_trusted_evidence: true
scanner:
  required: false
deployment:
  require_immutable_image: true
release:
  decision_mode: audit
`
	polAudit, err := config.ParsePolicyBytes([]byte(auditYAML), "")
	if err != nil {
		t.Fatalf("ParsePolicyBytes auditYAML: %v", err)
	}
	inAudit := sampleValidEvalInput()
	inAudit.Policy = polAudit
	inAudit.OMS = oms.Result{Status: verification.StatusInvalid, Reason: "bad signature"}
	decAudit := Evaluate(inAudit)
	if decAudit.DecisionMode != config.DecisionModeAudit || decAudit.GateStatus != StatusFail {
		t.Fatalf("expected audit mode to remain fail-closed (StatusFail), got %+v", decAudit)
	}
}
