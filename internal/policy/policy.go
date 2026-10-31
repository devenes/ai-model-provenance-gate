// Package policy implements the fail-closed release qualification policy engine.
package policy

import (
	"fmt"
	"strings"
	"time"

	"github.com/devenes/ai-model-provenance-gate/internal/bom"
	"github.com/devenes/ai-model-provenance-gate/internal/bundle"
	"github.com/devenes/ai-model-provenance-gate/internal/config"
	"github.com/devenes/ai-model-provenance-gate/internal/evaluation/llmreleasegate"
	"github.com/devenes/ai-model-provenance-gate/internal/formats/peft"
	"github.com/devenes/ai-model-provenance-gate/internal/oms"
	"github.com/devenes/ai-model-provenance-gate/internal/provenance"
	"github.com/devenes/ai-model-provenance-gate/internal/scanner"
	"github.com/devenes/ai-model-provenance-gate/internal/verification"
)

// GateStatus represents the final fail-closed decision of a policy evaluation.
type GateStatus string

const (
	StatusPass    GateStatus = "PASS"
	StatusFail    GateStatus = "FAIL"
	StatusBlocked GateStatus = "BLOCKED"
	StatusNotRun  GateStatus = "NOT_RUN"
	StatusError   GateStatus = "ERROR"
)

// Exit codes matching the portfolio release gate contract.
const (
	ExitPass     = 0
	ExitFail     = 1
	ExitInvalid  = 2
	ExitBlocked  = 3
	ExitInternal = 4
)

// ExitCodeForStatus maps a GateStatus to its deterministic process exit code.
func ExitCodeForStatus(st GateStatus) int {
	switch st {
	case StatusPass:
		return ExitPass
	case StatusFail:
		return ExitFail
	case StatusBlocked, StatusNotRun:
		return ExitBlocked
	default:
		return ExitInvalid
	}
}

// DecisionReason records an actionable finding contributing to the final policy decision.
type DecisionReason struct {
	Code     string `json:"code"`
	Category string `json:"category"`
	Severity string `json:"severity"` // "error", "warning", "info"
	Status   string `json:"status"`   // "PASS", "FAIL", "BLOCKED"
	Message  string `json:"message"`
}

// EvaluationInput aggregates all verified evidence signals for the policy engine.
type EvaluationInput struct {
	NotRun        bool
	Policy        config.Policy
	Inspection    bundle.InspectionResult
	BOM           bom.GeneratedBOM
	OMS           oms.Result
	HasEvaluation bool
	Evaluation    llmreleasegate.EvaluationSummary
	Provenance    provenance.Result
	Scanner       scanner.Result
	RuntimeImage  string
}

// Decision holds the deterministic outcome of the policy engine.
type Decision struct {
	GateStatus        GateStatus               `json:"gate_status"`
	ExitCode          int                      `json:"exit_code"`
	DecisionMode      string                   `json:"decision_mode"`
	PolicyDigest      string                   `json:"policy_digest"`
	Reasons           []DecisionReason         `json:"reasons"`
	ExceptionsApplied []config.PolicyException `json:"exceptions_applied,omitempty"`
}

// Evaluate executes the fail-closed release qualification policy state machine.
func Evaluate(in EvaluationInput) Decision {
	if in.NotRun {
		return Decision{
			GateStatus:   StatusNotRun,
			ExitCode:     ExitBlocked,
			DecisionMode: in.Policy.Release.DecisionMode,
			PolicyDigest: in.Policy.Digest,
			Reasons: []DecisionReason{
				{
					Code:     "GATE_NOT_RUN",
					Category: "execution",
					Severity: "warning",
					Status:   string(StatusNotRun),
					Message:  "policy evaluation was invoked in not_run mode",
				},
			},
		}
	}

	var reasons []DecisionReason
	var appliedExceptions []config.PolicyException
	hasFail := false
	hasBlocked := false

	recordCheck := func(ruleCode, category string, checkStatus GateStatus, msg string) {
		if checkStatus == StatusPass {
			reasons = append(reasons, DecisionReason{
				Code:     ruleCode,
				Category: category,
				Severity: "info",
				Status:   string(StatusPass),
				Message:  msg,
			})
			return
		}
		if ex, ok := in.Policy.FindException(ruleCode); ok {
			appliedExceptions = append(appliedExceptions, ex)
			reasons = append(reasons, DecisionReason{
				Code:     ruleCode + "_EXCEPTION_APPLIED",
				Category: category,
				Severity: "warning",
				Status:   string(StatusPass),
				Message:  fmt.Sprintf("%s [OVERRIDDEN by exception %s approved by %s: %s]", msg, ex.ID, ex.ApprovedBy, ex.Reason),
			})
			return
		}
		if expEx, expired := in.Policy.FindExpiredException(ruleCode, time.Now().UTC()); expired {
			msg = fmt.Sprintf("%s [exception %s expired at %s and cannot override failure]", msg, expEx.ID, expEx.ExpiresAt)
		}
		switch checkStatus {
		case StatusFail:
			hasFail = true
		case StatusBlocked:
			hasBlocked = true
		}
		reasons = append(reasons, DecisionReason{
			Code:     ruleCode,
			Category: category,
			Severity: "error",
			Status:   string(checkStatus),
			Message:  msg,
		})
	}

	// 1. Bundle Integrity & Hygiene checks
	recordCheck(
		"BUNDLE_IDENTITY_DETERMINISTIC",
		"bundle",
		StatusPass,
		fmt.Sprintf("computed deterministic model bundle identity %s (%d files, %d bytes)", in.Inspection.BundleID, in.Inspection.Manifest.FileCount, in.Inspection.Manifest.TotalBytes),
	)

	if !in.Policy.IsUnknownFileAllowed() && in.Inspection.Manifest.FormatSummary.UnknownFileCount > 0 {
		recordCheck(
			"BUNDLE_UNKNOWN_FILES_FORBIDDEN",
			"bundle",
			StatusFail,
			fmt.Sprintf("bundle contains %d unknown regular file(s): %v", in.Inspection.Manifest.FormatSummary.UnknownFileCount, in.Inspection.Manifest.SecurityFlags.UnknownRegularFiles),
		)
	}

	if in.Inspection.Manifest.SecurityFlags.ContainsRemoteCodeHooks {
		recordCheck(
			"BUNDLE_REMOTE_CODE_AUTO_MAP",
			"security",
			StatusFail,
			"model config.json contains auto_map custom code execution hooks",
		)
	}

	// 2. LoRA Relationship check
	lora := in.Inspection.Manifest.LoRARelationship
	if lora.IsAdapter {
		switch lora.VerificationStatus {
		case peft.StatusMismatch:
			recordCheck("LORA_BASE_MODEL_MISMATCH", "lora", StatusFail, lora.VerificationNotes)
		case peft.StatusMissing:
			recordCheck("LORA_METADATA_MISSING", "lora", StatusFail, lora.VerificationNotes)
		case peft.StatusDeclaredUnverified:
			if in.Policy.Bundle.RequireVerifiedLoRABase {
				recordCheck(
					"LORA_BASE_MODEL_UNVERIFIED",
					"lora",
					StatusBlocked,
					"policy requires cryptographic verification of LoRA base model bundle (--base-bundle), but base model is only DECLARED_UNVERIFIED",
				)
			} else {
				reasons = append(reasons, DecisionReason{
					Code:     "LORA_BASE_MODEL_DECLARED_UNVERIFIED",
					Category: "lora",
					Severity: "warning",
					Status:   string(StatusPass),
					Message:  lora.VerificationNotes,
				})
			}
		case peft.StatusVerified:
			recordCheck("LORA_BASE_MODEL_VERIFIED", "lora", StatusPass, lora.VerificationNotes)
		}
	}

	// 3. CycloneDX AI/ML-BOM consistency check
	if in.BOM.Digest != "" {
		recordCheck(
			"CYCLONEDX_BOM_VALIDATED",
			"bom",
			StatusPass,
			fmt.Sprintf("validated CycloneDX %s AI/ML-BOM (%s) with 1:1 file inventory correspondence", in.BOM.Document.SpecVersion, in.BOM.Digest),
		)
	}

	// 4. OpenSSF Model Signing (OMS) checks
	if in.Policy.Signing.RequireOMS {
		switch in.OMS.Status {
		case verification.StatusVerified:
			recordCheck(
				"OMS_SIGNATURE_VERIFIED",
				"signing",
				StatusPass,
				fmt.Sprintf("verified OMS signature (%s) by trusted signer %q (%s)", in.OMS.PredicateType, in.OMS.SignerID, in.OMS.SignerFingerprint),
			)
		case verification.StatusMissing:
			recordCheck("OMS_SIGNATURE_MISSING", "signing", StatusBlocked, in.OMS.Reason)
		case verification.StatusBlocked:
			recordCheck("OMS_VERIFICATION_BLOCKED", "signing", StatusBlocked, in.OMS.Reason)
		case verification.StatusUntrusted:
			recordCheck("OMS_SIGNER_UNTRUSTED", "signing", StatusFail, in.OMS.Reason)
		default:
			recordCheck("OMS_SIGNATURE_INVALID", "signing", StatusFail, in.OMS.Reason)
		}
	}

	// 5. LLM Release Gate Evaluation checks
	if in.Policy.IsEvaluationRequired() {
		if !in.HasEvaluation {
			recordCheck(
				"EVALUATION_EVIDENCE_MISSING",
				"evaluation",
				StatusBlocked,
				"mandatory LLM Release Gate evaluation report (--evaluation-report) was not provided",
			)
		} else {
			eval := in.Evaluation
			switch {
			case eval.TrustStatus == llmreleasegate.TrustInvalidOrTampered:
				recordCheck("EVALUATION_EVIDENCE_TAMPERED", "evaluation", StatusFail, eval.Reason)
			case eval.TrustStatus == llmreleasegate.TrustUntrustedSigner:
				recordCheck("EVALUATION_SIGNER_UNTRUSTED", "evaluation", StatusFail, eval.Reason)
			case eval.TrustStatus == llmreleasegate.TrustBlocked:
				recordCheck("EVALUATION_VERIFICATION_BLOCKED", "evaluation", StatusBlocked, eval.Reason)
			case eval.BindingStatus == llmreleasegate.BindingMismatch:
				recordCheck("EVALUATION_ARTIFACT_MISMATCH", "evaluation", StatusFail, eval.Reason)
			case eval.ReportedGateStatus == llmreleasegate.GateFail:
				recordCheck("EVALUATION_STATUS_FAIL", "evaluation", StatusFail, eval.Reason)
			case eval.ReportedGateStatus == llmreleasegate.GateBlocked:
				recordCheck("EVALUATION_STATUS_BLOCKED", "evaluation", StatusBlocked, eval.Reason)
			case eval.ReportedGateStatus == llmreleasegate.GateNotRun:
				recordCheck("EVALUATION_STATUS_NOT_RUN", "evaluation", StatusBlocked, eval.Reason)
			case eval.EvidenceQuality != llmreleasegate.EvidenceComplete || eval.ReportedExitCode != 0:
				recordCheck("EVALUATION_EVIDENCE_INCOMPLETE", "evaluation", StatusBlocked, eval.Reason)
			case in.Policy.Evaluation.RequireArtifactBinding && eval.BindingStatus == llmreleasegate.BindingUnbound:
				recordCheck("EVALUATION_ARTIFACT_UNBOUND", "evaluation", StatusBlocked, eval.Reason)
			case in.Policy.Evaluation.RequireArtifactBinding && in.Policy.Evaluation.RequireTrustedEvidence && !in.Policy.Evaluation.AllowPostHocBinding && eval.BindingMode == llmreleasegate.BindingModePostHocOperator:
				recordCheck("EVALUATION_POST_HOC_BINDING_REJECTED", "evaluation", StatusBlocked, eval.Reason)
			case in.Policy.Evaluation.RequireTrustedEvidence && eval.TrustStatus != llmreleasegate.TrustVerifiedTrusted:
				recordCheck("EVALUATION_EVIDENCE_UNTRUSTED", "evaluation", StatusBlocked, eval.Reason)
			case !eval.EligibleForRelease && eval.EffectiveGateStatus == llmreleasegate.GateFail:
				recordCheck("EVALUATION_POLICY_CONSTRAINT_FAILED", "evaluation", StatusFail, eval.Reason)
			case !eval.EligibleForRelease:
				recordCheck("EVALUATION_EVIDENCE_BLOCKED", "evaluation", StatusBlocked, eval.Reason)
			default:
				recordCheck("EVALUATION_QUALIFIED", "evaluation", StatusPass, eval.Reason)
			}
		}
	}

	// 6. Optional Upstream SLSA Build Provenance check
	if in.Policy.Provenance.RequireUpstreamSLSA {
		switch in.Provenance.Status {
		case verification.StatusVerified:
			recordCheck("UPSTREAM_SLSA_VERIFIED", "provenance", StatusPass, in.Provenance.Reason)
		case verification.StatusNotRun, verification.StatusMissing, verification.StatusBlocked:
			recordCheck("UPSTREAM_SLSA_MISSING_OR_BLOCKED", "provenance", StatusBlocked, in.Provenance.Reason)
		default:
			recordCheck("UPSTREAM_SLSA_INVALID", "provenance", StatusFail, in.Provenance.Reason)
		}
	}

	// 7. Security Scanner check
	switch in.Scanner.Status {
	case scanner.StatusFail:
		recordCheck("SCANNER_ISSUES_FOUND", "scanner", StatusFail, in.Scanner.Reason)
	case scanner.StatusBlocked:
		if in.Policy.Scanner.Required {
			recordCheck("SCANNER_REQUIRED_NOT_RUN", "scanner", StatusBlocked, in.Scanner.Reason)
		}
	case scanner.StatusPass:
		recordCheck("SCANNER_PASSED", "scanner", StatusPass, in.Scanner.Reason)
	case scanner.StatusNotRun:
		if in.Policy.Scanner.Required {
			recordCheck("SCANNER_REQUIRED_NOT_RUN", "scanner", StatusBlocked, in.Scanner.Reason)
		}
	}

	// 8. Optional Runtime Image Immutability check (when supplied during gate evaluate)
	if strings.TrimSpace(in.RuntimeImage) != "" && in.Policy.Deployment.RequireImmutableImage {
		if !IsImmutableOCIRef(in.RuntimeImage) {
			recordCheck(
				"RUNTIME_IMAGE_MUTABLE",
				"deployment",
				StatusFail,
				fmt.Sprintf("runtime image reference %q does not contain an immutable @sha256:<64-hex> digest", in.RuntimeImage),
			)
		} else {
			recordCheck(
				"RUNTIME_IMAGE_IMMUTABLE",
				"deployment",
				StatusPass,
				fmt.Sprintf("verified immutable runtime image digest %q", in.RuntimeImage),
			)
		}
	}

	finalStatus := StatusPass
	switch {
	case hasFail:
		finalStatus = StatusFail
	case hasBlocked:
		finalStatus = StatusBlocked
	}

	return Decision{
		GateStatus:        finalStatus,
		ExitCode:          ExitCodeForStatus(finalStatus),
		DecisionMode:      in.Policy.Release.DecisionMode,
		PolicyDigest:      in.Policy.Digest,
		Reasons:           reasons,
		ExceptionsApplied: appliedExceptions,
	}
}

// IsImmutableOCIRef returns true if imageRef pins an immutable @sha256:<64-lowercase-hex> digest.
func IsImmutableOCIRef(imageRef string) bool {
	imageRef = strings.TrimSpace(imageRef)
	idx := strings.LastIndex(imageRef, "@sha256:")
	if idx <= 0 {
		return false
	}
	hexPart := imageRef[idx+len("@sha256:"):]
	if len(hexPart) != 64 {
		return false
	}
	for _, r := range hexPart {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}
