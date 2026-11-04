// Package llmreleasegate implements the read-only adapter and cryptographic evidence binding
// verifier for LLM Release Gate (llm-release-gate.report/v1) reports.
package llmreleasegate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/devenes/ai-model-provenance-gate/internal/digest"
	"github.com/devenes/ai-model-provenance-gate/internal/signing"
	"github.com/devenes/ai-model-provenance-gate/internal/verification"
	"github.com/devenes/ai-model-provenance-gate/internal/version"
)

const (
	// ReportSchemaVersion is the exact schema version emitted by llm-release-gate.
	ReportSchemaVersion = "llm-release-gate.report/v1"
	// MetadataKeyModelBundleID is the candidate.metadata key used to bind an evaluation report to a bundle-identity/v1 digest.
	MetadataKeyModelBundleID = "model_bundle_id"
)

// GateStatus mirrors the llm-release-gate gateStatus enum.
type GateStatus string

const (
	GatePass    GateStatus = "PASS"
	GateFail    GateStatus = "FAIL"
	GateBlocked GateStatus = "BLOCKED"
	GateNotRun  GateStatus = "NOT_RUN"
)

// EvidenceQuality mirrors the llm-release-gate evidenceQuality enum.
type EvidenceQuality string

const (
	EvidenceComplete EvidenceQuality = "COMPLETE"
	EvidenceLimited  EvidenceQuality = "LIMITED"
)

// BindingStatus describes whether an evaluation report is cryptographically bound to the inspected model bundle.
type BindingStatus string

const (
	// BindingMatched indicates the report explicitly identifies the exact inspected model_bundle_id.
	BindingMatched BindingStatus = "MATCHED"
	// BindingMismatch indicates the report identifies a different model_bundle_id than the inspected bundle.
	BindingMismatch BindingStatus = "MISMATCH"
	// BindingUnbound indicates the report contains no model_bundle_id binding.
	BindingUnbound BindingStatus = "UNBOUND"
)

// BindingMode distinguishes evaluation-time native binding from post-hoc operator assertion.
type BindingMode string

const (
	// BindingModeNativeEvaluator indicates the report natively contains candidate.metadata.model_bundle_id and is attested by an evaluation producer.
	BindingModeNativeEvaluator BindingMode = "NATIVE_CI_EVALUATOR"
	// BindingModePostHocOperator indicates the report lacked candidate.metadata.model_bundle_id at evaluation time and was bound post-hoc via DSSE.
	BindingModePostHocOperator BindingMode = "POST_HOC_OPERATOR"
	// BindingModeReportMetadataOnly indicates the report contains candidate.metadata.model_bundle_id without a signed DSSE attestation.
	BindingModeReportMetadataOnly BindingMode = "REPORT_METADATA_ONLY"
	// BindingModeUnbound indicates neither the report nor an attestation binds to a model_bundle_id.
	BindingModeUnbound BindingMode = "UNBOUND"

	// AttestationKindTrustedEvaluator indicates the evaluation attestation was emitted by an automated trusted evaluator at evaluation time.
	AttestationKindTrustedEvaluator = "TRUSTED_EVALUATOR_ATTESTATION"
	// AttestationKindOperatorEndorsement indicates an unsigned external evaluation report was signed post-hoc as an operator endorsement.
	AttestationKindOperatorEndorsement = "OPERATOR_ENDORSEMENT"

	// ProducerRoleTrustedEvaluator is the signer role for automated evaluation producers.
	ProducerRoleTrustedEvaluator = "trusted-evaluator"
	// ProducerRoleOperatorEndorser is the signer role for post-hoc operator endorsements.
	ProducerRoleOperatorEndorser = "operator-endorser"
)

// TrustStatus distinguishes a plain local JSON file from cryptographically verified evaluation evidence.
type TrustStatus string

const (
	// TrustVerifiedTrusted indicates a valid DSSE evaluation attestation signed by a trusted evaluator key.
	TrustVerifiedTrusted TrustStatus = "VERIFIED_TRUSTED"
	// TrustUnverifiedLocalJSON indicates a plain unsigned JSON report on disk.
	TrustUnverifiedLocalJSON TrustStatus = "UNVERIFIED_LOCAL_JSON"
	// TrustUntrustedSigner indicates the evaluation attestation was signed by an unknown/untrusted signer.
	TrustUntrustedSigner TrustStatus = "UNTRUSTED_SIGNER"
	// TrustInvalidOrTampered indicates the evaluation attestation signature failed or the report digest was altered after signing.
	TrustInvalidOrTampered TrustStatus = "INVALID_OR_TAMPERED"
	// TrustBlocked indicates trusted verification was requested without public key material.
	TrustBlocked TrustStatus = "BLOCKED"
)

var (
	// ErrInvalidEvaluationReport is returned when an llm-release-gate JSON report fails schema validation.
	ErrInvalidEvaluationReport = errors.New("invalid llm-release-gate evaluation report")
	// ErrUnboundEvaluation is returned when an evaluation report lacks model_bundle_id artifact binding.
	ErrUnboundEvaluation = errors.New("evaluation report is UNBOUND (missing model_bundle_id)")
	// ErrArtifactMismatch is returned when an evaluation report is bound to a different model_bundle_id.
	ErrArtifactMismatch = errors.New("evaluation report model_bundle_id does not match inspected model bundle")
	// ErrUntrustedEvaluationEvidence is returned when evaluation evidence is unsigned, tampered, or signed by an untrusted key.
	ErrUntrustedEvaluationEvidence = errors.New("evaluation evidence is not cryptographically trusted")
	// ErrPostHocBindingRejected is returned when an unbound report is post-hoc bound in strict mode without native candidate.metadata.model_bundle_id.
	ErrPostHocBindingRejected = errors.New("post-hoc operator binding of an unbound evaluation report is rejected in strict mode")
	// ErrStaleEvaluationReport is returned when an evaluation report timestamp is older than policy max_age_hours or future-skewed.
	ErrStaleEvaluationReport = errors.New("evaluation report timestamp exceeds policy max_age_hours or is stale/replayed")
	// ErrSuiteDigestMismatch is returned when suite.digest does not match policy expected_suite_digest.
	ErrSuiteDigestMismatch = errors.New("evaluation report suite.digest does not match policy expected_suite_digest")
	// ErrDatasetDigestMismatch is returned when dataset.digest does not match policy expected_dataset_digest.
	ErrDatasetDigestMismatch = errors.New("evaluation report dataset.digest does not match policy expected_dataset_digest")
)

// RawReport mirrors the exact llm-release-gate.report/v1 JSON schema.
type RawReport struct {
	SchemaVersion    string              `json:"schemaVersion"`
	RunID            string              `json:"runId"`
	Timestamp        string              `json:"timestamp"`
	ToolVersion      string              `json:"toolVersion"`
	Suite            SuiteMetadata       `json:"suite"`
	Dataset          DatasetMetadata     `json:"dataset"`
	Graders          []GraderIdentity    `json:"graders"`
	Candidate        SubjectIdentity     `json:"candidate"`
	Baseline         *SubjectIdentity    `json:"baseline,omitempty"`
	Execution        ExecutionProfile    `json:"execution"`
	Evaluator        EvaluatorIdentity   `json:"evaluator"`
	Cases            []json.RawMessage   `json:"cases"`
	Metrics          AggregateMetrics    `json:"metrics"`
	Comparison       json.RawMessage     `json:"comparison,omitempty"`
	GateStatus       GateStatus          `json:"gateStatus"`
	EvidenceQuality  EvidenceQuality     `json:"evidenceQuality"`
	ComparisonStatus string              `json:"comparisonStatus"`
	ExitCode         int                 `json:"exitCode"`
	DecisionReasons  []DecisionReason    `json:"decisionReasons"`
	Warnings         []string            `json:"warnings,omitempty"`
	Artifacts        []ArtifactReference `json:"artifacts,omitempty"`
}

// SuiteMetadata mirrors llm-release-gate suite metadata.
type SuiteMetadata struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Path    string `json:"path,omitempty"`
	Digest  string `json:"digest"`
}

// DatasetMetadata mirrors llm-release-gate dataset metadata.
type DatasetMetadata struct {
	Path      string `json:"path,omitempty"`
	Digest    string `json:"digest"`
	CaseCount int    `json:"caseCount"`
}

// GraderIdentity mirrors llm-release-gate grader metadata.
type GraderIdentity struct {
	Type    string `json:"type"`
	Version string `json:"version"`
}

// SubjectIdentity mirrors llm-release-gate candidate/baseline metadata.
type SubjectIdentity struct {
	Name        string            `json:"name"`
	Version     string            `json:"version,omitempty"`
	Provider    string            `json:"provider"`
	Model       string            `json:"model"`
	Endpoint    string            `json:"endpoint,omitempty"`
	Environment string            `json:"environment,omitempty"`
	Digest      string            `json:"digest,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// ExecutionProfile mirrors llm-release-gate execution metadata.
type ExecutionProfile struct {
	Mode           string `json:"mode"`
	Timeout        string `json:"timeout"`
	Concurrency    int    `json:"concurrency"`
	Repetitions    int    `json:"repetitions"`
	WarmupRequests int    `json:"warmupRequests"`
	Environment    string `json:"environment,omitempty"`
}

// EvaluatorIdentity mirrors llm-release-gate evaluator metadata.
type EvaluatorIdentity struct {
	Name                string   `json:"name"`
	Version             string   `json:"version"`
	SourceTool          string   `json:"sourceTool,omitempty"`
	SourceFormatVersion string   `json:"sourceFormatVersion,omitempty"`
	UnmappedFields      []string `json:"unmappedFields,omitempty"`
}

// AggregateMetrics mirrors llm-release-gate aggregate metrics.
type AggregateMetrics struct {
	TotalPlannedCases        int             `json:"totalPlannedCases"`
	ExecutedCases            int             `json:"executedCases"`
	PassedCases              int             `json:"passedCases"`
	FailedCases              int             `json:"failedCases"`
	ErroredCases             int             `json:"erroredCases"`
	TimeoutCases             int             `json:"timeoutCases"`
	SkippedCases             int             `json:"skippedCases"`
	NotRunCases              int             `json:"notRunCases"`
	TotalAssertions          int             `json:"totalAssertions"`
	PassedAssertions         int             `json:"passedAssertions"`
	FailedRequiredAssertions int             `json:"failedRequiredAssertions"`
	FailedOptionalAssertions int             `json:"failedOptionalAssertions"`
	PassRate                 float64         `json:"passRate"`
	RequiredPassRate         *float64        `json:"requiredPassRate,omitempty"`
	OptionalPassRate         *float64        `json:"optionalPassRate,omitempty"`
	ErrorRate                float64         `json:"errorRate,omitempty"`
	RequestErrorRate         float64         `json:"requestErrorRate,omitempty"`
	TimeoutRate              float64         `json:"timeoutRate"`
	Latency                  json.RawMessage `json:"latency,omitempty"`
	TTFT                     json.RawMessage `json:"ttft,omitempty"`
	LatencyMeanMs            *float64        `json:"latencyMeanMs,omitempty"`
	LatencyMinMs             *float64        `json:"latencyMinMs,omitempty"`
	LatencyMaxMs             *float64        `json:"latencyMaxMs,omitempty"`
	LatencyP50Ms             *float64        `json:"latencyP50Ms,omitempty"`
	LatencyP95Ms             *float64        `json:"latencyP95Ms,omitempty"`
	TTFTMeanMs               *float64        `json:"ttftMeanMs,omitempty"`
	TTFTP50Ms                *float64        `json:"ttftP50Ms,omitempty"`
	TTFTP95Ms                *float64        `json:"ttftP95Ms,omitempty"`
	TotalPromptTokens        int             `json:"totalPromptTokens"`
	TotalCompletionTokens    int             `json:"totalCompletionTokens"`
	TotalTokens              int             `json:"totalTokens"`
}

// DecisionReason mirrors llm-release-gate decisionReasons entries.
type DecisionReason struct {
	Code     string `json:"code"`
	Category string `json:"category"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

// ArtifactReference mirrors llm-release-gate artifacts entries.
type ArtifactReference struct {
	Name   string `json:"name"`
	Role   string `json:"role"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// EvaluationEvidencePredicate is the predicate structure for evaluation-evidence/v1 DSSE attestations.
type EvaluationEvidencePredicate struct {
	SchemaVersion       string `json:"schema_version"`
	AttestationKind     string `json:"attestation_kind,omitempty"`
	Timestamp           string `json:"timestamp"`
	ModelBundleID       string `json:"model_bundle_id"`
	BindingMode         string `json:"binding_mode,omitempty"`
	ReportDigest        string `json:"report_digest"`
	RunID               string `json:"run_id"`
	EvaluationTimestamp string `json:"evaluation_timestamp,omitempty"`
	ToolVersion         string `json:"tool_version,omitempty"`
	GateStatus          string `json:"gate_status"`
	EvidenceQuality     string `json:"evidence_quality"`
	SuiteDigest         string `json:"suite_digest"`
	DatasetDigest       string `json:"dataset_digest"`
	EvaluatorName       string `json:"evaluator_name,omitempty"`
	EvaluatorVersion    string `json:"evaluator_version,omitempty"`
	ExecutionMode       string `json:"execution_mode,omitempty"`
	CandidateName       string `json:"candidate_name"`
	CandidateDigest     string `json:"candidate_digest,omitempty"`
	PromptConfigDigest  string `json:"prompt_config_digest,omitempty"`
}

// VerifyOptions configures evaluation report inspection and evidence verification.
type VerifyOptions struct {
	ExpectedBundleID       string
	AttestationPath        string
	TrustedSigners         []verification.TrustedSignerRule
	CandidateUntrustedKeys []*signing.PublicKey
	RequireArtifactBinding bool
	RequireTrustedEvidence bool
	AllowPostHocBinding    bool
	MaxAgeHours            int
	ExpectedSuiteDigest    string
	ExpectedDatasetDigest  string
	Now                    time.Time
}

// EvaluationSummary holds the normalized, verified outcome of inspecting an llm-release-gate report.
// It explicitly separates the 7 trust concepts:
//  1. ReportIntegrityVerified: The report file and its bound fields were not modified after signing.
//  2. ReportAuthenticityVerified: The evaluation attestation has a valid cryptographic DSSE signature.
//  3. ProducerIdentityVerified: The signer is a trusted evaluation producer (never true for post-hoc operator endorsements).
//  4. ArtifactBindingVerified: The evaluated artifact identity matches expected_bundle_id.
//  5. ExecutionEvidenceVerified: The report contains valid evaluator identity, execution mode, cases, COMPLETE quality, and PASS status.
//  6. SuiteDatasetIdentityVerified: suite.digest and dataset.digest are valid and match policy expectations.
//  7. FreshnessVerified: report timestamp is valid RFC3339 and within policy max_age_hours.
type EvaluationSummary struct {
	ReportPath                   string          `json:"report_path"`
	ReportDigest                 string          `json:"report_digest"`
	AttestationPath              string          `json:"attestation_path,omitempty"`
	AttestationDigest            string          `json:"attestation_digest,omitempty"`
	AttestationKind              string          `json:"attestation_kind,omitempty"`
	SchemaVersion                string          `json:"schema_version"`
	RunID                        string          `json:"run_id"`
	Timestamp                    string          `json:"timestamp"`
	ToolVersion                  string          `json:"tool_version"`
	CandidateName                string          `json:"candidate_name"`
	CandidateModel               string          `json:"candidate_model"`
	CandidateDigest              string          `json:"candidate_digest,omitempty"`
	SuiteName                    string          `json:"suite_name"`
	SuiteVersion                 string          `json:"suite_version"`
	SuiteDigest                  string          `json:"suite_digest"`
	DatasetDigest                string          `json:"dataset_digest"`
	DatasetCaseCount             int             `json:"dataset_case_count"`
	ReportedGateStatus           GateStatus      `json:"reported_gate_status"`
	EvidenceQuality              EvidenceQuality `json:"evidence_quality"`
	ReportedExitCode             int             `json:"reported_exit_code"`
	DeclaredBundleID             string          `json:"declared_bundle_id,omitempty"`
	AttestedBundleID             string          `json:"attested_bundle_id,omitempty"`
	ExpectedBundleID             string          `json:"expected_bundle_id"`
	BindingStatus                BindingStatus   `json:"binding_status"`
	BindingMode                  BindingMode     `json:"binding_mode"`
	TrustStatus                  TrustStatus     `json:"trust_status"`
	ReportIntegrityVerified      bool            `json:"report_integrity_verified"`
	ReportAuthenticityVerified   bool            `json:"report_authenticity_verified"`
	ProducerIdentityVerified     bool            `json:"producer_identity_verified"`
	OperatorEndorsementVerified  bool            `json:"operator_endorsement_verified"`
	ArtifactBindingVerified      bool            `json:"artifact_binding_verified"`
	ExecutionEvidenceVerified    bool            `json:"execution_evidence_verified"`
	SuiteDatasetIdentityVerified bool            `json:"suite_dataset_identity_verified"`
	FreshnessVerified            bool            `json:"freshness_verified"`
	SignerID                     string          `json:"signer_id,omitempty"`
	SignerFingerprint            string          `json:"signer_fingerprint,omitempty"`
	EffectiveGateStatus          GateStatus      `json:"effective_gate_status"`
	EligibleForRelease           bool            `json:"eligible_for_release"`
	Reason                       string          `json:"reason"`
}

// ParseAndValidateReport strictly parses raw bytes of an llm-release-gate.report/v1 JSON document.
func ParseAndValidateReport(rawBytes []byte) (RawReport, string, error) {
	dec := json.NewDecoder(bytes.NewReader(rawBytes))
	dec.DisallowUnknownFields()
	var rep RawReport
	if err := dec.Decode(&rep); err != nil {
		return RawReport{}, "", fmt.Errorf("%w: %v", ErrInvalidEvaluationReport, err)
	}
	if rep.SchemaVersion != ReportSchemaVersion {
		return RawReport{}, "", fmt.Errorf(
			"%w: schemaVersion %q != %q",
			ErrInvalidEvaluationReport, rep.SchemaVersion, ReportSchemaVersion,
		)
	}
	if strings.TrimSpace(rep.RunID) == "" || strings.TrimSpace(rep.Timestamp) == "" || strings.TrimSpace(rep.ToolVersion) == "" {
		return RawReport{}, "", fmt.Errorf("%w: missing runId, timestamp, or toolVersion", ErrInvalidEvaluationReport)
	}
	if _, err := time.Parse(time.RFC3339, strings.TrimSpace(rep.Timestamp)); err != nil {
		return RawReport{}, "", fmt.Errorf("%w: invalid RFC3339 timestamp %q: %v", ErrInvalidEvaluationReport, rep.Timestamp, err)
	}
	if err := digest.Validate(rep.Suite.Digest); err != nil {
		return RawReport{}, "", fmt.Errorf("%w: invalid suite.digest: %v", ErrInvalidEvaluationReport, err)
	}
	if err := digest.Validate(rep.Dataset.Digest); err != nil {
		return RawReport{}, "", fmt.Errorf("%w: invalid dataset.digest: %v", ErrInvalidEvaluationReport, err)
	}
	if strings.TrimSpace(rep.Candidate.Name) == "" || strings.TrimSpace(rep.Candidate.Provider) == "" || strings.TrimSpace(rep.Candidate.Model) == "" {
		return RawReport{}, "", fmt.Errorf("%w: missing candidate name, provider, or model", ErrInvalidEvaluationReport)
	}
	switch rep.GateStatus {
	case GatePass, GateFail, GateBlocked, GateNotRun:
	default:
		return RawReport{}, "", fmt.Errorf("%w: invalid gateStatus %q", ErrInvalidEvaluationReport, rep.GateStatus)
	}
	switch rep.EvidenceQuality {
	case EvidenceComplete, EvidenceLimited:
	default:
		return RawReport{}, "", fmt.Errorf("%w: invalid evidenceQuality %q", ErrInvalidEvaluationReport, rep.EvidenceQuality)
	}

	reportDigest := digest.ComputeNormalizedText(rawBytes)
	return rep, reportDigest, nil
}

// SignEvaluationEvidence creates a signed DSSE evaluation-evidence/v1 attestation binding an
// llm-release-gate report file to a specific model_bundle_id.
func SignEvaluationEvidence(reportPath string, modelBundleID string, priv *signing.PrivateKey, timestamp string) ([]byte, error) {
	return SignEvaluationEvidenceWithRole(reportPath, modelBundleID, priv, timestamp, ProducerRoleTrustedEvaluator)
}

// SignEvaluationEvidenceWithRole creates a signed DSSE evaluation-evidence/v1 attestation with an explicit
// producer role ("trusted-evaluator" vs "operator-endorser").
func SignEvaluationEvidenceWithRole(reportPath string, modelBundleID string, priv *signing.PrivateKey, timestamp string, producerRole string) ([]byte, error) {
	if err := digest.Validate(modelBundleID); err != nil {
		return nil, fmt.Errorf("invalid model_bundle_id: %w", err)
	}
	rawBytes, err := os.ReadFile(reportPath)
	if err != nil {
		return nil, fmt.Errorf("read evaluation report %q: %w", reportPath, err)
	}
	rep, repDigest, err := ParseAndValidateReport(rawBytes)
	if err != nil {
		return nil, err
	}

	// If the report itself already declares a model_bundle_id in candidate.metadata, it must match!
	declared := strings.TrimSpace(rep.Candidate.Metadata[MetadataKeyModelBundleID])
	if declared != "" && declared != modelBundleID {
		return nil, fmt.Errorf(
			"%w: report candidate.metadata[%q]=%s conflicts with requested bundle %s",
			ErrArtifactMismatch, MetadataKeyModelBundleID, declared, modelBundleID,
		)
	}

	bindingMode := BindingModePostHocOperator
	attKind := AttestationKindOperatorEndorsement
	if declared == modelBundleID && strings.TrimSpace(producerRole) != ProducerRoleOperatorEndorser {
		bindingMode = BindingModeNativeEvaluator
		attKind = AttestationKindTrustedEvaluator
	}

	bundleHex, err := digest.TrimPrefix(modelBundleID)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(timestamp) == "" {
		timestamp = time.Now().UTC().Format(time.RFC3339)
	}

	pred := EvaluationEvidencePredicate{
		SchemaVersion:       "evaluation-evidence/v1",
		AttestationKind:     attKind,
		Timestamp:           timestamp,
		ModelBundleID:       modelBundleID,
		BindingMode:         string(bindingMode),
		ReportDigest:        repDigest,
		RunID:               rep.RunID,
		EvaluationTimestamp: rep.Timestamp,
		ToolVersion:         rep.ToolVersion,
		GateStatus:          string(rep.GateStatus),
		EvidenceQuality:     string(rep.EvidenceQuality),
		SuiteDigest:         rep.Suite.Digest,
		DatasetDigest:       rep.Dataset.Digest,
		EvaluatorName:       rep.Evaluator.Name,
		EvaluatorVersion:    rep.Evaluator.Version,
		ExecutionMode:       rep.Execution.Mode,
		CandidateName:       rep.Candidate.Name,
		CandidateDigest:     rep.Candidate.Digest,
		PromptConfigDigest:  rep.Candidate.Digest,
	}
	predBytes, err := json.Marshal(pred)
	if err != nil {
		return nil, err
	}

	stmt := signing.InTotoStatement{
		Type: signing.InTotoStatementV1Type,
		Subject: []signing.ResourceDescriptor{
			{
				Name: "model-bundle:" + rep.Candidate.Name,
				Digest: map[string]string{
					"sha256": bundleHex,
				},
			},
		},
		PredicateType: version.EvaluationEvidencePredicateType,
		Predicate:     predBytes,
	}
	stmtBytes, err := json.Marshal(stmt)
	if err != nil {
		return nil, err
	}

	env, err := signing.SignDSSE(signing.InTotoPayloadType, stmtBytes, priv)
	if err != nil {
		return nil, err
	}
	out, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return nil, err
	}
	out = append(out, '\n')
	return out, nil
}

// Verify inspect and validates an llm-release-gate report and optional signed evaluation attestation
// against an expected Model Bundle Identity.
func Verify(reportPath string, opts VerifyOptions) (EvaluationSummary, error) {
	if err := digest.Validate(opts.ExpectedBundleID); err != nil {
		return EvaluationSummary{}, fmt.Errorf("expected bundle ID: %w", err)
	}

	rawBytes, err := os.ReadFile(reportPath)
	if err != nil {
		return EvaluationSummary{}, fmt.Errorf("read evaluation report %q: %w", reportPath, err)
	}

	var rawAtt []byte
	var attReadErr error
	if strings.TrimSpace(opts.AttestationPath) != "" {
		rawAtt, attReadErr = os.ReadFile(opts.AttestationPath)
		if attReadErr != nil {
			rep, repDigest, pErr := ParseAndValidateReport(rawBytes)
			if pErr != nil {
				return EvaluationSummary{}, pErr
			}
			summary := EvaluationSummary{
				ReportPath:          reportPath,
				ReportDigest:        repDigest,
				AttestationPath:     opts.AttestationPath,
				SchemaVersion:       rep.SchemaVersion,
				RunID:               rep.RunID,
				Timestamp:           rep.Timestamp,
				ToolVersion:         rep.ToolVersion,
				CandidateName:       rep.Candidate.Name,
				CandidateModel:      rep.Candidate.Model,
				CandidateDigest:     rep.Candidate.Digest,
				SuiteName:           rep.Suite.Name,
				SuiteVersion:        rep.Suite.Version,
				SuiteDigest:         rep.Suite.Digest,
				DatasetDigest:       rep.Dataset.Digest,
				DatasetCaseCount:    rep.Dataset.CaseCount,
				ReportedGateStatus:  rep.GateStatus,
				EvidenceQuality:     rep.EvidenceQuality,
				ReportedExitCode:    rep.ExitCode,
				ExpectedBundleID:    opts.ExpectedBundleID,
				TrustStatus:         TrustInvalidOrTampered,
				EffectiveGateStatus: GateBlocked,
				Reason:              fmt.Sprintf("read evaluation attestation %q: %v", opts.AttestationPath, attReadErr),
			}
			if rep.Candidate.Metadata != nil {
				summary.DeclaredBundleID = strings.TrimSpace(rep.Candidate.Metadata[MetadataKeyModelBundleID])
			}
			return summary, attReadErr
		}
	}

	sum, err := VerifyBytes(rawBytes, rawAtt, opts)
	sum.ReportPath = reportPath
	if strings.TrimSpace(opts.AttestationPath) != "" {
		sum.AttestationPath = opts.AttestationPath
	}
	return sum, err
}

// VerifyBytes inspects and validates an in-memory llm-release-gate report and optional signed evaluation attestation
// without performing any filesystem I/O.
func VerifyBytes(rawBytes []byte, rawAtt []byte, opts VerifyOptions) (EvaluationSummary, error) {
	if err := digest.Validate(opts.ExpectedBundleID); err != nil {
		return EvaluationSummary{}, fmt.Errorf("expected bundle ID: %w", err)
	}

	rep, repDigest, err := ParseAndValidateReport(rawBytes)
	if err != nil {
		return EvaluationSummary{}, err
	}

	summary := EvaluationSummary{
		ReportDigest:       repDigest,
		SchemaVersion:      rep.SchemaVersion,
		RunID:              rep.RunID,
		Timestamp:          rep.Timestamp,
		ToolVersion:        rep.ToolVersion,
		CandidateName:      rep.Candidate.Name,
		CandidateModel:     rep.Candidate.Model,
		CandidateDigest:    rep.Candidate.Digest,
		SuiteName:          rep.Suite.Name,
		SuiteVersion:       rep.Suite.Version,
		SuiteDigest:        rep.Suite.Digest,
		DatasetDigest:      rep.Dataset.Digest,
		DatasetCaseCount:   rep.Dataset.CaseCount,
		ReportedGateStatus: rep.GateStatus,
		EvidenceQuality:    rep.EvidenceQuality,
		ReportedExitCode:   rep.ExitCode,
		ExpectedBundleID:   opts.ExpectedBundleID,
		TrustStatus:        TrustUnverifiedLocalJSON,
	}

	if rep.Candidate.Metadata != nil {
		summary.DeclaredBundleID = strings.TrimSpace(rep.Candidate.Metadata[MetadataKeyModelBundleID])
	}

	// Step 1: Evaluate cryptographic trust if an evaluation attestation is supplied.
	var trustErr error
	var attestedBindingMode string
	var matchedAllowOperatorEndorsement bool
	var matchedSignerRole string
	if len(bytes.TrimSpace(rawAtt)) > 0 {
		summary.AttestationDigest = digest.ComputeBytes(rawAtt)

		envVer, verErr := verification.VerifyInTotoDSSE(rawAtt, opts.TrustedSigners, opts.CandidateUntrustedKeys)
		if verErr != nil {
			switch envVer.Status {
			case verification.StatusBlocked:
				summary.TrustStatus = TrustBlocked
			case verification.StatusUntrusted:
				summary.TrustStatus = TrustUntrustedSigner
				summary.ReportAuthenticityVerified = true
				summary.ProducerIdentityVerified = false
			default:
				summary.TrustStatus = TrustInvalidOrTampered
			}
			trustErr = fmt.Errorf("%w: %v", ErrUntrustedEvaluationEvidence, verErr)
		} else if envVer.Statement.PredicateType != version.EvaluationEvidencePredicateType {
			summary.TrustStatus = TrustInvalidOrTampered
			trustErr = fmt.Errorf(
				"%w: unexpected predicateType %q (expected %q)",
				ErrUntrustedEvaluationEvidence, envVer.Statement.PredicateType, version.EvaluationEvidencePredicateType,
			)
		} else {
			summary.ReportAuthenticityVerified = true
			matchedAllowOperatorEndorsement = envVer.AllowOperatorEndorsement
			matchedSignerRole = envVer.MatchedSignerRole
			var pred EvaluationEvidencePredicate
			if decErr := json.Unmarshal(envVer.Statement.Predicate, &pred); decErr != nil {
				summary.TrustStatus = TrustInvalidOrTampered
				trustErr = fmt.Errorf("%w: decode predicate: %v", ErrUntrustedEvaluationEvidence, decErr)
			} else if pred.ReportDigest != repDigest {
				// Report JSON was modified after the evaluation attestation was signed!
				summary.TrustStatus = TrustInvalidOrTampered
				summary.ReportIntegrityVerified = false
				trustErr = fmt.Errorf(
					"%w: evaluation report digest %s does not match signed attestation report_digest %s (report tampered)",
					ErrUntrustedEvaluationEvidence, repDigest, pred.ReportDigest,
				)
			} else if err := verifyBoundPredicateFields(pred, rep); err != nil {
				summary.TrustStatus = TrustInvalidOrTampered
				summary.ReportIntegrityVerified = false
				trustErr = fmt.Errorf("%w: %v", ErrUntrustedEvaluationEvidence, err)
			} else {
				summary.ReportIntegrityVerified = true
				attestedBindingMode = pred.BindingMode
				summary.AttestationKind = pred.AttestationKind
				if summary.AttestationKind == "" {
					if attestedBindingMode == string(BindingModePostHocOperator) {
						summary.AttestationKind = AttestationKindOperatorEndorsement
					} else {
						summary.AttestationKind = AttestationKindTrustedEvaluator
					}
				}
				if matchedSignerRole == ProducerRoleOperatorEndorser || summary.AttestationKind == AttestationKindOperatorEndorsement {
					summary.AttestationKind = AttestationKindOperatorEndorsement
					summary.OperatorEndorsementVerified = true
					summary.ProducerIdentityVerified = false
				} else {
					summary.ProducerIdentityVerified = true
				}
				subjHex := strings.ToLower(strings.TrimSpace(envVer.Statement.Subject[0].Digest["sha256"]))
				subjBundleID := digest.Prefix + subjHex
				if err := digest.Validate(subjBundleID); err != nil {
					summary.TrustStatus = TrustInvalidOrTampered
					trustErr = fmt.Errorf("%w: invalid attestation subject digest %q: %v", ErrUntrustedEvaluationEvidence, subjBundleID, err)
				} else if pred.ModelBundleID != "" && pred.ModelBundleID != subjBundleID {
					summary.TrustStatus = TrustInvalidOrTampered
					trustErr = fmt.Errorf(
						"%w: attestation subject %s != predicate model_bundle_id %s",
						ErrUntrustedEvaluationEvidence, subjBundleID, pred.ModelBundleID,
					)
				} else {
					summary.AttestedBundleID = subjBundleID
					summary.TrustStatus = TrustVerifiedTrusted
					summary.SignerID = envVer.MatchedSignerID
					summary.SignerFingerprint = envVer.SignerFingerprint
				}
			}
		}
	}

	// Step 2: Evaluate Artifact Binding and BindingMode (never infer identity from candidate.name, candidate.model, or candidate.digest).
	switch {
	case summary.DeclaredBundleID == "" && summary.AttestedBundleID == "":
		summary.BindingStatus = BindingUnbound
		summary.BindingMode = BindingModeUnbound
	case summary.DeclaredBundleID != "" && summary.AttestedBundleID != "" && summary.DeclaredBundleID != summary.AttestedBundleID:
		summary.BindingStatus = BindingMismatch
		summary.BindingMode = BindingModePostHocOperator
	default:
		boundID := summary.DeclaredBundleID
		if boundID == "" {
			boundID = summary.AttestedBundleID
		}
		if summary.DeclaredBundleID == "" && summary.AttestedBundleID != "" {
			summary.BindingMode = BindingModePostHocOperator
			summary.AttestationKind = AttestationKindOperatorEndorsement
			summary.ProducerIdentityVerified = false
			summary.OperatorEndorsementVerified = true
		} else if summary.DeclaredBundleID != "" && summary.AttestedBundleID != "" {
			if attestedBindingMode == string(BindingModePostHocOperator) || summary.AttestationKind == AttestationKindOperatorEndorsement {
				summary.BindingMode = BindingModePostHocOperator
				summary.ProducerIdentityVerified = false
				summary.OperatorEndorsementVerified = true
			} else {
				summary.BindingMode = BindingModeNativeEvaluator
			}
		} else {
			summary.BindingMode = BindingModeReportMetadataOnly
		}

		if err := digest.Validate(boundID); err != nil {
			summary.BindingStatus = BindingMismatch
		} else if boundID == opts.ExpectedBundleID {
			summary.BindingStatus = BindingMatched
			summary.ArtifactBindingVerified = true
		} else {
			summary.BindingStatus = BindingMismatch
		}
	}

	// Step 3: Compute EffectiveGateStatus and EligibleForRelease per the strict decision matrix.
	// First check tampering or invalid/untrusted signatures:
	if summary.TrustStatus == TrustInvalidOrTampered || summary.TrustStatus == TrustUntrustedSigner {
		summary.EffectiveGateStatus = GateFail
		summary.EligibleForRelease = false
		if trustErr != nil {
			summary.Reason = trustErr.Error()
			return summary, trustErr
		}
		summary.Reason = ErrUntrustedEvaluationEvidence.Error()
		return summary, ErrUntrustedEvaluationEvidence
	}
	if summary.TrustStatus == TrustBlocked {
		summary.EffectiveGateStatus = GateBlocked
		summary.EligibleForRelease = false
		summary.Reason = "missing trusted public key material to verify evaluation attestation"
		return summary, verification.ErrMissingVerificationMaterial
	}

	// Check artifact identity mismatch:
	if summary.BindingStatus == BindingMismatch {
		summary.EffectiveGateStatus = GateFail
		summary.EligibleForRelease = false
		summary.ArtifactBindingVerified = false
		summary.Reason = fmt.Sprintf(
			"evaluation report is bound to model_bundle_id %q (attested=%q), which does not match inspected bundle %q",
			summary.DeclaredBundleID, summary.AttestedBundleID, opts.ExpectedBundleID,
		)
		return summary, fmt.Errorf("%w: %s", ErrArtifactMismatch, summary.Reason)
	}

	// Check expected suite digest and dataset digest if configured in policy:
	if strings.TrimSpace(opts.ExpectedSuiteDigest) != "" && rep.Suite.Digest != strings.TrimSpace(opts.ExpectedSuiteDigest) {
		summary.EffectiveGateStatus = GateFail
		summary.EligibleForRelease = false
		summary.SuiteDatasetIdentityVerified = false
		summary.Reason = fmt.Sprintf(
			"evaluation report suite.digest %s does not match policy expected_suite_digest %s",
			rep.Suite.Digest, opts.ExpectedSuiteDigest,
		)
		return summary, fmt.Errorf("%w: %s", ErrSuiteDigestMismatch, summary.Reason)
	}
	if strings.TrimSpace(opts.ExpectedDatasetDigest) != "" && rep.Dataset.Digest != strings.TrimSpace(opts.ExpectedDatasetDigest) {
		summary.EffectiveGateStatus = GateFail
		summary.EligibleForRelease = false
		summary.SuiteDatasetIdentityVerified = false
		summary.Reason = fmt.Sprintf(
			"evaluation report dataset.digest %s does not match policy expected_dataset_digest %s",
			rep.Dataset.Digest, opts.ExpectedDatasetDigest,
		)
		return summary, fmt.Errorf("%w: %s", ErrDatasetDigestMismatch, summary.Reason)
	}
	summary.SuiteDatasetIdentityVerified = true

	// Check report timestamp freshness (max_age_hours) if configured in policy:
	if opts.MaxAgeHours > 0 {
		now := opts.Now
		if now.IsZero() {
			now = time.Now().UTC()
		}
		repTime, parseErr := time.Parse(time.RFC3339, strings.TrimSpace(rep.Timestamp))
		if parseErr != nil {
			summary.EffectiveGateStatus = GateFail
			summary.EligibleForRelease = false
			summary.FreshnessVerified = false
			summary.Reason = fmt.Sprintf("invalid report timestamp %q: %v", rep.Timestamp, parseErr)
			return summary, fmt.Errorf("%w: %s", ErrStaleEvaluationReport, summary.Reason)
		}
		maxAge := time.Duration(opts.MaxAgeHours) * time.Hour
		age := now.Sub(repTime)
		if age > maxAge || repTime.After(now.Add(5*time.Minute)) {
			summary.EffectiveGateStatus = GateFail
			summary.EligibleForRelease = false
			summary.FreshnessVerified = false
			summary.Reason = fmt.Sprintf(
				"evaluation report timestamp %s exceeds policy max_age_hours=%d (age=%s)",
				rep.Timestamp, opts.MaxAgeHours, age.Round(time.Second),
			)
			return summary, fmt.Errorf("%w: %s", ErrStaleEvaluationReport, summary.Reason)
		}
	}
	summary.FreshnessVerified = true

	// Check reported evaluation status:
	switch rep.GateStatus {
	case GateFail:
		summary.EffectiveGateStatus = GateFail
		summary.EligibleForRelease = false
		summary.Reason = "llm-release-gate reported gateStatus=FAIL"
		return summary, errors.New(summary.Reason)
	case GateBlocked:
		summary.EffectiveGateStatus = GateBlocked
		summary.EligibleForRelease = false
		summary.Reason = "llm-release-gate reported gateStatus=BLOCKED"
		return summary, errors.New(summary.Reason)
	case GateNotRun:
		summary.EffectiveGateStatus = GateBlocked
		summary.EligibleForRelease = false
		summary.Reason = "llm-release-gate reported gateStatus=NOT_RUN (treated as BLOCKED)"
		return summary, errors.New(summary.Reason)
	}

	if rep.EvidenceQuality != EvidenceComplete || rep.ExitCode != 0 ||
		strings.TrimSpace(rep.Evaluator.Name) == "" || strings.TrimSpace(rep.Evaluator.Version) == "" ||
		strings.TrimSpace(rep.Execution.Mode) == "" || len(rep.Cases) == 0 || rep.Metrics.ExecutedCases <= 0 {
		summary.EffectiveGateStatus = GateBlocked
		summary.EligibleForRelease = false
		summary.ExecutionEvidenceVerified = false
		summary.Reason = fmt.Sprintf(
			"llm-release-gate reported PASS but execution evidence is incomplete (evidenceQuality=%s, exitCode=%d, evaluator=%s@%s, mode=%s, executedCases=%d)",
			rep.EvidenceQuality, rep.ExitCode, rep.Evaluator.Name, rep.Evaluator.Version, rep.Execution.Mode, rep.Metrics.ExecutedCases,
		)
		return summary, errors.New(summary.Reason)
	}
	summary.ExecutionEvidenceVerified = true

	// Check missing artifact identity (UNBOUND):
	if summary.BindingStatus == BindingUnbound {
		if opts.RequireArtifactBinding {
			summary.EffectiveGateStatus = GateBlocked
			summary.EligibleForRelease = false
			summary.ArtifactBindingVerified = false
			summary.Reason = "evaluation report has no model_bundle_id (UNBOUND); strict policy blocks unbound evaluation reports"
			return summary, ErrUnboundEvaluation
		}
	}

	// Check post-hoc operator endorsement under strict policy:
	// An operator endorsement (or post-hoc binding without native candidate.metadata.model_bundle_id)
	// does NOT satisfy require_trusted_evidence unless explicitly authorized by AllowPostHocBinding
	// or by the matched signer rule's allow_operator_endorsement / role="operator-endorser".
	operatorEndorsementAuthorized := opts.AllowPostHocBinding || (matchedAllowOperatorEndorsement && summary.DeclaredBundleID != "")
	if opts.RequireTrustedEvidence && (summary.BindingMode == BindingModePostHocOperator || summary.AttestationKind == AttestationKindOperatorEndorsement) && !operatorEndorsementAuthorized {
		summary.EffectiveGateStatus = GateBlocked
		summary.EligibleForRelease = false
		summary.ArtifactBindingVerified = false
		summary.Reason = "evaluation attestation is a post-hoc operator endorsement and not proof of trusted evaluator execution; strict policy rejects operator endorsement unless explicitly authorized"
		return summary, fmt.Errorf("%w: %s", ErrPostHocBindingRejected, summary.Reason)
	}

	// Check trusted evidence requirement:
	if opts.RequireTrustedEvidence && summary.TrustStatus != TrustVerifiedTrusted {
		summary.EffectiveGateStatus = GateBlocked
		summary.EligibleForRelease = false
		summary.Reason = fmt.Sprintf(
			"evaluation report is %s (plain unsigned JSON is not proof of trusted evaluation under strict policy)",
			summary.TrustStatus,
		)
		return summary, ErrUntrustedEvaluationEvidence
	}

	summary.EffectiveGateStatus = GatePass
	summary.EligibleForRelease = true
	summary.Reason = fmt.Sprintf(
		"evaluation PASS verified (runId=%s, binding=%s, mode=%s, trust=%s)",
		rep.RunID, summary.BindingStatus, summary.BindingMode, summary.TrustStatus,
	)
	return summary, nil
}

func verifyBoundPredicateFields(pred EvaluationEvidencePredicate, rep RawReport) error {
	if pred.RunID != "" && pred.RunID != rep.RunID {
		return fmt.Errorf("predicate run_id %q != report runId %q", pred.RunID, rep.RunID)
	}
	if pred.EvaluationTimestamp != "" && pred.EvaluationTimestamp != rep.Timestamp {
		return fmt.Errorf("predicate evaluation_timestamp %q != report timestamp %q", pred.EvaluationTimestamp, rep.Timestamp)
	}
	if pred.ToolVersion != "" && pred.ToolVersion != rep.ToolVersion {
		return fmt.Errorf("predicate tool_version %q != report toolVersion %q", pred.ToolVersion, rep.ToolVersion)
	}
	if pred.GateStatus != "" && pred.GateStatus != string(rep.GateStatus) {
		return fmt.Errorf("predicate gate_status %q != report gateStatus %q", pred.GateStatus, rep.GateStatus)
	}
	if pred.EvidenceQuality != "" && pred.EvidenceQuality != string(rep.EvidenceQuality) {
		return fmt.Errorf("predicate evidence_quality %q != report evidenceQuality %q", pred.EvidenceQuality, rep.EvidenceQuality)
	}
	if pred.SuiteDigest != "" && pred.SuiteDigest != rep.Suite.Digest {
		return fmt.Errorf("predicate suite_digest %q != report suite.digest %q", pred.SuiteDigest, rep.Suite.Digest)
	}
	if pred.DatasetDigest != "" && pred.DatasetDigest != rep.Dataset.Digest {
		return fmt.Errorf("predicate dataset_digest %q != report dataset.digest %q", pred.DatasetDigest, rep.Dataset.Digest)
	}
	if pred.EvaluatorName != "" && pred.EvaluatorName != rep.Evaluator.Name {
		return fmt.Errorf("predicate evaluator_name %q != report evaluator.name %q", pred.EvaluatorName, rep.Evaluator.Name)
	}
	if pred.EvaluatorVersion != "" && pred.EvaluatorVersion != rep.Evaluator.Version {
		return fmt.Errorf("predicate evaluator_version %q != report evaluator.version %q", pred.EvaluatorVersion, rep.Evaluator.Version)
	}
	if pred.ExecutionMode != "" && pred.ExecutionMode != rep.Execution.Mode {
		return fmt.Errorf("predicate execution_mode %q != report execution.mode %q", pred.ExecutionMode, rep.Execution.Mode)
	}
	if pred.CandidateDigest != "" && pred.CandidateDigest != rep.Candidate.Digest {
		return fmt.Errorf("predicate candidate_digest %q != report candidate.digest %q", pred.CandidateDigest, rep.Candidate.Digest)
	}
	return nil
}
