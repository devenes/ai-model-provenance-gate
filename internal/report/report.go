// Package report renders machine-readable JSON and human-readable Markdown reports
// with explicit guarantee separation and pre-write secret redaction checks.
package report

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/devenes/ai-model-provenance-gate/internal/deployment"
	"github.com/devenes/ai-model-provenance-gate/internal/evaluation/llmreleasegate"
	"github.com/devenes/ai-model-provenance-gate/internal/formats/huggingface"
	"github.com/devenes/ai-model-provenance-gate/internal/manifest"
	"github.com/devenes/ai-model-provenance-gate/internal/oms"
	"github.com/devenes/ai-model-provenance-gate/internal/policy"
	"github.com/devenes/ai-model-provenance-gate/internal/provenance"
	"github.com/devenes/ai-model-provenance-gate/internal/scanner"
	"github.com/devenes/ai-model-provenance-gate/internal/version"
)

// GuaranteeMatrix explicitly records each distinct security guarantee so one is never conflated with another.
type GuaranteeMatrix struct {
	ArtifactIntegrity    string `json:"artifact_integrity"`
	ArtifactAuthenticity string `json:"artifact_authenticity"`
	SignerTrust          string `json:"signer_trust"`
	ArtifactProvenance   string `json:"artifact_provenance"`
	SecurityScanEvidence string `json:"security_scan_evidence"`
	BehavioralEvaluation string `json:"behavioral_evaluation"`
	ReleaseQualification string `json:"release_qualification"`
	DeploymentIdentity   string `json:"deployment_identity"`
}

// ArtifactRecord tracks a generated evidence file and its SHA-256 digest.
type ArtifactRecord struct {
	Name   string `json:"name"`
	Role   string `json:"role"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// PolicySummary captures policy metadata for the report.
type PolicySummary struct {
	SchemaVersion string `json:"schema_version"`
	Name          string `json:"name,omitempty"`
	Digest        string `json:"digest"`
	DecisionMode  string `json:"decision_mode"`
}

// GateReport is the unified versioned report structure for inspect, gate evaluate, and release verify.
type GateReport struct {
	SchemaVersion            string                            `json:"schema_version"`
	Command                  string                            `json:"command"`
	Timestamp                string                            `json:"timestamp"`
	Tool                     version.Metadata                  `json:"tool"`
	GateStatus               policy.GateStatus                 `json:"gate_status"`
	ExitCode                 int                               `json:"exit_code"`
	BundleID                 string                            `json:"bundle_id"`
	CompositionID            string                            `json:"composition_id,omitempty"`
	Manifest                 *manifest.BundleManifest          `json:"manifest,omitempty"`
	BOMDigest                string                            `json:"bom_digest,omitempty"`
	OMS                      *oms.Result                       `json:"oms,omitempty"`
	Evaluation               *llmreleasegate.EvaluationSummary `json:"evaluation,omitempty"`
	Scanner                  *scanner.Result                   `json:"scanner,omitempty"`
	UpstreamProvenance       *provenance.Result                `json:"upstream_provenance,omitempty"`
	ReleaseAttestationDigest string                            `json:"release_attestation_digest,omitempty"`
	Deployment               *deployment.VerificationResult    `json:"deployment,omitempty"`
	Policy                   *PolicySummary                    `json:"policy,omitempty"`
	Guarantees               GuaranteeMatrix                   `json:"guarantees"`
	Reasons                  []policy.DecisionReason           `json:"reasons"`
	Artifacts                []ArtifactRecord                  `json:"artifacts,omitempty"`
}

// RenderJSON serializes GateReport to indented JSON after verifying that no secret patterns leak into the report.
func RenderJSON(rep GateReport) ([]byte, error) {
	if rep.SchemaVersion == "" {
		rep.SchemaVersion = version.GateReportSchemaVersion
	}
	raw, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal GateReport JSON: %w", err)
	}
	raw = append(raw, '\n')
	if err := huggingface.ScanForSecrets(raw, "gate-report.json"); err != nil {
		return nil, err
	}
	return raw, nil
}

// RenderMarkdown renders a structured human-readable Markdown report from the exact same validated GateReport struct.
func RenderMarkdown(rep GateReport) ([]byte, error) {
	var b strings.Builder

	_, _ = fmt.Fprintf(&b, "# AI Model Provenance Gate Report (`%s`)\n\n", rep.Command)
	_, _ = fmt.Fprintf(&b, "- **Gate Status:** `%s` (Exit Code `%d`)\n", rep.GateStatus, rep.ExitCode)
	_, _ = fmt.Fprintf(&b, "- **Timestamp:** `%s`\n", rep.Timestamp)
	_, _ = fmt.Fprintf(&b, "- **Tool Version:** `%s` (`%s`)\n", rep.Tool.Version, rep.Tool.Platform)
	_, _ = fmt.Fprintf(&b, "- **Model Bundle Identity (`bundle-identity/v1`):** `%s`\n", rep.BundleID)
	if rep.CompositionID != "" {
		_, _ = fmt.Fprintf(&b, "- **Deployment Composition Identity (`deployment-composition/v1`):** `%s`\n", rep.CompositionID)
	}
	if rep.BOMDigest != "" {
		_, _ = fmt.Fprintf(&b, "- **CycloneDX AI/ML-BOM Digest:** `%s`\n", rep.BOMDigest)
	}
	if rep.ReleaseAttestationDigest != "" {
		_, _ = fmt.Fprintf(&b, "- **Release Qualification Attestation Digest:** `%s`\n", rep.ReleaseAttestationDigest)
	}
	if rep.Policy != nil {
		_, _ = fmt.Fprintf(&b, "- **Policy:** `%s` (mode=`%s`, digest=`%s`)\n", rep.Policy.Name, rep.Policy.DecisionMode, rep.Policy.Digest)
	}
	b.WriteString("\n---\n\n")

	b.WriteString("## 1. Security Guarantee Separation Matrix\n\n")
	b.WriteString("| Security Guarantee | Observed / Verified Status |\n")
	b.WriteString("|---|---|\n")
	_, _ = fmt.Fprintf(&b, "| **Artifact Integrity** | %s |\n", rep.Guarantees.ArtifactIntegrity)
	_, _ = fmt.Fprintf(&b, "| **Artifact Authenticity** | %s |\n", rep.Guarantees.ArtifactAuthenticity)
	_, _ = fmt.Fprintf(&b, "| **Signer Trust** | %s |\n", rep.Guarantees.SignerTrust)
	_, _ = fmt.Fprintf(&b, "| **Artifact Provenance** | %s |\n", rep.Guarantees.ArtifactProvenance)
	_, _ = fmt.Fprintf(&b, "| **Security Scan Evidence** | %s |\n", rep.Guarantees.SecurityScanEvidence)
	_, _ = fmt.Fprintf(&b, "| **Model Behavioral Evaluation** | %s |\n", rep.Guarantees.BehavioralEvaluation)
	_, _ = fmt.Fprintf(&b, "| **Release Qualification** | %s |\n", rep.Guarantees.ReleaseQualification)
	_, _ = fmt.Fprintf(&b, "| **Deployment Identity** | %s |\n\n", rep.Guarantees.DeploymentIdentity)

	b.WriteString("> **Note:** Each security guarantee is evaluated independently. A SHA-256 digest does not prove origin; a valid BOM or signature does not prove behavioral safety; an unbound evaluation `PASS` does not qualify a model bundle.\n\n")

	if rep.Manifest != nil {
		m := rep.Manifest
		b.WriteString("## 2. Model Bundle Inventory Summary\n\n")
		_, _ = fmt.Fprintf(&b, "- **Primary Format:** `%s`\n", m.FormatSummary.PrimaryFormat)
		_, _ = fmt.Fprintf(&b, "- **File Count:** `%d` regular files (`%d` bytes total)\n", m.FileCount, m.TotalBytes)
		_, _ = fmt.Fprintf(&b, "- **Manifest Digest:** `%s`\n", m.ManifestDigest)
		_, _ = fmt.Fprintf(&b, "- **Sharded Weights:** `%t` (`%d` shards, `%d` tensors)\n", m.FormatSummary.IsSharded, m.FormatSummary.ShardCount, m.FormatSummary.TotalTensors)
		_, _ = fmt.Fprintf(&b, "- **LoRA / PEFT Status:** `%s`\n\n", m.LoRARelationship.VerificationStatus)

		b.WriteString("| Relative Path | Role | Size (Bytes) | SHA-256 Digest |\n")
		b.WriteString("|---|---|---:|---|\n")
		for _, f := range m.Files {
			_, _ = fmt.Fprintf(&b, "| `%s` | `%s` | %d | `%s` |\n", f.Path, f.Role, f.Size, f.SHA256)
		}
		b.WriteString("\n")
	}

	b.WriteString("## 3. Decision Reasons\n\n")
	b.WriteString("| Status | Severity | Category | Code | Message |\n")
	b.WriteString("|---|---|---|---|---|\n")
	for _, r := range rep.Reasons {
		_, _ = fmt.Fprintf(&b, "| `%s` | `%s` | `%s` | `%s` | %s |\n", r.Status, r.Severity, r.Category, r.Code, r.Message)
	}
	b.WriteString("\n")

	raw := []byte(b.String())
	if err := huggingface.ScanForSecrets(raw, "gate-report.md"); err != nil {
		return nil, err
	}
	return raw, nil
}
