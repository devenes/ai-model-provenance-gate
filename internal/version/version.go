// Package version provides build metadata and schema contract identifiers.
package version

import (
	"fmt"
	"runtime"
)

const (
	// ToolName is the canonical CLI and evidence tool identifier.
	ToolName = "ai-model-provenance-gate"

	// BundleIdentitySchemaVersion is the canonical manifest identity version.
	BundleIdentitySchemaVersion = "bundle-identity/v1"

	// DeploymentCompositionSchemaVersion is the canonical deployment composition version.
	DeploymentCompositionSchemaVersion = "deployment-composition/v1"

	// ReleaseQualificationPredicateType is the in-toto v1 predicate URI for release qualification.
	ReleaseQualificationPredicateType = "https://github.com/devenes/ai-model-provenance-gate/attestation/release-qualification/v1"

	// EvaluationEvidencePredicateType is the in-toto v1 predicate URI for signed evaluation evidence.
	EvaluationEvidencePredicateType = "https://github.com/devenes/ai-model-provenance-gate/attestation/evaluation-evidence/v1"

	// GateReportSchemaVersion is the versioned schema identifier for gate and verification reports.
	GateReportSchemaVersion = "ai-model-provenance-gate.report/v1"
)

var (
	// ToolVersion is the semantic version of the tool, overridable via ldflags.
	ToolVersion = "0.1.0"
	// GitCommit is the VCS revision identifier, overridable via ldflags.
	GitCommit = "dev"
	// GitTreeState indicates whether the working tree was clean or dirty at build time.
	GitTreeState = "clean"
	// BuildDate is the RFC 3339 build timestamp, overridable via ldflags.
	BuildDate = "1970-01-01T00:00:00Z"
	// BuildType describes the build profile (e.g., dev, release, ci).
	BuildType = "dev"
)

// Metadata holds structured build provenance for CLI and report output.
type Metadata struct {
	Name          string `json:"name"`
	Version       string `json:"version"`
	GitCommit     string `json:"gitCommit"`
	GitTreeState  string `json:"gitTreeState"`
	BuildDate     string `json:"buildDate"`
	BuildType     string `json:"buildType"`
	GoVersion     string `json:"goVersion"`
	Platform      string `json:"platform"`
	SchemaVersion string `json:"schemaVersion"`
}

// Get returns the current build metadata.
func Get() Metadata {
	return Metadata{
		Name:          ToolName,
		Version:       ToolVersion,
		GitCommit:     GitCommit,
		GitTreeState:  GitTreeState,
		BuildDate:     BuildDate,
		BuildType:     BuildType,
		GoVersion:     runtime.Version(),
		Platform:      fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
		SchemaVersion: GateReportSchemaVersion,
	}
}
