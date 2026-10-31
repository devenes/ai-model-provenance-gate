// Package evidence writes dual-format JSON and Markdown report bundles to disk.
package evidence

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/devenes/ai-model-provenance-gate/internal/digest"
	"github.com/devenes/ai-model-provenance-gate/internal/report"
)

// WriteReportBundle writes both Markdown and JSON reports into outDir using baseName
// (e.g., "inspect-report", "gate-report", or "verify-report") and attaches the Markdown SHA-256 to rep.Artifacts.
func WriteReportBundle(outDir string, baseName string, rep report.GateReport) (jsonPath string, mdPath string, err error) {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return "", "", fmt.Errorf("create output directory %q: %w", outDir, err)
	}

	mdBytes, err := report.RenderMarkdown(rep)
	if err != nil {
		return "", "", err
	}
	mdFileName := baseName + ".md"
	mdPath = filepath.Join(outDir, mdFileName)
	if err := os.WriteFile(mdPath, mdBytes, 0o600); err != nil {
		return "", "", fmt.Errorf("write markdown report %q: %w", mdPath, err)
	}

	rep.Artifacts = append(rep.Artifacts, report.ArtifactRecord{
		Name:   mdFileName,
		Role:   "markdown-report",
		Path:   mdFileName,
		SHA256: digest.ComputeBytes(mdBytes),
	})

	jsonBytes, err := report.RenderJSON(rep)
	if err != nil {
		return "", "", err
	}
	jsonFileName := baseName + ".json"
	jsonPath = filepath.Join(outDir, jsonFileName)
	if err := os.WriteFile(jsonPath, jsonBytes, 0o600); err != nil {
		return "", "", fmt.Errorf("write JSON report %q: %w", jsonPath, err)
	}

	return jsonPath, mdPath, nil
}
