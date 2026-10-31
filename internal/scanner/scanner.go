// Package scanner implements the optional security scanner adapter interface (e.g., Protect AI ModelScan)
// while strictly distinguishing format-level serialization scanning from behavioral safety.
package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/devenes/ai-model-provenance-gate/internal/bundle"
	"github.com/devenes/ai-model-provenance-gate/internal/digest"
)

// Status represents the security scanner verification state.
type Status string

const (
	StatusPass    Status = "PASS"
	StatusFail    Status = "FAIL"
	StatusBlocked Status = "BLOCKED"
	StatusNotRun  Status = "NOT_RUN"
)

var (
	// ErrScannerRequiredButMissing is returned when policy requires a security scan, but neither a report nor a scanner binary is available.
	ErrScannerRequiredButMissing = errors.New("policy requires security scanner evidence, but no scan report or scanner binary was provided")
	// ErrScannerIssuesFound is returned when the scanner reports vulnerability issues above threshold.
	ErrScannerIssuesFound = errors.New("security scanner reported serialization vulnerabilities")
	// ErrInvalidScanReport is returned when a supplied ModelScan JSON report is malformed.
	ErrInvalidScanReport = errors.New("invalid ModelScan JSON report")
)

// ModelScanReport represents the JSON output structure of Protect AI ModelScan (`modelscan -r json`).
type ModelScanReport struct {
	ModelScanVersion string `json:"modelscan_version"`
	Timestamp        string `json:"timestamp"`
	InputPath        string `json:"input_path"`
	Summary          struct {
		TotalIssues      int            `json:"total_issues"`
		IssuesBySeverity map[string]int `json:"issues_by_severity"`
		TotalErrors      int            `json:"total_errors"`
		Skipped          []string       `json:"skipped"`
	} `json:"summary"`
	Issues []struct {
		Description string `json:"description"`
		Operator    string `json:"operator"`
		Module      string `json:"module"`
		Source      string `json:"source"`
		Scanner     string `json:"scanner"`
		Severity    string `json:"severity"`
	} `json:"issues"`
	Errors []any `json:"errors"`
}

// Options configures optional scanner verification.
type Options struct {
	Required       bool
	ReportPath     string
	RunLiveBinary  bool
	BinaryName     string
	Timeout        time.Duration
	MaxAllowedHigh int
}

// Result summarizes scanner execution or report ingestion.
type Result struct {
	Status                Status         `json:"status"`
	Tool                  string         `json:"tool,omitempty"`
	ToolVersion           string         `json:"tool_version,omitempty"`
	ReportPath            string         `json:"report_path,omitempty"`
	ReportDigest          string         `json:"report_digest,omitempty"`
	TotalIssues           int            `json:"total_issues"`
	IssuesBySeverity      map[string]int `json:"issues_by_severity,omitempty"`
	TotalErrors           int            `json:"total_errors"`
	SkippedFiles          int            `json:"skipped_files"`
	StaticSafetensorsSafe bool           `json:"static_safetensors_safe"`
	CoverageLimitation    string         `json:"coverage_limitation"`
	Reason                string         `json:"reason"`
}

const coverageDisclaimer = "Serialization format scanning (ModelScan + static Safetensors header check) detects unsafe opcodes/headers only; it does NOT establish model behavioral safety, alignment, or absence of weight backdoors."

// Evaluate evaluates security scanner evidence from a provided ModelScan JSON report or optional live binary.
func Evaluate(ctx context.Context, insp bundle.InspectionResult, opts Options) (Result, error) {
	staticSafe := !insp.Manifest.SecurityFlags.ContainsUnsafePickle &&
		!insp.Manifest.SecurityFlags.ContainsRemoteCodeHooks &&
		insp.Manifest.FormatSummary.HasSafetensorsWeights

	reportPath := strings.TrimSpace(opts.ReportPath)
	if reportPath == "" && !opts.RunLiveBinary {
		if opts.Required {
			return Result{
				Status:                StatusBlocked,
				StaticSafetensorsSafe: staticSafe,
				CoverageLimitation:    coverageDisclaimer,
				Reason:                ErrScannerRequiredButMissing.Error(),
			}, ErrScannerRequiredButMissing
		}
		return Result{
			Status:                StatusNotRun,
			StaticSafetensorsSafe: staticSafe,
			CoverageLimitation:    coverageDisclaimer,
			Reason:                "external format scanner not required by policy (static Safetensors header inspection performed)",
		}, nil
	}

	var rawBytes []byte
	var err error
	if reportPath != "" {
		rawBytes, err = os.ReadFile(reportPath)
		if err != nil {
			return Result{
				Status:                StatusBlocked,
				ReportPath:            reportPath,
				StaticSafetensorsSafe: staticSafe,
				CoverageLimitation:    coverageDisclaimer,
				Reason:                fmt.Sprintf("read scanner report %q: %v", reportPath, err),
			}, err
		}
	} else {
		rawBytes, err = runModelScanCLI(ctx, insp.RootPath, opts)
		if err != nil {
			return Result{
				Status:                StatusBlocked,
				StaticSafetensorsSafe: staticSafe,
				CoverageLimitation:    coverageDisclaimer,
				Reason:                err.Error(),
			}, err
		}
	}

	return parseAndEvaluateReport(rawBytes, reportPath, staticSafe)
}

func parseAndEvaluateReport(rawBytes []byte, reportPath string, staticSafe bool) (Result, error) {
	var rep ModelScanReport
	dec := json.NewDecoder(bytes.NewReader(rawBytes))
	if err := dec.Decode(&rep); err != nil {
		return Result{
			Status:                StatusBlocked,
			ReportPath:            reportPath,
			StaticSafetensorsSafe: staticSafe,
			CoverageLimitation:    coverageDisclaimer,
			Reason:                fmt.Sprintf("%v: %v", ErrInvalidScanReport, err),
		}, fmt.Errorf("%w: %v", ErrInvalidScanReport, err)
	}
	if strings.TrimSpace(rep.ModelScanVersion) == "" {
		return Result{
			Status:                StatusBlocked,
			ReportPath:            reportPath,
			StaticSafetensorsSafe: staticSafe,
			CoverageLimitation:    coverageDisclaimer,
			Reason:                "invalid ModelScan report: missing modelscan_version",
		}, ErrInvalidScanReport
	}

	repDigest := digest.ComputeNormalizedText(rawBytes)
	res := Result{
		Tool:                  "modelscan",
		ToolVersion:           rep.ModelScanVersion,
		ReportPath:            reportPath,
		ReportDigest:          repDigest,
		TotalIssues:           rep.Summary.TotalIssues,
		IssuesBySeverity:      rep.Summary.IssuesBySeverity,
		TotalErrors:           rep.Summary.TotalErrors,
		SkippedFiles:          len(rep.Summary.Skipped),
		StaticSafetensorsSafe: staticSafe,
		CoverageLimitation:    coverageDisclaimer,
	}

	if rep.Summary.TotalErrors > 0 {
		res.Status = StatusBlocked
		res.Reason = fmt.Sprintf("ModelScan reported %d scan execution error(s)", rep.Summary.TotalErrors)
		return res, errors.New(res.Reason)
	}

	if rep.Summary.TotalIssues > 0 || len(rep.Issues) > 0 {
		res.Status = StatusFail
		res.Reason = fmt.Sprintf("ModelScan detected %d unsafe serialization issue(s)", rep.Summary.TotalIssues)
		return res, fmt.Errorf("%w: %s", ErrScannerIssuesFound, res.Reason)
	}

	res.Status = StatusPass
	res.Reason = fmt.Sprintf("ModelScan v%s completed with 0 issues (%d non-executable/safetensors files skipped)", rep.ModelScanVersion, len(rep.Summary.Skipped))
	return res, nil
}

func runModelScanCLI(ctx context.Context, bundleRoot string, opts Options) ([]byte, error) {
	bin := strings.TrimSpace(opts.BinaryName)
	if bin == "" {
		bin = "modelscan"
	}
	resolved, err := exec.LookPath(bin)
	if err != nil {
		return nil, fmt.Errorf("external scanner binary %q is not installed on PATH: %w", bin, err)
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	cmdCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(cmdCtx, resolved, "-p", bundleRoot, "-r", "json", "--show-skipped")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err = cmd.Run()
	// Note: ModelScan exits 0 (no issues), 1 (issues found), or 3 (no supported files, e.g., pure safetensors).
	// If stdout contains valid JSON, parse it; otherwise return error.
	if stdout.Len() > 0 && bytes.HasPrefix(bytes.TrimSpace(stdout.Bytes()), []byte("{")) {
		return stdout.Bytes(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("execute %s: %w (%s)", bin, err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}
