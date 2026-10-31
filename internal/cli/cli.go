// Package cli implements the command-line interface for AI Model Provenance Gate.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/devenes/ai-model-provenance-gate/internal/attestation"
	"github.com/devenes/ai-model-provenance-gate/internal/bom"
	"github.com/devenes/ai-model-provenance-gate/internal/bundle"
	"github.com/devenes/ai-model-provenance-gate/internal/config"
	"github.com/devenes/ai-model-provenance-gate/internal/deployment"
	"github.com/devenes/ai-model-provenance-gate/internal/digest"
	"github.com/devenes/ai-model-provenance-gate/internal/evaluation/llmreleasegate"
	"github.com/devenes/ai-model-provenance-gate/internal/evidence"
	"github.com/devenes/ai-model-provenance-gate/internal/inventory"
	"github.com/devenes/ai-model-provenance-gate/internal/oms"
	"github.com/devenes/ai-model-provenance-gate/internal/policy"
	"github.com/devenes/ai-model-provenance-gate/internal/provenance"
	"github.com/devenes/ai-model-provenance-gate/internal/report"
	"github.com/devenes/ai-model-provenance-gate/internal/scanner"
	"github.com/devenes/ai-model-provenance-gate/internal/signing"
	"github.com/devenes/ai-model-provenance-gate/internal/verification"
	"github.com/devenes/ai-model-provenance-gate/internal/version"
)

// Run executes the CLI command and returns a deterministic process exit code (0..4).
func Run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printUsage(stderr)
		return policy.ExitInvalid
	}

	switch args[0] {
	case "-h", "--help", "help":
		if len(args) > 1 {
			return Run(ctx, append(args[1:], "--help"), stdout, stderr)
		}
		printUsage(stdout)
		return policy.ExitPass
	case "version", "--version", "-v":
		return runVersion(args[1:], stdout, stderr)
	case "inspect":
		return runInspect(args[1:], stdout, stderr)
	case "bundle":
		return runBundleAlias(args[1:], stdout, stderr)
	case "bom":
		return runBOM(args[1:], stdout, stderr)
	case "oms":
		return runOMS(ctx, args[1:], stdout, stderr)
	case "sign-model":
		return runOMSSignModel(args[1:], stdout, stderr)
	case "verify-model":
		return runOMSVerifyModel(ctx, args[1:], stdout, stderr)
	case "evidence", "eval":
		return runEvidence(args[1:], stdout, stderr)
	case "gate", "attest":
		return runGate(ctx, args[1:], stdout, stderr)
	case "release", "deploy":
		return runRelease(args[1:], stdout, stderr)
	case "keygen":
		return runKeygen(args[1:], stdout, stderr)
	default:
		_, _ = fmt.Fprintf(stderr, "error: unknown command %q\n\n", args[0])
		printUsage(stderr)
		return policy.ExitInvalid
	}
}

func isHelpFlag(arg string) bool {
	return arg == "-h" || arg == "--help" || arg == "help"
}

func hasHelpFlag(args []string) bool {
	for _, a := range args {
		if isHelpFlag(a) {
			return true
		}
	}
	return false
}

func printUsage(w io.Writer) {
	_, _ = fmt.Fprintln(w, `AI Model Provenance Gate (ai-model-provenance)
Model artifact identity, CycloneDX AI/ML-BOM, OpenSSF Model Signing, evaluation binding, and release qualification.

Usage:
  ai-model-provenance <command> [subcommand] [flags]

Core Commands:
  inspect             Inspect a local model bundle and generate deterministic bundle-identity/v1
  bom generate        Generate a CycloneDX 1.7 (or 1.6) AI/ML-BOM from a model bundle
  bom validate        Validate a CycloneDX AI/ML-BOM against official schema and optional bundle inventory
  oms sign            Sign a model bundle with an OpenSSF Model Signing v1.0 DSSE / Sigstore bundle
  oms verify          Verify an OpenSSF Model Signing v1.0 signature against a model bundle
  evidence bind-eval  Bind and sign an LLM Release Gate evaluation report to a model bundle
  evidence verify     Verify an LLM Release Gate evaluation report and optional attestation against a bundle
  gate evaluate       Evaluate release qualification policy and emit a signed in-toto attestation
  release verify      Verify deployment composition and model bundle against a release attestation
  keygen              Generate an Ed25519 PKCS#8/PKIX key pair for testing and offline signing
  version             Print version and build provenance metadata

Command Aliases:
  bundle              Alias for 'inspect' (e.g., 'bundle inspect --bundle <dir>')
  eval                Alias for 'evidence' (e.g., 'eval bind-eval ...', 'eval verify ...')
  attest              Alias for 'gate' (e.g., 'attest evaluate ...')
  deploy              Alias for 'release' (e.g., 'deploy verify ...')

Exit Codes:
  0  PASS             All required verification and policy checks succeeded
  1  FAIL             Cryptographic, integrity, or policy check failed (tampering / mismatch)
  2  INVALID          Invalid CLI usage, flags, or malformed configuration input
  3  BLOCKED          Missing required evidence, untrusted signer, or unauthorized post-hoc binding
  4  INTERNAL_ERROR   Unexpected filesystem or runtime execution error

Run 'ai-model-provenance <command> --help' for detailed subcommand flags and examples.`)
}

func runBundleAlias(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "inspect" {
		return runInspect(args[1:], stdout, stderr)
	}
	return runInspect(args, stdout, stderr)
}

func runVersion(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("version", flag.ContinueOnError)
	fs.SetOutput(stderr)
	asJSON := fs.Bool("json", false, "Output version metadata as JSON")
	if hasHelpFlag(args) {
		_, _ = fmt.Fprintln(stdout, `Usage:
  ai-model-provenance version [--json]

Flags:
  --json    Output structured version and build provenance metadata as JSON`)
		return policy.ExitPass
	}
	if err := fs.Parse(args); err != nil {
		return policy.ExitInvalid
	}
	meta := version.Get()
	if *asJSON {
		raw, _ := json.MarshalIndent(meta, "", "  ")
		_, _ = fmt.Fprintln(stdout, string(raw))
		return policy.ExitPass
	}
	_, _ = fmt.Fprintf(stdout, "%s version %s (commit=%s, date=%s, go=%s, platform=%s, schema=%s)\n",
		meta.Name, meta.Version, meta.GitCommit, meta.BuildDate, meta.GoVersion, meta.Platform, meta.SchemaVersion)
	return policy.ExitPass
}

func runInspect(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("inspect", flag.ContinueOnError)
	fs.SetOutput(stderr)
	bundlePath := fs.String("bundle", "", "Path to local model bundle directory (required)")
	outputDir := fs.String("output", "", "Output directory for manifest and reports (must be outside --bundle)")
	baseBundle := fs.String("base-bundle", "", "Optional path to base model bundle for LoRA verification")
	expectedBaseID := fs.String("expected-base-bundle-id", "", "Optional expected sha256:<hex> of base model bundle")

	if hasHelpFlag(args) {
		_, _ = fmt.Fprintln(stdout, `Inspect a local model bundle and compute deterministic bundle-identity/v1.

Usage:
  ai-model-provenance inspect --bundle <dir> [--output <dir>] [--base-bundle <dir>] [--expected-base-bundle-id <sha256:hex>]

Flags:`)
		fs.SetOutput(stdout)
		fs.PrintDefaults()
		_, _ = fmt.Fprintln(stdout, `
Examples:
  ai-model-provenance inspect --bundle ./examples/bundles/minimal-safetensors --output ./out/inspect`)
		return policy.ExitPass
	}
	if err := fs.Parse(args); err != nil {
		return policy.ExitInvalid
	}
	if strings.TrimSpace(*bundlePath) == "" {
		_, _ = fmt.Fprintln(stderr, "error: --bundle is required")
		return policy.ExitInvalid
	}

	opts := bundle.DefaultInspectOptions()
	opts.InventoryOptions.OutputPath = *outputDir
	opts.BaseBundlePath = *baseBundle
	opts.ExpectedBaseBundleID = *expectedBaseID

	insp, err := bundle.Inspect(*bundlePath, opts)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: bundle inspection failed: %v\n", err)
		return exitCodeForInspectError(err)
	}

	loraProvenance := fmt.Sprintf("LoRA status=%s", insp.Manifest.LoRARelationship.VerificationStatus)
	if !insp.Manifest.LoRARelationship.IsAdapter {
		loraProvenance = "Base model bundle (no PEFT/LoRA adapter present)"
	}

	rep := report.GateReport{
		SchemaVersion: version.GateReportSchemaVersion,
		Command:       "inspect",
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
		Tool:          version.Get(),
		GateStatus:    policy.StatusPass,
		ExitCode:      policy.ExitPass,
		BundleID:      insp.BundleID,
		Manifest:      &insp.Manifest,
		Guarantees: report.GuaranteeMatrix{
			ArtifactIntegrity:    fmt.Sprintf("VERIFIED (%s over %d regular files)", insp.BundleID, insp.Manifest.FileCount),
			ArtifactAuthenticity: "NOT_EVALUATED (SHA-256 digest does not establish origin or authenticity)",
			SignerTrust:          "NOT_EVALUATED",
			ArtifactProvenance:   loraProvenance,
			SecurityScanEvidence: "STATIC_HEADER_ONLY (Safetensors binary headers validated; no behavioral safety implied)",
			BehavioralEvaluation: "NOT_EVALUATED",
			ReleaseQualification: "NOT_EVALUATED",
			DeploymentIdentity:   "NOT_EVALUATED",
		},
		Reasons: []policy.DecisionReason{
			{
				Code:     "BUNDLE_INSPECTED",
				Category: "bundle",
				Severity: "info",
				Status:   string(policy.StatusPass),
				Message:  fmt.Sprintf("inspected %d files (%d bytes), bundle_id=%s", insp.Manifest.FileCount, insp.Manifest.TotalBytes, insp.BundleID),
			},
		},
	}

	if strings.TrimSpace(*outputDir) != "" {
		if err := os.MkdirAll(*outputDir, 0o755); err != nil {
			_, _ = fmt.Fprintf(stderr, "error: create output dir: %v\n", err)
			return policy.ExitInternal
		}
		manifestPath := filepath.Join(*outputDir, "bundle-manifest.json")
		if err := os.WriteFile(manifestPath, insp.ManifestJSON, 0o600); err != nil {
			_, _ = fmt.Fprintf(stderr, "error: write manifest: %v\n", err)
			return policy.ExitInternal
		}
		rep.Artifacts = append(rep.Artifacts, report.ArtifactRecord{
			Name:   "bundle-manifest.json",
			Role:   "bundle-manifest",
			Path:   "bundle-manifest.json",
			SHA256: insp.Manifest.ManifestDigest,
		})
		jsonPath, mdPath, wErr := evidence.WriteReportBundle(*outputDir, "inspect-report", rep)
		if wErr != nil {
			_, _ = fmt.Fprintf(stderr, "error: write report bundle: %v\n", wErr)
			return policy.ExitInternal
		}
		_, _ = fmt.Fprintf(stdout, "COMMAND=inspect GATE_STATUS=PASS BUNDLE_ID=%s FILES=%d MANIFEST=%s JSON=%s MARKDOWN=%s\n",
			insp.BundleID, insp.Manifest.FileCount, manifestPath, jsonPath, mdPath)
		return policy.ExitPass
	}

	_, _ = fmt.Fprintf(stdout, "COMMAND=inspect GATE_STATUS=PASS BUNDLE_ID=%s FILES=%d\n", insp.BundleID, insp.Manifest.FileCount)
	return policy.ExitPass
}

func runBOM(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stderr, "error: bom requires subcommand 'generate' or 'validate'")
		return policy.ExitInvalid
	}
	if isHelpFlag(args[0]) {
		_, _ = fmt.Fprintln(stdout, `Generate and validate CycloneDX 1.7 / 1.6 AI/ML-BOM documents.

Usage:
  ai-model-provenance bom <subcommand> [flags]

Subcommands:
  generate    Generate a CycloneDX 1.7 (or 1.6) AI/ML-BOM from a local model bundle
  validate    Validate a CycloneDX AI/ML-BOM against the official JSON Schema and optional bundle inventory

Examples:
  ai-model-provenance bom generate --bundle ./examples/bundles/minimal-safetensors --output ./out/bom.cdx.json
  ai-model-provenance bom validate --bom ./out/bom.cdx.json --bundle ./examples/bundles/minimal-safetensors`)
		return policy.ExitPass
	}
	switch args[0] {
	case "generate":
		fs := flag.NewFlagSet("bom generate", flag.ContinueOnError)
		fs.SetOutput(stderr)
		bundlePath := fs.String("bundle", "", "Path to local model bundle directory (required)")
		outputPath := fs.String("output", "", "Output file or directory for CycloneDX BOM (required)")
		specVer := fs.String("spec-version", bom.SpecVersion1_7, "CycloneDX specification version (1.6 or 1.7)")
		baseBundle := fs.String("base-bundle", "", "Optional path to base model bundle for LoRA verification")
		expectedBaseID := fs.String("expected-base-bundle-id", "", "Optional expected sha256:<hex> of base model bundle")
		modelName := fs.String("name", "", "Optional model component name")
		if hasHelpFlag(args[1:]) {
			_, _ = fmt.Fprintln(stdout, `Generate a CycloneDX 1.7 / 1.6 AI/ML-BOM from a local model bundle.

Usage:
  ai-model-provenance bom generate --bundle <dir> --output <file|dir> [--spec-version 1.7|1.6]

Flags:`)
			fs.SetOutput(stdout)
			fs.PrintDefaults()
			return policy.ExitPass
		}
		if err := fs.Parse(args[1:]); err != nil {
			return policy.ExitInvalid
		}
		if strings.TrimSpace(*bundlePath) == "" || strings.TrimSpace(*outputPath) == "" {
			_, _ = fmt.Fprintln(stderr, "error: --bundle and --output are required")
			return policy.ExitInvalid
		}
		opts := bundle.DefaultInspectOptions()
		opts.InventoryOptions.OutputPath = *outputPath
		opts.BaseBundlePath = *baseBundle
		opts.ExpectedBaseBundleID = *expectedBaseID

		insp, err := bundle.Inspect(*bundlePath, opts)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "error: inspect bundle: %v\n", err)
			return exitCodeForInspectError(err)
		}
		gen, err := bom.Generate(insp, bom.GenerateOptions{
			SpecVersion: *specVer,
			ModelName:   *modelName,
		})
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "error: generate BOM: %v\n", err)
			return policy.ExitInvalid
		}
		targetFile := *outputPath
		if st, sErr := os.Stat(targetFile); (sErr == nil && st.IsDir()) || strings.HasSuffix(targetFile, "/") {
			if err := os.MkdirAll(targetFile, 0o755); err != nil {
				_, _ = fmt.Fprintf(stderr, "error: mkdir: %v\n", err)
				return policy.ExitInternal
			}
			targetFile = filepath.Join(targetFile, "bom.cdx.json")
		} else {
			if err := os.MkdirAll(filepath.Dir(targetFile), 0o755); err != nil {
				_, _ = fmt.Fprintf(stderr, "error: mkdir: %v\n", err)
				return policy.ExitInternal
			}
		}
		if err := os.WriteFile(targetFile, gen.JSON, 0o600); err != nil {
			_, _ = fmt.Fprintf(stderr, "error: write BOM: %v\n", err)
			return policy.ExitInternal
		}
		_, _ = fmt.Fprintf(stdout, "COMMAND=bom-generate STATUS=PASS SPEC=%s BUNDLE_ID=%s BOM_DIGEST=%s OUTPUT=%s\n",
			gen.Document.SpecVersion, insp.BundleID, gen.Digest, targetFile)
		return policy.ExitPass

	case "validate":
		fs := flag.NewFlagSet("bom validate", flag.ContinueOnError)
		fs.SetOutput(stderr)
		bomPath := fs.String("bom", "", "Path to CycloneDX JSON BOM file (required)")
		bundlePath := fs.String("bundle", "", "Optional path to model bundle to verify 1:1 inventory consistency")
		if hasHelpFlag(args[1:]) {
			_, _ = fmt.Fprintln(stdout, `Validate a CycloneDX AI/ML-BOM against the official JSON Schema and optional bundle inventory.

Usage:
  ai-model-provenance bom validate --bom <file> [--bundle <dir>]

Flags:`)
			fs.SetOutput(stdout)
			fs.PrintDefaults()
			return policy.ExitPass
		}
		if err := fs.Parse(args[1:]); err != nil {
			return policy.ExitInvalid
		}
		if strings.TrimSpace(*bomPath) == "" {
			_, _ = fmt.Fprintln(stderr, "error: --bom is required")
			return policy.ExitInvalid
		}
		raw, err := os.ReadFile(*bomPath)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "error: read BOM: %v\n", err)
			return policy.ExitInvalid
		}
		var inspPtr *bundle.InspectionResult
		if strings.TrimSpace(*bundlePath) != "" {
			insp, iErr := bundle.Inspect(*bundlePath, bundle.DefaultInspectOptions())
			if iErr != nil {
				_, _ = fmt.Fprintf(stderr, "error: inspect bundle: %v\n", iErr)
				return exitCodeForInspectError(iErr)
			}
			inspPtr = &insp
		}
		if err := bom.Validate(raw, inspPtr); err != nil {
			_, _ = fmt.Fprintf(stderr, "error: BOM validation failed: %v\n", err)
			return policy.ExitFail
		}
		_, _ = fmt.Fprintf(stdout, "COMMAND=bom-validate STATUS=PASS BOM=%s\n", *bomPath)
		return policy.ExitPass

	default:
		_, _ = fmt.Fprintf(stderr, "error: unknown bom subcommand %q\n", args[0])
		return policy.ExitInvalid
	}
}

func runOMS(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stderr, "error: oms requires subcommand 'sign' or 'verify'")
		return policy.ExitInvalid
	}
	if isHelpFlag(args[0]) {
		_, _ = fmt.Fprintln(stdout, `Sign and verify model bundles using OpenSSF Model Signing (OMS v1.0).

Usage:
  ai-model-provenance oms <subcommand> [flags]

Subcommands:
  sign      Sign a model bundle and emit an OMS v1.0 DSSE / Sigstore v0.3 bundle
  verify    Verify an OMS v1.0 signature against a local model bundle and trusted signer

Examples:
  ai-model-provenance oms sign --bundle ./model --private-key ./signer.key --key-id model-signer-1 --output ./model.sig
  ai-model-provenance oms verify --bundle ./model --signature ./model.sig --public-key ./signer.pub --key-id model-signer-1`)
		return policy.ExitPass
	}
	switch args[0] {
	case "sign":
		fs := flag.NewFlagSet("oms sign", flag.ContinueOnError)
		fs.SetOutput(stderr)
		bundlePath := fs.String("bundle", "", "Path to local model bundle directory (required)")
		privKeyPath := fs.String("private-key", "", "Path to PEM private key (required)")
		keyID := fs.String("key-id", "", "Optional signer key ID")
		outputPath := fs.String("output", "", "Output path for OMS signature bundle (required, outside --bundle)")
		asBundle := fs.Bool("sigstore-bundle", true, "Wrap DSSE envelope in Sigstore v0.3 JSON bundle")
		if hasHelpFlag(args[1:]) {
			_, _ = fmt.Fprintln(stdout, `Sign a local model bundle with OpenSSF Model Signing v1.0.

Usage:
  ai-model-provenance oms sign --bundle <dir> --private-key <key.pem> --output <file> [--key-id <id>]

Flags:`)
			fs.SetOutput(stdout)
			fs.PrintDefaults()
			return policy.ExitPass
		}
		if err := fs.Parse(args[1:]); err != nil {
			return policy.ExitInvalid
		}
		if strings.TrimSpace(*bundlePath) == "" || strings.TrimSpace(*privKeyPath) == "" || strings.TrimSpace(*outputPath) == "" {
			_, _ = fmt.Fprintln(stderr, "error: --bundle, --private-key, and --output are required")
			return policy.ExitInvalid
		}
		opts := bundle.DefaultInspectOptions()
		opts.InventoryOptions.OutputPath = *outputPath
		insp, err := bundle.Inspect(*bundlePath, opts)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "error: inspect bundle: %v\n", err)
			return exitCodeForInspectError(err)
		}
		priv, err := signing.LoadPrivateKeyFile(*privKeyPath, *keyID)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "error: load private key: %v\n", err)
			return policy.ExitInvalid
		}
		sigBytes, err := oms.SignBundle(insp, priv, oms.SignOptions{AsSigstoreBundle: *asBundle})
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "error: sign bundle: %v\n", err)
			return policy.ExitInternal
		}
		if err := os.MkdirAll(filepath.Dir(*outputPath), 0o755); err != nil {
			_, _ = fmt.Fprintf(stderr, "error: mkdir: %v\n", err)
			return policy.ExitInternal
		}
		if err := os.WriteFile(*outputPath, sigBytes, 0o600); err != nil {
			_, _ = fmt.Fprintf(stderr, "error: write OMS signature: %v\n", err)
			return policy.ExitInternal
		}
		_, _ = fmt.Fprintf(stdout, "COMMAND=oms-sign STATUS=PASS BUNDLE_ID=%s KEY_FP=%s OUTPUT=%s\n",
			insp.BundleID, priv.Fingerprint, *outputPath)
		return policy.ExitPass

	case "verify":
		fs := flag.NewFlagSet("oms verify", flag.ContinueOnError)
		fs.SetOutput(stderr)
		bundlePath := fs.String("bundle", "", "Path to local model bundle directory (required)")
		sigPath := fs.String("signature", "", "Path to OMS signature file (required)")
		pubKeyPath := fs.String("public-key", "", "Path to trusted PEM public key")
		keyID := fs.String("key-id", "", "Optional expected key ID")
		mode := fs.String("mode", string(oms.ModeNative), "Verification mode: native or external-cli")
		if hasHelpFlag(args[1:]) {
			_, _ = fmt.Fprintln(stdout, `Verify an OpenSSF Model Signing v1.0 signature against a local model bundle.

Usage:
  ai-model-provenance oms verify --bundle <dir> --signature <file> [--public-key <pub.pem>] [--key-id <id>]

Flags:`)
			fs.SetOutput(stdout)
			fs.PrintDefaults()
			return policy.ExitPass
		}
		if err := fs.Parse(args[1:]); err != nil {
			return policy.ExitInvalid
		}
		if strings.TrimSpace(*bundlePath) == "" {
			_, _ = fmt.Fprintln(stderr, "error: --bundle is required")
			return policy.ExitInvalid
		}
		insp, err := bundle.Inspect(*bundlePath, bundle.DefaultInspectOptions())
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "error: inspect bundle: %v\n", err)
			return exitCodeForInspectError(err)
		}
		var trusted []verification.TrustedSignerRule
		var pubPaths []string
		if strings.TrimSpace(*pubKeyPath) != "" {
			pub, pErr := signing.LoadPublicKeyFile(*pubKeyPath, *keyID, *pubKeyPath)
			if pErr != nil {
				_, _ = fmt.Fprintf(stderr, "error: load public key: %v\n", pErr)
				return policy.ExitInvalid
			}
			trusted = append(trusted, verification.TrustedSignerRule{
				ID:             pub.KeyID,
				Name:           *pubKeyPath,
				KeyID:          *keyID,
				KeyFingerprint: pub.Fingerprint,
				PublicKey:      pub,
			})
			pubPaths = append(pubPaths, *pubKeyPath)
		}
		res, verErr := oms.VerifyBundle(ctx, insp, *sigPath, oms.VerifyOptions{
			Mode:           oms.AdapterMode(*mode),
			TrustedSigners: trusted,
			PublicKeyPaths: pubPaths,
		})
		if verErr != nil {
			_, _ = fmt.Fprintf(stderr, "COMMAND=oms-verify STATUS=%s REASON=%q\n", res.Status, res.Reason)
			if res.Status == verification.StatusBlocked || res.Status == verification.StatusMissing {
				return policy.ExitBlocked
			}
			return policy.ExitFail
		}
		_, _ = fmt.Fprintf(stdout, "COMMAND=oms-verify STATUS=%s BUNDLE_ID=%s SIGNER_FP=%s FILES=%d\n",
			res.Status, insp.BundleID, res.SignerFingerprint, res.VerifiedFileCount)
		return policy.ExitPass

	default:
		_, _ = fmt.Fprintf(stderr, "error: unknown oms subcommand %q\n", args[0])
		return policy.ExitInvalid
	}
}

func runEvidence(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stderr, "error: evidence requires subcommand 'bind-eval' or 'verify'")
		return policy.ExitInvalid
	}
	if isHelpFlag(args[0]) {
		_, _ = fmt.Fprintln(stdout, `Bind and verify LLM Release Gate evaluation evidence for a model bundle.

Usage:
  ai-model-provenance evidence <subcommand> [flags]

Subcommands:
  bind-eval    Cryptographically bind and sign an LLM Release Gate evaluation report to a model bundle
  verify       Verify an LLM Release Gate evaluation report and optional attestation against a model bundle

Examples:
  ai-model-provenance evidence bind-eval --bundle ./model --evaluation-report ./report.json --private-key ./eval.key --producer-role trusted-evaluator --output ./eval.dsse.json
  ai-model-provenance evidence verify --bundle ./model --evaluation-report ./report.json --evaluation-attestation ./eval.dsse.json --public-key ./eval.pub`)
		return policy.ExitPass
	}
	switch args[0] {
	case "bind-eval", "bind":
		fs := flag.NewFlagSet("evidence bind-eval", flag.ContinueOnError)
		fs.SetOutput(stderr)
		bundlePath := fs.String("bundle", "", "Path to local model bundle directory (required)")
		evalReportPath := fs.String("evaluation-report", "", "Path to llm-release-gate report.json (required)")
		privKeyPath := fs.String("private-key", "", "Path to evaluator PEM private key (required)")
		keyID := fs.String("key-id", "", "Optional evaluator key ID")
		producerRole := fs.String("producer-role", llmreleasegate.ProducerRoleOperatorEndorser, "Producer role: operator-endorser (default for post-hoc binding) or trusted-evaluator (for automated CI evaluation)")
		outputPath := fs.String("output", "", "Output path for signed DSSE evaluation attestation (required)")
		if hasHelpFlag(args[1:]) {
			_, _ = fmt.Fprintln(stdout, `Cryptographically bind and sign an LLM Release Gate evaluation report to a model bundle.

Usage:
  ai-model-provenance evidence bind-eval --bundle <dir> --evaluation-report <report.json> --private-key <key.pem> --output <file> [--producer-role trusted-evaluator|operator-endorser]

Flags:`)
			fs.SetOutput(stdout)
			fs.PrintDefaults()
			return policy.ExitPass
		}
		if err := fs.Parse(args[1:]); err != nil {
			return policy.ExitInvalid
		}
		if strings.TrimSpace(*bundlePath) == "" || strings.TrimSpace(*evalReportPath) == "" || strings.TrimSpace(*privKeyPath) == "" || strings.TrimSpace(*outputPath) == "" {
			_, _ = fmt.Fprintln(stderr, "error: --bundle, --evaluation-report, --private-key, and --output are required")
			return policy.ExitInvalid
		}
		if *producerRole != llmreleasegate.ProducerRoleOperatorEndorser && *producerRole != llmreleasegate.ProducerRoleTrustedEvaluator {
			_, _ = fmt.Fprintf(stderr, "error: invalid --producer-role %q (must be %q or %q)\n", *producerRole, llmreleasegate.ProducerRoleOperatorEndorser, llmreleasegate.ProducerRoleTrustedEvaluator)
			return policy.ExitInvalid
		}
		opts := bundle.DefaultInspectOptions()
		opts.InventoryOptions.OutputPath = *outputPath
		insp, err := bundle.Inspect(*bundlePath, opts)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "error: inspect bundle: %v\n", err)
			return exitCodeForInspectError(err)
		}
		priv, err := signing.LoadPrivateKeyFile(*privKeyPath, *keyID)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "error: load private key: %v\n", err)
			return policy.ExitInvalid
		}
		attBytes, err := llmreleasegate.SignEvaluationEvidenceWithRole(*evalReportPath, insp.BundleID, priv, "", *producerRole)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "error: bind evaluation evidence: %v\n", err)
			return policy.ExitFail
		}
		if err := os.MkdirAll(filepath.Dir(*outputPath), 0o755); err != nil {
			_, _ = fmt.Fprintf(stderr, "error: mkdir: %v\n", err)
			return policy.ExitInternal
		}
		if err := os.WriteFile(*outputPath, attBytes, 0o600); err != nil {
			_, _ = fmt.Fprintf(stderr, "error: write evaluation attestation: %v\n", err)
			return policy.ExitInternal
		}
		_, _ = fmt.Fprintf(stdout, "COMMAND=evidence-bind-eval STATUS=PASS BUNDLE_ID=%s SIGNER_FP=%s OUTPUT=%s\n",
			insp.BundleID, priv.Fingerprint, *outputPath)
		return policy.ExitPass

	case "verify", "verify-eval":
		fs := flag.NewFlagSet("evidence verify", flag.ContinueOnError)
		fs.SetOutput(stderr)
		bundlePath := fs.String("bundle", "", "Path to local model bundle directory (required)")
		evalReportPath := fs.String("evaluation-report", "", "Path to llm-release-gate report.json (required)")
		evalAttPath := fs.String("evaluation-attestation", "", "Optional path to signed DSSE evaluation attestation")
		pubKeyPath := fs.String("public-key", "", "Optional path to trusted evaluator PEM public key")
		keyID := fs.String("key-id", "", "Optional expected evaluator key ID")
		if hasHelpFlag(args[1:]) {
			_, _ = fmt.Fprintln(stdout, `Verify an LLM Release Gate evaluation report and optional attestation against a local model bundle.

Usage:
  ai-model-provenance evidence verify --bundle <dir> --evaluation-report <report.json> [--evaluation-attestation <att.json>] [--public-key <pub.pem>]

Flags:`)
			fs.SetOutput(stdout)
			fs.PrintDefaults()
			return policy.ExitPass
		}
		if err := fs.Parse(args[1:]); err != nil {
			return policy.ExitInvalid
		}
		if strings.TrimSpace(*bundlePath) == "" || strings.TrimSpace(*evalReportPath) == "" {
			_, _ = fmt.Fprintln(stderr, "error: --bundle and --evaluation-report are required")
			return policy.ExitInvalid
		}
		insp, err := bundle.Inspect(*bundlePath, bundle.DefaultInspectOptions())
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "error: inspect bundle: %v\n", err)
			return exitCodeForInspectError(err)
		}
		var trusted []verification.TrustedSignerRule
		if strings.TrimSpace(*pubKeyPath) != "" {
			pub, pErr := signing.LoadPublicKeyFile(*pubKeyPath, *keyID, *pubKeyPath)
			if pErr != nil {
				_, _ = fmt.Fprintf(stderr, "error: load public key: %v\n", pErr)
				return policy.ExitInvalid
			}
			trusted = append(trusted, verification.TrustedSignerRule{
				ID:             pub.KeyID,
				Name:           *pubKeyPath,
				KeyID:          *keyID,
				KeyFingerprint: pub.Fingerprint,
				PublicKey:      pub,
			})
		}
		sum, vErr := llmreleasegate.Verify(*evalReportPath, llmreleasegate.VerifyOptions{
			ExpectedBundleID:       insp.BundleID,
			AttestationPath:        *evalAttPath,
			TrustedSigners:         trusted,
			RequireArtifactBinding: true,
			RequireTrustedEvidence: strings.TrimSpace(*evalAttPath) != "",
		})
		if vErr != nil || sum.BindingStatus == llmreleasegate.BindingMismatch || sum.EffectiveGateStatus != "PASS" {
			_, _ = fmt.Fprintf(stderr, "COMMAND=evidence-verify STATUS=FAIL BINDING=%s TRUST=%s GATE_STATUS=%s REASON=%q\n",
				sum.BindingStatus, sum.TrustStatus, sum.EffectiveGateStatus, sum.Reason)
			return policy.ExitFail
		}
		_, _ = fmt.Fprintf(stdout, "COMMAND=evidence-verify STATUS=PASS BUNDLE_ID=%s BINDING=%s TRUST=%s GATE_STATUS=%s\n",
			insp.BundleID, sum.BindingStatus, sum.TrustStatus, sum.EffectiveGateStatus)
		return policy.ExitPass

	default:
		_, _ = fmt.Fprintf(stderr, "error: unknown evidence subcommand %q (expected 'bind-eval' or 'verify')\n", args[0])
		return policy.ExitInvalid
	}
}

func runGate(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stderr, "error: gate requires subcommand 'evaluate'")
		return policy.ExitInvalid
	}
	if isHelpFlag(args[0]) {
		_, _ = fmt.Fprintln(stdout, `Evaluate fail-closed release qualification policy and emit a signed in-toto attestation.

Usage:
  ai-model-provenance gate evaluate [flags]

Subcommands:
  evaluate    Verify model bundle, OMS signature, and evaluation evidence against policy.yaml

Run 'ai-model-provenance gate evaluate --help' for all flags.`)
		return policy.ExitPass
	}
	if args[0] != "evaluate" {
		_, _ = fmt.Fprintln(stderr, "error: gate requires subcommand 'evaluate'")
		return policy.ExitInvalid
	}
	fs := flag.NewFlagSet("gate evaluate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	bundlePath := fs.String("bundle", "", "Path to local model bundle directory (required)")
	baseBundle := fs.String("base-bundle", "", "Optional path to base model bundle for LoRA verification")
	expectedBaseID := fs.String("expected-base-bundle-id", "", "Optional expected sha256:<hex> of base model bundle")
	evalReportPath := fs.String("evaluation-report", "", "Path to llm-release-gate report.json")
	evalAttPath := fs.String("evaluation-attestation", "", "Path to signed evaluation DSSE attestation")
	omsSigPath := fs.String("oms-signature", "", "Path to OpenSSF Model Signing signature file")
	scannerReportPath := fs.String("scanner-report", "", "Optional path to ModelScan JSON report")
	upstreamProvPath := fs.String("upstream-provenance", "", "Optional path to upstream SLSA v1 provenance DSSE")
	policyPath := fs.String("policy", "", "Path to policy.yaml (defaults to strict fail-closed policy)")
	signingKeyPath := fs.String("signing-key", "", "Optional path to release authority PEM private key to sign qualification attestation")
	signingKeyID := fs.String("signing-key-id", "", "Optional release authority key ID")
	runtimeImage := fs.String("runtime-image", "", "Optional immutable OCI runtime image digest to bind into qualification attestation")
	servingConfigPath := fs.String("serving-config", "", "Optional serving configuration file to hash into qualification attestation")
	outputDir := fs.String("output", "", "Output directory for BOM, attestation, and reports (outside --bundle)")
	notRun := fs.Bool("not-run", false, "Record gate evaluation as NOT_RUN without approving release")

	if hasHelpFlag(args[1:]) {
		_, _ = fmt.Fprintln(stdout, `Evaluate release qualification policy and emit a signed in-toto Release Qualification Attestation.

Usage:
  ai-model-provenance gate evaluate --bundle <dir> --policy <policy.yaml> [flags]

Flags:`)
		fs.SetOutput(stdout)
		fs.PrintDefaults()
		return policy.ExitPass
	}
	if err := fs.Parse(args[1:]); err != nil {
		return policy.ExitInvalid
	}
	if strings.TrimSpace(*bundlePath) == "" {
		_, _ = fmt.Fprintln(stderr, "error: --bundle is required")
		return policy.ExitInvalid
	}

	var pol config.Policy
	var err error
	if strings.TrimSpace(*policyPath) != "" {
		pol, err = config.LoadPolicy(*policyPath)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "error: %v\n", err)
			return policy.ExitInvalid
		}
	} else {
		pol = config.StrictDefaultPolicy()
	}

	inspOpts := bundle.DefaultInspectOptions()
	inspOpts.InventoryOptions.RejectSymlinks = pol.Bundle.RejectSymlinks
	inspOpts.InventoryOptions.OutputPath = *outputDir
	inspOpts.BaseBundlePath = *baseBundle
	inspOpts.ExpectedBaseBundleID = *expectedBaseID

	insp, err := bundle.Inspect(*bundlePath, inspOpts)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: bundle inspection failed: %v\n", err)
		return exitCodeForInspectError(err)
	}

	genBOM, err := bom.Generate(insp, bom.GenerateOptions{})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: BOM generation failed: %v\n", err)
		return policy.ExitFail
	}

	// OMS verification
	omsTrusted, err := config.ResolveTrustedSigners(pol.Signing.TrustedSigners, pol.BaseDir, nil)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: resolve OMS trusted signers: %v\n", err)
		return policy.ExitInvalid
	}
	var omsPubPaths []string
	for _, ts := range pol.Signing.TrustedSigners {
		p := ts.PublicKeyPath
		if !filepath.IsAbs(p) && pol.BaseDir != "" {
			p = filepath.Join(pol.BaseDir, p)
		}
		omsPubPaths = append(omsPubPaths, p)
	}
	omsMode := oms.ModeNative
	if pol.Signing.OMSMode == "external-cli" {
		omsMode = oms.ModeExternalCLI
	}
	var omsRes oms.Result
	if strings.TrimSpace(*omsSigPath) != "" || pol.Signing.RequireOMS {
		omsRes, _ = oms.VerifyBundle(ctx, insp, *omsSigPath, oms.VerifyOptions{
			Mode:           omsMode,
			TrustedSigners: omsTrusted,
			PublicKeyPaths: omsPubPaths,
		})
	} else {
		omsRes = oms.Result{Status: verification.StatusNotRun, Mode: omsMode, Reason: "OMS verification not required by policy"}
	}

	// Evaluation verification (never conflate OMS model signers with evaluation producer signers)
	evalTrusted, err := config.ResolveTrustedSigners(pol.Evaluation.TrustedSigners, pol.BaseDir, nil)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: resolve evaluation trusted signers: %v\n", err)
		return policy.ExitInvalid
	}
	evalTrustedFPs := make(map[string]bool, len(evalTrusted))
	for _, et := range evalTrusted {
		if et.PublicKey != nil {
			evalTrustedFPs[et.PublicKey.Fingerprint] = true
		}
	}
	var evalUntrustedCandidates []*signing.PublicKey
	for _, ot := range omsTrusted {
		if ot.PublicKey != nil && !evalTrustedFPs[ot.PublicKey.Fingerprint] {
			evalUntrustedCandidates = append(evalUntrustedCandidates, ot.PublicKey)
		}
	}
	hasEval := strings.TrimSpace(*evalReportPath) != ""
	var evalSum llmreleasegate.EvaluationSummary
	if hasEval {
		var evalErr error
		evalSum, evalErr = llmreleasegate.Verify(*evalReportPath, llmreleasegate.VerifyOptions{
			ExpectedBundleID:       insp.BundleID,
			AttestationPath:        *evalAttPath,
			TrustedSigners:         evalTrusted,
			CandidateUntrustedKeys: evalUntrustedCandidates,
			RequireArtifactBinding: pol.Evaluation.RequireArtifactBinding,
			RequireTrustedEvidence: pol.Evaluation.RequireTrustedEvidence,
			AllowPostHocBinding:    pol.Evaluation.AllowPostHocBinding,
			MaxAgeHours:            pol.Evaluation.MaxAgeHours,
			ExpectedSuiteDigest:    pol.Evaluation.ExpectedSuiteDigest,
			ExpectedDatasetDigest:  pol.Evaluation.ExpectedDatasetDigest,
		})
		if evalErr != nil && errors.Is(evalErr, llmreleasegate.ErrInvalidEvaluationReport) {
			_, _ = fmt.Fprintf(stderr, "error: %v\n", evalErr)
			return policy.ExitInvalid
		}
	}

	// Optional Upstream SLSA Provenance verification (never conflate OMS model signers with SLSA builder signers)
	provTrusted, err := config.ResolveTrustedSigners(pol.Provenance.TrustedSigners, pol.BaseDir, nil)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: resolve provenance trusted signers: %v\n", err)
		return policy.ExitInvalid
	}
	provTrustedFPs := make(map[string]bool, len(provTrusted))
	for _, pt := range provTrusted {
		if pt.PublicKey != nil {
			provTrustedFPs[pt.PublicKey.Fingerprint] = true
		}
	}
	var provUntrustedCandidates []*signing.PublicKey
	for _, ot := range omsTrusted {
		if ot.PublicKey != nil && !provTrustedFPs[ot.PublicKey.Fingerprint] {
			provUntrustedCandidates = append(provUntrustedCandidates, ot.PublicKey)
		}
	}
	provRes, _ := provenance.VerifyUpstreamProvenance(provenance.VerifyOptions{
		AttestationPath:        *upstreamProvPath,
		ExpectedBundleID:       insp.BundleID,
		ExpectedBuilderIDs:     pol.Provenance.TrustedBuilders,
		TrustedSigners:         provTrusted,
		CandidateUntrustedKeys: provUntrustedCandidates,
	})

	// Scanner evaluation
	scanRes, _ := scanner.Evaluate(ctx, insp, scanner.Options{
		Required:   pol.Scanner.Required,
		ReportPath: *scannerReportPath,
	})

	var servingCfgDigest string
	if strings.TrimSpace(*servingConfigPath) != "" {
		rawCfg, cErr := os.ReadFile(*servingConfigPath)
		if cErr != nil {
			_, _ = fmt.Fprintf(stderr, "error: read serving config %q: %v\n", *servingConfigPath, cErr)
			return policy.ExitInvalid
		}
		servingCfgDigest = digest.ComputeNormalizedText(rawCfg)
	}

	dec := policy.Evaluate(policy.EvaluationInput{
		NotRun:        *notRun,
		Policy:        pol,
		Inspection:    insp,
		BOM:           genBOM,
		OMS:           omsRes,
		HasEvaluation: hasEval,
		Evaluation:    evalSum,
		Provenance:    provRes,
		Scanner:       scanRes,
		RuntimeImage:  *runtimeImage,
	})

	var privKey *signing.PrivateKey
	if strings.TrimSpace(*signingKeyPath) != "" {
		privKey, err = signing.LoadPrivateKeyFile(*signingKeyPath, *signingKeyID)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "error: load signing key: %v\n", err)
			return policy.ExitInvalid
		}
	} else if pol.Release.RequireSignedQualification && dec.GateStatus == policy.StatusPass {
		dec.GateStatus = policy.StatusBlocked
		dec.ExitCode = policy.ExitBlocked
		dec.Reasons = append(dec.Reasons, policy.DecisionReason{
			Code:     "RELEASE_SIGNING_KEY_MISSING",
			Category: "release",
			Severity: "error",
			Status:   string(policy.StatusBlocked),
			Message:  "policy requires a signed release qualification attestation, but --signing-key was not provided",
		})
	}

	var genAtt attestation.GeneratedAttestation
	if dec.GateStatus == policy.StatusPass {
		genAtt, err = attestation.BuildAndOptionallySign(attestation.BuildInput{
			Inspection:          insp,
			BOM:                 genBOM,
			OMS:                 omsRes,
			HasEvaluation:       hasEval,
			Evaluation:          evalSum,
			Scanner:             scanRes,
			Provenance:          provRes,
			RuntimeImage:        *runtimeImage,
			ServingConfigDigest: servingCfgDigest,
			Policy:              pol,
			Decision:            dec,
		}, privKey)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "error: build release attestation: %v\n", err)
			return policy.ExitInternal
		}
	}

	var evalPtr *llmreleasegate.EvaluationSummary
	if hasEval {
		evalPtr = &evalSum
	}

	rep := report.GateReport{
		SchemaVersion:            version.GateReportSchemaVersion,
		Command:                  "gate-evaluate",
		Timestamp:                time.Now().UTC().Format(time.RFC3339),
		Tool:                     version.Get(),
		GateStatus:               dec.GateStatus,
		ExitCode:                 dec.ExitCode,
		BundleID:                 insp.BundleID,
		Manifest:                 &insp.Manifest,
		BOMDigest:                genBOM.Digest,
		OMS:                      &omsRes,
		Evaluation:               evalPtr,
		Scanner:                  &scanRes,
		UpstreamProvenance:       &provRes,
		ReleaseAttestationDigest: genAtt.Digest,
		Policy: &report.PolicySummary{
			SchemaVersion: pol.SchemaVersion,
			Name:          pol.Name,
			Digest:        pol.Digest,
			DecisionMode:  pol.Release.DecisionMode,
		},
		Guarantees: buildGateGuaranteeMatrix(insp, omsRes, hasEval, evalSum, scanRes, provRes, dec, genAtt),
		Reasons:    dec.Reasons,
	}

	if strings.TrimSpace(*outputDir) != "" {
		if err := os.MkdirAll(*outputDir, 0o755); err != nil {
			_, _ = fmt.Fprintf(stderr, "error: create output dir: %v\n", err)
			return policy.ExitInternal
		}
		manifestPath := filepath.Join(*outputDir, "bundle-manifest.json")
		_ = os.WriteFile(manifestPath, insp.ManifestJSON, 0o600)
		bomPath := filepath.Join(*outputDir, "bom.cdx.json")
		_ = os.WriteFile(bomPath, genBOM.JSON, 0o600)

		rep.Artifacts = append(rep.Artifacts,
			report.ArtifactRecord{Name: "bundle-manifest.json", Role: "bundle-manifest", Path: "bundle-manifest.json", SHA256: insp.Manifest.ManifestDigest},
			report.ArtifactRecord{Name: "bom.cdx.json", Role: "cyclonedx-mlbom", Path: "bom.cdx.json", SHA256: genBOM.Digest},
		)

		if len(genAtt.JSONBytes) > 0 {
			attPath := filepath.Join(*outputDir, "attestation.json")
			_ = os.WriteFile(attPath, genAtt.JSONBytes, 0o600)
			rep.Artifacts = append(rep.Artifacts, report.ArtifactRecord{
				Name:   "attestation.json",
				Role:   "release-qualification-attestation",
				Path:   "attestation.json",
				SHA256: genAtt.Digest,
			})
		}

		jsonPath, mdPath, wErr := evidence.WriteReportBundle(*outputDir, "gate-report", rep)
		if wErr != nil {
			_, _ = fmt.Fprintf(stderr, "error: write report bundle: %v\n", wErr)
			return policy.ExitInternal
		}
		_, _ = fmt.Fprintf(stdout, "COMMAND=gate-evaluate GATE_STATUS=%s EXIT_CODE=%d BUNDLE_ID=%s BOM_DIGEST=%s JSON=%s MARKDOWN=%s\n",
			dec.GateStatus, dec.ExitCode, insp.BundleID, genBOM.Digest, jsonPath, mdPath)
	} else {
		_, _ = fmt.Fprintf(stdout, "COMMAND=gate-evaluate GATE_STATUS=%s EXIT_CODE=%d BUNDLE_ID=%s BOM_DIGEST=%s\n",
			dec.GateStatus, dec.ExitCode, insp.BundleID, genBOM.Digest)
	}

	for _, r := range dec.Reasons {
		_, _ = fmt.Fprintf(stdout, "  [%s/%s] %s: %s\n", strings.ToUpper(r.Severity), r.Category, r.Code, r.Message)
	}
	return dec.ExitCode
}

func runRelease(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stderr, "error: release requires subcommand 'verify'")
		return policy.ExitInvalid
	}
	if isHelpFlag(args[0]) {
		_, _ = fmt.Fprintln(stdout, `Verify deployment composition and candidate model bundle against a signed Release Qualification Attestation.

Usage:
  ai-model-provenance release verify [flags]

Subcommands:
  verify    Verify deployment bundle identity, release attestation signature, and runtime composition

Run 'ai-model-provenance release verify --help' for all flags.`)
		return policy.ExitPass
	}
	if args[0] != "verify" {
		_, _ = fmt.Fprintln(stderr, "error: release requires subcommand 'verify'")
		return policy.ExitInvalid
	}
	fs := flag.NewFlagSet("release verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	bundlePath := fs.String("bundle", "", "Path to deployment model bundle directory (required)")
	baseBundle := fs.String("base-bundle", "", "Optional path to base model bundle")
	attestationPath := fs.String("attestation", "", "Path to signed release qualification attestation (required)")
	policyPath := fs.String("policy", "", "Path to policy.yaml")
	deploymentPath := fs.String("deployment", "", "Optional path to deployment.yaml composition descriptor")
	pubKeyPath := fs.String("public-key", "", "Optional path to trusted release authority PEM public key")
	outputDir := fs.String("output", "", "Output directory for verification reports (outside --bundle)")

	if hasHelpFlag(args[1:]) {
		_, _ = fmt.Fprintln(stdout, `Verify a deployment model bundle and deployment composition against a signed Release Qualification Attestation.

Usage:
  ai-model-provenance release verify --bundle <dir> --attestation <attestation.json> [--deployment <deployment.yaml>] [--policy <policy.yaml>]

Flags:`)
		fs.SetOutput(stdout)
		fs.PrintDefaults()
		return policy.ExitPass
	}
	if err := fs.Parse(args[1:]); err != nil {
		return policy.ExitInvalid
	}
	if strings.TrimSpace(*bundlePath) == "" || strings.TrimSpace(*attestationPath) == "" {
		_, _ = fmt.Fprintln(stderr, "error: --bundle and --attestation are required")
		return policy.ExitInvalid
	}
	if err := inventory.ValidateOutputOutsideBundle(*bundlePath, *outputDir); err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)
		return policy.ExitInvalid
	}

	var pol config.Policy
	var err error
	if strings.TrimSpace(*policyPath) != "" {
		pol, err = config.LoadPolicy(*policyPath)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "error: %v\n", err)
			return policy.ExitInvalid
		}
	} else {
		pol = config.StrictDefaultPolicy()
	}

	signerConfigs := pol.Release.TrustedSigners
	var extraPubs []string
	if strings.TrimSpace(*pubKeyPath) != "" {
		extraPubs = append(extraPubs, *pubKeyPath)
	}
	trustedSigners, err := config.ResolveTrustedSigners(signerConfigs, pol.BaseDir, extraPubs)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: resolve trusted signers: %v\n", err)
		return policy.ExitInvalid
	}
	relTrustedFPs := make(map[string]bool, len(trustedSigners))
	for _, rt := range trustedSigners {
		if rt.PublicKey != nil {
			relTrustedFPs[rt.PublicKey.Fingerprint] = true
		}
	}
	otherConfigs := append([]config.TrustedSignerConfig{}, pol.Signing.TrustedSigners...)
	otherConfigs = append(otherConfigs, pol.Evaluation.TrustedSigners...)
	otherRules, _ := config.ResolveTrustedSigners(otherConfigs, pol.BaseDir, nil)
	var relUntrustedCandidates []*signing.PublicKey
	for _, or := range otherRules {
		if or.PublicKey != nil && !relTrustedFPs[or.PublicKey.Fingerprint] {
			relUntrustedCandidates = append(relUntrustedCandidates, or.PublicKey)
		}
	}

	verRes, _ := deployment.Verify(deployment.VerifyOptions{
		BundlePath:             *bundlePath,
		BaseBundlePath:         *baseBundle,
		DescriptorPath:         *deploymentPath,
		AttestationPath:        *attestationPath,
		Policy:                 pol,
		TrustedSigners:         trustedSigners,
		CandidateUntrustedKeys: relUntrustedCandidates,
	})

	deployGuarantee := "VERIFIED (local deployment bundle matches signed release attestation)"
	if verRes.CompositionID != "" {
		deployGuarantee = fmt.Sprintf("VERIFIED (composition_id=%s, immutable_image=%t)", verRes.CompositionID, verRes.RuntimeImageImmutable)
	}
	if verRes.GateStatus != policy.StatusPass {
		deployGuarantee = fmt.Sprintf("REJECTED (%s)", verRes.GateStatus)
	}

	rep := report.GateReport{
		SchemaVersion:            version.GateReportSchemaVersion,
		Command:                  "release-verify",
		Timestamp:                time.Now().UTC().Format(time.RFC3339),
		Tool:                     version.Get(),
		GateStatus:               verRes.GateStatus,
		ExitCode:                 verRes.ExitCode,
		BundleID:                 verRes.BundleID,
		CompositionID:            verRes.CompositionID,
		ReleaseAttestationDigest: verRes.QualificationVerification.AttestationDigest,
		Deployment:               &verRes,
		Policy: &report.PolicySummary{
			SchemaVersion: pol.SchemaVersion,
			Name:          pol.Name,
			Digest:        pol.Digest,
			DecisionMode:  pol.Release.DecisionMode,
		},
		Guarantees: report.GuaranteeMatrix{
			ArtifactIntegrity:    fmt.Sprintf("OBSERVED (%s)", verRes.BundleID),
			ArtifactAuthenticity: fmt.Sprintf("ATTESTATION_%s", verRes.QualificationVerification.Status),
			SignerTrust:          fmt.Sprintf("SIGNER=%s (%s)", verRes.QualificationVerification.SignerID, verRes.QualificationVerification.SignerFingerprint),
			ArtifactProvenance:   "BOUND_VIA_RELEASE_ATTESTATION",
			SecurityScanEvidence: "RECORDED_IN_ATTESTATION",
			BehavioralEvaluation: "RECORDED_IN_ATTESTATION",
			ReleaseQualification: fmt.Sprintf("%s (subject=%s)", verRes.QualificationVerification.Status, verRes.AttestedBundleID),
			DeploymentIdentity:   deployGuarantee,
		},
		Reasons: verRes.Reasons,
	}

	if strings.TrimSpace(*outputDir) != "" {
		if err := os.MkdirAll(*outputDir, 0o755); err != nil {
			_, _ = fmt.Fprintf(stderr, "error: create output dir: %v\n", err)
			return policy.ExitInternal
		}
		compManifestPath := filepath.Join(*outputDir, "deployment-manifest.json")
		_ = deployment.WriteCompositionManifest(compManifestPath, verRes)
		jsonPath, mdPath, wErr := evidence.WriteReportBundle(*outputDir, "verify-report", rep)
		if wErr != nil {
			_, _ = fmt.Fprintf(stderr, "error: write report bundle: %v\n", wErr)
			return policy.ExitInternal
		}
		_, _ = fmt.Fprintf(stdout, "COMMAND=release-verify GATE_STATUS=%s EXIT_CODE=%d BUNDLE_ID=%s COMPOSITION_ID=%s JSON=%s MARKDOWN=%s\n",
			verRes.GateStatus, verRes.ExitCode, verRes.BundleID, verRes.CompositionID, jsonPath, mdPath)
	} else {
		_, _ = fmt.Fprintf(stdout, "COMMAND=release-verify GATE_STATUS=%s EXIT_CODE=%d BUNDLE_ID=%s COMPOSITION_ID=%s\n",
			verRes.GateStatus, verRes.ExitCode, verRes.BundleID, verRes.CompositionID)
	}

	for _, r := range verRes.Reasons {
		_, _ = fmt.Fprintf(stdout, "  [%s/%s] %s: %s\n", strings.ToUpper(r.Severity), r.Category, r.Code, r.Message)
	}
	return verRes.ExitCode
}

func runKeygen(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	outDir := fs.String("output-dir", "", "Output directory for generated key pair (required)")
	name := fs.String("name", "signer", "Key filename prefix")
	if hasHelpFlag(args) {
		_, _ = fmt.Fprintln(stdout, `Generate an Ed25519 PKCS#8/PKIX key pair for testing and offline signing.

Usage:
  ai-model-provenance keygen --output-dir <dir> [--name <prefix>]

Flags:`)
		fs.SetOutput(stdout)
		fs.PrintDefaults()
		return policy.ExitPass
	}
	if err := fs.Parse(args); err != nil {
		return policy.ExitInvalid
	}
	if strings.TrimSpace(*outDir) == "" {
		_, _ = fmt.Fprintln(stderr, "error: --output-dir is required")
		return policy.ExitInvalid
	}
	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		_, _ = fmt.Fprintf(stderr, "error: mkdir: %v\n", err)
		return policy.ExitInternal
	}
	privPEM, pubPEM, fp, err := signing.GenerateEd25519KeyPairPEM()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: generate key pair: %v\n", err)
		return policy.ExitInternal
	}
	privPath := filepath.Join(*outDir, *name+".key")
	pubPath := filepath.Join(*outDir, *name+".pub")
	if err := os.WriteFile(privPath, privPEM, 0o600); err != nil {
		_, _ = fmt.Fprintf(stderr, "error: write private key: %v\n", err)
		return policy.ExitInternal
	}
	if err := os.WriteFile(pubPath, pubPEM, 0o644); err != nil {
		_, _ = fmt.Fprintf(stderr, "error: write public key: %v\n", err)
		return policy.ExitInternal
	}
	_, _ = fmt.Fprintf(stdout, "COMMAND=keygen STATUS=PASS FINGERPRINT=%s PRIVATE_KEY=%s PUBLIC_KEY=%s\n", fp, privPath, pubPath)
	return policy.ExitPass
}

func buildGateGuaranteeMatrix(
	insp bundle.InspectionResult,
	omsRes oms.Result,
	hasEval bool,
	evalSum llmreleasegate.EvaluationSummary,
	scanRes scanner.Result,
	provRes provenance.Result,
	dec policy.Decision,
	att attestation.GeneratedAttestation,
) report.GuaranteeMatrix {
	evalStr := "MISSING (mandatory evaluation report not provided)"
	if hasEval {
		evalStr = fmt.Sprintf("STATUS=%s, BINDING=%s, TRUST=%s (runId=%s)", evalSum.EffectiveGateStatus, evalSum.BindingStatus, evalSum.TrustStatus, evalSum.RunID)
	}
	qualStr := fmt.Sprintf("REJECTED (%s)", dec.GateStatus)
	if dec.GateStatus == policy.StatusPass {
		if att.Signed {
			qualStr = fmt.Sprintf("QUALIFIED_AND_SIGNED (DSSE digest=%s, signer=%s)", att.Digest, att.SignerFP)
		} else {
			qualStr = fmt.Sprintf("QUALIFIED_UNSIGNED (statement digest=%s)", att.Digest)
		}
	}
	return report.GuaranteeMatrix{
		ArtifactIntegrity:    fmt.Sprintf("VERIFIED (bundle_id=%s, files=%d)", insp.BundleID, insp.Manifest.FileCount),
		ArtifactAuthenticity: fmt.Sprintf("OMS_%s (%s)", omsRes.Status, omsRes.PredicateType),
		SignerTrust:          fmt.Sprintf("OMS_SIGNER=%s (%s)", omsRes.SignerID, omsRes.SignerFingerprint),
		ArtifactProvenance:   fmt.Sprintf("LORA=%s, UPSTREAM_SLSA=%s", insp.Manifest.LoRARelationship.VerificationStatus, provRes.Status),
		SecurityScanEvidence: fmt.Sprintf("SCANNER=%s (static_safetensors_safe=%t; does NOT establish behavioral safety)", scanRes.Status, scanRes.StaticSafetensorsSafe),
		BehavioralEvaluation: evalStr,
		ReleaseQualification: qualStr,
		DeploymentIdentity:   "PENDING_DEPLOYMENT_VERIFICATION (run `release verify` prior to serving)",
	}
}

func exitCodeForInspectError(err error) int {
	switch {
	case errors.Is(err, inventory.ErrOutputInsideBundle),
		errors.Is(err, inventory.ErrInvalidRelativePath):
		return policy.ExitInvalid
	default:
		return policy.ExitFail
	}
}
