# Phase 0 — Release Candidate Baseline Inspection (`v0.1.0-rc.1`)

**Inspection Timestamp:** `2026-10-31T08:28:00+03:00`  
**Repository:** `ai-model-provenance-gate`  
**Target Release Candidate:** `v0.1.0-rc.1`

---

## 1. Environment & Git State Snapshot

| Attribute | Observed Value |
|---|---|
| Host OS / Architecture | `Darwin arm64` (`Darwin Kernel Version 25.4.0`, Apple M1, macOS 26.4 `25E246`) |
| Go Toolchain | `go version go1.27.3 darwin/arm64` |
| Static Analysis Tools | `golangci-lint 2.11.4`, `govulncheck v1.1.4`, `shellcheck 0.11.0` |
| Current Branch | `main` (`origin/main`) |
| Head Commit | `eafb5e9 Initial commit` (contains `.gitattributes`) |
| Git Remote (`origin`) | `https://github.com/devenes/ai-model-provenance-gate.git` |
| Existing Git Tags | None (`git tag -l` returns empty) |

---

## 2. Mandatory Baseline Verification Answers

### 1. Is the working tree clean?
- **No (by design under safety constraints).** `git log` contains only the initial repository commit (`eafb5e9 Initial commit` with `.gitattributes`). Under the non-negotiable safety rules (*"Do NOT create commits unless explicitly asked"* and *"Do NOT push to GitHub"*), all implementation packages, tests, documentation, workflows, and verification artifacts reside in the local working tree awaiting explicit owner authorization to commit and tag.
- No stray compiled binaries (`bin/`, `dist/`), coverage profiles (`coverage.out`), or private keys (`*.key`, `*.pem`) remain after build/clean steps.

### 2. Are there uncommitted files?
- **Yes.** All project files (`go.mod`, `go.sum`, `Makefile`, `README.md`, `CHANGELOG.md`, `LICENSE`, `.gitignore`, `.golangci.yml`, `.github/workflows/`, `cmd/`, `internal/`, `pkg/`, `configs/`, `examples/`, `schemas/`, `scripts/`, `testdata/`, `docs/`, and `artifacts/`) are currently untracked in the working tree on `main`.

### 3. Are local and remote branches synchronized?
- **Yes.** Local `main` points to `eafb5e9`, identical to `origin/main` (`0` commits ahead, `0` commits behind). No unpushed commits exist.

### 4. Does a `v0.1.0` or `v0.1.0-rc.1` tag already exist?
- **No.** Neither `v0.1.0` nor `v0.1.0-rc.1` exists locally or on the remote.

### 5. Does `LICENSE` exist?
- **Yes (in local working tree; owner approval required prior to public push).** `ai-model-provenance-gate/LICENSE` is present in the workspace and contains the standard `MIT License` (`Copyright (c) 2026 Enes Turan`), matching the sibling repository `llm-release-gate/LICENSE`. Because it is currently uncommitted, its publication status is tracked as `OWNER_APPROVAL_REQUIRED` in `docs/release/OPEN_SOURCE_READINESS.md` before any public GitHub push or release.

### 6. Are repository URLs, module names, and binary names consistent?
- **Yes.**
  - **Go Module Path:** `github.com/devenes/ai-model-provenance-gate` (`go.mod`, `Makefile`, `scripts/package-release.sh`, all internal imports).
  - **Repository Name & Remote URL:** `ai-model-provenance-gate` (`https://github.com/devenes/ai-model-provenance-gate`).
  - **CLI Binary Name:** `ai-model-provenance` (`cmd/ai-model-provenance/main.go`, `Makefile`, `scripts/package-release.sh`, `.github/workflows/ci.yml`, `.github/workflows/release.yml`, `README.md`).
  - **Version Metadata:** Updated to `0.1.0-rc.1` across `internal/version/version.go`, `Makefile`, `scripts/package-release.sh`, `CHANGELOG.md`, and release candidate artifacts.

### 7. Are temporary artifacts, test keys, or build outputs tracked in Git?
- **No.** `.gitignore` explicitly blocks:
  - `/bin/`, `/dist/`, `/ai-model-provenance`, `/ai-model-provenance-gate`
  - `coverage.out`, `*.test`
  - `*.key`, `*.pem` (with `!*example*.pub` exception for public verification keys only)
  - `.DS_Store`
- All ephemeral private keys used in unit tests and E2E scripts are generated inside temporary directories (`t.TempDir()` or `mktemp -d`) and cleaned up on exit.

### 8. Are all `AUD-01` through `AUD-10` remediations present in actual source code?
- **Yes — independently verified against actual source code:**

| Finding ID | Remediation Verification in Source Code | Status |
|---|---|---|
| `AUD-01` | `go.mod` uses `github.com/CycloneDX/cyclonedx-go v0.12.0` (`SpecVersion1_7`); `internal/bom/bom.go` embeds and validates against official `bom-1.7.schema.json`, `bom-1.6.schema.json`, `spdx.schema.json`, and `jsf-0.82.schema.json` using `github.com/santhosh-tekuri/jsonschema/v6 v6.0.3`. | `VERIFIED_CLOSED` |
| `AUD-02` | `internal/bom/bom.go` populates the root `dependencies` graph (`modelRootRef` -> `weightsGroupRef`, `configGroupRef`, `tokenizerGroupRef`, `adapterGroupRef`, and base model ref) and validates node completeness in `ValidateBytes`. | `VERIFIED_CLOSED` |
| `AUD-03` | `internal/signing/signing.go`, `internal/signing/sigstore_verify.go`, `internal/oms/oms.go`, and `internal/cli/oms_conformance.go` implement multi-curve ECDSA (`P-256`, `P-384`, `P-521`), Ed25519, RSA (`PKCS#1v15` & `RSA-PSS`), X.509 certificate chain verification (`id-kp-codeSigning`), offline Sigstore Bundle v0.3 keyless verification (Fulcio leaf cert validity window, OIDC SAN + issuer oid `1.3.6.1.4.1.57264.1.8`, Rekor v1 SET signature + checkpoint), and legacy `v0.2.0` PAE compatibility. Passed **80/80** default and **55/55** `test_verify.py` (**87/87** total offline-capable) upstream `ossf/model-signing-spec` conformance tests. | `VERIFIED_CLOSED` |
| `AUD-04` | `internal/oms/oms.go` rejects duplicate resource names, relative path traversal (`..`, leading `/`, Windows separators), symlink/FIFO/device entries, and enforces strict 1-to-1 file set and SHA-256 digest correspondence with the bundle inventory. | `VERIFIED_CLOSED` |
| `AUD-05` | `internal/evaluation/llmreleasegate/adapter.go` separates 7 granular boolean trust flags (`ReportPresent`, `SchemaValid`, `GateStatusPass`, `BundleIDBound`, `SuiteDigestVerified`, `SignatureVerified`, `TrustedSignerVerified`) and checks `MaxAgeHours`, `ExpectedSuiteDigest`, and `ExpectedDatasetDigest`. | `VERIFIED_CLOSED` |
| `AUD-06` | `internal/evaluation/llmreleasegate/adapter.go` and `internal/cli/cli.go` classify default `evidence bind-eval` (`--producer-role operator-endorser`) as `OPERATOR_ENDORSEMENT` (`POST_HOC_OPERATOR`) and reject it under `require_trusted_evidence: true` (`EVALUATION_POST_HOC_BINDING_REJECTED` -> `BLOCKED`) unless `allow_operator_endorsement: true` is explicitly configured in policy. | `VERIFIED_CLOSED` |
| `AUD-07` | `EvaluationEvidencePredicate` in `internal/evaluation/llmreleasegate/adapter.go` binds `EvaluatorName`, `EvaluatorVersion`, `ExecutionMode`, `EvaluationTimestamp`, `ToolVersion`, and `PromptConfigDigest` and cross-verifies all fields against the raw evaluation report during verification. | `VERIFIED_CLOSED` |
| `AUD-08` | `internal/provenance/provenance.go` supports both SLSA v1.0 (`https://slsa.dev/provenance/v1`) and SLSA v1.2 (`https://slsa.dev/provenance/v1.2`), keeping SLSA build provenance strictly distinct from `release-qualification/v1`. | `VERIFIED_CLOSED` |
| `AUD-09` | `internal/config/config.go` and `internal/policy/policy.go` implement `strict`, `permissive`, and `audit` decision modes, enforce mandatory RFC 3339 exception `expires_at` timestamps in strict mode, reject expired exceptions, and enforce `require_immutable_image`, `allowed_registries`, `expected_serving_config_digest`, and `allowed_adapters`. | `VERIFIED_CLOSED` |
| `AUD-10` | `internal/inventory/inventory.go` and `internal/inventory/hardlink_unix.go` enforce `os.Lstat`, reject symlinks, hardlinks (`nlink > 1`), FIFOs, sockets, device nodes, traversal paths, non-UTF8/control characters, case-folding collisions, NFC normalization collisions, and post-read TOCTOU mutations. | `VERIFIED_CLOSED` |

---

## 3. Sibling Repository Isolation Check

- `llm-release-gate`: Inspected read-only (`git status` unmodified).
- `ai-platform-conformance-kit`: Untouched (`git status` unmodified).
