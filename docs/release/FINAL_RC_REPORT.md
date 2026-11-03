# Final Release Candidate Engineering Report (`v0.1.0-rc.1`)

**Project:** AI Model Provenance Gate (`ai-model-provenance-gate`)  
**Binary Name:** `ai-model-provenance`  
**Release Candidate Version:** `0.1.0-rc.1`  
**Date:** `2026-10-31`  
**Final Verdict:** **`READY_FOR_RELEASE_CANDIDATE_WITH_LIMITATIONS`**

---

## 1. Executive Verdict & Rationale

**AI Model Provenance Gate `v0.1.0-rc.1`** has passed all local engineering, static analysis, race detection, vulnerability scanning, CycloneDX 1.7 official schema validation, OpenSSF Model Signing v1.0 offline conformance, clean-install smoke testing, and 10-scenario negative tampering verification gates.

The verdict is recorded as **`READY_FOR_RELEASE_CANDIDATE_WITH_LIMITATIONS`** (rather than unconditional `READY_FOR_RELEASE_CANDIDATE`) to preserve strict engineering honesty regarding three external/environment boundaries:
1. **Owner License & Push Authorization (`OWNER_APPROVAL_REQUIRED`):** `ai-model-provenance-gate/LICENSE` (`MIT License`) is present in the local workspace and packaged archives, but committing, tagging, and pushing to GitHub require explicit owner authorization.
2. **Host-Only Native Runtime Execution (`NOT_RUN` on non-host OS/Arch):** All 5 release archives (`darwin/arm64`, `darwin/amd64`, `linux/amd64`, `linux/arm64`, `windows/amd64`) were cross-compiled (`CGO_ENABLED=0`) and structurally verified via `file`, `tar`/`zip`, and `shasum -a 256`, while native runtime execution was performed on the local `darwin/arm64` host (Linux/Windows runtime execution requires CI runners).
3. **Live Keyless OIDC Signing Network Tests (`BLOCKED` locally):** `87/87` offline-capable tests in the official upstream `ossf/model-signing-spec` conformance suite passed (`80/80` default suite + `55/55` `test_verify.py`), while the `7` live Fulcio/Rekor OIDC token signing tests are honestly marked `BLOCKED` in local offline execution and wired to an optional `workflow_dispatch` job in `.github/workflows/ci.yml`.

---

## 2. Independent Verification of Prior Audit Findings (`AUD-01` .. `AUD-10`)

Every prior audit finding was re-verified against the actual source code and test suite:

| ID | Domain | Verification Evidence | Status |
|---|---|---|---|
| `AUD-01` | CycloneDX 1.7 SDK & Official Schema Validation | `github.com/CycloneDX/cyclonedx-go v0.12.0` (`SpecVersion1_7`) + `github.com/santhosh-tekuri/jsonschema/v6 v6.0.3` validating embedded official `bom-1.7.schema.json`, `bom-1.6.schema.json`, `spdx.schema.json`, and `jsf-0.82.schema.json` (`13/13` tests in `internal/bom`). | `PASS` |
| `AUD-02` | CycloneDX Root Dependency Graph & SPDX Normalization | `internal/bom/bom.go` normalizes SPDX licenses (`apache-2.0` -> `Apache-2.0`) and populates/validates root `dependencies` across weights, configs, tokenizers, adapters, and base models. | `PASS` |
| `AUD-03` | OpenSSF Model Signing v1.0 Upstream Conformance | `internal/signing/signing.go`, `internal/signing/sigstore_verify.go`, `internal/oms/oms.go`, and `internal/cli/oms_conformance.go` pass **80/80** default and **55/55** `test_verify.py` (**87/87** offline-capable) upstream `ossf/model-signing-spec` tests. | `PASS` |
| `AUD-04` | OMS Resource Path & Duplicate Digest Hardening | `internal/oms/oms.go` rejects duplicate resource names, path traversal (`..`, leading `/`, `\`), and enforces 1-to-1 file correspondence with the bundle inventory. | `PASS` |
| `AUD-05` | LLM Release Gate 7-Boolean Trust Separation | `internal/evaluation/llmreleasegate/adapter.go` separates `ReportPresent`, `SchemaValid`, `GateStatusPass`, `BundleIDBound`, `SuiteDigestVerified`, `SignatureVerified`, and `TrustedSignerVerified`. | `PASS` |
| `AUD-06` | Post-Hoc `OPERATOR_ENDORSEMENT` Separation | Default `evidence bind-eval` (`--producer-role operator-endorser`) is classified as `OPERATOR_ENDORSEMENT` (`POST_HOC_OPERATOR`) and rejected by strict policy (`EVALUATION_POST_HOC_BINDING_REJECTED` -> `BLOCKED`, exit `3`). | `PASS` |
| `AUD-07` | Evaluator Context & Timestamp Binding | `EvaluationEvidencePredicate` binds and verifies `EvaluatorName`, `EvaluatorVersion`, `ExecutionMode`, `EvaluationTimestamp`, `ToolVersion`, `SuiteDigest`, and `DatasetDigest`. | `PASS` |
| `AUD-08` | SLSA v1.0 & v1.2 Build Provenance | `internal/provenance/provenance.go` verifies `https://slsa.dev/provenance/v1` and `https://slsa.dev/provenance/v1.2` with dedicated `provenance.trusted_signers`. | `PASS` |
| `AUD-09` | Policy Decision Modes & Exception Expiry | `internal/config/config.go` and `internal/policy/policy.go` enforce `strict`, `permissive`, and `audit` modes and reject expired RFC 3339 exceptions. | `PASS` |
| `AUD-10` | Filesystem Traversal, Hardlink, NFC & TOCTOU Guards | `internal/inventory/inventory.go` and `internal/inventory/hardlink_unix.go` pass `21/21` security tests rejecting symlinks, hardlinks (`nlink > 1`), FIFOs, non-UTF8/control characters, case collisions, NFC collisions, and mid-stream TOCTOU mutations. | `PASS` |

---

## 3. Phase 1 Quality Gate Summary

Full verbatim output is recorded in [`artifacts/release-candidate/quality-gate-results.txt`](../../artifacts/release-candidate/quality-gate-results.txt):

| Check | Command | Result |
|---|---|---|
| Formatting | `gofmt -s -l .` | `PASS` (0 unformatted files) |
| Static Vet | `go vet ./...` | `PASS` (exit `0`) |
| Unit & Integration Tests | `go test -count=1 ./...` | `PASS` (9 test packages, exit `0`) |
| Race Detector Suite | `go test -count=1 -race ./...` | `PASS` (9 test packages, exit `0`) |
| Linter | `golangci-lint run ./...` | `PASS` (`0 issues`) |
| Vulnerability Check | `govulncheck ./...` | `PASS` (`No vulnerabilities found`) |
| Module Integrity | `go mod verify` | `PASS` (`all modules verified`) |
| Shell Script Linter | `shellcheck scripts/*.sh` | `PASS` (exit `0`) |
| Composite Gate | `make check` | `PASS` (exit `0`) |

---

## 4. Release Candidate Packaging Matrix (`v0.1.0-rc.1`)

All release candidate artifacts are stored in [`artifacts/release-candidate/v0.1.0-rc.1/`](../../artifacts/release-candidate/v0.1.0-rc.1/) and indexed in [`manifest.json`](../../artifacts/release-candidate/v0.1.0-rc.1/manifest.json):

| Platform | Archive Name | Archive SHA-256 | Binary Size | File Header Verification | Runtime Smoke Status |
|---|---|---|---|---|---|
| `darwin/arm64` | `ai-model-provenance_0.1.0-rc.1_darwin_arm64.tar.gz` | `3867f7bc8dd05ee77f92c43e1fb8442068c06aa93e0eaaaec3b8f1e303adb498` | `7,379,858 B` | `Mach-O 64-bit executable arm64` | `PASS` (native host execution verified) |
| `darwin/amd64` | `ai-model-provenance_0.1.0-rc.1_darwin_amd64.tar.gz` | `dfb9d7df4483142bc78f099ff7f269903ad011dcd72fb1729aa50104f6fb1957` | `7,912,416 B` | `Mach-O 64-bit executable x86_64` | `NOT_RUN` (cross-compiled; verified via header) |
| `linux/amd64` | `ai-model-provenance_0.1.0-rc.1_linux_amd64.tar.gz` | `34cabc6cbace62ace8167628ddcf73bdc8f452e33da4955af1daa1c6c636b433` | `7,774,368 B` | `ELF 64-bit LSB executable, x86-64, statically linked, stripped` | `NOT_RUN` (cross-compiled; verified via header) |
| `linux/arm64` | `ai-model-provenance_0.1.0-rc.1_linux_arm64.tar.gz` | `1b47746bc1b6bc845fc94124dbf62a4db28858a2161a1ffebd1d9ab1a2cd28ca` | `7,274,656 B` | `ELF 64-bit LSB executable, ARM aarch64, statically linked, stripped` | `NOT_RUN` (cross-compiled; verified via header) |
| `windows/amd64` | `ai-model-provenance_0.1.0-rc.1_windows_amd64.zip` | `d795e49850d9346ba66094bcad6270805ee3c54193fd04760f83037699fe8e50` | `7,966,208 B` | `PE32+ executable (console) x86-64, for MS Windows` | `NOT_RUN` (cross-compiled; verified via header) |

---

## 5. Clean Installation Smoke Test & Final E2E Demonstration Results

Executed from the packaged archive `ai-model-provenance_0.1.0-rc.1_darwin_arm64.tar.gz` extracted into an isolated temporary directory outside the repository. Full logs and artifacts are preserved in [`artifacts/release-candidate/v0.1.0-rc.1/clean-install-smoke-test/`](../../artifacts/release-candidate/v0.1.0-rc.1/clean-install-smoke-test/):

### Positive Lifecycle (Steps 1–12)
- **Archive Checksum Verification:** `ai-model-provenance_0.1.0-rc.1_darwin_arm64.tar.gz: OK`
- **Subcommand & Alias Help UX:** `19/19` `--help` invocations exited `0`.
- **Bundle Inspection (`inspect`):** `GATE_STATUS=PASS`, `BUNDLE_ID=sha256:2c5f9757efe8c44d095cb3969c166928ccfaefc7cf80fc2b1ef8639505347adb` (`8` files, `1,104` bytes).
- **CycloneDX 1.7 Generation & Validation (`bom generate` / `bom validate`):** `STATUS=PASS`, `SPEC=1.7`, `BOM_DIGEST=sha256:0905e056c13a1df219d5d4decd5283ac3897ef60df618f9cf57d085b135e8a32`.
- **OMS v1.0 Signing & Verification (`oms sign` / `oms verify`):** `STATUS=VERIFIED`, `FILES=8`.
- **LLM Release Gate Binding & Verification (`evidence bind-eval` / `evidence verify`):** `STATUS=PASS`, `BINDING=MATCHED`, `TRUST=VERIFIED_TRUSTED`, `GATE_STATUS=PASS`.
- **Release Qualification Gate (`gate evaluate`):** `GATE_STATUS=PASS`, `EXIT_CODE=0`, emitted signed `attestation.json`.
- **Pre-Deployment Composition Verification (`release verify`):** `GATE_STATUS=PASS`, `EXIT_CODE=0`, `COMPOSITION_ID=sha256:928cfc44decf9e6d0b63e1c8bda069aed0030b7601a173495940008514f3df6a`.

### Negative & Tampering Scenarios (`Neg-01` .. `Neg-10`)

| Scenario ID | Tampering / Policy Violation Scenario | Expected Exit | Observed Exit | Reason Code Verified | Result |
|---|---|---|---|---|---|
| `Neg-01` | Stealthy byte flip inside `model.safetensors` tensor payload | `1` (`FAIL`) | `1` | `DEPLOYMENT_ARTIFACT_TAMPERED` | `PASS` |
| `Neg-02` | Modified `tokenizer.json` vocabulary in deployment bundle | `1` (`FAIL`) | `1` | `DEPLOYMENT_ARTIFACT_TAMPERED` | `PASS` |
| `Neg-03` | Stealthy byte flip inside `adapter_model.safetensors` payload | `1` (`FAIL`) | `1` | `DEPLOYMENT_ARTIFACT_TAMPERED` | `PASS` |
| `Neg-04` | Modified LoRA rank (`r: 8 -> 64`) in `adapter_config.json` | `1` (`FAIL`) | `1` | `DEPLOYMENT_ARTIFACT_TAMPERED` | `PASS` |
| `Neg-05` | Modified `report.json` (`runId`) after evaluation signing | `1` (`FAIL`) | `1` | `EVALUATION_EVIDENCE_TAMPERED` | `PASS` |
| `Neg-06` | Evaluation report bound to a different `model_bundle_id` | `1` (`FAIL`) | `1` | `EVALUATION_ARTIFACT_MISMATCH` | `PASS` |
| `Neg-07` | Unsigned evaluation report under strict policy | `3` (`BLOCKED`) | `3` | `EVALUATION_EVIDENCE_UNTRUSTED` | `PASS` |
| `Neg-08` | Default post-hoc operator endorsement (`operator-endorser`) under strict policy | `3` (`BLOCKED`) | `3` | `EVALUATION_POST_HOC_BINDING_REJECTED` | `PASS` |
| `Neg-09` | OMS signature signed by untrusted/rogue key | `1` (`FAIL`) | `1` | `OMS_SIGNATURE_INVALID` | `PASS` |
| `Neg-10` | Mutable runtime container tag (`:latest`) in `deployment.yaml` | `1` (`FAIL`) | `1` | `DEPLOYMENT_RUNTIME_IMAGE_MUTABLE` | `PASS` |

---

## 6. Sibling Repository Isolation & Safety Verification

- `llm-release-gate`: Untouched (`git status` clean).
- `ai-platform-conformance-kit`: Untouched (`git status` clean).
- No commits, tags, pushes, or GitHub Releases were executed.
