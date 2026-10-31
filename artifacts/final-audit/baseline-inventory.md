# Read-Only Baseline Inspection Inventory (`artifacts/final-audit/baseline-inventory.md`)

**Timestamp:** `2026-10-31T02:03:00+03:00`  
**Workspace:** `/Users/enes/GitHub/ai-model-provenance-gate`

---

## 1. Git Status, Branch, and Remotes

- **Branch:** `main` (uncommitted initial workspace tree; zero remote pushes or tags)
- **Remotes:** None configured (`git remote -v` empty)
- **Sibling Isolation Check:**
  - `/Users/enes/GitHub/llm-release-gate`: clean (`git status -s` empty)
  - `/Users/enes/GitHub/ai-platform-conformance-kit`: clean (`git status -s` empty)

---

## 2. Go Version and Module Graph (`go.mod` / `go.sum`)

- **Go Version:** `go1.27.3 darwin/arm64`
- **Module Path:** `github.com/devenes/ai-model-provenance-gate`
- **Direct Dependencies:**
  - `github.com/CycloneDX/cyclonedx-go v0.12.0`
  - `github.com/santhosh-tekuri/jsonschema/v6 v6.0.3`
  - `golang.org/x/text v0.42.0`
  - `gopkg.in/yaml.v3 v3.0.1`

---

## 3. Existing Packages, Schemas, Workflows, Scripts, and Artifacts

### Go Packages (`cmd/` & `internal/`)
- `cmd/ai-model-provenance/main.go`: CLI entry point.
- `internal/attestation`: in-toto Statement v1 release qualification attestation (`release-qualification/v1`).
- `internal/bom`: CycloneDX 1.7 / 1.6 AI/ML-BOM generator and official JSON Schema validator.
- `internal/bundle`: Model bundle inspector, role classifier, and deterministic identity synthesis.
- `internal/cli`: CLI subcommands (`inspect`, `bom`, `oms`, `evidence`, `gate`, `release`, `keygen`, `version`, and OMS conformance interfaces `sign` / `verify`).
- `internal/config`: Strict YAML configuration loader (`policy/v1`, `deployment-composition/v1`).
- `internal/deployment`: Deployment composition verifier and `deployment-composition/v1` digest engine.
- `internal/digest`: Streaming SHA-256 engine with pre/post `fstat` TOCTOU detection.
- `internal/evaluation/llmreleasegate`: Read-only `llm-release-gate.report/v1` adapter and `evaluation-evidence/v1` DSSE verifier.
- `internal/evidence`: Evidence collector for gate evaluation and release verification.
- `internal/formats/huggingface`: Static Hugging Face `config.json`, `tokenizer.json`, and `chat_template` inspector.
- `internal/formats/peft`: Static PEFT/LoRA `adapter_config.json` inspector.
- `internal/formats/safetensors`: Static `.safetensors` binary header and `model.safetensors.index.json` inspector.
- `internal/identity`: RFC 8785 (JCS) canonical JSON serializer and `bundle-identity/v1` / `deployment-composition/v1` identity calculator.
- `internal/inventory`: Safe filesystem walker rejecting symlinks, special files, path traversal, and NFC collisions.
- `internal/manifest`: Canonical bundle manifest structure.
- `internal/oms`: OpenSSF Model Signing v1.0 (`https://model_signing/signature/v1.0`) native and external CLI verifier.
- `internal/policy`: Fail-closed policy engine (`strict`, `audit`, `permissive`).
- `internal/provenance`: SLSA v1.0 / v1.1 / v1.2 build provenance verifier.
- `internal/report`: JSON and Markdown gate report generator with secret redaction guard.
- `internal/scanner`: Optional ModelScan adapter and unsafe format detector.
- `internal/signing`: Multi-algorithm key/certificate/Sigstore v0.3 DSSE signer and verifier.
- `internal/testdata`: Deterministic synthetic model bundle generator for unit and E2E tests.
- `internal/verification`: Signer trust rule matching (`key_id`, `public_key_sha256`, `subject`, `issuer`, `san_uri`).
- `internal/version`: Build-time version metadata.

### Schemas (`schemas/`)
- `schemas/cyclonedx/bom-1.7.schema.json`, `bom-1.6.schema.json`, `spdx.schema.json`, `jsf-0.82.schema.json`, `cryptography-defs.schema.json`
- `schemas/policy/policy.schema.json`
- `schemas/attestations/release-qualification.schema.json`
- `schemas/reports/gate-report.schema.json`, `cyclonedx-mlbom-profile.schema.json`

### Workflows & Scripts
- `.github/workflows/ci.yml`, `.github/workflows/release.yml`
- `scripts/run-e2e-demo.sh`, `scripts/package-release.sh`

### Existing Artifacts Preserved
- `artifacts/baseline/`
- `artifacts/final-validation/`
- `artifacts/audit/`
