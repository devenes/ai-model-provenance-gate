# AI Model Provenance Gate `v0.1.0-rc.1` — Release Notes

**Release Candidate:** `v0.1.0-rc.1`  
**Release Date:** `2026-10-31`  
**Go Toolchain:** `go1.27.3`

---

## Core Product Guarantee

> **The exact model artifact that passed trusted evaluation, was signed by an authorized producer, and received release qualification approval must be the exact artifact verified for deployment.**

---

## Highlights in `v0.1.0-rc.1`

### 1. Deterministic Model Bundle Identity (`bundle-identity/v1`)
- Computes an immutable `sha256:<64-hex>` identity over local model directories (`config.json`, `.safetensors` shards, `model.safetensors.index.json`, `tokenizer.json`, `chat_template.jinja`, and PEFT/LoRA `adapter_config.json` / `adapter_model.safetensors`) using RFC 8785 JSON Canonicalization Scheme (JCS).
- Streams arbitrary-sized weight files in 4 MiB buffers with pre-read and post-read `os.Stat` TOCTOU mutation guards.
- Enforces `os.Lstat` traversal, rejecting symlinks, hardlinks (`nlink > 1`), FIFOs, sockets, device files, relative traversal paths, non-UTF8/control characters, case-folding collisions, and Unicode NFC normalization collisions.

### 2. CycloneDX 1.7 & 1.6 AI/ML-BOM (`github.com/CycloneDX/cyclonedx-go v0.12.0`)
- Emits standards-compliant CycloneDX `1.7` (default) and `1.6` AI/ML-BOM documents (`machine-learning-model` root component, `modelCard`, component hashes, SPDX license normalization, and complete root `dependencies` graph).
- Validates all generated and ingested BOMs offline against the embedded official CycloneDX `bom-1.7.schema.json`, `bom-1.6.schema.json`, `spdx.schema.json`, and `jsf-0.82.schema.json` schemas.
- Separates `observed` facts from `declared_unverified` configuration claims.

### 3. OpenSSF Model Signing v1.0 Interoperability
- Signs and verifies OpenSSF Model Signing `v1.0` (`https://model_signing/signature/v1.0`) and `v0.1` (`https://model_signing/digests/v0.1`) DSSE envelopes and Sigstore v0.3 bundles.
- Supports Ed25519, ECDSA (`P-256`, `P-384`, `P-521`), RSA (`PKCS#1v15`, `RSA-PSS`), X.509 certificate chains (`id-kp-codeSigning`), and offline Sigstore keyless verification (Fulcio leaf certificate validity window, OIDC SAN + issuer oid `1.3.6.1.4.1.57264.1.8`, Rekor v1 SET signature & checkpoint).
- Validated against the official upstream `ossf/model-signing-spec` conformance suite (**80/80** default offline tests and **55/55** `test_verify.py` verification bundles; **87/87** total offline-capable cases).

### 4. LLM Release Gate Evidence Binding & Producer Role Separation
- Consumes `llm-release-gate.report/v1` reports and evaluates 7 independent trust flags (`ReportPresent`, `SchemaValid`, `GateStatusPass`, `BundleIDBound`, `SuiteDigestVerified`, `SignatureVerified`, `TrustedSignerVerified`).
- Distinguishes automated CI `TRUSTED_SIGNED_EVIDENCE` (`--producer-role trusted-evaluator`) from post-hoc `OPERATOR_ENDORSEMENT` (`--producer-role operator-endorser`), blocking unauthorized post-hoc endorsements under strict policy (`EVALUATION_POST_HOC_BINDING_REJECTED`).

### 5. Signed Release Qualification Attestation & Pre-Deployment Verification
- Emits signed `https://in-toto.io/Statement/v1` DSSE attestations (`release-qualification/v1`) and verifies upstream SLSA v1.0 / v1.2 build provenance.
- Verifies `deployment-composition/v1` descriptors (`release verify` / `deploy verify`) binding the approved `model_bundle_id`, immutable OCI runtime image digest (`@sha256:...`), serving configuration digest, and allowed LoRA adapters prior to serving.

---

## Supported Platforms & Archives

| OS | Architecture | Archive | Binary |
|---|---|---|---|
| macOS | Apple Silicon (`arm64`) | `ai-model-provenance_0.1.0-rc.1_darwin_arm64.tar.gz` | `ai-model-provenance` |
| macOS | Intel (`amd64`) | `ai-model-provenance_0.1.0-rc.1_darwin_amd64.tar.gz` | `ai-model-provenance` |
| Linux | x86_64 (`amd64`) | `ai-model-provenance_0.1.0-rc.1_linux_amd64.tar.gz` | `ai-model-provenance` |
| Linux | ARM64 (`arm64`) | `ai-model-provenance_0.1.0-rc.1_linux_arm64.tar.gz` | `ai-model-provenance` |
| Windows | x86_64 (`amd64`) | `ai-model-provenance_0.1.0-rc.1_windows_amd64.zip` | `ai-model-provenance.exe` |

Verify archive integrity before installation:

```bash
shasum -a 256 -c checksums.txt
```
