# Dependency and Tooling Inventory

**Generated:** 2026-10-31T00:10:00+03:00  
**Phase:** Phase 0 — Environment and Baseline Inspection

---

## 1. Go Module & Runtime Dependencies

To maintain portfolio consistency with `llm-release-gate` and `ai-platform-conformance-kit`, minimize supply-chain attack surface, and guarantee offline build reproducibility on macOS Apple Silicon (`darwin/arm64`) and Linux (`linux/amd64`, `linux/arm64`):

| Dependency | Version | License | Purpose |
|---|---|---|---|
| Go Standard Library (`go 1.27.3`) | `1.27.3` | BSD-3-Clause | Streaming SHA-256 (`crypto/sha256`), asymmetric cryptography (`crypto/ed25519`, `crypto/ecdsa`, `crypto/rsa`, `crypto/x509`, `encoding/pem`), JSON parsing/serialization (`encoding/json`), safe filesystem traversal (`os`, `io/fs`, `path/filepath`), subprocess execution (`os/exec`), CLI flag parsing (`flag`). |
| `gopkg.in/yaml.v3` | `v3.0.1` | MIT / Apache-2.0 | Strict YAML decoding (`KnownFields(true)`) for release policies (`policy.yaml`) and deployment descriptors (`deployment.yaml`). |

### Rationale for Zero-CGO & Minimal Dependency Surface
- **No custom cryptography:** All cryptographic hashing (`SHA-256`) and digital signature operations (`Ed25519`, `ECDSA P-256/P-384 with SHA-256/SHA-384`, `RSA-PSS / PKCS#1v15 with SHA-256`) use the vetted Go standard library (`crypto/*`) and standard RFC 8032 / FIPS 186-5 / PKIX (`x509.ParsePKIXPublicKey`, `x509.ParsePKCS8PrivateKey`) primitives inside the standard DSSE v1.0 Pre-Authentication Encoding (`PAE`) envelope specification.
- **No external runtime dependencies:** No Python runtime, model runtime, container daemon, or cloud credentials are required to run `ai-model-provenance-gate`.

---

## 2. External CLI Tool Availability & Adapter Strategy

| External Tool | Installed Locally? | Adapter Strategy in `ai-model-provenance-gate` |
|---|---|---|
| **OpenSSF Model Signing (`model_signing` CLI)** | Not installed (`NOT_FOUND`) | 1. **Native OMS v1.0 DSSE / Sigstore Bundle Verifier & Signer:** Parses and verifies OpenSSF Model Signing v1.0 (`https://model_signing/signature/v1.0` and `https://model_signing/digests/v0.1`) in-toto v1 Statements wrapped in either raw DSSE envelopes or Sigstore v0.2/v0.3 Bundles (`.sig` / `.sigstore.json`) using Go's standard `crypto/ed25519`, `crypto/ecdsa`, and `crypto/x509` libraries.<br>2. **Safe Subprocess CLI Adapter (`model_signing`):** Also supports invoking the external `model_signing` CLI (`model_signing verify key ...`) with explicit argument arrays, timeouts, and output capture when configured (`mode: cli`). Reports `BLOCKED` (never fabricated `PASS`) if `mode: cli` is explicitly requested and the binary is absent. |
| **Sigstore Cosign (`cosign` CLI)** | Not installed (`NOT_FOUND`) | 1. **Native Offline Key-Based DSSE Attestation Signer & Verifier:** Signs and verifies in-toto Statement v1 release qualification attestations (`application/vnd.in-toto+json`) using standard PEM-encoded PKIX public keys and PKCS#8 private keys (identical to `cosign` / DSSE PAE format).<br>2. **Optional `cosign` Subprocess Adapter:** Supports invoking `cosign verify-blob` / `cosign verify-attestation` when requested and installed; fails closed (`BLOCKED`) if requested when unavailable. |
| **Protect AI ModelScan (`modelscan` CLI)** | Not installed (`NOT_FOUND`) | 1. **Report Ingestion Adapter:** Parses and validates ModelScan JSON output reports (`modelscan -p <bundle> -r json`), enforcing severity thresholds and checking scanned/skipped file correspondence against the model bundle inventory.<br>2. **Optional Live Subprocess Adapter:** Can invoke `modelscan` safely if present; if policy sets `scanner.required: true` and neither a valid bound scan report nor the `modelscan` binary is available, the gate fails closed with `BLOCKED`. |
| **CycloneDX Validator** | `cyclonedx` CLI not installed | Built-in strict CycloneDX 1.6 / 1.7 JSON schema validator (`schemas/reports/cyclonedx-mlbom-profile.schema.json` + programmatic structural and enum validation against official CycloneDX 1.6/1.7 ML-BOM specification rules). |
| **Linters & Vulnerability Scanners** | `golangci-lint 2.14.0` & `govulncheck v1.9.0` installed | Executed in local validation and CI (`make lint`, `make vulncheck`). |
