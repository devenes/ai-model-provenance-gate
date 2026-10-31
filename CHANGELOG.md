# Changelog

All notable changes to **AI Model Provenance Gate** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-10-31

First stable release of **AI Model Provenance Gate** (`v0.1.0`), promoted from `0.1.0-rc.1` following full security audit remediation (`AUD-01`..`AUD-10`), CycloneDX 1.7 official schema validation, OpenSSF Model Signing v1.0 upstream conformance verification (`80/80` default suite, `55/55` `test_verify.py`, `87/87` offline-capable cases), and clean-install end-to-end tampering validation under the MIT License.

## [0.1.0-rc.1] - 2026-10-31

### Added
- **Deterministic Model Bundle Identity (`bundle-identity/v1`)**:
  - Streaming SHA-256 hashing (`internal/digest`) with 4 MiB bounded buffers and pre/post-read `os.Stat` TOCTOU mutation detection.
  - Safe filesystem inventory (`internal/inventory`) using `os.Lstat`, rejecting symlinks, hardlinks (`nlink > 1`), FIFOs, sockets, device files, relative traversal paths, non-UTF8/control characters, case-folding collisions, and Unicode NFC normalization collisions.
  - Static Safetensors binary header parser (`internal/formats/safetensors`), Hugging Face `config.json` / `tokenizer.json` / `model.safetensors.index.json` cross-checker (`internal/formats/huggingface`), and PEFT/LoRA `adapter_config.json` provenance classifier (`internal/formats/peft`).
  - RFC 8785 JSON Canonicalization Scheme (JCS) serializer (`pkg/canonicaljson`) producing deterministic `sha256:<64-hex>` bundle IDs.
- **CycloneDX 1.7 & 1.6 AI/ML-BOM (`internal/bom`)**:
  - Upgraded to `github.com/CycloneDX/cyclonedx-go v0.12.0` (`SpecVersion1_7` default, `SpecVersion1_6` supported).
  - Embedded official CycloneDX `bom-1.7.schema.json`, `bom-1.6.schema.json`, `spdx.schema.json`, and `jsf-0.82.schema.json` validated via `github.com/santhosh-tekuri/jsonschema/v6 v6.0.3`.
  - Added SPDX license normalization, complete root `dependencies` graph generation/validation, and `observed` vs `declared_unverified` metadata provenance properties.
- **OpenSSF Model Signing v1.0 Interoperability (`internal/oms`, `internal/signing`)**:
  - Native Go DSSE and Sigstore Bundle `v0.3` signing and verification for `https://model_signing/signature/v1.0` and `https://model_signing/digests/v0.1`.
  - Support for Ed25519, ECDSA (`P-256`, `P-384`, `P-521`), RSA (`PKCS#1v15`, `RSA-PSS`), X.509 certificate chains (`id-kp-codeSigning`), and offline Sigstore keyless verification (Fulcio leaf certificate validity window, OIDC SAN + issuer oid `1.3.6.1.4.1.57264.1.8`, Rekor v1 SET signature & checkpoint).
  - Validated against the official upstream `ossf/model-signing-spec` conformance test suite (**80/80** default offline tests and **55/55** `test_verify.py` verification tests; **87/87** total offline-capable cases).
- **LLM Release Gate Evidence Adapter (`internal/evaluation/llmreleasegate`)**:
  - Ingests `llm-release-gate.report/v1` reports with 7 separate trust flags (`ReportPresent`, `SchemaValid`, `GateStatusPass`, `BundleIDBound`, `SuiteDigestVerified`, `SignatureVerified`, `TrustedSignerVerified`).
  - Enforces producer role separation between `TRUSTED_SIGNED_EVIDENCE` (`--producer-role trusted-evaluator`) and post-hoc `OPERATOR_ENDORSEMENT` (`--producer-role operator-endorser`), blocking unauthorized post-hoc bindings under strict policy (`EVALUATION_POST_HOC_BINDING_REJECTED`).
- **in-toto Release Qualification Attestation & SLSA v1.0/v1.2 Provenance (`internal/attestation`, `internal/provenance`)**:
  - Emits signed `https://in-toto.io/Statement/v1` DSSE envelopes with predicate `https://ai-model-provenance-gate.dev/attestation/release-qualification/v1`.
  - Verifies upstream SLSA v1.0 (`https://slsa.dev/provenance/v1`) and SLSA v1.2 (`https://slsa.dev/provenance/v1.2`) provenance with dedicated trusted signer separation.
- **Fail-Closed Policy Engine & Deployment Composition Verifier (`internal/policy`, `internal/deployment`)**:
  - Supports `strict`, `permissive`, and `audit` decision modes, mandatory RFC 3339 exception `expires_at` enforcement in strict mode, and deterministic exit codes (`0`..`4`).
  - Verifies `deployment-composition/v1` descriptors binding `model_bundle_id`, immutable `@sha256:...` OCI runtime images, `allowed_registries`, `serving_config_digest`, and `allowed_adapters`.
- **CLI User Experience & Release Engineering (`internal/cli`, `scripts/package-release.sh`)**:
  - Full `--help` support across all commands, subcommands, and aliases (`inspect`/`bundle`, `bom`, `oms`, `evidence`/`eval`, `gate`/`attest`, `release`/`deploy`, `keygen`, `version`).
  - Cross-platform release packaging (`darwin/arm64`, `darwin/amd64`, `linux/amd64`, `linux/arm64`, `windows/amd64`) with `checksums.txt`, `SHA256SUMS`, and `manifest.json`.
