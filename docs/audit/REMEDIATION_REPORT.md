# Remediation Report (`docs/audit/REMEDIATION_REPORT.md`)

**Project:** AI Model Provenance Gate (`ai-model-provenance-gate`)  
**Date:** `2026-10-31`

---

## 1. Detailed Code Remediations by Finding

### `AUD-01` & `AUD-02` — Official CycloneDX 1.7 Schema Validation & SDK Integration
- **Files Modified:**
  - [`go.mod`](../../go.mod)
  - [`internal/bom/schema_validator.go`](../../internal/bom/schema_validator.go)
  - [`internal/bom/bom.go`](../../internal/bom/bom.go)
  - [`internal/bom/bom_test.go`](../../internal/bom/bom_test.go)
  - [`internal/bom/schemas/`](../../internal/bom/schemas/) & [`schemas/cyclonedx/`](../../schemas/cyclonedx/)
- **Changes Made:**
  1. Added `github.com/CycloneDX/cyclonedx-go v0.12.0` and `github.com/santhosh-tekuri/jsonschema/v6 v6.0.3`.
  2. Embedded official `bom-1.7.schema.json`, `bom-1.6.schema.json`, `spdx.schema.json`, `jsf-0.82.schema.json`, and `cryptography-defs.schema.json`.
  3. Implemented `ValidateOfficialCycloneDXSchema` and `cyclonedx.NewBOMDecoder` round-trip verification inside `bom.Validate()`.
  4. Added `NormalizeSPDXLicense()` to map common case-insensitive SPDX identifiers in Hugging Face `config.json` to official SPDX case, and enforced full root `dependencies` graph coverage.
- **Verification:** `go test -v -race ./internal/bom/...` (`PASS`, 13/13 cases in [`artifacts/final-audit/cyclonedx-validation.json`](../../artifacts/final-audit/cyclonedx-validation.json)).

---

### `AUD-03` & `AUD-04` — OpenSSF Model Signing (OMS v1.0) Upstream Conformance
- **Files Modified:**
  - [`internal/signing/signing.go`](../../internal/signing/signing.go)
  - [`internal/signing/sigstore_verify.go`](../../internal/signing/sigstore_verify.go)
  - [`internal/signing/sigstore_trusted_root.json`](../../internal/signing/sigstore_trusted_root.json)
  - [`internal/signing/signing_test.go`](../../internal/signing/signing_test.go)
  - [`internal/verification/verification.go`](../../internal/verification/verification.go)
  - [`internal/oms/oms.go`](../../internal/oms/oms.go)
  - [`internal/cli/oms_conformance.go`](../../internal/cli/oms_conformance.go)
- **Changes Made:**
  1. Added ECDSA P-384 (`SHA-384`), ECDSA P-521 (`SHA-512`), and RSA PKCS#1v15 + PSS support.
  2. Implemented `SignCertificateBundle` and `VerifyCertificateBundle` with X.509 PKI chain verification at signing time and mandatory `id-kp-codeSigning` EKU enforcement.
  3. Implemented `VerifySigstoreBundle` for offline verification of keyless Sigstore v0.3 bundles against the embedded Sigstore Public Good trusted root (Fulcio chain, OIDC issuer OID, SAN identity, Rekor SET/checkpoint signature, and RFC 6962 Merkle inclusion proof).
  4. Implemented the upstream `ossf/model-signing-spec` CLI interface (`sign key`, `sign certificate`, `verify key`, `verify certificate`, `verify sigstore`).
- **Verification:** `80 passed, 0 failed` in default offline suite and `55/55 passed` in `test_verify.py` (`87/87` total offline-capable conformance cases passed; [`artifacts/final-audit/oms-conformance-report.md`](../../artifacts/final-audit/oms-conformance-report.md)).

---

### `AUD-05`, `AUD-06`, & `AUD-07` — Evaluation Evidence Trust Separation, Operator Endorsement, and Freshness
- **Files Modified:**
  - [`internal/evaluation/llmreleasegate/adapter.go`](../../internal/evaluation/llmreleasegate/adapter.go)
  - [`internal/evaluation/llmreleasegate/adapter_test.go`](../../internal/evaluation/llmreleasegate/adapter_test.go)
  - [`internal/config/config.go`](../../internal/config/config.go)
  - [`internal/cli/cli.go`](../../internal/cli/cli.go)
  - [`internal/cli/cli_test.go`](../../internal/cli/cli_test.go)
- **Changes Made:**
  1. Removed signer-role fallback in `internal/cli/cli.go` so OMS model signers can never satisfy `evaluation.trusted_signers`, `provenance.trusted_signers`, or `release.trusted_signers`.
  2. Added `AttestationKind` (`TRUSTED_EVALUATOR_ATTESTATION` vs. `OPERATOR_ENDORSEMENT`), `--producer-role` (`operator-endorser` default on `evidence bind-eval`), and bound `evaluation_timestamp`, `tool_version`, `evaluator_name`, `evaluator_version`, `execution_mode`, and `prompt_config_digest` into `EvaluationEvidencePredicate`.
  3. Added all 7 explicit trust flags to `EvaluationSummary` (`report_integrity_verified`, `report_authenticity_verified`, `producer_identity_verified`, `operator_endorsement_verified`, `artifact_binding_verified`, `execution_evidence_verified`, `suite_dataset_identity_verified`, `freshness_verified`).
  4. Enforced `max_age_hours`, `expected_suite_digest`, `expected_dataset_digest`, and strict rejection of unauthorized post-hoc operator endorsements (`ErrPostHocBindingRejected`).
- **Verification:** `go test -v -race ./internal/evaluation/llmreleasegate/...` (`PASS`, 13/13 cases in [`artifacts/final-audit/evaluation-trust-results.json`](../../artifacts/final-audit/evaluation-trust-results.json)).

---

### `AUD-08` & `AUD-09` — SLSA v1.2 Provenance & Policy Exception Expiration
- **Files Modified:**
  - [`internal/provenance/provenance.go`](../../internal/provenance/provenance.go), [`internal/provenance/provenance_test.go`](../../internal/provenance/provenance_test.go)
  - [`internal/policy/policy.go`](../../internal/policy/policy.go), [`internal/policy/policy_test.go`](../../internal/policy/policy_test.go)
  - [`schemas/policy/policy.schema.json`](../../schemas/policy/policy.schema.json)
- **Changes Made:**
  1. Enforced non-empty `buildDefinition.buildType` and `runDetails.builder.id` in `VerifyUpstreamProvenance`, and added `provenance_test.go`.
  2. Enforced RFC3339 validation and runtime UTC expiration checks on `PolicyException.ExpiresAt`, added `DecisionModeAudit = "audit"`, and added `policy_test.go`.
- **Verification:** `go test -v -race ./internal/provenance/... ./internal/policy/...` (`PASS`).

---

### `AUD-10` — Cross-Platform Path & Hard-Link Security
- **Files Modified:**
  - [`internal/inventory/inventory.go`](../../internal/inventory/inventory.go)
  - [`internal/inventory/hardlink_unix.go`](../../internal/inventory/hardlink_unix.go), [`internal/inventory/hardlink_other.go`](../../internal/inventory/hardlink_other.go)
  - [`internal/bundle/bundle_test.go`](../../internal/bundle/bundle_test.go)
- **Changes Made:**
  1. Rejected Windows drive prefixes (`:`), Windows reserved device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1`..`COM9`, `LPT1`..`LPT9`), and trailing spaces/dots in path segments.
  2. Rejected hard-linked files (`nlink > 1`, `ErrHardLinkRejected`) when `RejectSymlinks` is enabled.
- **Verification:** `go test -v -race ./internal/bundle/...` (`PASS`, 21/21 cases in [`artifacts/final-audit/filesystem-security-results.json`](../../artifacts/final-audit/filesystem-security-results.json)).
