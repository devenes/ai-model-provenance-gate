# LLM Release Gate Compatibility & Baseline Inspection Report

**Generated:** 2026-10-31T00:10:00+03:00  
**Phase:** Phase 0 — Environment and Baseline Inspection  
**Inspected Repository:** `llm-release-gate` (Strictly Read-Only)

---

## 1. Repository State Verification

- **Path:** `llm-release-gate`
- **Module:** `github.com/devenes/llm-release-gate` (`go 1.27.3`)
- **Report Schema Version:** `"llm-release-gate.report/v1"` (`llm-release-gate/schemas/report.schema.json`)
- **Candidate Config Schema Version:** `"llm-release-gate/v1"`, `kind: "CandidateConfig"` (`llm-release-gate/schemas/candidate.schema.json`)
- **Modification Status:** Untouched (`read-only` isolation maintained).

---

## 2. Inspected Schema Structure (`llm-release-gate.report/v1`)

From `llm-release-gate/schemas/report.schema.json` and `llm-release-gate/internal/result/result.go`:

### Top-Level Required Fields
- `schemaVersion`: Must equal `"llm-release-gate.report/v1"`
- `runId`: Non-empty string (e.g., `"run-4fc2a8fa4f816ae6"`)
- `timestamp`: RFC 3339 timestamp string
- `toolVersion`: Non-empty string (e.g., `"0.1.0"`)
- `suite`: `{ "name": string, "version": string, "path"?: string, "digest": "sha256:<64-hex>" }`
- `dataset`: `{ "path"?: string, "digest": "sha256:<64-hex>", "caseCount": int }`
- `graders`: Array of `{ "type": string, "version": string }`
- `candidate`: `{ "name": string, "version"?: string, "provider": string, "model": string, "endpoint"?: string, "environment"?: string, "digest"?: string, "metadata"?: map[string]string }`
- `execution`: `{ "mode": "native"|"ingested"|"not_run"|"comparison_only", "timeout": string, "concurrency": int, "repetitions": int, "warmupRequests": int, "environment"?: string }`
- `evaluator`: `{ "name": string, "version": string, "sourceTool"?: string, "sourceFormatVersion"?: string, "unmappedFields"?: []string }`
- `cases`: Array of per-case execution results
- `metrics`: Aggregate execution and assertion counts
- `gateStatus`: Enum `["PASS", "FAIL", "BLOCKED", "NOT_RUN"]`
- `evidenceQuality`: Enum `["COMPLETE", "LIMITED"]`
- `comparisonStatus`: Enum `["COMPARABLE", "NOT_COMPARABLE", "NOT_APPLICABLE"]`
- `exitCode`: Integer enum `[0, 1, 2, 3, 4]`
- `decisionReasons`: Array of `{ "code": string, "category": string, "severity": "error"|"warning"|"info", "message": string }`

---

## 3. Critical Findings on Artifact Identity & Evidence Authenticity

### Finding 1: No First-Class `model_bundle_id` Field Exists Today
- In `llm-release-gate.report/v1`, `candidate.digest` is the SHA-256 digest of the **candidate YAML configuration file** (`candidate.yaml`) or ingested Promptfoo JSON file—**not** a digest of the model weights, tokenizer, or model bundle directory.
- Top-level and nested objects in `schemas/report.schema.json` set `"additionalProperties": false`, EXCEPT `candidate.metadata` (`map[string]string` in Go, `"type": "object"` in JSON Schema).
- Existing fixtures in `llm-release-gate/examples/basic/baselines/approved.json` set:
  ```json
  "candidate": {
    "name": "customer-assistant-candidate-v1.1",
    "version": "1.1.0",
    "provider": "fake",
    "model": "fake-deterministic-v1",
    "environment": "local-ci",
    "digest": "sha256:96eef63b79a77e33b46dfaf4498e491fb0df4f46b63621bdcb259ee620d06c48",
    "metadata": {
      "adapter": "support-lora-v2"
    }
  }
  ```
- Consequently, an unmodified baseline fixture from `llm-release-gate` **does not contain a cryptographic model bundle identity**.

### Finding 2: Plain JSON Output Without Cryptographic Signatures
- `llm-release-gate` outputs plain JSON (`report.json`) and Markdown (`report.md`).
- As documented in `llm-release-gate/docs/security.md`, `llm-release-gate` does not sign `report.json` or emit DSSE/in-toto attestations.

---

## 4. Adapter Design & Binding Contract for `ai-model-provenance-gate`

To honor strict security guarantees without modifying `llm-release-gate`:

1. **Artifact Binding Resolution (`binding_status`):**
   - The `llmreleasegate` adapter inspects `candidate.metadata["model_bundle_id"]` (and optional `candidate.metadata["lora_adapter_bundle_id"]` / `candidate.metadata["base_model_bundle_id"]`).
   - If `candidate.metadata["model_bundle_id"]` is **absent or empty** (as in unmodified legacy `llm-release-gate` reports):
     - Binding status is `UNBOUND`.
     - The adapter **never** infers model identity from `candidate.name`, `candidate.model`, or `candidate.digest`.
     - Under strict policy (`require_artifact_binding: true`), release qualification returns `BLOCKED`.
   - If `candidate.metadata["model_bundle_id"]` is present:
     - If it matches the inspected Model Bundle Identity (`sha256:<64-hex>`), binding status is `MATCHED`.
     - If it differs from the inspected Model Bundle Identity, binding status is `MISMATCH`, and release qualification returns `FAIL`.

2. **Evidence Authenticity Resolution (`trust_status`):**
   - A plain JSON report (`report.json`) without a verified cryptographic signature or DSSE evaluation attestation has `trust_status: UNVERIFIED_LOCAL_JSON`.
   - Under strict policy (`require_trusted_evidence: true`), an unsigned `report.json` cannot pass release qualification (`BLOCKED`), even if `gateStatus == "PASS"` and `candidate.metadata["model_bundle_id"]` matches.
   - To satisfy `require_trusted_evidence: true`, the evaluation report must be accompanied by a verifiable DSSE signature/attestation (`--evaluation-signature` / `--evaluation-public-key` or trusted signer policy) proving that an authorized evaluator key signed the exact `report.json` digest (`sha256:<64-hex>`) and bound it to the model bundle.

3. **Evaluation Status Mapping:**
   - `gateStatus == "PASS"` + `evidenceQuality == "COMPLETE"` + `exitCode == 0` + `binding_status == MATCHED` + `trust_status == VERIFIED_TRUSTED` $\rightarrow$ `PASS` (Eligible for release).
   - `gateStatus == "PASS"` + `evidenceQuality == "LIMITED"` $\rightarrow$ `BLOCKED`.
   - `gateStatus == "FAIL"` $\rightarrow$ `FAIL`.
   - `gateStatus == "BLOCKED"` $\rightarrow$ `BLOCKED`.
   - `gateStatus == "NOT_RUN"` $\rightarrow$ `BLOCKED`.
   - Missing `model_bundle_id` (`UNBOUND`) $\rightarrow$ `BLOCKED` (under strict policy).
   - Mismatched `model_bundle_id` (`MISMATCH`) $\rightarrow$ `FAIL`.
   - Tampered report digest or untrusted/missing signature when `require_trusted_evidence: true` $\rightarrow$ `FAIL` (if signature invalid/tampered) or `BLOCKED` (if signature missing).
