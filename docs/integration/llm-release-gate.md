# LLM Release Gate Integration Guide and Future Contract Proposal

## 1. Current State of `llm-release-gate` (`llm-release-gate.report/v1`)

Read-only inspection of `/Users/enes/GitHub/llm-release-gate` confirmed:
- `llm-release-gate` emits JSON reports conforming to `schemas/report.schema.json` (`"schemaVersion": "llm-release-gate.report/v1"`).
- Top-level `gateStatus` values are `"PASS"`, `"FAIL"`, `"BLOCKED"`, and `"NOT_RUN"`, paired with `evidenceQuality` (`"COMPLETE"` or `"LIMITED"`) and `exitCode` (`0..4`).
- `suite.digest` (`sha256:<64-hex>`) and `dataset.digest` (`sha256:<64-hex>`) record the cryptographic digests of the evaluation suite and test dataset.
- `candidate.digest` records the SHA-256 digest of `candidate.yaml`, **not** the model bundle weights.
- `candidate.metadata` is an open `map[string]string` (`"type": "object"` in `schemas/report.schema.json` and `schemas/candidate.schema.json`).
- Reports are plain UTF-8 JSON (`report.json`) without cryptographic signatures.

---

## 2. How `ai-model-provenance-gate` Verifies `llm-release-gate` Evidence Today

Without modifying `llm-release-gate`, you can bind and sign an evaluation report in two steps:

### Step 1: Include `model_bundle_id` in `candidate.yaml` Metadata
After running `ai-model-provenance inspect --bundle ./model-bundle`, place the resulting `bundle_id` in `candidate.yaml` before running `llm-release-gate`:

```yaml
apiVersion: llm-release-gate/v1
kind: CandidateConfig
metadata:
  name: customer-assistant-candidate-v1.1
  version: "1.1.0"
  environment: local-ci
  metadata:
    model_bundle_id: "sha256:<64-hex-bundle-identity>"
    adapter: "support-lora-v2"
```

### Step 2: Sign the Evaluation Evidence (`evidence bind-eval`)
Bind the generated `report.json` digest and `model_bundle_id` into a signed DSSE `evaluation-evidence/v1` attestation using the trusted evaluator key:

```bash
ai-model-provenance evidence bind-eval \
  --bundle ./model-bundle \
  --evaluation-report ./eval/report.json \
  --private-key ./keys/eval-signer.key \
  --key-id eval-signer-1 \
  --output ./eval/eval-attestation.dsse.json
```

### Five Independent Evaluation Guarantees (`EvaluationSummary`)

`ai-model-provenance-gate` never conflates evaluation report formatting with cryptographic authenticity or artifact identity. Every `EvaluationSummary` tracks five orthogonal booleans:

1. **`report_integrity_verified`**: `report.json` was not modified after the DSSE evaluation attestation was signed (`pred.report_digest == sha256(report.json)`).
2. **`report_authenticity_verified`**: The DSSE v1.0 PAE signature over the `evaluation-evidence/v1` statement is mathematically valid.
3. **`producer_identity_verified`**: The signing key is explicitly listed in `evaluation.trusted_signers` in `policy.yaml`. OMS model-signing keys (`signing.trusted_signers`) are **never** implicitly trusted as evaluation producers.
4. **`artifact_binding_verified`**: The report's `candidate.metadata.model_bundle_id` and the attestation subject both match the inspected `model_bundle_id`.
5. **`execution_evidence_verified`**: `gateStatus == "PASS"`, `evidenceQuality == "COMPLETE"`, `exitCode == 0`, `suite.digest` and `dataset.digest` match policy (`expected_suite_digest`, `expected_dataset_digest`), and `timestamp` is within `max_age_hours`.

### Security Boundary: Native CI Binding (`NATIVE_CI_EVALUATOR`) vs. Post-Hoc Operator Binding (`POST_HOC_OPERATOR`)

If an operator takes an unbound `report.json` (which did not record `candidate.metadata.model_bundle_id` at evaluation time) and runs `evidence bind-eval` after the fact, that signature **only proves that the signer asserted the binding**; it does **not** prove that `llm-release-gate` evaluated that model bundle during the run.

- When `report.json` natively contains `candidate.metadata.model_bundle_id == <bundle_id>` and is signed by an authorized evaluation producer, `binding_mode` is `"NATIVE_CI_EVALUATOR"`.
- When `report.json` lacks `candidate.metadata.model_bundle_id` and is bound externally via `evidence bind-eval`, `binding_mode` is `"POST_HOC_OPERATOR"`.
- Under **strict mode** (`decision_mode: strict`, `require_artifact_binding: true`, `require_trusted_evidence: true`), `POST_HOC_OPERATOR` bindings are **rejected (`BLOCKED`)** (`EVALUATION_POST_HOC_BINDING_REJECTED`). Post-hoc bindings are only accepted in `permissive` mode when `evaluation.allow_post_hoc_binding: true` is explicitly configured and signed by an authorized `evaluation.trusted_signers` key.

### Decision Matrix Enforced by the Adapter (`internal/evaluation/llmreleasegate`)

| Evaluation Evidence Supplied | `BindingStatus` | `BindingMode` | `TrustStatus` | Resulting Gate Status (Strict Policy) |
|---|---|---|---|---|
| `PASS` + `COMPLETE` + native `model_bundle_id` + valid trusted evaluator DSSE | `MATCHED` | `NATIVE_CI_EVALUATOR` | `VERIFIED_TRUSTED` | **`PASS`** (Eligible for release) |
| `PASS` + `COMPLETE` + unbound report + post-hoc `evidence bind-eval` DSSE | `MATCHED` | `POST_HOC_OPERATOR` | `VERIFIED_TRUSTED` | **`BLOCKED`** (`EVALUATION_POST_HOC_BINDING_REJECTED`) |
| `FAIL` | Any | Any | Any | **`FAIL`** |
| `BLOCKED` | Any | Any | Any | **`BLOCKED`** |
| `NOT_RUN` | Any | Any | Any | **`BLOCKED`** |
| `PASS` with `evidenceQuality: "LIMITED"` | Any | Any | Any | **`BLOCKED`** |
| Missing `model_bundle_id` (no report metadata and no DSSE) | `UNBOUND` | `UNBOUND` | Any | **`BLOCKED`** |
| Different `model_bundle_id` (evaluated another bundle) | `MISMATCH` | Any | Any | **`FAIL`** |
| Plain unsigned `report.json` (no `--evaluation-attestation`) | `MATCHED` | `REPORT_METADATA_ONLY` | `UNVERIFIED_LOCAL_JSON` | **`BLOCKED`** |
| Signed by OMS model key not in `evaluation.trusted_signers` | Any | Any | `UNTRUSTED_SIGNER` | **`FAIL`** |
| Modified `report.json` or modified attestation subject digest | Any | Any | `INVALID_OR_TAMPERED` | **`FAIL`** |
| Stale report (`timestamp` > `max_age_hours`) or wrong suite/dataset digest | `MATCHED` | Any | `VERIFIED_TRUSTED` | **`FAIL`** |

---

## 3. Non-Invasive Proposal for Future `llm-release-gate` v1.1 Enhancement

*(Note: Per strict isolation rules, `/Users/enes/GitHub/llm-release-gate` has not been modified. This section documents the proposed upstream contract for a future version of `llm-release-gate`.)*

1. **First-Class `candidate.modelBundleId` Field in `schemas/report.schema.json`:**
   Add an optional pattern-validated field to `candidate` in `schemas/candidate.schema.json` and `schemas/report.schema.json`:
   ```json
   "modelBundleId": {
     "type": "string",
     "pattern": "^sha256:[0-9a-f]{64}$",
     "description": "Deterministic bundle-identity/v1 digest of the local model artifact under evaluation."
   }
   ```
2. **CLI Flag `--bundle-manifest` on `llm-release-gate run`:**
   Allow `llm-release-gate run --suite suite.yaml --candidate candidate.yaml --bundle-manifest bundle-manifest.json` to read `bundle_id` and `manifest_digest` directly from `ai-model-provenance inspect` output and embed both in `report.json`.
3. **Optional Native DSSE Attestation Output (`--signing-key`):**
   Allow `llm-release-gate run` to optionally emit `report.dsse.json` (`https://in-toto.io/Statement/v1`) directly at the conclusion of an evaluation run.
