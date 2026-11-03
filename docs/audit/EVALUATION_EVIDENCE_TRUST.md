# LLM Release Gate Evaluation Evidence Trust Model (`docs/audit/EVALUATION_EVIDENCE_TRUST.md`)

**Component:** [`internal/evaluation/llmreleasegate/adapter.go`](../../internal/evaluation/llmreleasegate/adapter.go), [`internal/cli/cli.go`](../../internal/cli/cli.go)  
**Sibling Repository (Read-Only):** `llm-release-gate`  
**Evidence Artifact:** [`artifacts/final-audit/evaluation-trust-results.json`](../../artifacts/final-audit/evaluation-trust-results.json)

---

## 1. Sibling Repository Inspection Findings

Read-only inspection of `llm-release-gate` (`schemas/report.schema.json`, `internal/report/types.go`, `examples/basic/baselines/approved.json`) confirmed:
1. `llm-release-gate` emits plain, unsigned JSON reports (`schemaVersion: "llm-release-gate.report/v1"`).
2. `SubjectIdentity` (`candidate` / `baseline`) provides an extensible `metadata: map[string]string` map (`additionalProperties: {"type": "string"}`), where `candidate.metadata["model_bundle_id"]` can be populated without violating `llm-release-gate`'s strict JSON schema.
3. Existing baseline fixtures in `llm-release-gate` (such as `examples/basic/baselines/approved.json`) do not contain `model_bundle_id` and are therefore `UNBOUND`.

---

## 2. Explicit Separation of the 7 Trust Concepts

[`EvaluationSummary`](../../internal/evaluation/llmreleasegate/adapter.go) explicitly separates and reports:

| Trust Dimension | Field | Meaning |
|---|---|---|
| **1. Report Integrity** | `report_integrity_verified` | The `report.json` bytes and all bound predicate fields (`run_id`, `evaluation_timestamp`, `tool_version`, `gate_status`, `evidence_quality`, `suite_digest`, `dataset_digest`, `evaluator_name`, `evaluator_version`, `execution_mode`, `candidate_digest`) match the signed DSSE predicate. |
| **2. Report Authenticity** | `report_authenticity_verified` | The DSSE v1.0 signature over the `evaluation-evidence/v1` in-toto Statement v1 is mathematically valid. |
| **3. Trusted Evaluator Identity** | `producer_identity_verified` | The DSSE attestation was emitted as `TRUSTED_EVALUATOR_ATTESTATION` (`--producer-role trusted-evaluator`) and signed by a key in `evaluation.trusted_signers`. **Never set to `true` for post-hoc operator endorsements.** |
| **3b. Operator Endorsement** | `operator_endorsement_verified` | The DSSE attestation was emitted via post-hoc `evidence bind-eval` (`--producer-role operator-endorser`, the default) or on a report without native `candidate.metadata["model_bundle_id"]`. |
| **4. Artifact Binding** | `artifact_binding_verified` | `model_bundle_id` in the report/attestation matches the inspected model bundle's deterministic `bundle-identity/v1` digest (never inferred from `candidate.name`, `candidate.model`, or `candidate.digest`). |
| **5. Execution Evidence** | `execution_evidence_verified` | The report contains non-empty `evaluator.name`, `evaluator.version`, `execution.mode`, `cases` (`> 0`), `metrics.executedCases` (`> 0`), `evidenceQuality == "COMPLETE"`, `exitCode == 0`, and `gateStatus == "PASS"`. |
| **6. Suite & Dataset Identity** | `suite_dataset_identity_verified` | `suite.digest` and `dataset.digest` are valid SHA-256 digests and match `evaluation.expected_suite_digest` / `evaluation.expected_dataset_digest` when configured in `policy.yaml`. |
| **7. Freshness / Replay Protection** | `freshness_verified` | `timestamp` is valid RFC3339, not future-skewed (`> 5m`), and within `evaluation.max_age_hours` when configured in `policy.yaml`. |

---

## 3. Strict Policy Treatment of `evidence bind-eval` (Operator Endorsement vs. Trusted Evaluator)

- By default, `ai-model-provenance evidence bind-eval` sets `--producer-role operator-endorser`, emitting `attestation_kind: "OPERATOR_ENDORSEMENT"` and `binding_mode: "POST_HOC_OPERATOR"`.
- Under strict policy (`require_trusted_evidence: true`), an `OPERATOR_ENDORSEMENT` **does not** satisfy `require_trusted_evidence` and is rejected as `BLOCKED` (`EVALUATION_POST_HOC_BINDING_REJECTED`, exit `3`) unless:
  1. The configured signer in `evaluation.trusted_signers` explicitly sets `allow_operator_endorsement: true` (and the report contains `candidate.metadata["model_bundle_id"]`), or
  2. The policy is in `permissive` mode with `allow_post_hoc_binding: true`.
- Even when explicitly authorized by policy, an operator endorsement keeps `producer_identity_verified: false` and `operator_endorsement_verified: true` so reports and attestations never misrepresent an operator endorsement as proof of trusted evaluator execution.
- Signer-role conflation is strictly forbidden: keys in `signing.trusted_signers` (OMS model signers) are never accepted as evaluation signers unless explicitly listed in `evaluation.trusted_signers`.
