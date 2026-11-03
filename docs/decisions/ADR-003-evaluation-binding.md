# ADR-003: LLM Release Gate Evaluation Evidence Binding Contract

- **Status:** Accepted
- **Date:** 2026-10-31
- **Context:** Phase 1 — Architecture and Technical Feasibility

## Context
`ai-model-provenance-gate` must verify that the behavioural evaluation report produced by `llm-release-gate` (`llm-release-gate.report/v1`) applies to the exact model bundle under inspection and originates from a trusted evaluation source.

Our read-only inspection of `llm-release-gate` established two critical facts:
1. `schemas/report.schema.json` enforces `"additionalProperties": false` on all objects **except** `candidate.metadata` (`map[string]string`). It does **not** define a dedicated top-level `model_bundle_id` field, and `candidate.digest` is only the SHA-256 of `candidate.yaml`.
2. `llm-release-gate` outputs plain JSON (`report.json`) and Markdown (`report.md`) without cryptographic signatures or DSSE envelopes.
3. We are strictly prohibited from modifying `llm-release-gate`.

## Decision
1. **Schema-Compatible Artifact Binding via `candidate.metadata["model_bundle_id"]`:**
   - Because `candidate.metadata` in `llm-release-gate` is an open `map[string]string` propagated directly from `candidate.yaml` into `report.json` (and valid under `schemas/report.schema.json`), an evaluation run can bind to a model bundle today without modifying `llm-release-gate` code by setting `metadata.metadata.model_bundle_id: "sha256:<64-hex>"` in `candidate.yaml` (or via a signed evaluation evidence attestation).
   - If a supplied `llm-release-gate.report/v1` report lacks `candidate.metadata["model_bundle_id"]` (and has no signed evaluation attestation binding it), the adapter classifies the report as `UNBOUND`. It **never** infers artifact identity from `candidate.name`, `candidate.model`, or `candidate.digest`. Under strict policy (`require_artifact_binding: true`), `UNBOUND` evaluates to `BLOCKED`.
   - If `model_bundle_id` is present and differs from the inspected bundle's `bundle_id`, the adapter classifies the report as `MISMATCH` and evaluates to `FAIL`.
2. **Distinguishing Plain JSON from Trusted Evaluation Evidence:**
   - A plain `report.json` file has `trust_status: UNVERIFIED_LOCAL_JSON`.
   - When `policy.evaluation.require_trusted_evidence: true` (default in strict mode), an unsigned `report.json` is rejected with `BLOCKED` even if `gateStatus == "PASS"` and `model_bundle_id` matches.
   - To establish `trust_status: VERIFIED_TRUSTED`, `ai-model-provenance-gate` supports verifying (and creating via `evidence bind-eval`) a signed DSSE evaluation evidence attestation (`evaluation-evidence/v1`) signed by a key in `policy.evaluation.trusted_signers` that binds the exact `report.json` SHA-256 digest (`report_digest`), `suite.digest`, `dataset.digest`, and `model_bundle_id`.
3. **Separate Upstream Integration Proposal:**
   - We document a non-invasive proposal in `docs/integration/llm-release-gate.md` for a future `llm-release-gate` release to add first-class `--model-bundle-manifest` ingestion and native DSSE signing.

## Consequences
- **Positive:** Preserves strict read-only isolation of `llm-release-gate`, prevents unbound or forged `PASS` reports from passing strict release qualification, and works seamlessly with `llm-release-gate`'s existing `report.schema.json`.
