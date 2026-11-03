# Implementation Decisions Summary

**Phase:** Phase 1 — Architecture and Technical Feasibility

This document summarizes the key technical and architectural decisions made following Phase 0 baseline inspection and standards research. Detailed Architecture Decision Records (ADRs) are maintained under `docs/decisions/`.

---

## 1. Summary of Major Engineering Choices

| Area | Decision | Rationale | Detailed Record |
|---|---|---|---|
| **Go Toolchain & Dependencies** | Go `1.27.3` + `gopkg.in/yaml.v3 v3.0.1` + Go standard library (`crypto/*`, `encoding/*`). Zero CGO. | Matches sibling portfolio repositories (`llm-release-gate`, `ai-platform-conformance-kit`), eliminates stdlib advisory `GO-2026-6809` in `1.27.2`, guarantees zero-dependency vulnerability surface, and enables fast CPU-only cross-compilation. | `artifacts/baseline/dependency-inventory.md` |
| **Deterministic Bundle Identity** | `bundle-identity/v1` serialized via RFC 8785 (JSON Canonicalization Scheme - JCS) over sorted NFC-normalized relative paths, roles, sizes, and SHA-256 digests. | Eliminates filesystem enumeration order, OS path separator differences, absolute path leakage, and timestamp variability. | [`ADR-001`](../decisions/ADR-001-artifact-identity.md) |
| **OpenSSF Model Signing (OMS) Integration** | Dual-mode OMS v1.0 adapter: native Go DSSE/Sigstore-bundle verifier & signer (`https://model_signing/signature/v1.0`) + safe subprocess adapter for external `model_signing` CLI. | `model_signing` Python CLI is not pre-installed on the host (`NOT_FOUND`), and the product cannot require a Python runtime. Because OMS v1.0 is an in-toto v1 Statement inside a DSSE envelope/Sigstore bundle, Go's standard `crypto/*` verifies genuine OMS v1.0 key signatures offline while also supporting the external CLI when present. | [`ADR-002`](../decisions/ADR-002-oms-integration.md) |
| **LLM Release Gate Binding** | Strict read-only adapter for `llm-release-gate.report/v1`. Checks `candidate.metadata["model_bundle_id"]` and optional signed `evaluation-evidence/v1` DSSE attestation. Unmodified legacy reports without `model_bundle_id` return `UNBOUND` (`BLOCKED` in strict policy). | Inspection of `llm-release-gate` proved that `llm-release-gate.report/v1` has no first-class `model_bundle_id` field and outputs unsigned JSON, while `candidate.metadata` is an open `map[string]string` allowed by `report.schema.json`. | [`ADR-003`](../decisions/ADR-003-evaluation-binding.md) |
| **Release Qualification Attestation** | in-toto Statement v1 (`https://in-toto.io/Statement/v1`) wrapped in DSSE v1.0 (`application/vnd.in-toto+json`) with project-owned predicate `https://github.com/devenes/ai-model-provenance-gate/attestation/release-qualification/v1`. | Keeps post-hoc release qualification strictly separate from SLSA build provenance (`https://slsa.dev/provenance/v1`) and supports offline key-based verification with PEM public keys (`Ed25519`, `ECDSA P-256`, `RSA`). | [`ADR-004`](../decisions/ADR-004-release-attestation.md) |

---

## 2. Binary & CLI Naming Convention

- Primary binary name: `ai-model-provenance` (and alias build support for `ai-model-provenance-gate`), matching the prompt's CLI contract (`ai-model-provenance inspect`, `ai-model-provenance gate evaluate`, `ai-model-provenance release verify`, plus `bom`, `oms`, `evidence`, `version`).
- Process exit codes match the portfolio-wide contract:
  - `0`: `PASS`
  - `1`: `FAIL`
  - `2`: `INVALID_INPUT` / `ERROR` (usage/schema error)
  - `3`: `BLOCKED` / `NOT_RUN`
  - `4`: `INTERNAL_ERROR`
