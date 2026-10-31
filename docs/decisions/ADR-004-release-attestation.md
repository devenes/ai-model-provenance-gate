# ADR-004: in-toto Release Qualification Attestation and Separation from SLSA Build Provenance

- **Status:** Accepted
- **Date:** 2026-10-31
- **Context:** Phase 1 — Architecture and Technical Feasibility

## Context
When a model bundle passes inspection, CycloneDX BOM generation, OMS signature verification, and bound behavioral evaluation under a release policy, `ai-model-provenance-gate` must emit a cryptographically verifiable attestation that downstream deployment pipelines (`release verify`) can validate offline before serving the model.

A common anti-pattern in supply-chain tools is emitting a `https://slsa.dev/provenance/v1` predicate from a post-build policy gate and claiming SLSA compliance. Per the official SLSA specification (`https://slsa.dev/spec/v1.0/`), SLSA build provenance can only be emitted by the builder that actually executed the build/training job.

## Decision
1. **Standard Envelope:**
   We use the official **in-toto Attestation Statement v1** (`_type: "https://in-toto.io/Statement/v1"`) wrapped in a standard **DSSE v1.0 envelope** (`payloadType: "application/vnd.in-toto+json"`).
2. **Project-Owned Release Qualification Predicate:**
   We define the explicit predicate type:
   `https://github.com/devenes/ai-model-provenance-gate/attestation/release-qualification/v1`
   The statement `subject` is the inspected model bundle (`digest.sha256 = <64-hex-bundle-id>`), and the predicate records:
   - `bundle`: `bundle_id`, `manifest_digest`, file count, total bytes, primary format, LoRA verification status.
   - `bom`: CycloneDX BOM SHA-256 digest and spec version.
   - `oms_verification`: Verification status, signer key ID, signer public key SHA-256 fingerprint, and OMS signature digest.
   - `evaluation`: `gateStatus`, `evidenceQuality`, `binding_status`, `trust_status`, `report_digest`, `suite_digest`, `dataset_digest`, and `run_id`.
   - `scanner`: Scanner execution status and report digest (when applicable).
   - `runtime`: Optional deployment runtime identity when bound at qualification time.
   - `policy`: Policy schema version, policy SHA-256 digest, decision mode, and any explicit auditable policy exceptions applied.
   - `decision`: Final `gate_status` (`PASS`) and decision reasons.
3. **No False SLSA Provenance Claims:**
   `ai-model-provenance-gate` never emits `https://slsa.dev/provenance/v1`. If an upstream training pipeline provides an existing signed SLSA provenance statement, `ai-model-provenance-gate` can verify its DSSE signature and subject digest as optional upstream provenance evidence.

## Consequences
- **Positive:** Provides an unambiguous, tamper-evident, offline-verifiable qualification credential for `release verify` while maintaining full integrity with in-toto and SLSA specifications.
