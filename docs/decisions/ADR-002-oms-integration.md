# ADR-002: OpenSSF Model Signing (OMS) Integration Architecture

- **Status:** Accepted
- **Date:** 2026-10-31
- **Context:** Phase 1 — Architecture and Technical Feasibility

## Context
The product must integrate OpenSSF Model Signing (OMS) to verify model bundle authenticity, component digest correspondence, and signer trust, including offline verification with configured trusted keys.

During Phase 0 baseline inspection and standards research, we verified:
1. The official OMS specification (`https://github.com/ossf/model-signing-spec`, v1.0) defines an OMS signature as an **in-toto Attestation Statement v1** (`https://in-toto.io/Statement/v1`) with predicate type `https://model_signing/signature/v1.0` (or `https://model_signing/digests/v0.1`), wrapped inside a **DSSE v1.0 envelope** (`application/vnd.in-toto+json`) or a **Sigstore Bundle** (`application/vnd.dev.sigstore.bundle.v0.3+json`).
2. Each `subject` entry in the OMS in-toto Statement records a relative file path (`name`) and its `digest.sha256`.
3. The Python CLI reference implementation (`model_signing` from `https://github.com/ossf/model-signing`) is **not installed** on the baseline machine (`which model-signing` $\rightarrow$ `NOT_FOUND`), and our product requirements explicitly forbid a mandatory Python runtime.
4. Our product requirements also forbid inventing custom cryptographic algorithms or custom signing protocols.

## Decision
We implement an evidence-based, dual-adapter OMS package (`internal/oms`) behind a clean `Verifier` interface:

1. **Native Standard-Compliant OMS v1.0 Verifier & Signer (`mode: native`, default):**
   - Uses standard Go cryptography (`crypto/ed25519`, `crypto/ecdsa`, `crypto/rsa`, `crypto/sha256`, `crypto/x509`, `encoding/pem`) to verify and generate standard DSSE v1.0 Pre-Authentication Encoding (`PAE`) signatures over genuine in-toto v1 Statements (`https://model_signing/signature/v1.0`).
   - Supports both raw DSSE envelopes and Sigstore v0.2/v0.3 JSON Bundles (`dsseEnvelope`).
   - Verifies that the signing public key's PKIX SHA-256 fingerprint matches an entry in `policy.signing.trusted_signers`.
   - Enforces strict 1-to-1 file digest correspondence between the OMS statement `subject` list and the inspected `bundle-identity/v1` file inventory (detecting tampered weights, missing signed files, and extra unsigned files).
2. **External `model_signing` Subprocess Adapter (`mode: external-cli`):**
   - Invokes `model_signing verify key <bundle> --signature <sig> --public-key <pubkey>` using `exec.CommandContext` with an explicit argument slice (no shell interpolation), bounded timeout, and captured stdout/stderr.
   - If `mode: external-cli` is selected when `model_signing` is not installed on `PATH`, the adapter fails closed with status `BLOCKED` (`OMS_CLI_NOT_FOUND`) and never simulates a pass.

## Consequences
- **Positive:** Fulfils offline key-based OMS v1.0 verification and conformance testing without requiring a Python runtime, while using 100% standardized formats (in-toto v1 + DSSE v1.0 + Sigstore Bundle + PKIX PEM keys) and Go stdlib cryptography. Also provides direct subprocess compatibility with the Python `model_signing` CLI when installed.
- **Negative / Trade-off:** Keyless Fulcio/Rekor transparency log verification requires either an online TUF/Rekor check or the external `model_signing` CLI; offline verification requires local PEM public keys.
