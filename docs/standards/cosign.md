# Sigstore and Cosign Standard Reference

## 1. Official Sources
- **Sigstore Documentation:** https://docs.sigstore.dev/
- **Cosign Repository:** https://github.com/sigstore/cosign
- **Sigstore Protobuf / Bundle Specs:** https://github.com/sigstore/protobuf-specs

## 2. Signing and Verification Modes

### 2.1 Offline Key-Based Signing & Verification (Primary Local/CI Mode)
- Uses standard PEM-encoded PKIX public keys (`-----BEGIN PUBLIC KEY-----`) and PKCS#8 private keys (`-----BEGIN PRIVATE KEY-----`), supporting **Ed25519** and **ECDSA P-256 (SHA-256)**.
- Produces standard DSSE envelopes (`application/vnd.in-toto+json`) and Sigstore v0.3-compatible Bundle JSON documents (`application/vnd.dev.sigstore.bundle.v0.3+json`).
- **Offline Verification Requirements:**
  - Offline verification succeeds **only** when the verifier possesses:
    1. The signed DSSE envelope or Sigstore bundle,
    2. The artifact/subject being verified, and
    3. The trusted public key material (`--public-key` or `trusted_signers` in `policy.yaml`).
  - If trusted public key material is missing, verification fails closed (`BLOCKED` / `MISSING_VERIFICATION_MATERIAL`).

### 2.2 Optional External `cosign` CLI Integration
- When `--signer-mode=cosign-cli` is explicitly configured and `cosign` is installed on `PATH`, `ai-model-provenance-gate` can invoke `cosign verify-blob` / `cosign verify-attestation --offline --key <pub>`.
- Because `cosign` is not installed on the baseline development machine (`which cosign` $\rightarrow$ `NOT_FOUND`), the native Go DSSE / PKIX verifier serves as the primary offline cryptographic engine, using standard cryptographic algorithms from the Go standard library (`crypto/ed25519`, `crypto/ecdsa`, `crypto/rsa`, `crypto/sha256`, `crypto/x509`).
- Keyless OIDC/Fulcio/Rekor verification requires live network access to Fulcio/Rekor and a trusted TUF root; in offline local environments without a TUF trust root and certificate chain bundle, keyless verification is explicitly reported as `BLOCKED`.
