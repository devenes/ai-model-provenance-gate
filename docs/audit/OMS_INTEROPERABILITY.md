# OpenSSF Model Signing (OMS v1.0) Interoperability & Conformance Report (`docs/audit/OMS_INTEROPERABILITY.md`)

**Components:** [`internal/oms`](../../internal/oms/oms.go), [`internal/signing`](../../internal/signing/signing.go), [`internal/signing/sigstore_verify.go`](../../internal/signing/sigstore_verify.go), [`internal/cli/oms_conformance.go`](../../internal/cli/oms_conformance.go)  
**Evidence Artifacts:**
- [`artifacts/final-audit/oms-conformance-results.json`](../../artifacts/final-audit/oms-conformance-results.json)
- [`artifacts/final-audit/oms-conformance-report.md`](../../artifacts/final-audit/oms-conformance-report.md)

---

## 1. Upstream Specification & Conformance Suite

- **Upstream Specification Repository:** `https://github.com/ossf/model-signing-spec` (`commit 91bf841e8ccf97a3ed97309387e9298d1ac18ba2`)
- **Upstream Conformance Fixtures:** `ghcr.io/ossf/model-signing-spec/conformance-test-cases:v1.0.0`
- **Supported Statement & Bundle Formats:**
  - Sigstore Bundle v0.3 (`application/vnd.dev.sigstore.bundle.v0.3+json`) and raw DSSE v1.0 envelopes (`application/vnd.in-toto+json`).
  - in-toto Statement v1 (`https://in-toto.io/Statement/v1`).
  - OMS v1.0 predicate (`https://model_signing/signature/v1.0`) and backward-compatible OMS v0.1/v0.2 digest predicates (`https://model_signing/Digests/v0.1`).

---

## 2. Cryptographic Verification Modes

1. **Bare-Key Mode (`key`):**
   - Supports Ed25519, ECDSA P-256 (`secp256r1` / SHA-256), ECDSA P-384 (`secp384r1` / SHA-384), ECDSA P-521 (`secp521r1` / SHA-512), and RSA (2048+ bits, PKCS#1v15 and PSS).
   - Enforces strict verification method isolation: certificate-signed or keyless Sigstore bundles are rejected if verified via bare-key mode (`certificate-verify-as-key_fail`, `sigstore-verify-as-key_fail`).
2. **X.509 Certificate Chain Mode (`certificate`):**
   - Verifies leaf, intermediate, and root CA certificate chains at signing time, enforces `id-kp-codeSigning` (`1.3.6.1.5.5.7.3.3`) Extended Key Usage on the leaf certificate, and rejects expired or not-yet-valid certificates across the entire chain.
   - Supports historical OMS `v0.2.0` escaped-newline DSSE PAE compatibility (`compatPAE`) strictly scoped to `https://model_signing/Digests/v0.1`.
3. **Offline Sigstore Keyless Mode (`sigstore`):**
   - Verifies Fulcio leaf/intermediate chains against the embedded Sigstore Public Good trusted root ([`internal/signing/sigstore_trusted_root.json`](../../internal/signing/sigstore_trusted_root.json)), checks the OIDC issuer OID (`1.3.6.1.4.1.57264.1.1` and `1.3.6.1.4.1.57264.1.8`) and Subject Alternative Name (email or URI) against `--identity` and `--identity-provider`, and verifies the Rekor transparency log Checkpoint / SET and RFC 6962 Merkle inclusion proof over the canonicalized `dsse:0.0.1` / `intoto:0.0.2` log entry.
4. **Optional External Python `model_signing` Subprocess Mode (`external-cli`):**
   - Invokes external `model_signing` CLI when `signing.oms_mode: "external-cli"` is configured; fails closed with `BLOCKED` (`ErrExternalCLIUnavailable`, exit `3`) when the external Python binary is not installed on the host.

---

## 3. Upstream Conformance Results

| Suite | Command | Total | Passed | Failed | Skipped | Status |
|---|---|---:|---:|---:|---:|---|
| Default Conformance Suite (`test_roundtrip.py` + `test_verify.py`) | `pytest --entrypoint=bin/ai-model-provenance` | 92 | **80** | **0** | 12 | **PASS** |
| All Pre-Committed Verify Bundles (`test_verify.py` incl. Sigstore v0.3) | `SIGSTORE_ID_TOKEN=offline-verify-only pytest test/test_verify.py --entrypoint=bin/ai-model-provenance` | 55 | **55** | **0** | **0** | **PASS** |
| Combined Offline-Capable Conformance Suite | `32` offline roundtrips + `55` pre-committed verify cases | **87** | **87** | **0** | 5 (live Fulcio/Rekor OIDC sign roundtrips) | **PASS** |
| External Python `model_signing` CLI on Host | `oms verify --mode external-cli` | 1 | 0 | 0 | 0 | **BLOCKED** (`model_signing` binary not installed on host) |
