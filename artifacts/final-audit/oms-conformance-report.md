# OpenSSF Model Signing (OMS v1.0) Upstream Conformance Report

**Binary Tested:** `/Users/enes/GitHub/ai-model-provenance-gate/bin/ai-model-provenance`  
**Upstream Suite:** `https://github.com/ossf/model-signing-spec` (`commit 91bf841e8ccf97a3ed97309387e9298d1ac18ba2`)  
**OCI Fixtures:** `ghcr.io/ossf/model-signing-spec/conformance-test-cases:v1.0.0`

---

## 1. Execution Summary

| Execution Mode | Command | Collected | Passed | Failed | Skipped |
|---|---|---:|---:|---:|---:|
| **Default Offline Suite (`test_roundtrip.py` + `test_verify.py`)** | `pytest --entrypoint=bin/ai-model-provenance` | 92 | **80** | **0** | 12 |
| **Full Pre-Committed Bundle Verification (`test_verify.py` incl. Sigstore v0.3)** | `SIGSTORE_ID_TOKEN=offline-verify-only pytest test/test_verify.py --entrypoint=bin/ai-model-provenance` | 55 | **55** | **0** | **0** |
| **Combined Offline-Capable Conformance Coverage** | All offline-verifiable cases (`32` roundtrip + `55` verify) | **87** | **87** | **0** | 5 (online OIDC signing only) |

---

## 2. Verified Capabilities & Test Categories

### A. Sign-Then-Verify Roundtrip Tests (`test/test_roundtrip.py` — 32/32 Offline Passed)
- **Bare-Key Roundtrips:** ECDSA P-256 (`key-p256`), ECDSA P-384 (`key-p384`), ECDSA P-521 (`key-p521`), Ed25519, RSA.
- **X.509 Certificate PKI Chain Roundtrips:** 3-level PKI chain (`certificate-simple`), multi-file subdirectory models (`certificate-multi-file`), self-signed certificate (`certificate-self-signed`).
- **Path & Ignore Semantics:** `.git`, `.gitignore`, `.gitattributes` root auto-exclusion (`key-default-ignores`, `key-multi-git-dirs`, `key-multi-gitignore`), nested `.gitignore` preservation (`key-nested-git-not-excluded`), `--ignore-paths` exact matching (`key-ignore-paths-exact-match`), `--ignore-unsigned-files` (`key-ignore-unsigned`), signature inside model directory auto-exclusion (`key-sig-inside-model`), dotfiles and hidden directories (`key-dotfile-included`, `key-files-in-hidden-dir`), Unicode filenames (`key-unicode-filename`), spaces/special characters (`key-special-chars-path`), zero-byte files (`key-empty-file`), single-file models (`key-single-file`).
- **Mandatory Negative Roundtrips:** Empty directory rejection (`key-empty-model-rejected`), symlink rejection (`key-symlink-default-rejected`), symlink cycle rejection (`key-symlink-cycle`), symlink escaping root rejection (`key-symlink-outside-root`).

### B. Pre-Committed Verification Tests (`test/test_verify.py` — 55/55 Passed)
- **Positive Verification (6/6 Passed):** `positive/certificate-simple`, `positive/key-ignore-paths`, `positive/key-multi-file`, `positive/key-simple`, `positive/key-simple-ignore-unsigned-files`, `positive/key-single-file`.
- **Historical & Cross-Client Interoperability (15/15 Passed):**
  - Cross-language Go/Python interop: `historical/go-interop-certificate`, `historical/go-interop-key`.
  - Legacy `v0.2.0` (`https://model_signing/Digests/v0.1` with escaped-newline PAE): `historical/historical-v0.2.0-certificate`.
  - `v0.3.1`, `v1.0.0`, `v1.0.1`, `v1.1.0` across `elliptic-key`, `certificate`, and `sigstore` bundles (`12/12` passed).
- **Negative & Adversarial Verification (34/34 Passed):**
  - **PKI / X.509:** Missing `id-kp-codeSigning` EKU, expired leaf/intermediate/root/all certificates, not-yet-valid leaf/intermediate certificates, wrong CA root, verification method confusion (`certificate-verify-as-key_fail`, `certificate-verify-as-sigstore_fail`, `key-verify-as-certificate_fail`, `key-verify-as-sigstore_fail`, `sigstore-verify-as-key_fail`).
  - **Sigstore Keyless v0.3:** Tampered model content (`sigstore-tampered-content_fail`), wrong SAN identity (`sigstore-wrong-identity_fail`), wrong OIDC issuer (`sigstore-wrong-issuer_fail`).
  - **Envelope & Digests:** Corrupted JSON, truncated bundle, empty file, missing `dsseEnvelope`, empty signatures, wrong key, wrong `mediaType`, wrong `payloadType`, wrong `_type`, wrong `predicateType`, missing `serialization`, empty `resources`, tampered file content, missing file, extra unsigned file.
