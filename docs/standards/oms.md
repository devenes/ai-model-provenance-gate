# OpenSSF Model Signing (OMS) Standard Reference

## 1. Official Sources
- **OpenSSF Model Signing Repository:** https://github.com/ossf/model-signing
- **OpenSSF Model Signing Specification:** https://github.com/ossf/model-signing-spec (`spec/v1.0.md`)
- **PyPI Reference Package:** https://pypi.org/project/model-signing/

## 2. Specification Architecture
OpenSSF Model Signing (OMS) specifies how machine learning models and their constituent files are hashed, serialized into an **in-toto Attestation Statement v1** (`https://in-toto.io/Statement/v1`), and cryptographically signed inside a **DSSE (Dead Simple Signing Envelope)** (`application/vnd.in-toto+json`), optionally packaged inside a **Sigstore Bundle** (`application/vnd.dev.sigstore.bundle.v0.3+json` or `v0.2`).

### 2.1 OMS Statement Structure
- `_type`: `"https://in-toto.io/Statement/v1"`
- `subject`: Array of resource descriptors representing the signed files in the model directory (or shard slices):
  ```json
  {
    "name": "model.safetensors",
    "digest": {
      "sha256": "<64-lowercase-hex>"
    }
  }
  ```
- `predicateType`:
  - OMS v1.0: `"https://model_signing/signature/v1.0"`
  - OMS v0.1 (legacy): `"https://model_signing/digests/v0.1"`
- `predicate`:
  - `serialization`: Describes the hashing/serialization method (`{"method": "files", "hash_type": "sha256", "allow_symlinks": false, "ignore_paths": [...]}`).
  - `resources` (when nested resource descriptors are used in v1.0).

### 2.2 Envelope Formats
An OMS signature artifact (`model.sig` or `oms.sigstore.json`) is stored in one of two standardized formats:
1. **Sigstore Bundle JSON (`application/vnd.dev.sigstore.bundle.v0.3+json` or `v0.2`):**
   Contains `verificationMaterial` (`publicKey` hint or `x509CertificateChain`) and `dsseEnvelope` (`payloadType`, `payload`, `signatures`).
2. **Raw DSSE Envelope JSON:**
   Contains `payloadType: "application/vnd.in-toto+json"`, `payload` (Base64-encoded in-toto Statement v1 JSON), and `signatures` (`[{"keyid": "...", "sig": "<base64-sig-over-PAE>"}]`).

## 3. Adapter Strategy & Feasibility Analysis

Per the Phase 0 baseline inspection:
- The external Python CLI `model_signing` (`pip install model-signing`) is **not pre-installed** on the target host (`which model-signing` $\rightarrow$ `NOT_FOUND`), and the product requirements prohibit mandatory Python runtimes.
- However, OMS v1.0 signatures are standard **DSSE v1.0 envelopes** over **in-toto v1 Statements** signed using standard PKIX asymmetric keys (`Ed25519`, `ECDSA P-256/P-384`, `RSA`).

Therefore, `ai-model-provenance-gate` implements a **dual-mode OMS adapter** (`internal/oms`):

### Mode 1: Native Go OMS v1.0 Verifier & Test Signer (Default, Zero External Runtime)
1. **Envelope Parsing:** Parses both Sigstore Bundle JSON (`v0.2`/`v0.3` extracting `dsseEnvelope`) and raw DSSE Envelope JSON.
2. **Cryptographic Verification:** Reconstructs the exact DSSE v1.0 Pre-Authentication Encoding (`PAE`):
   `DSSEv1 <len(payloadType)> <payloadType> <len(payload)> <payload>`
   and verifies the signature using the Go standard library (`crypto/ed25519`, `crypto/ecdsa`, `crypto/rsa`, `crypto/x509`) against the configured trusted PEM public keys.
3. **Signer Trust Evaluation:** Computes the SHA-256 PKIX public key fingerprint (`sha256:<64-hex>`) and checks `keyid` / signer identity against the policy's `signing.trusted_signers` list. Unknown signers return `UNTRUSTED_SIGNER` (`FAIL` under strict policy).
4. **Strict Inventory Digest Correspondence:** Decodes the in-toto v1 Statement, validates `predicateType` (`https://model_signing/signature/v1.0` or `https://model_signing/digests/v0.1`), and verifies a **1-to-1 correspondence** between the OMS `subject` (and `predicate.resources` if present) file digests and the inspected model bundle file inventory:
   - Any modified file digest $\rightarrow$ `DIGEST_MISMATCH` (`FAIL`)
   - Any unsigned extra file in bundle $\rightarrow$ `UNSIGNED_FILE_PRESENT` (`FAIL`)
   - Any signed file missing from bundle $\rightarrow$ `SIGNED_FILE_MISSING` (`FAIL`)

### Mode 2: External `model_signing` Subprocess Adapter (`--oms-mode=external-cli`)
- Invokes `model_signing verify key <bundle> --signature <sig> --public-key <pubkey>` using `exec.CommandContext` with explicit argument arrays (no shell interpolation), a strict timeout, and bounded stdout/stderr capture.
- If `--oms-mode=external-cli` is requested when `model_signing` is not installed on `PATH`, the adapter returns `BLOCKED` (`OMS_CLI_UNAVAILABLE`) and never simulates success.
