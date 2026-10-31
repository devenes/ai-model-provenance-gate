# Security & Trust Assessment (`docs/audit/SECURITY_TRUST_ASSESSMENT.md`)

**Project:** AI Model Provenance Gate (`ai-model-provenance-gate`)  
**Assessment Scope:** Cryptographic boundaries, threat model, trust guarantees, and residual risks.

---

## 1. Security Guarantee Matrix

| Security Dimension | What IS Cryptographically Proven | What is Declared / Unverified unless Checked | What is Out of Scope |
|---|---|---|---|
| **1. Model Bundle Identity (`bundle-identity/v1`)** | Exact streaming SHA-256 digest, byte size, role, and NFC-normalized POSIX relative path of every regular file in the model bundle, serialized via RFC 8785 (JCS). | External Hugging Face Hub repo names (`_name_or_path`) in `config.json` are tagged `declared_unverified`. | Post-verification disk mutation after `release verify` exits if the host OS / container runtime allows writable model mounts. |
| **2. CycloneDX 1.7 AI/ML-BOM** | 1:1 file component correspondence and SHA-256 hash consistency with the inspected model bundle; schema compliance with official `bom-1.7.schema.json`. | License strings in `config.json` (`declared_unverified`) and PEFT base model names without `--base-bundle` (`DECLARED_UNVERIFIED`). | Legal license audit or training-data copyright provenance. |
| **3. OpenSSF Model Signing (OMS v1.0)** | DSSE v1.0 / Sigstore v0.3 cryptographic authenticity, X.509 PKI chain or Fulcio/Rekor transparency proof, signer authorization against `signing.trusted_signers`, and 1:1 per-file SHA-256 digest match. | Behavioral safety or evaluation quality of the signed weights. | Hardware HSM / PKCS#11 token management during signing. |
| **4. Behavioral Evaluation Evidence (`llm-release-gate`)** | Report SHA-256 integrity, DSSE signature authenticity, signer role separation (`evaluation.trusted_signers`), `model_bundle_id` binding, suite/dataset digests, and timestamp freshness. | Post-hoc operator endorsements (`OPERATOR_ENDORSEMENT`) prove an operator endorsed a report file, **not** that an isolated CI evaluator executed the suite. | Correctness of the evaluation prompts or grading rubric inside `llm-release-gate`. |
| **5. Upstream SLSA Provenance (`slsa.dev/provenance/v1`)** | Optional verification of upstream SLSA v1.0/v1.1/v1.2 DSSE provenance, subject digest match, `buildDefinition.buildType`, and `runDetails.builder.id` against `provenance.trusted_builders`. | Not required unless `provenance.require_upstream_slsa: true`. | `ai-model-provenance-gate` is a post-hoc verifier and never claims to be a SLSA build service. |
| **6. Release Qualification Attestation (`release-qualification/v1`)** | in-toto Statement v1 + DSSE v1.0 signature by `release.trusted_signers` binding `model_bundle_id`, BOM digest, OMS digest, evaluation digest, policy digest, runtime image digest, and serving config digest. |Unsigned statements when `--signing-key` is omitted (rejected under `require_signed_qualification: true`). | Live Kubernetes admission webhook enforcement (delegated to platform conformance / admission controllers). |
| **7. Deployment Composition (`deployment-composition/v1`)** | Live model bundle identity matches attested release subject and `deployment.yaml`, runtime image uses an immutable `@sha256:<64-hex>` digest, serving config digest matches, and active LoRA adapters are allowlisted. | Runtime container behavior after process launch. | GPU kernel / vLLM runtime memory isolation. |

---

## 2. Adversarial Threat Mitigations Verified

1. **Tokenizer, Chat Template, LoRA Adapter, or Weight Substitution:**
   - Any 1-byte modification to `tokenizer.json`, `chat_template.jinja`, `adapter_config.json`, `adapter_model.safetensors`, or `model.safetensors` changes `bundle-identity/v1` and causes `release verify` to fail closed with `DEPLOYMENT_ARTIFACT_TAMPERED` (exit `1`).
2. **TOCTOU Concurrent File Mutation During Hashing:**
   - [`internal/digest/digest.go`](../../internal/digest/digest.go) compares pre-read `os.Lstat` and post-read `f.Stat()` (`dev`, `ino`, `size`, `mtime`, `mode`) and aborts with `ErrConcurrentMutation` if a file changes while being hashed.
3. **Filesystem Traversal, Symlinks, Hard Links, and Cross-Platform Path Collisions:**
   - [`internal/inventory/inventory.go`](../../internal/inventory/inventory.go) rejects symlinks (including symlinked bundle root), hard-linked files (`nlink > 1`), FIFOs/sockets/devices, `../` traversal, backslashes, Windows drive prefixes (`:`), Windows reserved names (`CON`, `PRN`, `AUX`, `NUL`, `COM1`..`COM9`, `LPT1`..`LPT9`), Unicode NFC/NFD collisions, and case-folding collisions.
4. **Malicious Safetensors Headers & Unsafe Pickle Deserialization:**
   - [`internal/formats/safetensors/safetensors.go`](../../internal/formats/safetensors/safetensors.go) enforces a 100 MiB header cap before allocation, rejects Pickle magic bytes (`\x80\x02`..`\x80\x05`) disguised as `.safetensors`, and verifies contiguous, non-overlapping tensor `data_offsets` and exact `dtype * product(shape)` byte sizes without loading tensors into RAM.
5. **Cross-Role Signer Substitution:**
   - OMS model signers (`signing.trusted_signers`), evaluation producers (`evaluation.trusted_signers`), SLSA builders (`provenance.trusted_signers`), and release authorities (`release.trusted_signers`) are strictly isolated; signing an evaluation or release attestation with an OMS model key fails verification (`UNTRUSTED`).
