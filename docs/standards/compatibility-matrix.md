# Standards Compatibility Matrix

**Project:** `ai-model-provenance-gate`  
**Phase:** Phase 1 — Architecture and Technical Feasibility

---

## 1. Standards Overview & Support Matrix

| Standard / Specification | Official Specification URL | Target Version | Implementation Level in MVP | Verification Mechanism | Known Limitations |
|---|---|---|---|---|---|
| **Deterministic Bundle Identity (`bundle-identity/v1`)** | Project-owned canonical manifest contract + RFC 8785 (JCS) | `v1` (`bundle-identity/v1`) | **Full Native Support** | Streaming SHA-256 over regular files + RFC 8785 canonical JSON serialization | Local scan captures point-in-time file contents; protects against mid-read mutation (size/mtime/re-hash checks) but cannot prevent post-scan disk modification without re-verification. |
| **CycloneDX AI/ML-BOM** | `https://cyclonedx.org/`<br>`https://github.com/CycloneDX/specification` | `1.6` (default) / `1.7` supported | **Full Native Generation & Schema Validation** | Built-in structural & JSON Schema validation against CycloneDX 1.6/1.7 ML-BOM profile | Distinguishes observed metadata (`config.json`, `.safetensors` headers, `adapter_config.json`) from declared metadata (`base_model_name_or_path`). Does not invent unobserved training datasets or licenses. |
| **OpenSSF Model Signing (OMS)** | `https://github.com/ossf/model-signing`<br>`https://github.com/ossf/model-signing-spec` | `v1.0` (`https://model_signing/signature/v1.0`) & `v0.1` (`https://model_signing/digests/v0.1`) | **Full Native DSSE/Bundle Key Verification + Optional External CLI Adapter** | Cryptographic DSSE PAE verification (`Ed25519`, `ECDSA`, `RSA`) + per-file SHA-256 subject correspondence check against inspected bundle inventory | Python `model_signing` CLI is not installed on the baseline host; native Go OMS v1.0 DSSE/Sigstore-bundle key signing & verification operates offline without Python. External CLI mode returns `BLOCKED` if invoked when `model_signing` is absent. |
| **in-toto Attestation Framework** | `https://in-toto.io/`<br>`https://github.com/in-toto/attestation` | Statement `v1` (`https://in-toto.io/Statement/v1`) & DSSE `v1.0` | **Full Native Support** | DSSE Pre-Authentication Encoding (`DSSEv1`) signature generation & verification + subject digest matching | Release qualification predicate (`https://github.com/devenes/ai-model-provenance-gate/attestation/release-qualification/v1`) is distinct from upstream build provenance. |
| **SLSA** | `https://slsa.dev/` | `v1.0` / `v1.1` (`https://slsa.dev/provenance/v1`) | **Optional Upstream Provenance Verification Only** | Validates upstream SLSA v1.0/v1.1 provenance statement subject & builder if supplied | **Does NOT claim SLSA build provenance generation.** Post-hoc qualification gates are verifiers, not training/build platforms. |
| **Sigstore & Cosign** | `https://docs.sigstore.dev/`<br>`https://github.com/sigstore/cosign` | Sigstore Bundle `v0.2` / `v0.3` & PEM Key Pairs | **Offline Key-Based DSSE / Bundle Verification + Optional `cosign` CLI Adapter** | Standard PKIX Public Key (`PEM`) signature verification over DSSE PAE & Sigstore Bundles | Keyless Fulcio/Rekor online transparency log verification is out of scope for offline CPU-only local validation unless `cosign` is installed and configured. |
| **Safetensors & Hugging Face / PEFT** | `https://github.com/huggingface/safetensors`<br>`https://huggingface.co/docs/peft` | Safetensors v1 binary header, `model.safetensors.index.json`, PEFT `adapter_config.json` | **Full Static Header Inspection (No Deserialization)** | 8-byte little-endian header size bounds check, UTF-8 JSON tensor descriptor validation, offset contiguity check, pickle/zip spoofing detection | Inspects headers statically without loading tensor weights into RAM or executing Python/`trust_remote_code`. |
| **LLM Release Gate Report** | `https://github.com/devenes/llm-release-gate` | `llm-release-gate.report/v1` | **Full Adapter & Cryptographic Evidence Binding** | Strict JSON schema validation, `candidate.metadata["model_bundle_id"]` binding check, detached DSSE signature verification | Unmodified legacy `llm-release-gate` reports lack `model_bundle_id` and signatures, and therefore evaluate to `UNBOUND` / `BLOCKED` under strict policy. |
| **Protect AI ModelScan** | `https://github.com/protectai/modelscan` | JSON Report v1 (`modelscan -r json`) | **Optional Report Ingestion & Subprocess Interface** | Validates scan report digest, severity counts, and scanned file correspondence | `modelscan` CLI is not installed on host; optional in default policy (`scanner.required: false`), fails closed (`BLOCKED`) when `scanner.required: true` and evidence is missing. |

---

## 2. Guarantee Separation Matrix

`ai-model-provenance-gate` strictly separates security guarantees and never conflates one with another:

| Guarantee | What Establishes It | What It Does NOT Prove |
|---|---|---|
| **Artifact Integrity** | Deterministic `bundle-identity/v1` manifest & file SHA-256 digests | Does not prove who created the model, whether it is safe, or whether it passed behavioral evaluation. |
| **Artifact Authenticity** | Valid cryptographic signature (OMS v1.0 / DSSE) over the exact file digests | Does not prove the signer is authorized unless verified against configured trusted signers. |
| **Signer Trust** | Public key fingerprint / identity matching policy `trusted_signers` | Does not prove behavioral quality or absence of prompt injection/regression. |
| **Artifact Provenance** | Verified upstream lineage (`adapter_config.json` + verified base model bundle digest or upstream SLSA provenance) | A declared `base_model_name_or_path` string without a verified base model bundle digest is only `DECLARED_UNVERIFIED`. |
| **Security Scan Evidence** | Bound ModelScan report + static Safetensors/pickle header inspection | Does not establish behavioral safety, alignment, or evaluation quality. |
| **Model Behavioral Evaluation** | `llm-release-gate.report/v1` (`PASS`, `COMPLETE`) cryptographically bound to `model_bundle_id` and signed by a trusted evaluator | Does not apply to any other model bundle or modified tokenizer/adapter. |
| **Release Qualification** | Signed in-toto v1 Release Qualification Attestation binding bundle ID, BOM digest, OMS status, evaluation digest, and policy digest | Does not verify runtime container image or serving configuration unless Deployment Composition Verification is executed. |
| **Deployment Identity** | `deployment-composition/v1` binding `model_bundle_id`, immutable OCI runtime image `@sha256:...` digest, serving config digest, and active adapters | Does not verify live cluster state or runtime memory integrity inside Kubernetes. |
