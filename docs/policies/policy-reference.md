# Policy Configuration Reference (`policy/v1`)

`ai-model-provenance-gate` uses a strict, fail-closed YAML policy configuration validated against [`schemas/policy/policy.schema.json`](../../schemas/policy/policy.schema.json). Unknown YAML fields are rejected at parse time (`yaml.Decoder.KnownFields(true)`).

---

## 1. Complete Policy Example

```yaml
schema_version: "v1"
name: "production-strict-policy"

bundle:
  reject_symlinks: true
  require_deterministic_identity: true
  allow_unknown_files: false
  require_verified_lora_base: false

signing:
  require_oms: true
  oms_mode: "native" # "native" (default) or "external-cli"
  trusted_signers:
    - id: "model-builder-key-1"
      name: "AI Training Pipeline Signer"
      key_id: "model-signer-1"
      key_fingerprint: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
      public_key_path: "./keys/model-signer.pub"

evaluation:
  required: true
  required_status: PASS
  require_artifact_binding: true
  require_trusted_evidence: true
  trusted_signers:
    - id: "eval-gate-key-1"
      name: "LLM Release Gate CI Signer"
      key_id: "eval-signer-1"
      public_key_path: "./keys/eval-signer.pub"

provenance:
  require_upstream_slsa: false
  trusted_builders:
    - "https://github.com/devenes/training-pipeline/.github/workflows/train.yml"

scanner:
  required: false

deployment:
  require_immutable_image: true
  require_serving_config: true
  allowed_adapters:
    - "support-lora-v2"

release:
  decision_mode: strict # "strict" or "permissive"
  require_signed_qualification: true
  trusted_signers:
    - id: "release-authority-key-1"
      name: "Platform Security Release Authority"
      key_id: "release-signer-1"
      public_key_path: "./keys/release-signer.pub"
```

---

## 2. Fail-Closed Rules in `strict` Mode

Under `release.decision_mode: strict`:
- **Missing required OMS signature** $\rightarrow$ `BLOCKED` (exit code `3`)
- **Invalid OMS signature or file digest mismatch** $\rightarrow$ `FAIL` (exit code `1`)
- **Untrusted OMS signer** $\rightarrow$ `FAIL` (exit code `1`)
- **Missing mandatory evaluation report** $\rightarrow$ `BLOCKED` (exit code `3`)
- **Unbound evaluation report (`missing model_bundle_id`)** $\rightarrow$ `BLOCKED` (exit code `3`)
- **Unsigned evaluation report (`UNVERIFIED_LOCAL_JSON`)** $\rightarrow$ `BLOCKED` (exit code `3`)
- **Mismatched evaluation `model_bundle_id`** $\rightarrow$ `FAIL` (exit code `1`)
- **Failed evaluation (`gateStatus: FAIL`)** $\rightarrow$ `FAIL` (exit code `1`)
- **Required scanner not run** $\rightarrow$ `BLOCKED` (exit code `3`)
- **Mutable runtime image tag (missing `@sha256:<64-hex>`)** $\rightarrow$ `FAIL` (exit code `1`)
- **Policy exceptions (`release.exceptions`)** $\rightarrow$ Rejected at policy validation time in `strict` mode; only permitted when `decision_mode: permissive`, where every applied exception is recorded in the attestation and report.
