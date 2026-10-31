# AI Model Provenance Gate Report (`gate-evaluate`)

- **Gate Status:** `PASS` (Exit Code `0`)
- **Timestamp:** `2026-10-31T05:35:58Z`
- **Tool Version:** `0.1.0-rc.1` (`darwin/arm64`)
- **Model Bundle Identity (`bundle-identity/v1`):** `sha256:c0a72555e7a14d64e27e5f559b14a2c564d502064043e8a2e5cbca8130d9a3e4`
- **CycloneDX AI/ML-BOM Digest:** `sha256:065090c31b2029868e23e3f0e45fa7a64bd62d34470427b6889e766cc44ccbb1`
- **Release Qualification Attestation Digest:** `sha256:0c7b4ab6a930dbb5bfa21a947c1ea6a4e0e9e3a74e08b5ebd85abaafa0e942d0`
- **Policy:** `e2e-test-strict-policy` (mode=`strict`, digest=`sha256:86ebc584bed2b313d49771f1ce3db1789dabdb97b5b0ed8143c5e64dc48a930a`)

---

## 1. Security Guarantee Separation Matrix

| Security Guarantee | Observed / Verified Status |
|---|---|
| **Artifact Integrity** | VERIFIED (bundle_id=sha256:c0a72555e7a14d64e27e5f559b14a2c564d502064043e8a2e5cbca8130d9a3e4, files=8) |
| **Artifact Authenticity** | OMS_VERIFIED (https://model_signing/signature/v1.0) |
| **Signer Trust** | OMS_SIGNER=test-model-signer-1 (sha256:6d96519bb0155408eaf7b37ebf541a517ac028523a8a1a6e2ebe071adae3f511) |
| **Artifact Provenance** | LORA=DECLARED_UNVERIFIED, UPSTREAM_SLSA=NOT_RUN |
| **Security Scan Evidence** | SCANNER=NOT_RUN (static_safetensors_safe=true; does NOT establish behavioral safety) |
| **Model Behavioral Evaluation** | STATUS=PASS, BINDING=MATCHED, TRUST=VERIFIED_TRUSTED (runId=run-e2e-demo-001) |
| **Release Qualification** | QUALIFIED_AND_SIGNED (DSSE digest=sha256:0c7b4ab6a930dbb5bfa21a947c1ea6a4e0e9e3a74e08b5ebd85abaafa0e942d0, signer=sha256:2d19512cc4f6f51004a898b2dcbfd76f0a0f0b453dface80b70e808b4030fa55) |
| **Deployment Identity** | PENDING_DEPLOYMENT_VERIFICATION (run `release verify` prior to serving) |

> **Note:** Each security guarantee is evaluated independently. A SHA-256 digest does not prove origin; a valid BOM or signature does not prove behavioral safety; an unbound evaluation `PASS` does not qualify a model bundle.

## 2. Model Bundle Inventory Summary

- **Primary Format:** `huggingface-safetensors+peft-lora`
- **File Count:** `8` regular files (`1200` bytes total)
- **Manifest Digest:** `sha256:0dc06f2fd134f58ef03937a0a730295796c19b6c228cfa0f42c0ffb6b9c938bd`
- **Sharded Weights:** `false` (`0` shards, `2` tensors)
- **LoRA / PEFT Status:** `DECLARED_UNVERIFIED`

| Relative Path | Role | Size (Bytes) | SHA-256 Digest |
|---|---|---:|---|
| `adapter_config.json` | `lora_config` | 262 | `sha256:6c4f7b8ea6fc856042d45710cee3e0aba8bd15177a522a4697861c849f29632c` |
| `adapter_model.safetensors` | `lora_weights` | 150 | `sha256:c585aa0986f7f5160ddb9a06dc326ea9d14a0db081968d0d98d3f6ce1334f32a` |
| `chat_template.jinja` | `chat_template` | 86 | `sha256:f4d1104c5ba32eb68635cd14e885f1a97ff2a3ccb592e8c43c9ddadf17e527ba` |
| `config.json` | `model_config` | 323 | `sha256:d6b1d5424f6f342c10c03d4e7c786721f07fc329cbe4736860d631e42f612b5c` |
| `model.safetensors` | `model_weights` | 166 | `sha256:260f32873456c0f6fcdb904d700f00e364e63b7768d6a8a8b7ac9de6ebaba7cb` |
| `special_tokens_map.json` | `special_tokens` | 39 | `sha256:eca4fc6cd74e0f8e3d429064f09c1462e11bcf5e3f9a0a5dff8a3ccdf5ef7eca` |
| `tokenizer.json` | `tokenizer_vocab` | 95 | `sha256:d611fe64b1902a3eb4fa0b64b1ea447b4e20711238587b66def7dc15f31b1839` |
| `tokenizer_config.json` | `tokenizer_config` | 79 | `sha256:d571c6ab7534df1578ff3957701aa540c0d5aa0ceed9d3be4676368d99d5cfeb` |

## 3. Decision Reasons

| Status | Severity | Category | Code | Message |
|---|---|---|---|---|
| `PASS` | `info` | `bundle` | `BUNDLE_IDENTITY_DETERMINISTIC` | computed deterministic model bundle identity sha256:c0a72555e7a14d64e27e5f559b14a2c564d502064043e8a2e5cbca8130d9a3e4 (8 files, 1200 bytes) |
| `PASS` | `warning` | `lora` | `LORA_BASE_MODEL_DECLARED_UNVERIFIED` | base_model_name_or_path="meta-llama/Llama-3-8B" (revision="043235d6088ecd3dd5fb5ca3592b6913fd516027") is declared in adapter_config.json without cryptographic verification of base model weights |
| `PASS` | `info` | `bom` | `CYCLONEDX_BOM_VALIDATED` | validated CycloneDX 1.7 AI/ML-BOM (sha256:065090c31b2029868e23e3f0e45fa7a64bd62d34470427b6889e766cc44ccbb1) with 1:1 file inventory correspondence |
| `PASS` | `info` | `signing` | `OMS_SIGNATURE_VERIFIED` | verified OMS signature (https://model_signing/signature/v1.0) by trusted signer "test-model-signer-1" (sha256:6d96519bb0155408eaf7b37ebf541a517ac028523a8a1a6e2ebe071adae3f511) |
| `PASS` | `info` | `evaluation` | `EVALUATION_QUALIFIED` | evaluation PASS verified (runId=run-e2e-demo-001, binding=MATCHED, mode=NATIVE_CI_EVALUATOR, trust=VERIFIED_TRUSTED) |
| `PASS` | `info` | `deployment` | `RUNTIME_IMAGE_IMMUTABLE` | verified immutable runtime image digest "ghcr.io/vllm/vllm-openai@sha256:7777777777777777777777777777777777777777777777777777777777777777" |

