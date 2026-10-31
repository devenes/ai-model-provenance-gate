# AI Model Provenance Gate Report (`gate-evaluate`)

- **Gate Status:** `PASS` (Exit Code `0`)
- **Timestamp:** `2026-10-31T05:42:27Z`
- **Tool Version:** `0.1.0-rc.1` (`darwin/arm64`)
- **Model Bundle Identity (`bundle-identity/v1`):** `sha256:2c5f9757efe8c44d095cb3969c166928ccfaefc7cf80fc2b1ef8639505347adb`
- **CycloneDX AI/ML-BOM Digest:** `sha256:0905e056c13a1df219d5d4decd5283ac3897ef60df618f9cf57d085b135e8a32`
- **Release Qualification Attestation Digest:** `sha256:5b7ad472598459972ff17765bf7197881cb36b75f1d98478f419cd2295829976`
- **Policy:** `rc1-strict-policy` (mode=`strict`, digest=`sha256:9b24240cc0267d6915786785ebc02cac0afbe374fe2e8e8a8406b4d75e2ce95b`)

---

## 1. Security Guarantee Separation Matrix

| Security Guarantee | Observed / Verified Status |
|---|---|
| **Artifact Integrity** | VERIFIED (bundle_id=sha256:2c5f9757efe8c44d095cb3969c166928ccfaefc7cf80fc2b1ef8639505347adb, files=8) |
| **Artifact Authenticity** | OMS_VERIFIED (https://model_signing/signature/v1.0) |
| **Signer Trust** | OMS_SIGNER=model-signer-1 (sha256:6d7c55a006110aa89381a96fa9bb33090db535aa13a1ba6d14f96cc2bb793854) |
| **Artifact Provenance** | LORA=DECLARED_UNVERIFIED, UPSTREAM_SLSA=NOT_RUN |
| **Security Scan Evidence** | SCANNER=NOT_RUN (static_safetensors_safe=true; does NOT establish behavioral safety) |
| **Model Behavioral Evaluation** | STATUS=PASS, BINDING=MATCHED, TRUST=VERIFIED_TRUSTED (runId=run-rc1-smoke-001) |
| **Release Qualification** | QUALIFIED_AND_SIGNED (DSSE digest=sha256:5b7ad472598459972ff17765bf7197881cb36b75f1d98478f419cd2295829976, signer=sha256:ef385f7bc28ac44e805a621e0da4a753b65475ad40d1b64473ac280c2a0c07c1) |
| **Deployment Identity** | PENDING_DEPLOYMENT_VERIFICATION (run `release verify` prior to serving) |

> **Note:** Each security guarantee is evaluated independently. A SHA-256 digest does not prove origin; a valid BOM or signature does not prove behavioral safety; an unbound evaluation `PASS` does not qualify a model bundle.

## 2. Model Bundle Inventory Summary

- **Primary Format:** `huggingface-safetensors+peft-lora`
- **File Count:** `8` regular files (`1104` bytes total)
- **Manifest Digest:** `sha256:27fe73020c39f523e851b738fd7888a1f411935240642b2ce4919343e10b554f`
- **Sharded Weights:** `false` (`0` shards, `2` tensors)
- **LoRA / PEFT Status:** `DECLARED_UNVERIFIED`

| Relative Path | Role | Size (Bytes) | SHA-256 Digest |
|---|---|---:|---|
| `adapter_config.json` | `lora_config` | 262 | `sha256:6c4f7b8ea6fc856042d45710cee3e0aba8bd15177a522a4697861c849f29632c` |
| `adapter_model.safetensors` | `lora_weights` | 150 | `sha256:c585aa0986f7f5160ddb9a06dc326ea9d14a0db081968d0d98d3f6ce1334f32a` |
| `chat_template.jinja` | `chat_template` | 86 | `sha256:f4d1104c5ba32eb68635cd14e885f1a97ff2a3ccb592e8c43c9ddadf17e527ba` |
| `config.json` | `model_config` | 227 | `sha256:ddfe37df2fe5d519ffb491d34fcfd561447638927ed837bad793a55687d9622c` |
| `model.safetensors` | `model_weights` | 166 | `sha256:260f32873456c0f6fcdb904d700f00e364e63b7768d6a8a8b7ac9de6ebaba7cb` |
| `special_tokens_map.json` | `special_tokens` | 39 | `sha256:eca4fc6cd74e0f8e3d429064f09c1462e11bcf5e3f9a0a5dff8a3ccdf5ef7eca` |
| `tokenizer.json` | `tokenizer_vocab` | 95 | `sha256:d611fe64b1902a3eb4fa0b64b1ea447b4e20711238587b66def7dc15f31b1839` |
| `tokenizer_config.json` | `tokenizer_config` | 79 | `sha256:d571c6ab7534df1578ff3957701aa540c0d5aa0ceed9d3be4676368d99d5cfeb` |

## 3. Decision Reasons

| Status | Severity | Category | Code | Message |
|---|---|---|---|---|
| `PASS` | `info` | `bundle` | `BUNDLE_IDENTITY_DETERMINISTIC` | computed deterministic model bundle identity sha256:2c5f9757efe8c44d095cb3969c166928ccfaefc7cf80fc2b1ef8639505347adb (8 files, 1104 bytes) |
| `PASS` | `warning` | `lora` | `LORA_BASE_MODEL_DECLARED_UNVERIFIED` | base_model_name_or_path="meta-llama/Llama-3-8B" (revision="043235d6088ecd3dd5fb5ca3592b6913fd516027") is declared in adapter_config.json without cryptographic verification of base model weights |
| `PASS` | `info` | `bom` | `CYCLONEDX_BOM_VALIDATED` | validated CycloneDX 1.7 AI/ML-BOM (sha256:0905e056c13a1df219d5d4decd5283ac3897ef60df618f9cf57d085b135e8a32) with 1:1 file inventory correspondence |
| `PASS` | `info` | `signing` | `OMS_SIGNATURE_VERIFIED` | verified OMS signature (https://model_signing/signature/v1.0) by trusted signer "model-signer-1" (sha256:6d7c55a006110aa89381a96fa9bb33090db535aa13a1ba6d14f96cc2bb793854) |
| `PASS` | `info` | `evaluation` | `EVALUATION_QUALIFIED` | evaluation PASS verified (runId=run-rc1-smoke-001, binding=MATCHED, mode=NATIVE_CI_EVALUATOR, trust=VERIFIED_TRUSTED) |
| `PASS` | `info` | `deployment` | `RUNTIME_IMAGE_IMMUTABLE` | verified immutable runtime image digest "ghcr.io/vllm/vllm-openai@sha256:7777777777777777777777777777777777777777777777777777777777777777" |

