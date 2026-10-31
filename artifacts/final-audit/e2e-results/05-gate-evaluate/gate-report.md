# AI Model Provenance Gate Report (`gate-evaluate`)

- **Gate Status:** `PASS` (Exit Code `0`)
- **Timestamp:** `2026-10-30T23:17:03Z`
- **Tool Version:** `0.1.0` (`darwin/arm64`)
- **Model Bundle Identity (`bundle-identity/v1`):** `sha256:5cf4da3cb4001a33d87d0dcd06439061bf9b293ad2bcdcf7fc7ba4411887e61a`
- **CycloneDX AI/ML-BOM Digest:** `sha256:d6b6d91c092149f824eb83d27f4c0fd32ad5aae33e731e54023bd29c41a82f30`
- **Release Qualification Attestation Digest:** `sha256:5672afb6d05fb875d4dad3ee80b044ead9b562f2eca137ce2e1dd8eb5c9dd6d6`
- **Policy:** `final-audit-strict-policy` (mode=`strict`, digest=`sha256:8d03a624eeb133833230c14056f6df039be455e3e49b811e2c8bfd2bad996434`)

---

## 1. Security Guarantee Separation Matrix

| Security Guarantee | Observed / Verified Status |
|---|---|
| **Artifact Integrity** | VERIFIED (bundle_id=sha256:5cf4da3cb4001a33d87d0dcd06439061bf9b293ad2bcdcf7fc7ba4411887e61a, files=8) |
| **Artifact Authenticity** | OMS_VERIFIED (https://model_signing/signature/v1.0) |
| **Signer Trust** | OMS_SIGNER=test-model-signer-1 (sha256:5615ffbcb4ab11bfc6c31871c53d5b2ed340c68cf4a0f5d5e3a2afecb980b2c9) |
| **Artifact Provenance** | LORA=DECLARED_UNVERIFIED, UPSTREAM_SLSA=NOT_RUN |
| **Security Scan Evidence** | SCANNER=NOT_RUN (static_safetensors_safe=true; does NOT establish behavioral safety) |
| **Model Behavioral Evaluation** | STATUS=PASS, BINDING=MATCHED, TRUST=VERIFIED_TRUSTED (runId=run-e2e-final-audit-001) |
| **Release Qualification** | QUALIFIED_AND_SIGNED (DSSE digest=sha256:5672afb6d05fb875d4dad3ee80b044ead9b562f2eca137ce2e1dd8eb5c9dd6d6, signer=sha256:6387843b1d3507615d31cf66e2c33e558d780cb5bec210c19aff5377becb0d65) |
| **Deployment Identity** | PENDING_DEPLOYMENT_VERIFICATION (run `release verify` prior to serving) |

> **Note:** Each security guarantee is evaluated independently. A SHA-256 digest does not prove origin; a valid BOM or signature does not prove behavioral safety; an unbound evaluation `PASS` does not qualify a model bundle.

## 2. Model Bundle Inventory Summary

- **Primary Format:** `huggingface-safetensors+peft-lora`
- **File Count:** `8` regular files (`1194` bytes total)
- **Manifest Digest:** `sha256:9a6f91acaeafd8b4a3dd84268f3fd1b00b27961a6241e6165a759e6ca2ce3bf5`
- **Sharded Weights:** `false` (`0` shards, `2` tensors)
- **LoRA / PEFT Status:** `DECLARED_UNVERIFIED`

| Relative Path | Role | Size (Bytes) | SHA-256 Digest |
|---|---|---:|---|
| `adapter_config.json` | `lora_config` | 262 | `sha256:6c4f7b8ea6fc856042d45710cee3e0aba8bd15177a522a4697861c849f29632c` |
| `adapter_model.safetensors` | `lora_weights` | 150 | `sha256:c585aa0986f7f5160ddb9a06dc326ea9d14a0db081968d0d98d3f6ce1334f32a` |
| `chat_template.jinja` | `chat_template` | 86 | `sha256:a391b8b64fee310563afc6c4a493bd8d4ba31356eaa6fa62e1883f66049dce4b` |
| `config.json` | `model_config` | 323 | `sha256:d6b1d5424f6f342c10c03d4e7c786721f07fc329cbe4736860d631e42f612b5c` |
| `model.safetensors` | `model_weights` | 166 | `sha256:260f32873456c0f6fcdb904d700f00e364e63b7768d6a8a8b7ac9de6ebaba7cb` |
| `special_tokens_map.json` | `special_tokens` | 39 | `sha256:eca4fc6cd74e0f8e3d429064f09c1462e11bcf5e3f9a0a5dff8a3ccdf5ef7eca` |
| `tokenizer.json` | `tokenizer_vocab` | 95 | `sha256:d611fe64b1902a3eb4fa0b64b1ea447b4e20711238587b66def7dc15f31b1839` |
| `tokenizer_config.json` | `tokenizer_config` | 73 | `sha256:9a47466be4cb43e20cf62aaa04bad6a732cea00f09e3be64c68091507a480639` |

## 3. Decision Reasons

| Status | Severity | Category | Code | Message |
|---|---|---|---|---|
| `PASS` | `info` | `bundle` | `BUNDLE_IDENTITY_DETERMINISTIC` | computed deterministic model bundle identity sha256:5cf4da3cb4001a33d87d0dcd06439061bf9b293ad2bcdcf7fc7ba4411887e61a (8 files, 1194 bytes) |
| `PASS` | `warning` | `lora` | `LORA_BASE_MODEL_DECLARED_UNVERIFIED` | base_model_name_or_path="meta-llama/Llama-3-8B" (revision="043235d6088ecd3dd5fb5ca3592b6913fd516027") is declared in adapter_config.json without cryptographic verification of base model weights |
| `PASS` | `info` | `bom` | `CYCLONEDX_BOM_VALIDATED` | validated CycloneDX 1.7 AI/ML-BOM (sha256:d6b6d91c092149f824eb83d27f4c0fd32ad5aae33e731e54023bd29c41a82f30) with 1:1 file inventory correspondence |
| `PASS` | `info` | `signing` | `OMS_SIGNATURE_VERIFIED` | verified OMS signature (https://model_signing/signature/v1.0) by trusted signer "test-model-signer-1" (sha256:5615ffbcb4ab11bfc6c31871c53d5b2ed340c68cf4a0f5d5e3a2afecb980b2c9) |
| `PASS` | `info` | `evaluation` | `EVALUATION_QUALIFIED` | evaluation PASS verified (runId=run-e2e-final-audit-001, binding=MATCHED, mode=NATIVE_CI_EVALUATOR, trust=VERIFIED_TRUSTED) |
| `PASS` | `info` | `deployment` | `RUNTIME_IMAGE_IMMUTABLE` | verified immutable runtime image digest "ghcr.io/vllm/vllm-openai@sha256:7777777777777777777777777777777777777777777777777777777777777777" |

