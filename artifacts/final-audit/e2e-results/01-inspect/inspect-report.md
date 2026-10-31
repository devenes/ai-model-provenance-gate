# AI Model Provenance Gate Report (`inspect`)

- **Gate Status:** `PASS` (Exit Code `0`)
- **Timestamp:** `2026-10-30T23:17:03Z`
- **Tool Version:** `0.1.0` (`darwin/arm64`)
- **Model Bundle Identity (`bundle-identity/v1`):** `sha256:5cf4da3cb4001a33d87d0dcd06439061bf9b293ad2bcdcf7fc7ba4411887e61a`

---

## 1. Security Guarantee Separation Matrix

| Security Guarantee | Observed / Verified Status |
|---|---|
| **Artifact Integrity** | VERIFIED (sha256:5cf4da3cb4001a33d87d0dcd06439061bf9b293ad2bcdcf7fc7ba4411887e61a over 8 regular files) |
| **Artifact Authenticity** | NOT_EVALUATED (SHA-256 digest does not establish origin or authenticity) |
| **Signer Trust** | NOT_EVALUATED |
| **Artifact Provenance** | LoRA status=DECLARED_UNVERIFIED |
| **Security Scan Evidence** | STATIC_HEADER_ONLY (Safetensors binary headers validated; no behavioral safety implied) |
| **Model Behavioral Evaluation** | NOT_EVALUATED |
| **Release Qualification** | NOT_EVALUATED |
| **Deployment Identity** | NOT_EVALUATED |

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
| `PASS` | `info` | `bundle` | `BUNDLE_INSPECTED` | inspected 8 files (1194 bytes), bundle_id=sha256:5cf4da3cb4001a33d87d0dcd06439061bf9b293ad2bcdcf7fc7ba4411887e61a |

