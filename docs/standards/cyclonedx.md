# CycloneDX AI/ML-BOM Standard Reference

## 1. Official Sources
- **CycloneDX Homepage:** https://cyclonedx.org/
- **CycloneDX Specification Repository:** https://github.com/CycloneDX/specification
- **CycloneDX AI/ML-BOM Capability Guide:** https://cyclonedx.org/capabilities/mlbom/
- **Official JSON Schemas:**
  - CycloneDX 1.6 (ECMA-424 1st Ed.): `http://cyclonedx.org/schema/bom-1.6.schema.json`
  - CycloneDX 1.7 (ECMA-424 2nd Ed.): `http://cyclonedx.org/schema/bom-1.7.schema.json`
- **Package URL (PURL) Specification:** https://github.com/package-url/purl-spec

## 2. Schema Version Selection
`ai-model-provenance-gate` supports generating **CycloneDX 1.6** (`specVersion: "1.6"`, `$schema: "http://cyclonedx.org/schema/bom-1.6.schema.json"`) and **CycloneDX 1.7** (`specVersion: "1.7"`, `$schema: "http://cyclonedx.org/schema/bom-1.7.schema.json"`), defaulting to `1.7` (configurable via `--spec-version 1.6|1.7`).

Both versions define identical core structures for `machine-learning-model` components, `modelCard`, `pedigree`, `components`, `hashes`, `externalReferences`, and `dependencies`.

## 3. Supported AI/ML-BOM Fields & Mapping Rules

### 3.1 Top-Level BOM Envelope
- `bomFormat`: `"CycloneDX"`
- `specVersion`: `"1.7"` (or `"1.6"`)
- `serialNumber`: Deterministic or RFC 4122 UUID URN (`urn:uuid:...`) derived from the bundle identity so repeated deterministic runs produce reproducible BOMs when `--deterministic` is active.
- `version`: `1`
- `metadata`:
  - `timestamp`: RFC 3339 UTC timestamp.
  - `tools.components`: Identifies `ai-model-provenance-gate` (`type: "application"`).
  - `component`: The primary `machine-learning-model` component representing the inspected model bundle.

### 3.2 Primary `machine-learning-model` Component
- `type`: `"machine-learning-model"`
- `bom-ref`: `"model-bundle:<sha256-hex>"`
- `name`: Observed bundle name or declared model identifier.
- `version`: Observed revision or bundle digest prefix.
- `hashes`: `[{"alg": "SHA-256", "content": "<64-hex-bundle-identity>"}]`
- `modelCard`:
  - `modelParameters.architectureFamily`: Populated **only** when observed in `config.json` (`model_type`, e.g., `"llama"`, `"mistral"`, `"qwen2"`).
  - `modelParameters.modelArchitecture`: Populated **only** when observed in `config.json` (`architectures[0]`, e.g., `"LlamaForCausalLM"`).
  - `modelParameters.task`: Populated **only** when observed in `adapter_config.json` (`task_type`) or `config.json` (`architectures`).
- `properties`:
  - Explicitly distinguishes `"provenance:source": "observed"` vs `"provenance:source": "declared_unverified"` for metadata fields.
  - Records bundle identity (`provenance:model_bundle_id`), format classification, tensor count, total weight bytes, quantization metadata (if observed in `config.json` `quantization_config`), and LoRA relationship state (`VERIFIED`, `DECLARED_UNVERIFIED`, `MISSING`, `MISMATCH`).

### 3.3 File & Sub-Component Inventory (`components` & `dependencies`)
Every regular file in the deterministic inventory is represented in `components`:
- Model weights (`.safetensors`), shards (`model-00001-of-00002.safetensors`), index (`model.safetensors.index.json`), configuration (`config.json`, `generation_config.json`), tokenizer files (`tokenizer.json`, `tokenizer_config.json`, `special_tokens_map.json`, vocabularies, `chat_template.jinja`), and unknown regular files are emitted with:
  - `type`: `"file"` (or `"machine-learning-model"` for a distinct LoRA adapter sub-component)
  - `bom-ref`: `"file:<normalized-relative-path>"`
  - `name`: `<normalized-relative-path>`
  - `hashes`: `[{"alg": "SHA-256", "content": "<64-hex-file-sha256>"}]`
  - `properties`: Component role classification (`model_weights`, `weight_shard`, `weight_index`, `model_config`, `tokenizer_config`, `tokenizer_vocab`, `chat_template`, `lora_config`, `lora_weights`, `quantization_config`, `unknown_file`), file size in bytes, and metadata provenance (`observed`).

### 3.4 LoRA / PEFT Adapter and Base Model Relationship (`pedigree` & `dependencies`)
When `adapter_config.json` is present:
- A dedicated component (`type: "machine-learning-model"`, `bom-ref: "component:lora-adapter"`) represents the PEFT/LoRA adapter with its observed `peft_type`, rank `r`, `lora_alpha`, and `target_modules`.
- The base model reference (`base_model_name_or_path` and optional `revision`) is recorded in `pedigree.ancestors` with an explicit property `"provenance:verification_status"` set to one of:
  - `VERIFIED` (when a base model bundle was provided and its computed `bundle-identity/v1` matches the expected base model digest)
  - `DECLARED_UNVERIFIED` (when `base_model_name_or_path` is declared in `adapter_config.json` without cryptographic verification of the base model files)
  - `MISSING` (when `adapter_config.json` lacks `base_model_name_or_path`)
  - `MISMATCH` (when the supplied base model bundle digest does not match the expected base model digest)

### 3.5 Non-Invention Rules
- **Licenses:** Only populated in `licenses` if explicitly declared in an observed metadata file; accompanied by `"provenance:license_verification": "declared_unverified"`. Never fabricated if absent.
- **Filenames:** Never treated as proof of model origin or identity.
