# Artifact Identity Specification

## 1. Two Mandatory, Non-Interchangeable Identities

`ai-model-provenance-gate` defines and enforces two distinct cryptographic identities that must **never** be confused or substituted for one another:

| Identity | Schema Identifier | Scope | Changes When |
|---|---|---|---|
| **Model Bundle Identity** | `bundle-identity/v1` | All regular files in the local model bundle directory (weights, shards, index, `config.json`, tokenizers, vocabularies, chat templates, LoRA configs/weights, quantization metadata, and any unknown regular files). | Any byte of any file is altered, any file is renamed/added/removed, or any file size changes. |
| **Deployment Composition Identity** | `deployment-composition/v1` | The qualified `Model Bundle Identity` + optional `Base Model Bundle Identity` + immutable OCI runtime container image digest (`@sha256:...`) + serving configuration digest + runtime profile & active adapter selection. | The model bundle changes **OR** the container image digest, serving flags/config, or active LoRA adapter mapping changes. |

---

## 2. Deterministic Model Bundle Identity (`bundle-identity/v1`)

### 2.1 Path Normalization & Collision Detection Rules
For every entry discovered under the bundle root directory:
1. **No Absolute Paths:** Paths are computed strictly relative to the resolved bundle root directory.
2. **POSIX Separator Normalization:** Platform path separators are converted to forward slashes (`/`), and leading `./` prefixes are stripped.
3. **Traversal & Segment Rejection:** Any relative path that is empty, starts with `/`, contains `..` segments, contains NUL bytes (`\x00`), or contains control characters (`< 0x20` or `0x7F`) is rejected immediately.
4. **Unicode Normalization & Case/Collision Detection:**
   - Relative paths must be valid UTF-8.
   - To prevent cross-platform macOS (APFS NFD/case-insensitive) vs Linux (ext4/xfs byte-exact) ambiguity, the inspector normalizes paths to Unicode **NFC** for canonical comparison and checks for both **NFC-equivalent collisions** and **case-folding collisions** (`strings.ToLower`). If two distinct filesystem entries collide under NFC or ASCII case-folding, inspection fails closed (`PATH_COLLISION`).
5. **No Silent Omission:** Every regular file inside the bundle root is included in `files[]`. Unknown regular files are classified with `role: "unknown_file"` and included in the manifest and bundle identity calculation.
6. **External Output Isolation:** Generated manifests, BOMs, attestations, and reports must be written outside the inspected bundle root directory. If the user specifies an `--output` path inside `--bundle`, the CLI rejects the command before touching the filesystem (`OUTPUT_INSIDE_BUNDLE`).

### 2.2 Canonical Manifest Structure (`bundle-identity/v1`)
The canonical identity hash input is an RFC 8785 (JSON Canonicalization Scheme - JCS) byte representation of the `CanonicalIdentityDocument`:

```json
{
  "files": [
    {
      "path": "config.json",
      "role": "model_config",
      "sha256": "sha256:...",
      "size": 612
    },
    {
      "path": "model.safetensors",
      "role": "model_weights",
      "sha256": "sha256:...",
      "size": 4096
    }
  ],
  "schema_version": "bundle-identity/v1"
}
```

- `files` is sorted in strict lexicographical UTF-8 byte order of `path`.
- Under RFC 8785 (JCS):
  - Object keys are sorted lexicographically by UTF-16 code units (for ASCII keys, identical to UTF-8 byte order).
  - No insignificant whitespace is emitted.
  - Integers (`size`) are formatted as base-10 integers without leading zeros, exponents, or fractions.
- **Model Bundle Identity (`bundle_id`):**
  $$\text{bundle\_id} = \text{"sha256:"} \mathbin{\Vert} \text{HEX}(\text{SHA256}(\text{JCS}(\text{CanonicalIdentityDocument})))$$
- **Full Manifest (`bundle-manifest.json`):**
  Includes the canonical `files` array, `schema_version: "bundle-identity/v1"`, `bundle_id`, plus rich static inspection metadata (`format_summary`, `safetensors_headers`, `lora_relationship`, `metadata_provenance`), which is hashed separately as `manifest_digest`. Keeping environment timestamps and informational notes out of `CanonicalIdentityDocument` guarantees that the exact same model bundle produces the exact same `bundle_id` across any machine, OS, directory location, or time of day.

---

## 3. File-System Safety & TOCTOU Protections

1. **Symlink Rejection:** Uses `os.Lstat` during traversal and rejects symbolic links (`fs.ModeSymlink`) by default (`SYMLINK_REJECTED`), preventing symlink escape attacks outside the bundle root.
2. **Special File Rejection:** Rejects device nodes, named pipes (FIFOs), sockets, and irregular files (`UNSUPPORTED_FILE_TYPE`).
3. **Streaming SHA-256 with Mid-Hash Mutation Detection:**
   - Before reading a file, `os.Lstat` records `pre_size`, `pre_mode`, and `pre_mtime`.
   - File contents are streamed through `crypto/sha256` using a fixed 64 KiB buffer (`io.CopyBuffer`) while counting exact bytes read (`bytes_read`).
   - After EOF, `file.Stat()` and `os.Lstat(path)` record `post_size`, `post_mode`, and `post_mtime`.
   - If `bytes_read != pre_size`, `pre_size != post_size`, or `pre_mtime != post_mtime`, the digest engine aborts with `CONCURRENT_FILE_MUTATION` (TOCTOU detected).
4. **Remaining TOCTOU Limitation:**
   A local CLI scan verifies the artifact state at the time of inspection/verification. It cannot prevent an attacker with local write privileges from modifying files *after* the CLI process exits. Therefore, `ai-model-provenance-gate release verify` re-computes the streaming SHA-256 inventory and `bundle_id` immediately prior to deployment handoff.

---

## 4. LoRA / PEFT Relationship Verification States

Base models and LoRA/PEFT adapters are modeled as separate components. When `adapter_config.json` is present, its base model relationship is evaluated into one of four explicit states:

| State | Meaning |
|---|---|
| `VERIFIED` | `adapter_config.json` is present, a base model bundle (or expected base model `bundle_id`) was supplied, and the computed `bundle-identity/v1` of the base model matches the expected base model digest. |
| `DECLARED_UNVERIFIED` | `adapter_config.json` declares `base_model_name_or_path` (and optional `revision`), but the cryptographic `bundle-identity/v1` of the base model weights has not been verified against local base model files. |
| `MISSING` | The bundle contains adapter weights (`adapter_model.safetensors`) or `adapter_config.json`, but `base_model_name_or_path` is missing/empty. |
| `MISMATCH` | A base model bundle or expected base model digest/architecture was supplied for verification, and the observed base model `bundle_id` or architecture family conflicts with the adapter. |
