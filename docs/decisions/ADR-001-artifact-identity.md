# ADR-001: Deterministic Model Bundle Identity and Canonical Serialization

- **Status:** Accepted
- **Date:** 2026-10-31
- **Context:** Phase 1 — Architecture and Technical Feasibility

## Context
AI models are multi-file bundles consisting of weight shards (`.safetensors`), shard indices (`model.safetensors.index.json`), model configurations (`config.json`), tokenizers (`tokenizer.json`, `tokenizer_config.json`), chat templates, and optional PEFT/LoRA adapters (`adapter_config.json`, `adapter_model.safetensors`). Standard container or single-blob checksums do not directly address directory-based model bundles, and naive archive hashing (`tar | sha256sum`) breaks determinism due to filesystem enumeration order, inode timestamps, UID/GID metadata, OS path separators, and macOS APFS vs Linux ext4 Unicode normalization differences.

Furthermore, a model bundle identity (`bundle-identity/v1`) must be strictly separated from a deployment composition identity (`deployment-composition/v1`) which additionally binds the OCI runtime container digest, serving configuration digest, and runtime profile.

## Decision
1. **Versioned Contract (`bundle-identity/v1`):**
   We define a canonical identity payload containing `schema_version: "bundle-identity/v1"` and a sorted `files` array where each entry contains `path` (normalized POSIX relative path), `role` (deterministic component classification), `sha256` (`sha256:<64-lowercase-hex>`), and `size` (integer byte length).
2. **RFC 8785 (JSON Canonicalization Scheme - JCS):**
   We serialize the canonical identity payload according to RFC 8785 (deterministic lexicographical key ordering, no whitespace, canonical integer formatting, canonical UTF-8 string escaping) and compute `bundle_id = "sha256:" + hex(sha256(jcs_bytes))`.
3. **Path Normalization & Collision Rejection:**
   - Reject symlinks, special files, absolute paths, `..` traversal, control characters, and non-UTF-8 paths.
   - Normalize paths to Unicode NFC and reject any bundle containing two files whose paths collide under NFC normalization or ASCII case-folding (`strings.ToLower`).
   - Include all unknown regular files as `role: "unknown_file"` so no file in the bundle can bypass identity hashing.
   - Require output directories to reside outside the inspected bundle root to prevent recursive self-hashing.

## Consequences
- **Positive:** Identical model bundle contents produce the exact same `bundle_id` regardless of directory path, filesystem order, timestamps, or operating system (`darwin/arm64` vs `linux/amd64`).
- **Negative / Trade-off:** Any extra file (e.g., an uncleaned `.DS_Store` or scratch file) inside the model directory changes the `bundle_id` or triggers a policy warning/rejection. This is intentional: silent omission of unknown files would allow smuggling unverified payloads inside a signed bundle directory.
