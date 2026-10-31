# Security Limitations and Operational Boundaries

`ai-model-provenance-gate` is designed for high-assurance artifact identity, evidence binding, and offline cryptographic verification. Operators and security architects must understand the following explicit boundaries:

## 1. Point-in-Time Local Filesystem Verification (Post-Scan TOCTOU)
- During execution, `ai-model-provenance-gate` detects concurrent file mutations (`ErrConcurrentMutation`) by comparing pre-open `os.Lstat`, open file descriptor `Stat()`, bytes streamed, and post-read `Lstat`/`Stat()` sizes, inodes, and modification times.
- **Limitation:** No user-space CLI can prevent a privileged local process from modifying files on disk *after* the CLI process terminates.
- **Operational Control:** Run `ai-model-provenance release verify` immediately prior to container packaging or model loading in an isolated, read-only staging mount.

## 2. Static Header Inspection vs. Deep Weight Analysis
- `ai-model-provenance-gate` validates `.safetensors` binary headers (header byte length bounds, UTF-8 JSON validity, dtype validity, contiguous `data_offsets`, and absence of Pickle/ZIP magic bytes) and streams raw tensor bytes through `crypto/sha256`.
- **Limitation:** Static inspection does not detect neural trojans, sleeper backdoors, or fine-tuning poisoning encoded purely as valid floating-point tensor weights. Behavioral and regression testing must be performed via [`llm-release-gate`](https://github.com/devenes/llm-release-gate) and bound to the model bundle identity.

## 3. External Tooling & Offline Key Management
- Offline signature verification (`oms verify`, `gate evaluate`, `release verify`) requires that trusted public keys be provisioned and protected via configuration (`policy.yaml` / `--public-key`). If an attacker can modify `policy.yaml` or replace the trusted public key files on the verification host, they can substitute their own trust root.
- **Operational Control:** Pin `key_fingerprint: "sha256:<64-hex>"` in `policy.yaml` and verify the `policy_digest` recorded in `release-qualification/v1` attestations.

## 4. SLSA Build Provenance Scope
- `ai-model-provenance-gate` is a post-hoc inspection and release qualification gate, **not** an isolated training or build execution service.
- Issuing a `release-qualification/v1` in-toto attestation does **not** constitute SLSA Build Level compliance. Upstream SLSA provenance (`https://slsa.dev/provenance/v1`) must be emitted by the training/build platform itself and can then be verified by `ai-model-provenance-gate`.

## 5. Local Deployment Descriptor vs. Live Cluster State
- In the MVP release, `ai-model-provenance release verify` validates the local deployment composition descriptor (`deployment.yaml`), serving configuration file digest, immutable OCI image reference (`@sha256:...`), and local model bundle directory.
- It does **not** query a live Kubernetes API server or inspect running container memory. Live cluster/infrastructure conformance is the responsibility of [`ai-platform-conformance-kit`](https://github.com/devenes/ai-platform-conformance-kit).
