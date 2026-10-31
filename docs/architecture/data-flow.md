# System Data Flow

## 1. End-to-End Lifecycle Data Flow

```mermaid
sequenceDiagram
    autonumber
    participant User as Engineer / CI Pipeline
    participant CLI as ai-model-provenance
    participant Bundle as Local Model Bundle
    participant Eval as LLM Release Gate Report
    participant Artifacts as Output Artifacts Directory

    Note over User,Artifacts: Stage 1: Model Inspection & BOM Generation
    User->>CLI: inspect --bundle ./model --output ./out
    CLI->>Bundle: Safe Lstat walk + Static Safetensors/HF/PEFT parse
    CLI->>Bundle: Streaming SHA-256 + TOCTOU stat verification
    CLI->>Artifacts: Write bundle-manifest.json (bundle-identity/v1)
    CLI->>Artifacts: Write inspect-report.json & inspect-report.md

    User->>CLI: bom generate --bundle ./model --output ./out/bom.cdx.json
    CLI->>Artifacts: Write CycloneDX 1.7 AI/ML-BOM + validate schema

    Note over User,Artifacts: Stage 2: OMS Verification & Evaluation Binding
    User->>CLI: gate evaluate --bundle ./model --oms-signature ./oms.sig --evaluation-report ./eval.json --policy ./policy.yaml --signing-key ./release.key --output ./out
    CLI->>Bundle: Recompute bundle-identity/v1 (sha256:...)
    CLI->>CLI: Verify OMS v1.0 DSSE signature + trusted signer + 1:1 file digests
    CLI->>Eval: Parse llm-release-gate.report/v1 + check model_bundle_id binding + verify evaluator signature
    CLI->>CLI: Evaluate fail-closed policy (PASS / FAIL / BLOCKED)
    CLI->>Artifacts: Emit signed in-toto Release Qualification Attestation (attestation.dsse.json)
    CLI->>Artifacts: Emit gate-report.json & gate-report.md

    Note over User,Artifacts: Stage 3: Pre-Deployment Composition Verification
    User->>CLI: release verify --bundle ./deploy-model --deployment ./deployment.yaml --attestation ./out/attestation.dsse.json --policy ./policy.yaml --public-key ./release.pub --output ./out-verify
    CLI->>Bundle: Recompute bundle-identity/v1 of deployment model directory
    CLI->>CLI: Verify Release Qualification DSSE signature against trusted release.pub
    CLI->>CLI: Compare deployment bundle_id == attested subject digest == descriptor model_bundle_id
    CLI->>CLI: Verify immutable OCI runtime image digest (@sha256:...), serving config digest, and active LoRA adapters
    CLI->>Artifacts: Emit verify-report.json & verify-report.md (Exit 0 on PASS, Exit 1/3 on Tamper/Mismatch)
```

---

## 2. Artifact Inputs and Outputs by Command

| Command | Primary Inputs | Primary Outputs |
|---|---|---|
| `inspect` | `--bundle <dir>`<br>`[--base-bundle <dir>]` | `bundle-manifest.json` (`bundle-identity/v1`)<br>`inspect-report.json`<br>`inspect-report.md` |
| `bom generate` / `bom validate` | `--bundle <dir>` (or `--bom <file>`) | `bom.cdx.json` (CycloneDX 1.6/1.7 ML-BOM) |
| `oms sign` / `oms verify` | `--bundle <dir>`<br>`--signature <oms.sig>`<br>`--public-key <pub.pem>` (or `--private-key`) | `oms.sig.json` (OMS v1.0 DSSE/Sigstore bundle)<br>`oms-report.json` |
| `evidence bind-eval` | `--bundle <dir>`<br>`--evaluation-report <report.json>`<br>`--private-key <eval.key>` | `evaluation-attestation.dsse.json` (`evaluation-evidence/v1`) |
| `gate evaluate` | `--bundle <dir>`<br>`--policy <policy.yaml>`<br>`[--oms-signature <oms.sig>]`<br>`[--evaluation-report <report.json>]`<br>`[--evaluation-attestation <eval.dsse.json>]`<br>`[--scanner-report <scan.json>]`<br>`[--signing-key <release.key>]` | `release-attestation.dsse.json` (`release-qualification/v1`)<br>`bom.cdx.json`<br>`bundle-manifest.json`<br>`gate-report.json`<br>`gate-report.md` |
| `release verify` | `--bundle <dir>`<br>`--attestation <release-attestation.dsse.json>`<br>`--policy <policy.yaml>`<br>`[--deployment <deployment.yaml>]`<br>`[--public-key <release.pub>]` | `deployment-manifest.json` (`deployment-composition/v1`)<br>`verify-report.json`<br>`verify-report.md` |
