# End-to-End Validation Guide

## 1. Product Thesis Demonstration

The end-to-end validation scenario (`scripts/run-e2e-demo.sh` and `TestEndToEndProductThesisLifecycle` in `internal/cli/cli_test.go`) executes all 14 mandatory steps using a synthetic local Hugging Face + Safetensors + PEFT LoRA model bundle:

1. **Create a local model bundle** (`config.json`, `model.safetensors`, `tokenizer_config.json`, `tokenizer.json`, `special_tokens_map.json`, `chat_template.jinja`, `adapter_config.json`, `adapter_model.safetensors`).
2. **Inspect the model** (`ai-model-provenance inspect`).
3. **Generate its deterministic identity** (`bundle-identity/v1` via RFC 8785 JCS).
4. **Generate and validate its CycloneDX 1.7 AI/ML-BOM** (`ai-model-provenance bom generate` & `bom validate`).
5. **Create a valid OMS v1.0-signed model bundle** with an ephemeral controlled test key (`ai-model-provenance oms sign`).
6. **Verify the model signature and trusted signer** (`ai-model-provenance oms verify`).
7. **Bind and sign `llm-release-gate.report/v1` evaluation evidence** to the exact `model_bundle_id` (`ai-model-provenance evidence bind-eval`).
8. **Evaluate the strict release policy** (`ai-model-provenance gate evaluate`).
9. **Produce release qualification evidence** (`gate-report.json`, `gate-report.md`, `bom.cdx.json`, `bundle-manifest.json`).
10. **Sign and verify the `release-qualification/v1` in-toto DSSE attestation**.
11. **Copy the approved deployment fixture and run `release verify`** $\rightarrow$ **`PASS` (Exit Code `0`)**.
12. **Tamper with the deployment bundle's `tokenizer.json` (and LoRA adapter)**.
13. **Re-run `ai-model-provenance release verify`**.
14. **Verify that the modified deployment artifact is rejected** $\rightarrow$ **`FAIL` (Exit Code `1`, `DEPLOYMENT_ARTIFACT_TAMPERED`)**.

## 2. Running the Demonstration Locally

```bash
make e2e
```
or directly:
```bash
./scripts/run-e2e-demo.sh
```

Note: Ephemeral private signing keys generated during the E2E run are stored in a temporary directory and destroyed immediately upon script exit so that **no private keys are ever stored inside the repository**.
