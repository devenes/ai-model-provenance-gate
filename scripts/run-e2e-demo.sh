#!/usr/bin/env bash
# End-to-End Product Thesis Validation Script for AI Model Provenance Gate
# Executes all 14 mandatory E2E steps using synthetic fixtures and ephemeral test keys.
# NOTE: Ephemeral private keys are created in a temporary directory and deleted on exit
# so that no private signing keys are ever stored in the repository.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${ROOT_DIR}/bin/ai-model-provenance"
OUT_BASE="${ROOT_DIR}/artifacts/final-validation/e2e-demo"

if [[ ! -x "${BIN}" ]]; then
  mkdir -p "${ROOT_DIR}/bin"
  CGO_ENABLED=0 go build -trimpath -o "${BIN}" "${ROOT_DIR}/cmd/ai-model-provenance"
fi

TMP_WORK="$(mktemp -d)"
cleanup() {
  rm -rf "${TMP_WORK}"
}
trap cleanup EXIT

rm -rf "${OUT_BASE}"
mkdir -p "${OUT_BASE}"

echo "==> [Step 1] Creating synthetic local Hugging Face + Safetensors + LoRA model bundle..."
BUNDLE_DIR="${TMP_WORK}/model-bundle"
DEPLOY_DIR="${TMP_WORK}/deployment-model"
KEYS_DIR="${TMP_WORK}/ephemeral-keys"
mkdir -p "${BUNDLE_DIR}" "${KEYS_DIR}"

# Generate deterministic synthetic bundle via a small Go helper invocation using go test or inline generator:
cat > "${BUNDLE_DIR}/config.json" <<'EOF'
{
  "architectures": ["LlamaForCausalLM"],
  "model_type": "llama",
  "torch_dtype": "bfloat16",
  "vocab_size": 32000,
  "hidden_size": 4096,
  "num_hidden_layers": 32,
  "num_attention_heads": 32,
  "license": "apache-2.0",
  "quantization_config": {
    "quant_method": "awq",
    "bits": 4,
    "group_size": 128
  }
}
EOF

cat > "${BUNDLE_DIR}/tokenizer_config.json" <<'EOF'
{
  "tokenizer_class": "PreTrainedTokenizerFast",
  "model_max_length": 8192
}
EOF

cat > "${BUNDLE_DIR}/tokenizer.json" <<'EOF'
{"version":"1.0","model":{"type":"BPE","vocab":{"<s>":0,"</s>":1,"assistant":2,"verified":3}}}
EOF

cat > "${BUNDLE_DIR}/special_tokens_map.json" <<'EOF'
{"bos_token":"<s>","eos_token":"</s>"}
EOF

cat > "${BUNDLE_DIR}/chat_template.jinja" <<'EOF'
{{ bos_token }}{% for m in messages %}{{ m['role'] }}: {{ m['content'] }}{% endfor %}
EOF

cat > "${BUNDLE_DIR}/adapter_config.json" <<'EOF'
{
  "peft_type": "LORA",
  "task_type": "CAUSAL_LM",
  "base_model_name_or_path": "meta-llama/Llama-3-8B",
  "revision": "043235d6088ecd3dd5fb5ca3592b6913fd516027",
  "r": 8,
  "lora_alpha": 16,
  "lora_dropout": 0.05,
  "target_modules": ["q_proj", "v_proj"]
}
EOF

# Write valid binary .safetensors files (8-byte little-endian header length + JSON header + raw tensor bytes)
python3 - "${BUNDLE_DIR}" <<'PYEOF'
import json, struct, sys, os
bundle_dir = sys.argv[1]

def write_safetensors(path, tensor_name, dtype, shape, byte_val, byte_len):
    header = {
        "__metadata__": {"format": "pt"},
        tensor_name: {
            "dtype": dtype,
            "shape": shape,
            "data_offsets": [0, byte_len]
        }
    }
    h_bytes = json.dumps(header, separators=(",", ":")).encode("utf-8")
    with open(path, "wb") as f:
        f.write(struct.pack("<Q", len(h_bytes)))
        f.write(h_bytes)
        f.write(bytes([byte_val]) * byte_len)

write_safetensors(os.path.join(bundle_dir, "model.safetensors"), "model.layers.0.self_attn.q_proj.weight", "BF16", [4, 4], 0x2A, 32)
write_safetensors(os.path.join(bundle_dir, "adapter_model.safetensors"), "base_model.model.layers.0.lora_A.weight", "F16", [2, 4], 0x3B, 16)
PYEOF

echo "==> [Step 2 & 3] Inspecting model bundle & deriving deterministic bundle-identity/v1..."
"${BIN}" inspect --bundle "${BUNDLE_DIR}" --output "${OUT_BASE}/01-inspect"
BUNDLE_ID="$(jq -r '.bundle_id' "${OUT_BASE}/01-inspect/bundle-manifest.json")"
echo "    Derived Model Bundle Identity: ${BUNDLE_ID}"

echo "==> [Step 4] Generating and validating CycloneDX 1.7 AI/ML-BOM..."
"${BIN}" bom generate --bundle "${BUNDLE_DIR}" --output "${OUT_BASE}/02-bom/bom.cdx.json" --spec-version 1.7
"${BIN}" bom validate --bom "${OUT_BASE}/02-bom/bom.cdx.json" --bundle "${BUNDLE_DIR}"

echo "==> [Step 5 & 6] Generating ephemeral test keys, signing OMS v1.0 bundle, and verifying signature..."
"${BIN}" keygen --output-dir "${KEYS_DIR}" --name model-signer
"${BIN}" keygen --output-dir "${KEYS_DIR}" --name eval-signer
"${BIN}" keygen --output-dir "${KEYS_DIR}" --name release-signer

# Copy ONLY public keys into the validation evidence directory (never persist private keys)
mkdir -p "${OUT_BASE}/public-keys"
cp "${KEYS_DIR}/"*.pub "${OUT_BASE}/public-keys/"

"${BIN}" oms sign \
  --bundle "${BUNDLE_DIR}" \
  --private-key "${KEYS_DIR}/model-signer.key" \
  --key-id "test-model-signer-1" \
  --output "${OUT_BASE}/03-oms/model.sig.json"

"${BIN}" oms verify \
  --bundle "${BUNDLE_DIR}" \
  --signature "${OUT_BASE}/03-oms/model.sig.json" \
  --public-key "${OUT_BASE}/public-keys/model-signer.pub" \
  --key-id "test-model-signer-1"

echo "==> [Step 7] Creating & signing bound LLM Release Gate evaluation report (TEST-ONLY FIXTURE)..."
mkdir -p "${OUT_BASE}/04-evaluation"
cat > "${OUT_BASE}/04-evaluation/eval-report.json" <<EOF
{
  "schemaVersion": "llm-release-gate.report/v1",
  "runId": "run-e2e-demo-001",
  "timestamp": "2026-10-31T00:00:00Z",
  "toolVersion": "0.1.0",
  "suite": {
    "name": "customer-assistant-regression",
    "version": "1.0.0",
    "path": "examples/basic/suite.yaml",
    "digest": "sha256:aacc5f5bd47e335484803969a97f415f06e00a6c0681c95a056918f8a22e53fb"
  },
  "dataset": {
    "path": "examples/basic/cases.jsonl",
    "digest": "sha256:c83d9a10096a9d2e4bfaaebb8b8e298f724a185c75c4887a81bfdcb4ecd5323a",
    "caseCount": 3
  },
  "graders": [
    { "type": "exact-match", "version": "1.0.0" },
    { "type": "json-schema", "version": "1.0.0" }
  ],
  "candidate": {
    "name": "customer-assistant-candidate-v1.1",
    "version": "1.1.0",
    "provider": "fake",
    "model": "fake-deterministic-v1",
    "environment": "test-only-e2e-fixture",
    "digest": "sha256:96eef63b79a77e33b46dfaf4498e491fb0df4f46b63621bdcb259ee620d06c48",
    "metadata": {
      "model_bundle_id": "${BUNDLE_ID}",
      "adapter": "support-lora-v2",
      "fixture_notice": "test-only-synthetic-evaluation-fixture"
    }
  },
  "execution": {
    "mode": "native",
    "timeout": "15s",
    "concurrency": 1,
    "repetitions": 1,
    "warmupRequests": 0,
    "environment": "test-only-e2e-fixture"
  },
  "evaluator": {
    "name": "llm-release-gate-native",
    "version": "1.0.0"
  },
  "cases": [
    {
      "id": "case-001",
      "repetition": 1,
      "status": "passed",
      "required": true,
      "assertions": []
    }
  ],
  "metrics": {
    "totalPlannedCases": 1,
    "executedCases": 1,
    "passedCases": 1,
    "failedCases": 0,
    "erroredCases": 0,
    "timeoutCases": 0,
    "skippedCases": 0,
    "notRunCases": 0,
    "totalAssertions": 1,
    "passedAssertions": 1,
    "failedRequiredAssertions": 0,
    "failedOptionalAssertions": 0,
    "passRate": 1.0,
    "timeoutRate": 0.0,
    "totalPromptTokens": 20,
    "totalCompletionTokens": 10,
    "totalTokens": 30
  },
  "gateStatus": "PASS",
  "evidenceQuality": "COMPLETE",
  "comparisonStatus": "NOT_APPLICABLE",
  "exitCode": 0,
  "decisionReasons": [
    {
      "code": "ALL_REQUIRED_CHECKS_PASSED",
      "category": "policy",
      "severity": "info",
      "message": "all required checks passed on synthetic test fixture"
    }
  ]
}
EOF

"${BIN}" evidence bind-eval \
  --bundle "${BUNDLE_DIR}" \
  --evaluation-report "${OUT_BASE}/04-evaluation/eval-report.json" \
  --private-key "${KEYS_DIR}/eval-signer.key" \
  --key-id "test-eval-signer-1" \
  --producer-role "trusted-evaluator" \
  --output "${OUT_BASE}/04-evaluation/eval-attestation.dsse.json"

echo "==> [Step 8, 9, 10] Evaluating strict release policy & signing in-toto Release Qualification Attestation..."
cat > "${OUT_BASE}/policy-strict-test.yaml" <<EOF
# TEST-ONLY STRICT POLICY FIXTURE FOR E2E VALIDATION
schema_version: "v1"
name: "e2e-test-strict-policy"
bundle:
  reject_symlinks: true
  require_deterministic_identity: true
  allow_unknown_files: false
signing:
  require_oms: true
  oms_mode: "native"
  trusted_signers:
    - id: "test-model-signer-1"
      name: "E2E Test Model Signer"
      key_id: "test-model-signer-1"
      public_key_path: "./public-keys/model-signer.pub"
evaluation:
  required: true
  required_status: PASS
  require_artifact_binding: true
  require_trusted_evidence: true
  trusted_signers:
    - id: "test-eval-signer-1"
      name: "E2E Test Evaluation Signer"
      key_id: "test-eval-signer-1"
      public_key_path: "./public-keys/eval-signer.pub"
scanner:
  required: false
deployment:
  require_immutable_image: true
  require_serving_config: true
  allowed_adapters:
    - "support-lora-v2"
release:
  decision_mode: strict
  require_signed_qualification: true
  trusted_signers:
    - id: "test-release-signer-1"
      name: "E2E Test Release Authority"
      key_id: "test-release-signer-1"
      public_key_path: "./public-keys/release-signer.pub"
EOF

cat > "${OUT_BASE}/serving-config.yaml" <<'EOF'
# Test-only serving configuration
max_model_len: 8192
dtype: bfloat16
tensor_parallel_size: 1
EOF

SERVING_CFG_DIGEST="sha256:$(shasum -a 256 "${OUT_BASE}/serving-config.yaml" | awk '{print $1}')"
RUNTIME_IMAGE="ghcr.io/vllm/vllm-openai@sha256:7777777777777777777777777777777777777777777777777777777777777777"

"${BIN}" gate evaluate \
  --bundle "${BUNDLE_DIR}" \
  --oms-signature "${OUT_BASE}/03-oms/model.sig.json" \
  --evaluation-report "${OUT_BASE}/04-evaluation/eval-report.json" \
  --evaluation-attestation "${OUT_BASE}/04-evaluation/eval-attestation.dsse.json" \
  --policy "${OUT_BASE}/policy-strict-test.yaml" \
  --signing-key "${KEYS_DIR}/release-signer.key" \
  --signing-key-id "test-release-signer-1" \
  --runtime-image "${RUNTIME_IMAGE}" \
  --serving-config "${OUT_BASE}/serving-config.yaml" \
  --output "${OUT_BASE}/05-gate-evaluate"

echo "==> [Step 11] Copying approved model bundle to deployment staging & running release verify (expect PASS)..."
cp -R "${BUNDLE_DIR}" "${DEPLOY_DIR}"

cat > "${OUT_BASE}/deployment.yaml" <<EOF
# TEST-ONLY DEPLOYMENT COMPOSITION DESCRIPTOR
schema_version: "deployment-composition/v1"
name: "e2e-test-deployment"
model_bundle_id: "${BUNDLE_ID}"
runtime_image: "${RUNTIME_IMAGE}"
runtime_profile: "cpu-bf16"
serving_config_path: "./serving-config.yaml"
serving_config_digest: "${SERVING_CFG_DIGEST}"
active_adapters:
  - "support-lora-v2"
serving_parameters:
  max_model_len: "8192"
EOF

"${BIN}" release verify \
  --bundle "${DEPLOY_DIR}" \
  --attestation "${OUT_BASE}/05-gate-evaluate/attestation.json" \
  --deployment "${OUT_BASE}/deployment.yaml" \
  --policy "${OUT_BASE}/policy-strict-test.yaml" \
  --output "${OUT_BASE}/06-release-verify-pass"

echo "==> [Step 12, 13, 14] Modifying tokenizer in deployment bundle and re-running release verify (expect FAIL)..."
cat > "${DEPLOY_DIR}/tokenizer.json" <<'EOF'
{"version":"1.0","model":{"type":"BPE","vocab":{"<s>":0,"</s>":1,"tampered_token":999}}}
EOF

set +e
"${BIN}" release verify \
  --bundle "${DEPLOY_DIR}" \
  --attestation "${OUT_BASE}/05-gate-evaluate/attestation.json" \
  --deployment "${OUT_BASE}/deployment.yaml" \
  --policy "${OUT_BASE}/policy-strict-test.yaml" \
  --output "${OUT_BASE}/07-release-verify-tampered"
TAMPER_EXIT=$?
set -e

if [[ "${TAMPER_EXIT}" -ne 1 ]]; then
  echo "ERROR: Expected exit code 1 (FAIL) on tampered deployment artifact, got ${TAMPER_EXIT}" >&2
  exit 1
fi

echo "==> E2E Demonstration succeeded! Approved bundle PASSED (exit 0) and tampered bundle FAILED (exit 1)."
