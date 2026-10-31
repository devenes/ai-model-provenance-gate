#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${ROOT_DIR}/bin/ai-model-provenance"
AUDIT_DIR="${ROOT_DIR}/artifacts/audit"
mkdir -p "${AUDIT_DIR}"

echo "=== STEP 1: Build binary ==="
go build -o "${BIN}" "${ROOT_DIR}/cmd/ai-model-provenance"
"${BIN}" version

echo "=== STEP 2: Create clean temporary workspace ==="
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT
echo "Workspace: ${WORK}"

echo "=== STEP 3: Generate test keys ==="
"${BIN}" keygen --output-dir "${WORK}/keys" --name model-signer
"${BIN}" keygen --output-dir "${WORK}/keys" --name eval-signer
"${BIN}" keygen --output-dir "${WORK}/keys" --name release-signer
"${BIN}" keygen --output-dir "${WORK}/keys" --name rogue-signer

echo "=== STEP 4: Create realistic Safetensors + tokenizer + config + LoRA bundle ==="
mkdir -p "${WORK}/bundle"
python3 - "${WORK}/bundle" <<'PY'
import json, struct, sys
from pathlib import Path

d = Path(sys.argv[1])
(d / "config.json").write_text(json.dumps({
    "architectures": ["LlamaForCausalLM"],
    "model_type": "llama",
    "torch_dtype": "bfloat16",
    "vocab_size": 32000,
    "hidden_size": 4096,
    "num_hidden_layers": 32,
    "num_attention_heads": 32,
    "license": "apache-2.0"
}, indent=2) + "\n")

def make_safetensors(tensor_name, dtype, shape, elem_size, fill_byte):
    n_elems = 1
    for s in shape:
        n_elems *= s
    n_bytes = n_elems * elem_size
    header = {
        "__metadata__": {"format": "pt"},
        tensor_name: {"dtype": dtype, "shape": shape, "data_offsets": [0, n_bytes]}
    }
    hdr_bytes = json.dumps(header, separators=(",", ":")).encode("utf-8")
    return struct.pack("<Q", len(hdr_bytes)) + hdr_bytes + (bytes([fill_byte]) * n_bytes)

(d / "model.safetensors").write_bytes(make_safetensors("model.layers.0.self_attn.q_proj.weight", "BF16", [4, 4], 2, 0x2A))
(d / "tokenizer_config.json").write_text('{"tokenizer_class":"PreTrainedTokenizerFast","model_max_length":8192}\n')
(d / "tokenizer.json").write_text('{"version":"1.0","model":{"type":"BPE","vocab":{"<s>":0,"</s>":1,"assistant":2}}}\n')
(d / "special_tokens_map.json").write_text('{"bos_token":"<s>","eos_token":"</s>"}\n')
(d / "chat_template.jinja").write_text("{{ bos_token }}{% for m in messages %}{{ m['content'] }}{% endfor %}\n")
(d / "adapter_config.json").write_text(json.dumps({
    "peft_type": "LORA",
    "task_type": "CAUSAL_LM",
    "base_model_name_or_path": "meta-llama/Llama-3-8B",
    "revision": "043235d",
    "r": 8,
    "lora_alpha": 16,
    "target_modules": ["q_proj", "v_proj"]
}, indent=2) + "\n")
(d / "adapter_model.safetensors").write_bytes(make_safetensors("base_model.model.layers.0.lora_A.weight", "F16", [2, 4], 2, 0x11))
PY
ls -la "${WORK}/bundle"

echo "=== STEP 5: Run inspect and record bundle_id ==="
"${BIN}" inspect --bundle "${WORK}/bundle" --output "${WORK}/out-inspect"
BUNDLE_ID="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["bundle_id"])' "${WORK}/out-inspect/bundle-manifest.json")"
echo "Recorded BUNDLE_ID=${BUNDLE_ID}"

echo "=== STEP 6: Run bom generate (CycloneDX 1.7) ==="
"${BIN}" bom generate --bundle "${WORK}/bundle" --spec-version 1.7 --output "${WORK}/out-bom/bom.cdx.json"

echo "=== STEP 7: Validate BOM against official CycloneDX 1.7 schema ==="
"${BIN}" bom validate --bom "${WORK}/out-bom/bom.cdx.json" --bundle "${WORK}/bundle"

echo "=== STEP 8: Sign model bundle with OMS v1.0 ==="
"${BIN}" oms sign \
  --bundle "${WORK}/bundle" \
  --private-key "${WORK}/keys/model-signer.key" \
  --key-id model-signer-1 \
  --output "${WORK}/sigs/model.sig"

echo "=== STEP 9: Verify OMS signature ==="
"${BIN}" oms verify \
  --bundle "${WORK}/bundle" \
  --signature "${WORK}/sigs/model.sig" \
  --public-key "${WORK}/keys/model-signer.pub" \
  --key-id model-signer-1

echo "=== STEP 10: Create llm-release-gate report bound to bundle_id ==="
mkdir -p "${WORK}/eval"
python3 - "${WORK}/eval/report.json" "${BUNDLE_ID}" <<'PY'
import json, sys
dst, bid = sys.argv[1], sys.argv[2]
doc = {
  "schemaVersion": "llm-release-gate.report/v1",
  "runId": "run-audit-e2e-001",
  "timestamp": "2026-10-31T00:00:00Z",
  "toolVersion": "0.1.0",
  "suite": {
    "name": "customer-assistant",
    "version": "1.0.0",
    "digest": "sha256:aacc5f5bd47e335484803969a97f415f06e00a6c0681c95a056918f8a22e53fb"
  },
  "dataset": {
    "digest": "sha256:c83d9a10096a9d2e4bfaaebb8b8e298f724a185c75c4887a81bfdcb4ecd5323a",
    "caseCount": 3
  },
  "graders": [{"type": "exact-match", "version": "1.0.0"}],
  "candidate": {
    "name": "customer-assistant-v1",
    "version": "1.0.0",
    "provider": "fake",
    "model": "fake-deterministic-v1",
    "digest": "sha256:96eef63b79a77e33b46dfaf4498e491fb0df4f46b63621bdcb259ee620d06c48",
    "metadata": {
      "model_bundle_id": bid,
      "adapter": "support-lora-v2"
    }
  },
  "execution": {"mode": "native", "timeout": "15s", "concurrency": 1, "repetitions": 1, "warmupRequests": 0},
  "evaluator": {"name": "llm-release-gate-native", "version": "1.0.0"},
  "cases": [{"id": "c1", "repetition": 1, "status": "passed", "required": True, "assertions": []}],
  "metrics": {
    "totalPlannedCases": 1, "executedCases": 1, "passedCases": 1, "failedCases": 0,
    "erroredCases": 0, "timeoutCases": 0, "skippedCases": 0, "notRunCases": 0,
    "totalAssertions": 1, "passedAssertions": 1, "failedRequiredAssertions": 0, "failedOptionalAssertions": 0,
    "passRate": 1.0, "timeoutRate": 0.0, "totalPromptTokens": 10, "totalCompletionTokens": 5, "totalTokens": 15
  },
  "gateStatus": "PASS",
  "evidenceQuality": "COMPLETE",
  "comparisonStatus": "NOT_APPLICABLE",
  "exitCode": 0,
  "decisionReasons": [{"code": "ALL_REQUIRED_CHECKS_PASSED", "category": "policy", "severity": "info", "message": "passed"}]
}
json.dump(doc, open(dst, "w"), indent=2)
PY

echo "=== STEP 11: Sign/bind evaluation evidence ==="
"${BIN}" evidence bind-eval \
  --bundle "${WORK}/bundle" \
  --evaluation-report "${WORK}/eval/report.json" \
  --private-key "${WORK}/keys/eval-signer.key" \
  --key-id eval-signer-1 \
  --output "${WORK}/eval/eval-attestation.dsse.json"

echo "=== STEP 12 & 13: Run gate evaluate in strict mode and produce signed release qualification attestation ==="
cat > "${WORK}/policy.yaml" <<EOF
schema_version: "v1"
name: "audit-strict-policy"
bundle:
  reject_symlinks: true
  require_deterministic_identity: true
signing:
  require_oms: true
  trusted_signers:
    - id: "model-signer-1"
      name: "Model Signer"
      key_id: "model-signer-1"
      public_key_path: "${WORK}/keys/model-signer.pub"
evaluation:
  required_status: PASS
  require_artifact_binding: true
  require_trusted_evidence: true
  trusted_signers:
    - id: "eval-signer-1"
      name: "Evaluation Signer"
      key_id: "eval-signer-1"
      public_key_path: "${WORK}/keys/eval-signer.pub"
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
    - id: "release-signer-1"
      name: "Release Qualification Authority"
      key_id: "release-signer-1"
      public_key_path: "${WORK}/keys/release-signer.pub"
EOF

cat > "${WORK}/serving-config.yaml" <<EOF
max_model_len: 8192
dtype: bfloat16
tensor_parallel_size: 1
EOF

IMMUTABLE_IMAGE="ghcr.io/vllm/vllm-openai@sha256:5555555555555555555555555555555555555555555555555555555555555555"

"${BIN}" gate evaluate \
  --bundle "${WORK}/bundle" \
  --oms-signature "${WORK}/sigs/model.sig" \
  --evaluation-report "${WORK}/eval/report.json" \
  --evaluation-attestation "${WORK}/eval/eval-attestation.dsse.json" \
  --policy "${WORK}/policy.yaml" \
  --signing-key "${WORK}/keys/release-signer.key" \
  --signing-key-id release-signer-1 \
  --runtime-image "${IMMUTABLE_IMAGE}" \
  --serving-config "${WORK}/serving-config.yaml" \
  --output "${WORK}/out-gate"

ls -la "${WORK}/out-gate/attestation.json"
SERVING_DIGEST="$(python3 -c 'import hashlib,sys; print("sha256:"+hashlib.sha256(open(sys.argv[1],"rb").read().replace(b"\r\n",b"\n")).hexdigest())' "${WORK}/serving-config.yaml")"

echo "=== STEP 14: Run release verify on approved deployment composition ==="
cp -R "${WORK}/bundle" "${WORK}/deploy-bundle"
cat > "${WORK}/deployment.yaml" <<EOF
schema_version: "deployment-composition/v1"
name: "prod-deployment"
model_bundle_id: "${BUNDLE_ID}"
runtime_image: "${IMMUTABLE_IMAGE}"
runtime_profile: "cpu-bf16"
serving_config_path: "${WORK}/serving-config.yaml"
serving_config_digest: "${SERVING_DIGEST}"
active_adapters:
  - "support-lora-v2"
serving_parameters:
  max_model_len: "8192"
EOF

"${BIN}" release verify \
  --bundle "${WORK}/deploy-bundle" \
  --attestation "${WORK}/out-gate/attestation.json" \
  --deployment "${WORK}/deployment.yaml" \
  --policy "${WORK}/policy.yaml" \
  --output "${WORK}/out-verify-pass"

expect_fail() {
  local step_desc="$1"
  local expected_code="$2"
  shift 2
  set +e
  "$@"
  local rc=$?
  set -e
  echo "  -> Exit code: ${rc} (expected ${expected_code})"
  if [[ "${rc}" -ne "${expected_code}" ]]; then
    echo "ERROR: ${step_desc} returned exit code ${rc}, expected ${expected_code}" >&2
    exit 1
  fi
}

echo "=== STEP 15: Tamper with tokenizer.json and confirm release verify FAILS (exit 1) ==="
cp -R "${WORK}/bundle" "${WORK}/deploy-tamper-tok"
echo '{"version":"1.0","model":{"type":"BPE","vocab":{"<s>":0,"</s>":1,"poisoned":2}}}' > "${WORK}/deploy-tamper-tok/tokenizer.json"
expect_fail "Step 15 tamper tokenizer.json" 1 \
  "${BIN}" release verify \
  --bundle "${WORK}/deploy-tamper-tok" \
  --attestation "${WORK}/out-gate/attestation.json" \
  --deployment "${WORK}/deployment.yaml" \
  --policy "${WORK}/policy.yaml"

echo "=== STEP 16: Tamper with model.safetensors and confirm release verify FAILS (exit 1) ==="
cp -R "${WORK}/bundle" "${WORK}/deploy-tamper-weights"
python3 - "${WORK}/deploy-tamper-weights/model.safetensors" <<'PY'
import sys
p = sys.argv[1]
data = bytearray(open(p, "rb").read())
data[-1] ^= 0xFF
open(p, "wb").write(data)
PY
expect_fail "Step 16 tamper model.safetensors" 1 \
  "${BIN}" release verify \
  --bundle "${WORK}/deploy-tamper-weights" \
  --attestation "${WORK}/out-gate/attestation.json" \
  --deployment "${WORK}/deployment.yaml" \
  --policy "${WORK}/policy.yaml"

echo "=== STEP 17: Tamper with adapter_model.safetensors and confirm release verify FAILS (exit 1) ==="
cp -R "${WORK}/bundle" "${WORK}/deploy-tamper-lora"
python3 - "${WORK}/deploy-tamper-lora/adapter_model.safetensors" <<'PY'
import sys
p = sys.argv[1]
data = bytearray(open(p, "rb").read())
data[-1] ^= 0xFF
open(p, "wb").write(data)
PY
expect_fail "Step 17 tamper adapter_model.safetensors" 1 \
  "${BIN}" release verify \
  --bundle "${WORK}/deploy-tamper-lora" \
  --attestation "${WORK}/out-gate/attestation.json" \
  --deployment "${WORK}/deployment.yaml" \
  --policy "${WORK}/policy.yaml"

echo "=== STEP 18: Tamper with serving-config.yaml and confirm release verify FAILS (exit 1) ==="
cp "${WORK}/serving-config.yaml" "${WORK}/serving-config.bak"
echo "max_model_len: 1024" > "${WORK}/serving-config.yaml"
expect_fail "Step 18 tamper serving-config.yaml" 1 \
  "${BIN}" release verify \
  --bundle "${WORK}/deploy-bundle" \
  --attestation "${WORK}/out-gate/attestation.json" \
  --deployment "${WORK}/deployment.yaml" \
  --policy "${WORK}/policy.yaml"
mv "${WORK}/serving-config.bak" "${WORK}/serving-config.yaml"

echo "=== STEP 19: Replace runtime image digest with mutable tag and confirm release verify FAILS (exit 1) ==="
sed 's|@sha256:5555555555555555555555555555555555555555555555555555555555555555|:latest|g' "${WORK}/deployment.yaml" > "${WORK}/deployment-mutable.yaml"
expect_fail "Step 19 mutable runtime image tag" 1 \
  "${BIN}" release verify \
  --bundle "${WORK}/deploy-bundle" \
  --attestation "${WORK}/out-gate/attestation.json" \
  --deployment "${WORK}/deployment-mutable.yaml" \
  --policy "${WORK}/policy.yaml"

echo "=== STEP 20: Substitute evaluation report for another bundle and confirm gate evaluate FAILS (exit 1) ==="
OTHER_BUNDLE_ID="sha256:9999999999999999999999999999999999999999999999999999999999999999"
python3 - "${WORK}/eval/report.json" "${WORK}/eval/other-report.json" "${OTHER_BUNDLE_ID}" <<'PY'
import json, sys
src, dst, bid = sys.argv[1], sys.argv[2], sys.argv[3]
doc = json.load(open(src))
doc["candidate"]["metadata"]["model_bundle_id"] = bid
json.dump(doc, open(dst, "w"), indent=2)
PY
expect_fail "Step 20 substitute evaluation report for another bundle" 1 \
  "${BIN}" gate evaluate \
  --bundle "${WORK}/bundle" \
  --oms-signature "${WORK}/sigs/model.sig" \
  --evaluation-report "${WORK}/eval/other-report.json" \
  --policy "${WORK}/policy.yaml" \
  --signing-key "${WORK}/keys/release-signer.key" \
  --signing-key-id release-signer-1

echo "=== ALL 20 INDEPENDENT E2E VALIDATION STEPS PASSED ==="
