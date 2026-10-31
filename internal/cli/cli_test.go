package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/devenes/ai-model-provenance-gate/internal/bundle"
	"github.com/devenes/ai-model-provenance-gate/internal/digest"
	"github.com/devenes/ai-model-provenance-gate/internal/formats/safetensors"
	"github.com/devenes/ai-model-provenance-gate/internal/policy"
)

func createEndToEndModelBundle(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	cfg := `{
  "architectures": ["LlamaForCausalLM"],
  "model_type": "llama",
  "torch_dtype": "bfloat16",
  "vocab_size": 32000,
  "hidden_size": 4096,
  "num_hidden_layers": 32,
  "num_attention_heads": 32,
  "license": "apache-2.0"
}`
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(cfg), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	w, err := safetensors.BuildSyntheticSafetensors([]safetensors.SyntheticTensor{
		{Name: "model.layers.0.self_attn.q_proj.weight", DType: "BF16", Shape: []int64{4, 4}},
	}, map[string]string{"format": "pt"})
	if err != nil {
		t.Fatalf("build weights: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "model.safetensors"), w, 0o600); err != nil {
		t.Fatalf("write weights: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tokenizer_config.json"), []byte(`{"tokenizer_class":"PreTrainedTokenizerFast","model_max_length":8192}`), 0o600); err != nil {
		t.Fatalf("write tokenizer_config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tokenizer.json"), []byte(`{"version":"1.0","model":{"type":"BPE","vocab":{"<s>":0,"</s>":1,"support":2}}}`), 0o600); err != nil {
		t.Fatalf("write tokenizer: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "special_tokens_map.json"), []byte(`{"bos_token":"<s>","eos_token":"</s>"}`), 0o600); err != nil {
		t.Fatalf("write special_tokens_map: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "chat_template.jinja"), []byte("{{ bos_token }}{% for m in messages %}{{ m['content'] }}{% endfor %}"), 0o600); err != nil {
		t.Fatalf("write chat_template: %v", err)
	}
	adapterCfg := `{
  "peft_type": "LORA",
  "task_type": "CAUSAL_LM",
  "base_model_name_or_path": "meta-llama/Llama-3-8B",
  "revision": "043235d",
  "r": 8,
  "lora_alpha": 16,
  "target_modules": ["q_proj", "v_proj"]
}`
	if err := os.WriteFile(filepath.Join(dir, "adapter_config.json"), []byte(adapterCfg), 0o600); err != nil {
		t.Fatalf("write adapter_config: %v", err)
	}
	aw, err := safetensors.BuildSyntheticSafetensors([]safetensors.SyntheticTensor{
		{Name: "base_model.model.layers.0.lora_A.weight", DType: "F16", Shape: []int64{2, 4}},
	}, map[string]string{"format": "pt"})
	if err != nil {
		t.Fatalf("build adapter weights: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "adapter_model.safetensors"), aw, 0o600); err != nil {
		t.Fatalf("write adapter weights: %v", err)
	}
}

func runCmd(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func TestEndToEndProductThesisLifecycle(t *testing.T) {
	tmp := t.TempDir()

	// Step 1: Create local model bundle
	bundleDir := filepath.Join(tmp, "model-bundle")
	createEndToEndModelBundle(t, bundleDir)

	// Step 2 & 3: Inspect the model & generate deterministic identity
	inspectOut := filepath.Join(tmp, "out-inspect")
	code, out, errOut := runCmd(t, "inspect", "--bundle", bundleDir, "--output", inspectOut)
	if code != policy.ExitPass {
		t.Fatalf("inspect failed (code=%d): %s / %s", code, out, errOut)
	}
	insp, err := bundle.Inspect(bundleDir, bundle.DefaultInspectOptions())
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if !strings.Contains(out, "BUNDLE_ID="+insp.BundleID) {
		t.Fatalf("expected BUNDLE_ID=%s in stdout, got %s", insp.BundleID, out)
	}

	// Step 4: Generate and validate CycloneDX AI/ML-BOM
	bomPath := filepath.Join(tmp, "out-bom", "bom.cdx.json")
	code, out, errOut = runCmd(t, "bom", "generate", "--bundle", bundleDir, "--output", bomPath)
	if code != policy.ExitPass {
		t.Fatalf("bom generate failed (code=%d): %s / %s", code, out, errOut)
	}
	code, out, errOut = runCmd(t, "bom", "validate", "--bom", bomPath, "--bundle", bundleDir)
	if code != policy.ExitPass {
		t.Fatalf("bom validate failed (code=%d): %s / %s", code, out, errOut)
	}

	// Step 5 & 6: Generate controlled test keys, sign with OMS v1.0, and verify model signature & trusted signer
	keysDir := filepath.Join(tmp, "keys")
	code, _, errOut = runCmd(t, "keygen", "--output-dir", keysDir, "--name", "model-signer")
	if code != policy.ExitPass {
		t.Fatalf("keygen model-signer failed: %s", errOut)
	}
	code, _, errOut = runCmd(t, "keygen", "--output-dir", keysDir, "--name", "eval-signer")
	if code != policy.ExitPass {
		t.Fatalf("keygen eval-signer failed: %s", errOut)
	}
	code, _, errOut = runCmd(t, "keygen", "--output-dir", keysDir, "--name", "release-signer")
	if code != policy.ExitPass {
		t.Fatalf("keygen release-signer failed: %s", errOut)
	}

	omsSigPath := filepath.Join(tmp, "signatures", "model.sig")
	code, _, errOut = runCmd(t, "oms", "sign",
		"--bundle", bundleDir,
		"--private-key", filepath.Join(keysDir, "model-signer.key"),
		"--key-id", "model-signer-1",
		"--output", omsSigPath,
	)
	if code != policy.ExitPass {
		t.Fatalf("oms sign failed: %s", errOut)
	}

	code, out, errOut = runCmd(t, "oms", "verify",
		"--bundle", bundleDir,
		"--signature", omsSigPath,
		"--public-key", filepath.Join(keysDir, "model-signer.pub"),
		"--key-id", "model-signer-1",
	)
	if code != policy.ExitPass || !strings.Contains(out, "STATUS=VERIFIED") {
		t.Fatalf("oms verify failed (code=%d): %s / %s", code, out, errOut)
	}

	// Step 7: Create evaluation evidence bound to exact model identity and sign it
	evalReportPath := filepath.Join(tmp, "eval", "report.json")
	_ = os.MkdirAll(filepath.Dir(evalReportPath), 0o755)
	evalJSON := `{
  "schemaVersion": "llm-release-gate.report/v1",
  "runId": "run-e2e-001",
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
      "model_bundle_id": "` + insp.BundleID + `",
      "adapter": "support-lora-v2"
    }
  },
  "execution": {"mode": "native", "timeout": "15s", "concurrency": 1, "repetitions": 1, "warmupRequests": 0},
  "evaluator": {"name": "llm-release-gate-native", "version": "1.0.0"},
  "cases": [{"id": "c1", "repetition": 1, "status": "passed", "required": true, "assertions": []}],
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
}`
	_ = os.WriteFile(evalReportPath, []byte(evalJSON), 0o600)

	// First verify that default post-hoc operator endorsement (`evidence bind-eval` without --producer-role trusted-evaluator)
	// is classified as OPERATOR_ENDORSEMENT and rejected by strict policy unless explicitly authorized.
	operatorEvalAttPath := filepath.Join(tmp, "eval", "operator-endorsement.dsse.json")
	code, _, errOut = runCmd(t, "evidence", "bind-eval",
		"--bundle", bundleDir,
		"--evaluation-report", evalReportPath,
		"--private-key", filepath.Join(keysDir, "eval-signer.key"),
		"--key-id", "eval-signer-1",
		"--output", operatorEvalAttPath,
	)
	if code != policy.ExitPass {
		t.Fatalf("operator evidence bind-eval failed: %s", errOut)
	}

	evalAttPath := filepath.Join(tmp, "eval", "eval-attestation.dsse.json")
	code, _, errOut = runCmd(t, "evidence", "bind-eval",
		"--bundle", bundleDir,
		"--evaluation-report", evalReportPath,
		"--private-key", filepath.Join(keysDir, "eval-signer.key"),
		"--key-id", "eval-signer-1",
		"--producer-role", "trusted-evaluator",
		"--output", evalAttPath,
	)
	if code != policy.ExitPass {
		t.Fatalf("evidence bind-eval failed: %s", errOut)
	}

	// Step 8, 9, 10: Evaluate strict release policy, produce release qualification evidence, and sign it
	policyYAML := `schema_version: "v1"
name: "strict-e2e-policy"
bundle:
  reject_symlinks: true
  require_deterministic_identity: true
signing:
  require_oms: true
  trusted_signers:
    - id: "model-signer-1"
      name: "Model Signer"
      key_id: "model-signer-1"
      public_key_path: "` + filepath.ToSlash(filepath.Join(keysDir, "model-signer.pub")) + `"
evaluation:
  required_status: PASS
  require_artifact_binding: true
  require_trusted_evidence: true
  trusted_signers:
    - id: "eval-signer-1"
      name: "Evaluation Signer"
      key_id: "eval-signer-1"
      public_key_path: "` + filepath.ToSlash(filepath.Join(keysDir, "eval-signer.pub")) + `"
scanner:
  required: false
deployment:
  require_immutable_image: true
  require_serving_config: true
release:
  decision_mode: strict
  require_signed_qualification: true
  trusted_signers:
    - id: "release-signer-1"
      name: "Release Authority"
      key_id: "release-signer-1"
      public_key_path: "` + filepath.ToSlash(filepath.Join(keysDir, "release-signer.pub")) + `"
`
	policyPath := filepath.Join(tmp, "policy.yaml")
	_ = os.WriteFile(policyPath, []byte(policyYAML), 0o600)

	servingCfgPath := filepath.Join(tmp, "serving-config.yaml")
	servingCfgBytes := []byte("max_model_len: 8192\ndtype: bfloat16\n")
	_ = os.WriteFile(servingCfgPath, servingCfgBytes, 0o600)
	servingCfgDigest := digest.ComputeNormalizedText(servingCfgBytes)
	immutableImage := "ghcr.io/vllm/vllm-openai@sha256:5555555555555555555555555555555555555555555555555555555555555555"

	gateOut := filepath.Join(tmp, "out-gate")
	// Verify that unauthorized post-hoc operator endorsement is BLOCKED by strict policy:
	code, out, errOut = runCmd(t, "gate", "evaluate",
		"--bundle", bundleDir,
		"--oms-signature", omsSigPath,
		"--evaluation-report", evalReportPath,
		"--evaluation-attestation", operatorEvalAttPath,
		"--policy", policyPath,
		"--signing-key", filepath.Join(keysDir, "release-signer.key"),
		"--signing-key-id", "release-signer-1",
		"--runtime-image", immutableImage,
		"--serving-config", servingCfgPath,
	)
	if code != policy.ExitBlocked || !strings.Contains(out, "EVALUATION_POST_HOC_BINDING_REJECTED") {
		t.Fatalf("expected gate evaluate to BLOCK operator endorsement under strict policy, got code=%d out=%s err=%s", code, out, errOut)
	}

	code, out, errOut = runCmd(t, "gate", "evaluate",
		"--bundle", bundleDir,
		"--oms-signature", omsSigPath,
		"--evaluation-report", evalReportPath,
		"--evaluation-attestation", evalAttPath,
		"--policy", policyPath,
		"--signing-key", filepath.Join(keysDir, "release-signer.key"),
		"--signing-key-id", "release-signer-1",
		"--runtime-image", immutableImage,
		"--serving-config", servingCfgPath,
		"--output", gateOut,
	)
	if code != policy.ExitPass || !strings.Contains(out, "GATE_STATUS=PASS") {
		t.Fatalf("gate evaluate failed (code=%d): %s / %s", code, out, errOut)
	}

	releaseAttPath := filepath.Join(gateOut, "attestation.json")
	if _, err := os.Stat(releaseAttPath); err != nil {
		t.Fatalf("expected release attestation at %s: %v", releaseAttPath, err)
	}

	// Step 11: Copy approved deployment fixture and verify it passes release verify
	deployBundleDir := filepath.Join(tmp, "deployment-model")
	createEndToEndModelBundle(t, deployBundleDir)

	deployDescYAML := `schema_version: "deployment-composition/v1"
name: "prod-deployment"
model_bundle_id: "` + insp.BundleID + `"
runtime_image: "` + immutableImage + `"
runtime_profile: "cpu-bf16"
serving_config_path: "serving-config.yaml"
serving_config_digest: "` + servingCfgDigest + `"
active_adapters:
  - "support-lora-v2"
serving_parameters:
  max_model_len: "8192"
`
	deployDescPath := filepath.Join(tmp, "deployment.yaml")
	_ = os.WriteFile(deployDescPath, []byte(deployDescYAML), 0o600)

	verifyPassOut := filepath.Join(tmp, "out-verify-pass")
	code, out, errOut = runCmd(t, "release", "verify",
		"--bundle", deployBundleDir,
		"--attestation", releaseAttPath,
		"--deployment", deployDescPath,
		"--policy", policyPath,
		"--output", verifyPassOut,
	)
	if code != policy.ExitPass || !strings.Contains(out, "GATE_STATUS=PASS") {
		t.Fatalf("release verify on unmodified deployment bundle failed (code=%d): %s / %s", code, out, errOut)
	}

	// Step 12, 13, 14: Modify the tokenizer in the deployment bundle and confirm release verify REJECTS it!
	if err := os.WriteFile(filepath.Join(deployBundleDir, "tokenizer.json"), []byte(`{"version":"1.0","model":{"type":"BPE","vocab":{"<s>":0,"</s>":1,"backdoor":2}}}`), 0o600); err != nil {
		t.Fatalf("modify tokenizer: %v", err)
	}

	verifyTamperOut := filepath.Join(tmp, "out-verify-tamper")
	code, out, errOut = runCmd(t, "release", "verify",
		"--bundle", deployBundleDir,
		"--attestation", releaseAttPath,
		"--deployment", deployDescPath,
		"--policy", policyPath,
		"--output", verifyTamperOut,
	)
	if code != policy.ExitFail || !strings.Contains(out, "GATE_STATUS=FAIL") || !strings.Contains(out, "DEPLOYMENT_ARTIFACT_TAMPERED") {
		t.Fatalf("expected release verify to FAIL with DEPLOYMENT_ARTIFACT_TAMPERED on modified tokenizer, got code=%d out=%s err=%s", code, out, errOut)
	}
}

func TestCLIHelpAndAliasesUX(t *testing.T) {
	helpInvocations := [][]string{
		{"--help"},
		{"-h"},
		{"help"},
		{"version", "--help"},
		{"inspect", "--help"},
		{"bundle", "--help"},
		{"bundle", "inspect", "--help"},
		{"bom", "--help"},
		{"bom", "generate", "--help"},
		{"bom", "validate", "--help"},
		{"oms", "--help"},
		{"oms", "sign", "--help"},
		{"oms", "verify", "--help"},
		{"evidence", "--help"},
		{"evidence", "bind-eval", "--help"},
		{"evidence", "verify", "--help"},
		{"eval", "--help"},
		{"eval", "bind-eval", "--help"},
		{"eval", "verify", "--help"},
		{"gate", "--help"},
		{"gate", "evaluate", "--help"},
		{"attest", "--help"},
		{"release", "--help"},
		{"release", "verify", "--help"},
		{"deploy", "--help"},
		{"deploy", "verify", "--help"},
		{"keygen", "--help"},
	}

	for _, args := range helpInvocations {
		code, out, errOut := runCmd(t, args...)
		if code != policy.ExitPass {
			t.Fatalf("help invocation %v returned exit code %d (expected 0), out=%q, err=%q", args, code, out, errOut)
		}
		if !strings.Contains(out, "Usage:") {
			t.Fatalf("help invocation %v did not include 'Usage:' in stdout: %q", args, out)
		}
	}
}
