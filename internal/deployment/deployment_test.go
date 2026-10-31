package deployment

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/devenes/ai-model-provenance-gate/internal/attestation"
	"github.com/devenes/ai-model-provenance-gate/internal/bom"
	"github.com/devenes/ai-model-provenance-gate/internal/bundle"
	"github.com/devenes/ai-model-provenance-gate/internal/config"
	"github.com/devenes/ai-model-provenance-gate/internal/digest"
	"github.com/devenes/ai-model-provenance-gate/internal/evaluation/llmreleasegate"
	"github.com/devenes/ai-model-provenance-gate/internal/formats/safetensors"
	"github.com/devenes/ai-model-provenance-gate/internal/oms"
	"github.com/devenes/ai-model-provenance-gate/internal/policy"
	"github.com/devenes/ai-model-provenance-gate/internal/provenance"
	"github.com/devenes/ai-model-provenance-gate/internal/scanner"
	"github.com/devenes/ai-model-provenance-gate/internal/signing"
	"github.com/devenes/ai-model-provenance-gate/internal/verification"
)

func createFullModelBundle(t *testing.T, dir string, weightSeed byte, tokText string, loraRank string) bundle.InspectionResult {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{"architectures":["LlamaForCausalLM"],"model_type":"llama"}`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	w, err := safetensors.BuildSyntheticSafetensors([]safetensors.SyntheticTensor{
		{Name: "model.layers.0.weight", DType: "BF16", Shape: []int64{4, 4}, Data: bytesRepeat(weightSeed, 32)},
	}, map[string]string{"format": "pt"})
	if err != nil {
		t.Fatalf("build weights: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "model.safetensors"), w, 0o600); err != nil {
		t.Fatalf("write weights: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tokenizer.json"), []byte(tokText), 0o600); err != nil {
		t.Fatalf("write tokenizer: %v", err)
	}
	if loraRank != "" {
		adapterCfg := `{"peft_type":"LORA","task_type":"CAUSAL_LM","base_model_name_or_path":"meta-llama/Llama-3-8B","r":` + loraRank + `}`
		if err := os.WriteFile(filepath.Join(dir, "adapter_config.json"), []byte(adapterCfg), 0o600); err != nil {
			t.Fatalf("write adapter_config: %v", err)
		}
		aw, err := safetensors.BuildSyntheticSafetensors([]safetensors.SyntheticTensor{
			{Name: "base_model.model.layers.0.lora_A.weight", DType: "F16", Shape: []int64{2, 4}, Data: bytesRepeat(weightSeed^0x55, 16)},
		}, nil)
		if err != nil {
			t.Fatalf("build adapter weights: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, "adapter_model.safetensors"), aw, 0o600); err != nil {
			t.Fatalf("write adapter weights: %v", err)
		}
	}
	insp, err := bundle.Inspect(dir, bundle.DefaultInspectOptions())
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	return insp
}

func bytesRepeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func TestPolicyAttestationAndDeploymentMatrix(t *testing.T) {
	ctx := context.Background()
	tmp := t.TempDir()
	modelDir := filepath.Join(tmp, "approved-model")
	insp := createFullModelBundle(t, modelDir, 0x11, `{"version":"1.0","vocab":{"ok":1}}`, "8")

	genBOM, err := bom.Generate(insp, bom.GenerateOptions{Timestamp: "2026-10-31T00:00:00Z"})
	if err != nil {
		t.Fatalf("Generate BOM: %v", err)
	}

	privPEM, pubPEM, fp, err := signing.GenerateEd25519KeyPairPEM()
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	priv, _ := signing.ParsePrivateKeyPEM(privPEM, "release-authority-1")
	pub, _ := signing.ParsePublicKeyPEM(pubPEM, "release-authority-1", "Release Authority")
	trustedSigners := []verification.TrustedSignerRule{
		{ID: "release-authority-1", Name: "Release Authority", KeyID: "release-authority-1", KeyFingerprint: fp, PublicKey: pub},
	}

	omsBytes, err := oms.SignBundle(insp, priv, oms.SignOptions{AsSigstoreBundle: true})
	if err != nil {
		t.Fatalf("SignBundle: %v", err)
	}
	omsPath := filepath.Join(tmp, "model.sig")
	_ = os.WriteFile(omsPath, omsBytes, 0o600)

	omsRes, err := oms.VerifyBundle(ctx, insp, omsPath, oms.VerifyOptions{TrustedSigners: trustedSigners})
	if err != nil || omsRes.Status != verification.StatusVerified {
		t.Fatalf("VerifyBundle: %v", err)
	}

	evalSum := llmreleasegate.EvaluationSummary{
		ReportDigest:        "sha256:aacc5f5bd47e335484803969a97f415f06e00a6c0681c95a056918f8a22e53fb",
		SuiteDigest:         "sha256:aacc5f5bd47e335484803969a97f415f06e00a6c0681c95a056918f8a22e53fb",
		DatasetDigest:       "sha256:c83d9a10096a9d2e4bfaaebb8b8e298f724a185c75c4887a81bfdcb4ecd5323a",
		RunID:               "run-001",
		ReportedGateStatus:  llmreleasegate.GatePass,
		EffectiveGateStatus: llmreleasegate.GatePass,
		EvidenceQuality:     llmreleasegate.EvidenceComplete,
		ReportedExitCode:    0,
		BindingStatus:       llmreleasegate.BindingMatched,
		TrustStatus:         llmreleasegate.TrustVerifiedTrusted,
		EligibleForRelease:  true,
		Reason:              "evaluation verified",
	}

	strictPol := config.StrictDefaultPolicy()
	strictPol.Deployment.RequireServingConfig = true
	strictPol.Deployment.AllowedAdapters = []string{"support-lora-v1"}

	immutableImage := "ghcr.io/vllm/vllm-openai@sha256:4444444444444444444444444444444444444444444444444444444444444444"
	servingCfgPath := filepath.Join(tmp, "serving-config.yaml")
	servingCfgBytes := []byte("max_model_len: 8192\ntensor_parallel_size: 1\n")
	_ = os.WriteFile(servingCfgPath, servingCfgBytes, 0o600)
	servingCfgDigest := digest.ComputeNormalizedText(servingCfgBytes)

	dec := policy.Evaluate(policy.EvaluationInput{
		Policy:        strictPol,
		Inspection:    insp,
		BOM:           genBOM,
		OMS:           omsRes,
		HasEvaluation: true,
		Evaluation:    evalSum,
		Scanner:       scanner.Result{Status: scanner.StatusNotRun},
		Provenance:    provenance.Result{Status: verification.StatusNotRun},
		RuntimeImage:  immutableImage,
	})
	if dec.GateStatus != policy.StatusPass || dec.ExitCode != 0 {
		t.Fatalf("expected policy PASS, got %+v", dec)
	}

	att, err := attestation.BuildAndOptionallySign(attestation.BuildInput{
		Timestamp:           "2026-10-31T00:00:00Z",
		Inspection:          insp,
		BOM:                 genBOM,
		OMS:                 omsRes,
		HasEvaluation:       true,
		Evaluation:          evalSum,
		Scanner:             scanner.Result{Status: scanner.StatusNotRun},
		Provenance:          provenance.Result{Status: verification.StatusNotRun},
		RuntimeImage:        immutableImage,
		ServingConfigDigest: servingCfgDigest,
		Policy:              strictPol,
		Decision:            dec,
	}, priv)
	if err != nil {
		t.Fatalf("BuildAndOptionallySign: %v", err)
	}
	attPath := filepath.Join(tmp, "release-attestation.dsse.json")
	_ = os.WriteFile(attPath, att.JSONBytes, 0o600)

	writeDescriptor := func(name string, d Descriptor) string {
		p := filepath.Join(tmp, name)
		raw, mErr := json.MarshalIndent(d, "", "  ")
		if mErr != nil {
			t.Fatalf("marshal descriptor: %v", mErr)
		}
		_ = os.WriteFile(p, raw, 0o600)
		return p
	}

	validDesc := Descriptor{
		SchemaVersion:       "deployment-composition/v1",
		Name:                "prod-customer-assistant",
		ModelBundleID:       insp.BundleID,
		RuntimeImage:        immutableImage,
		RuntimeProfile:      "cpu-fp16",
		ServingConfigPath:   "serving-config.yaml",
		ServingConfigDigest: servingCfgDigest,
		ActiveAdapters:      []string{"support-lora-v1"},
		ServingParameters:   map[string]string{"max_model_len": "8192"},
	}
	validDescPath := writeDescriptor("deployment-valid.json", validDesc)

	// 1. Matching model bundle & deployment descriptor -> PASS
	verPass, err := Verify(VerifyOptions{
		BundlePath:      modelDir,
		DescriptorPath:  validDescPath,
		AttestationPath: attPath,
		Policy:          strictPol,
		TrustedSigners:  trustedSigners,
	})
	if err != nil || verPass.GateStatus != policy.StatusPass || verPass.CompositionID == "" {
		t.Fatalf("expected deployment PASS, got %+v (err=%v)", verPass, err)
	}
	if verPass.CompositionID == verPass.BundleID {
		t.Fatalf("CompositionID and BundleID must be distinct identities")
	}

	// 2. Modified weights -> FAIL
	modWeightsDir := filepath.Join(tmp, "mod-weights")
	_ = createFullModelBundle(t, modWeightsDir, 0x99, `{"version":"1.0","vocab":{"ok":1}}`, "8")
	verModWeights, err := Verify(VerifyOptions{
		BundlePath:      modWeightsDir,
		DescriptorPath:  validDescPath,
		AttestationPath: attPath,
		Policy:          strictPol,
		TrustedSigners:  trustedSigners,
	})
	if err == nil || verModWeights.GateStatus != policy.StatusFail {
		t.Fatalf("expected FAIL on modified weights, got %+v", verModWeights)
	}

	// 3. Modified tokenizer -> FAIL
	modTokDir := filepath.Join(tmp, "mod-tok")
	_ = createFullModelBundle(t, modTokDir, 0x11, `{"version":"1.0","vocab":{"tampered":999}}`, "8")
	verModTok, err := Verify(VerifyOptions{
		BundlePath:      modTokDir,
		DescriptorPath:  validDescPath,
		AttestationPath: attPath,
		Policy:          strictPol,
		TrustedSigners:  trustedSigners,
	})
	if err == nil || verModTok.GateStatus != policy.StatusFail {
		t.Fatalf("expected FAIL on modified tokenizer, got %+v", verModTok)
	}

	// 4. Different LoRA -> FAIL
	modLoRADir := filepath.Join(tmp, "mod-lora")
	_ = createFullModelBundle(t, modLoRADir, 0x11, `{"version":"1.0","vocab":{"ok":1}}`, "32")
	verModLoRA, err := Verify(VerifyOptions{
		BundlePath:      modLoRADir,
		DescriptorPath:  validDescPath,
		AttestationPath: attPath,
		Policy:          strictPol,
		TrustedSigners:  trustedSigners,
	})
	if err == nil || verModLoRA.GateStatus != policy.StatusFail {
		t.Fatalf("expected FAIL on different LoRA, got %+v", verModLoRA)
	}

	// 5. Changed runtime image digest -> FAIL
	changedImageDesc := validDesc
	changedImageDesc.RuntimeImage = "ghcr.io/vllm/vllm-openai@sha256:9999999999999999999999999999999999999999999999999999999999999999"
	changedImagePath := writeDescriptor("deployment-changed-img.json", changedImageDesc)
	verChangedImg, err := Verify(VerifyOptions{
		BundlePath:      modelDir,
		DescriptorPath:  changedImagePath,
		AttestationPath: attPath,
		Policy:          strictPol,
		TrustedSigners:  trustedSigners,
	})
	if err == nil || verChangedImg.GateStatus != policy.StatusFail {
		t.Fatalf("expected FAIL on changed runtime image digest, got %+v", verChangedImg)
	}

	// 6. Mutable image tag -> FAIL
	mutableImgDesc := validDesc
	mutableImgDesc.RuntimeImage = "ghcr.io/vllm/vllm-openai:latest"
	mutableImgPath := writeDescriptor("deployment-mutable-img.json", mutableImgDesc)
	verMutableImg, err := Verify(VerifyOptions{
		BundlePath:      modelDir,
		DescriptorPath:  mutableImgPath,
		AttestationPath: attPath,
		Policy:          strictPol,
		TrustedSigners:  trustedSigners,
	})
	if err == nil || verMutableImg.GateStatus != policy.StatusFail {
		t.Fatalf("expected FAIL on mutable runtime image tag, got %+v", verMutableImg)
	}

	// 7. Changed serving configuration -> FAIL
	changedCfgFile := filepath.Join(tmp, "serving-config-tampered.yaml")
	_ = os.WriteFile(changedCfgFile, []byte("max_model_len: 1024\ntrust_remote_code: true\n"), 0o600)
	changedCfgDesc := validDesc
	changedCfgDesc.ServingConfigPath = "serving-config-tampered.yaml"
	changedCfgPath := writeDescriptor("deployment-changed-cfg.json", changedCfgDesc)
	verChangedCfg, err := Verify(VerifyOptions{
		BundlePath:      modelDir,
		DescriptorPath:  changedCfgPath,
		AttestationPath: attPath,
		Policy:          strictPol,
		TrustedSigners:  trustedSigners,
	})
	if err == nil || verChangedCfg.GateStatus != policy.StatusFail {
		t.Fatalf("expected FAIL on changed serving configuration, got %+v", verChangedCfg)
	}

	// 8. Missing required configuration -> BLOCKED
	missingCfgDesc := validDesc
	missingCfgDesc.ServingConfigPath = ""
	missingCfgDesc.ServingConfigDigest = ""
	missingCfgPath := writeDescriptor("deployment-missing-cfg.json", missingCfgDesc)
	verMissingCfg, err := Verify(VerifyOptions{
		BundlePath:      modelDir,
		DescriptorPath:  missingCfgPath,
		AttestationPath: attPath,
		Policy:          strictPol,
		TrustedSigners:  trustedSigners,
	})
	if err == nil || verMissingCfg.GateStatus != policy.StatusBlocked {
		t.Fatalf("expected BLOCKED on missing required serving configuration, got %+v", verMissingCfg)
	}

	// 9. Altered attestation payload (forged/tampered DSSE payload) -> FAIL
	var env signing.DSSEEnvelope
	_ = json.Unmarshal(att.JSONBytes, &env)
	rawStmt, _ := base64.StdEncoding.DecodeString(env.Payload)
	alteredStmt := strings.Replace(string(rawStmt), "release-qualification/v1", "release-qualification/v1-tampered", 1)
	env.Payload = base64.StdEncoding.EncodeToString([]byte(alteredStmt))
	alteredBytes, _ := json.Marshal(env)
	alteredAttPath := filepath.Join(tmp, "altered-att.dsse.json")
	_ = os.WriteFile(alteredAttPath, alteredBytes, 0o600)
	verAlteredAtt, err := Verify(VerifyOptions{
		BundlePath:      modelDir,
		DescriptorPath:  validDescPath,
		AttestationPath: alteredAttPath,
		Policy:          strictPol,
		TrustedSigners:  trustedSigners,
	})
	if err == nil || verAlteredAtt.GateStatus != policy.StatusFail {
		t.Fatalf("expected FAIL on altered attestation, got %+v", verAlteredAtt)
	}
}
