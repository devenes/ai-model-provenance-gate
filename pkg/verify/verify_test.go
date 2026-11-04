package verify_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/devenes/ai-model-provenance-gate/internal/bundle"
	"github.com/devenes/ai-model-provenance-gate/internal/formats/safetensors"
	"github.com/devenes/ai-model-provenance-gate/pkg/verify"
)

func sampleDescriptors() []verify.FileEntry {
	return []verify.FileEntry{
		{
			Path:   "config.json",
			Role:   "model_config",
			SHA256: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
			Size:   256,
		},
		{
			Path:   "model.safetensors",
			Role:   "model_weights",
			SHA256: "sha256:2222222222222222222222222222222222222222222222222222222222222222",
			Size:   4096,
		},
		{
			Path:   "tokenizer.json",
			Role:   "tokenizer_vocab",
			SHA256: "sha256:3333333333333333333333333333333333333333333333333333333333333333",
			Size:   512,
		},
	}
}

func sampleEvalReportJSON(bundleID string, now time.Time) []byte {
	rep := map[string]any{
		"schemaVersion": "llm-release-gate.report/v1",
		"runId":         "run-test-001",
		"timestamp":     now.UTC().Format(time.RFC3339),
		"toolVersion":   "0.1.0",
		"suite": map[string]any{
			"name":    "medical-qa-gate",
			"version": "1.0.0",
			"digest":  "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
		"dataset": map[string]any{
			"digest":    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			"caseCount": 2,
		},
		"graders": []map[string]any{
			{"type": "exact-match", "version": "1.0.0"},
		},
		"evaluator": map[string]any{
			"name":    "llm-release-gate",
			"version": "0.1.0",
		},
		"execution": map[string]any{
			"mode":        "native",
			"timeout":     "15s",
			"concurrency": 1,
			"repetitions": 1,
		},
		"candidate": map[string]any{
			"name":     "gemma-2b-it",
			"version":  "1.0.0",
			"provider": "openai-compatible",
			"model":    "gemma-2b-it",
			"digest":   "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
			"metadata": map[string]string{
				"model_bundle_id": bundleID,
			},
		},
		"cases": []map[string]any{
			{"id": "c1", "repetition": 1, "status": "passed", "required": true, "assertions": []any{}},
			{"id": "c2", "repetition": 1, "status": "passed", "required": true, "assertions": []any{}},
		},
		"metrics": map[string]any{
			"totalPlannedCases": 2,
			"executedCases":     2,
			"passedCases":       2,
		},
		"gateStatus":       "PASS",
		"evidenceQuality":  "COMPLETE",
		"comparisonStatus": "NOT_APPLICABLE",
		"exitCode":         0,
		"decisionReasons": []map[string]any{
			{"code": "ALL_CHECKS_PASSED", "category": "policy", "severity": "info", "message": "all checks passed"},
		},
	}
	raw, _ := json.MarshalIndent(rep, "", "  ")
	return append(raw, '\n')
}

func buildNativeEvalAttestation(t *testing.T, rawReport []byte, bundleID string, privPEM []byte, keyID string, now time.Time) []byte {
	t.Helper()
	rawAtt, err := verify.SignNativeEvaluationBytes(rawReport, bundleID, privPEM, keyID, now.UTC().Format(time.RFC3339))
	if err != nil {
		t.Fatalf("SignNativeEvaluationBytes: %v", err)
	}
	return rawAtt
}

func TestDescriptorEquivalenceWithFilesystemInspect(t *testing.T) {
	tmpDir := t.TempDir()
	weights, err := safetensors.BuildSyntheticSafetensors([]safetensors.SyntheticTensor{
		{
			Name:  "model.layers.0.self_attn.q_proj.weight",
			DType: "BF16",
			Shape: []int64{4, 4},
			Data:  make([]byte, 32),
		},
	}, map[string]string{"format": "pt"})
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{
		"config.json":       []byte(`{"model_type":"gemma","architectures":["GemmaForCausalLM"]}`),
		"model.safetensors": weights,
		"tokenizer.json":    []byte(`{"version":"1.0"}`),
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(tmpDir, name), content, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	insp, err := bundle.Inspect(tmpDir, bundle.InspectOptions{})
	if err != nil {
		t.Fatalf("bundle.Inspect: %v", err)
	}

	descriptors := make([]verify.FileEntry, 0, len(insp.Inventory.Files))
	// Add in reverse order to verify canonical sorting
	for i := len(insp.Inventory.Files) - 1; i >= 0; i-- {
		f := insp.Inventory.Files[i]
		descriptors = append(descriptors, verify.FileEntry{
			Path:   f.Path,
			SHA256: f.SHA256,
			Size:   f.Size,
		})
	}

	idRes, err := verify.ComputeBundleIdentityFromDescriptors(descriptors)
	if err != nil {
		t.Fatalf("ComputeBundleIdentityFromDescriptors: %v", err)
	}
	if idRes.BundleID != insp.BundleID {
		t.Fatalf("BundleID mismatch: got %s, want %s", idRes.BundleID, insp.BundleID)
	}

	bm, err := verify.VerifyBundleManifestBytes(insp.ManifestJSON, descriptors, verify.ManifestVerifyOptions{})
	if err != nil {
		t.Fatalf("VerifyBundleManifestBytes: %v", err)
	}
	if bm.BundleID != insp.BundleID {
		t.Fatalf("verified BundleID mismatch: got %s, want %s", bm.BundleID, insp.BundleID)
	}
	if bm.ManifestDigest != insp.Manifest.ManifestDigest {
		t.Fatalf("ManifestDigest mismatch: got %s, want %s", bm.ManifestDigest, insp.Manifest.ManifestDigest)
	}
}

func TestFullInMemoryVerificationChainAndTamperResistance(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	files := sampleDescriptors()

	// Generate 3 distinct domain keys: modelSigner, evaluator, releaseAuthority
	msPriv, msPub, msFP, err := verify.GenerateEd25519KeyPairPEM()
	if err != nil {
		t.Fatal(err)
	}
	evPriv, evPub, evFP, err := verify.GenerateEd25519KeyPairPEM()
	if err != nil {
		t.Fatal(err)
	}
	raPriv, raPub, raFP, err := verify.GenerateEd25519KeyPairPEM()
	if err != nil {
		t.Fatal(err)
	}

	modelSigners := []verify.TrustedSignerRule{
		{ID: "model-signer-1", KeyID: "ms-1", KeyFingerprint: msFP, PublicKeyPEM: msPub},
	}
	evaluators := []verify.TrustedSignerRule{
		{ID: "eval-signer-1", KeyID: "ev-1", KeyFingerprint: evFP, PublicKeyPEM: evPub},
	}
	releaseAuthorities := []verify.TrustedSignerRule{
		{ID: "rel-signer-1", KeyID: "ra-1", KeyFingerprint: raFP, PublicKeyPEM: raPub},
	}
	allCandidates := append(append([]verify.TrustedSignerRule{}, modelSigners...), evaluators...)
	allCandidates = append(allCandidates, releaseAuthorities...)

	// 1. Build & verify bundle-manifest.json
	rawManifest, bm, err := verify.BuildBundleManifestBytes(files, verify.BuildManifestOptions{
		ModelType:    "gemma",
		Architecture: "GemmaForCausalLM",
		ModelName:    "gemma-2b-it",
		Timestamp:    now.Format(time.RFC3339),
	})
	if err != nil {
		t.Fatalf("BuildBundleManifestBytes: %v", err)
	}
	_ = rawManifest

	// Tamper descriptor test
	tamperedFiles := sampleDescriptors()
	tamperedFiles[1].SHA256 = "sha256:9999999999999999999999999999999999999999999999999999999999999999"
	if _, err := verify.VerifyBundleManifestBytes(rawManifest, tamperedFiles, verify.ManifestVerifyOptions{}); err == nil {
		t.Fatal("expected VerifyBundleManifestBytes to fail on tampered weight layer digest")
	}

	// 2. Build & verify OMS v1.0 signature
	rawOMS, err := verify.SignOMSBytesFromDescriptors(files, msPriv, "ms-1")
	if err != nil {
		t.Fatalf("SignOMSBytesFromDescriptors: %v", err)
	}
	omsRes, err := verify.VerifyOMSBytes(rawOMS, files, verify.OMSVerifyOptions{
		TrustedModelSigners: modelSigners,
		UntrustedCandidates: allCandidates,
	})
	if err != nil || omsRes.Status != verify.StatusVerified {
		t.Fatalf("VerifyOMSBytes failed: status=%s err=%v", omsRes.Status, err)
	}

	// Cross-domain rejection: OMS signed by evaluator key must fail modelSigners check
	rawOMSWrongDomain, err := verify.SignOMSBytesFromDescriptors(files, evPriv, "ev-1")
	if err != nil {
		t.Fatal(err)
	}
	if wrongRes, err := verify.VerifyOMSBytes(rawOMSWrongDomain, files, verify.OMSVerifyOptions{
		TrustedModelSigners: modelSigners,
		UntrustedCandidates: allCandidates,
	}); err == nil || wrongRes.Status != verify.StatusUntrusted {
		t.Fatalf("expected cross-domain OMS signature to return StatusUntrusted, got status=%s err=%v", wrongRes.Status, err)
	}

	// 3. Build & verify CycloneDX 1.7 AI/ML-BOM
	rawBOM, bomCanonHash, err := verify.GenerateBOMBytesFromDescriptors(files, verify.BuildManifestOptions{
		ModelType:    "gemma",
		Architecture: "GemmaForCausalLM",
		ModelName:    "gemma-2b-it",
		Timestamp:    now.Format(time.RFC3339),
	})
	if err != nil {
		t.Fatalf("GenerateBOMBytesFromDescriptors: %v", err)
	}
	bomRes, err := verify.VerifyBOMBytes(rawBOM, &bm, files)
	if err != nil || bomRes.Status != verify.StatusVerified {
		t.Fatalf("VerifyBOMBytes failed: status=%s err=%v", bomRes.Status, err)
	}
	if bomRes.CanonicalHash != bomCanonHash {
		t.Fatalf("BOM canonical hash mismatch: got %s, want %s", bomRes.CanonicalHash, bomCanonHash)
	}

	// 4. Build & verify native Evaluation Evidence
	rawReport := sampleEvalReportJSON(bm.BundleID, now)
	rawEvalAtt := buildNativeEvalAttestation(t, rawReport, bm.BundleID, evPriv, "ev-1", now)

	evalRes, err := verify.VerifyEvaluationBytes(rawReport, rawEvalAtt, verify.EvalVerifyOptions{
		TrustedEvaluators:      evaluators,
		UntrustedCandidates:    allCandidates,
		ExpectedBundleID:       bm.BundleID,
		RequireArtifactBinding: true,
		RequireTrustedEvidence: true,
		AllowPostHocBinding:    false,
		MaxAge:                 24 * time.Hour,
		Now:                    now,
	})
	if err != nil || evalRes.Status != verify.StatusVerified {
		t.Fatalf("VerifyEvaluationBytes failed: status=%s reason=%s err=%v", evalRes.Status, evalRes.Reason, err)
	}

	// Reject POST_HOC_OPERATOR when AllowPostHocBinding == false
	rawPostHocAtt, err := verify.SignPostHocEvaluationBytes(rawReport, bm.BundleID, evPriv, "ev-1", now.Format(time.RFC3339))
	if err != nil {
		t.Fatal(err)
	}
	if phRes, err := verify.VerifyEvaluationBytes(rawReport, rawPostHocAtt, verify.EvalVerifyOptions{
		TrustedEvaluators:      evaluators,
		UntrustedCandidates:    allCandidates,
		ExpectedBundleID:       bm.BundleID,
		RequireArtifactBinding: true,
		RequireTrustedEvidence: true,
		AllowPostHocBinding:    false,
		MaxAge:                 24 * time.Hour,
		Now:                    now,
	}); err == nil || phRes.EligibleForRelease {
		t.Fatalf("expected POST_HOC_OPERATOR evaluation evidence to be rejected, got status=%s eligible=%v", phRes.Status, phRes.EligibleForRelease)
	}

	// 5. Build & verify Release Qualification Attestation
	rawRelAtt, _, err := verify.SignReleaseQualificationBytes(verify.ReleaseBuildInput{
		Timestamp:           now.Format(time.RFC3339),
		Manifest:            bm,
		BOMCanonicalDigest:  bomRes.CanonicalHash,
		BOMSpecVersion:      bomRes.SpecVersion,
		OMS:                 omsRes,
		Evaluation:          evalRes,
		RuntimeImage:        "us-west4-docker.pkg.dev/PROJECT_ID/models/serving@sha256:4444444444444444444444444444444444444444444444444444444444444444",
		ServingConfigDigest: "sha256:5555555555555555555555555555555555555555555555555555555555555555",
	}, raPriv, "ra-1")
	if err != nil {
		t.Fatalf("SignReleaseQualificationBytes: %v", err)
	}

	relRes, err := verify.VerifyReleaseQualificationBytes(rawRelAtt, verify.ReleaseVerifyOptions{
		TrustedAuthorities:            releaseAuthorities,
		UntrustedCandidates:           allCandidates,
		ExpectedBundleID:              bm.BundleID,
		ExpectedManifestDigest:        bm.ManifestDigest,
		ExpectedBOMDigest:             bomRes.CanonicalHash,
		ExpectedOMSSignatureDigest:    omsRes.SignatureDigest,
		ExpectedEvalReportDigest:      evalRes.ReportDigest,
		ExpectedEvalAttestationDigest: evalRes.AttestationDigest,
		RequireTrustedEvaluator:       true,
		RejectPostHocBinding:          true,
		MaxAge:                        24 * time.Hour,
		Now:                           now,
	})
	if err != nil || relRes.Status != verify.StatusVerified {
		t.Fatalf("VerifyReleaseQualificationBytes failed: status=%s reason=%s err=%v", relRes.Status, relRes.Reason, err)
	}

	// Cross-evidence transplant rejection: pass a different ExpectedBOMDigest
	if badRel, err := verify.VerifyReleaseQualificationBytes(rawRelAtt, verify.ReleaseVerifyOptions{
		TrustedAuthorities:            releaseAuthorities,
		UntrustedCandidates:           allCandidates,
		ExpectedBundleID:              bm.BundleID,
		ExpectedManifestDigest:        bm.ManifestDigest,
		ExpectedBOMDigest:             "sha256:9999999999999999999999999999999999999999999999999999999999999999",
		ExpectedOMSSignatureDigest:    omsRes.SignatureDigest,
		ExpectedEvalReportDigest:      evalRes.ReportDigest,
		ExpectedEvalAttestationDigest: evalRes.AttestationDigest,
		RequireTrustedEvaluator:       true,
		RejectPostHocBinding:          true,
		MaxAge:                        24 * time.Hour,
		Now:                           now,
	}); err == nil || badRel.Status == verify.StatusVerified {
		t.Fatalf("expected transplanted BOM digest to fail VerifyReleaseQualificationBytes")
	}
}
