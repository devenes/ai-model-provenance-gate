package oms

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/devenes/ai-model-provenance-gate/internal/bundle"
	"github.com/devenes/ai-model-provenance-gate/internal/formats/safetensors"
	"github.com/devenes/ai-model-provenance-gate/internal/signing"
	"github.com/devenes/ai-model-provenance-gate/internal/verification"
)

func createTestModelBundle(t *testing.T, dir string) bundle.InspectionResult {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{"architectures":["LlamaForCausalLM"],"model_type":"llama"}`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	w, err := safetensors.BuildSyntheticSafetensors([]safetensors.SyntheticTensor{
		{Name: "model.layers.0.weight", DType: "F16", Shape: []int64{4, 4}},
	}, map[string]string{"format": "pt"})
	if err != nil {
		t.Fatalf("build safetensors: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "model.safetensors"), w, 0o600); err != nil {
		t.Fatalf("write weights: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tokenizer.json"), []byte(`{"version":"1.0"}`), 0o600); err != nil {
		t.Fatalf("write tokenizer: %v", err)
	}
	insp, err := bundle.Inspect(dir, bundle.DefaultInspectOptions())
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	return insp
}

func TestOMSSigningAndVerificationMatrix(t *testing.T) {
	ctx := context.Background()
	bundleDir := filepath.Join(t.TempDir(), "model")
	insp := createTestModelBundle(t, bundleDir)

	// Generate trusted and untrusted key pairs
	trustedPrivPEM, trustedPubPEM, trustedFP, err := signing.GenerateEd25519KeyPairPEM()
	if err != nil {
		t.Fatalf("gen trusted key: %v", err)
	}
	trustedPriv, err := signing.ParsePrivateKeyPEM(trustedPrivPEM, "trusted-release-key")
	if err != nil {
		t.Fatalf("parse trusted priv: %v", err)
	}
	trustedPub, err := signing.ParsePublicKeyPEM(trustedPubPEM, "trusted-release-key", "Trusted Model Signer")
	if err != nil {
		t.Fatalf("parse trusted pub: %v", err)
	}

	untrustedPrivPEM, untrustedPubPEM, _, err := signing.GenerateEd25519KeyPairPEM()
	if err != nil {
		t.Fatalf("gen untrusted key: %v", err)
	}
	untrustedPriv, err := signing.ParsePrivateKeyPEM(untrustedPrivPEM, "unknown-key-99")
	if err != nil {
		t.Fatalf("parse untrusted priv: %v", err)
	}
	untrustedPub, err := signing.ParsePublicKeyPEM(untrustedPubPEM, "unknown-key-99", "Untrusted Signer")
	if err != nil {
		t.Fatalf("parse untrusted pub: %v", err)
	}

	trustedRules := []verification.TrustedSignerRule{
		{
			ID:             "signer-1",
			Name:           "Trusted Model Signer",
			KeyID:          "trusted-release-key",
			KeyFingerprint: trustedFP,
			PublicKey:      trustedPub,
		},
	}

	// 1. Valid trusted signature (Sigstore Bundle wrapping OMS v1.0 DSSE)
	sigBytes, err := SignBundle(insp, trustedPriv, SignOptions{AsSigstoreBundle: true})
	if err != nil {
		t.Fatalf("SignBundle: %v", err)
	}
	sigPath := filepath.Join(t.TempDir(), "model.sig")
	if err := os.WriteFile(sigPath, sigBytes, 0o600); err != nil {
		t.Fatalf("write sig: %v", err)
	}

	resValid, err := VerifyBundle(ctx, insp, sigPath, VerifyOptions{
		TrustedSigners: trustedRules,
	})
	if err != nil || resValid.Status != verification.StatusVerified {
		t.Fatalf("expected VERIFIED, got status=%s err=%v", resValid.Status, err)
	}
	if !resValid.DigestsMatchInventory || resValid.VerifiedFileCount != 3 {
		t.Fatalf("unexpected file correspondence result: %+v", resValid)
	}

	// 2. Missing signature -> MISSING
	resMissing, err := VerifyBundle(ctx, insp, "", VerifyOptions{TrustedSigners: trustedRules})
	if err == nil || resMissing.Status != verification.StatusMissing {
		t.Fatalf("expected MISSING for empty path, got %s", resMissing.Status)
	}

	// 3. Missing verification material -> BLOCKED
	resNoKey, err := VerifyBundle(ctx, insp, sigPath, VerifyOptions{})
	if !errors.Is(err, verification.ErrMissingVerificationMaterial) || resNoKey.Status != verification.StatusBlocked {
		t.Fatalf("expected BLOCKED for missing verification material, got status=%s err=%v", resNoKey.Status, err)
	}

	// 4. Unknown signer -> UNTRUSTED
	untrustedSigBytes, err := SignBundle(insp, untrustedPriv, SignOptions{AsSigstoreBundle: false})
	if err != nil {
		t.Fatalf("SignBundle untrusted: %v", err)
	}
	untrustedSigPath := filepath.Join(t.TempDir(), "untrusted.sig")
	if err := os.WriteFile(untrustedSigPath, untrustedSigBytes, 0o600); err != nil {
		t.Fatalf("write untrusted sig: %v", err)
	}
	resUntrusted, err := VerifyBundle(ctx, insp, untrustedSigPath, VerifyOptions{
		TrustedSigners:         trustedRules,
		CandidateUntrustedKeys: []*signing.PublicKey{untrustedPub},
	})
	if !errors.Is(err, verification.ErrUntrustedSigner) || resUntrusted.Status != verification.StatusUntrusted {
		t.Fatalf("expected UNTRUSTED for unknown signer, got status=%s err=%v", resUntrusted.Status, err)
	}

	// Also test unknown signer when CandidateUntrustedKeys is empty (detected via unknown keyid)
	resUntrustedKeyID, err := VerifyBundle(ctx, insp, untrustedSigPath, VerifyOptions{
		TrustedSigners: trustedRules,
	})
	if !errors.Is(err, verification.ErrUntrustedSigner) || resUntrustedKeyID.Status != verification.StatusUntrusted {
		t.Fatalf("expected UNTRUSTED for unknown keyid, got status=%s err=%v", resUntrustedKeyID.Status, err)
	}

	// 5. Invalid signature (corrupted sig bytes for known keyid) -> INVALID
	corruptedJSON := strings.Replace(string(sigBytes), `"sig": "`, `"sig": "AAAA`, 1)
	corruptedPath := filepath.Join(t.TempDir(), "corrupted.sig")
	if err := os.WriteFile(corruptedPath, []byte(corruptedJSON), 0o600); err != nil {
		t.Fatalf("write corrupted: %v", err)
	}
	resInvalid, err := VerifyBundle(ctx, insp, corruptedPath, VerifyOptions{TrustedSigners: trustedRules})
	if err == nil || resInvalid.Status != verification.StatusInvalid {
		t.Fatalf("expected INVALID for corrupted signature, got status=%s err=%v", resInvalid.Status, err)
	}

	// 6. Wrong subject digest / tampered tokenizer after signing -> INVALID (ErrComponentDigestMismatch)
	tamperedDir := filepath.Join(t.TempDir(), "tampered-model")
	_ = createTestModelBundle(t, tamperedDir)
	if err := os.WriteFile(filepath.Join(tamperedDir, "tokenizer.json"), []byte(`{"version":"1.0","hacked":true}`), 0o600); err != nil {
		t.Fatalf("tamper tokenizer: %v", err)
	}
	inspTampered, err := bundle.Inspect(tamperedDir, bundle.DefaultInspectOptions())
	if err != nil {
		t.Fatalf("Inspect tampered: %v", err)
	}
	resTampered, err := VerifyBundle(ctx, inspTampered, sigPath, VerifyOptions{TrustedSigners: trustedRules})
	if !errors.Is(err, ErrComponentDigestMismatch) || resTampered.Status != verification.StatusInvalid {
		t.Fatalf("expected ErrComponentDigestMismatch / INVALID on tampered tokenizer, got status=%s err=%v", resTampered.Status, err)
	}
	if len(resTampered.MismatchedFiles) != 1 || resTampered.MismatchedFiles[0] != "tokenizer.json" {
		t.Fatalf("expected tokenizer.json in MismatchedFiles, got %v", resTampered.MismatchedFiles)
	}

	// 7. External CLI mode when model_signing is not installed -> BLOCKED (never simulated PASS)
	resExtCLI, err := VerifyBundle(ctx, insp, sigPath, VerifyOptions{
		Mode:           ModeExternalCLI,
		ExternalBinary: "nonexistent-model-signing-binary",
		TrustedSigners: trustedRules,
	})
	if !errors.Is(err, ErrExternalCLIUnavailable) || resExtCLI.Status != verification.StatusBlocked {
		t.Fatalf("expected BLOCKED when external CLI is unavailable, got status=%s err=%v", resExtCLI.Status, err)
	}
}
