package provenance

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/devenes/ai-model-provenance-gate/internal/signing"
	"github.com/devenes/ai-model-provenance-gate/internal/verification"
)

const testSLSABundleID = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
const testSLSABundleHex = "1111111111111111111111111111111111111111111111111111111111111111"

func buildSignedSLSAStatement(t *testing.T, priv *signing.PrivateKey, subjectHex string, predicateType string, pred any) []byte {
	t.Helper()
	predBytes, err := json.Marshal(pred)
	if err != nil {
		t.Fatalf("marshal predicate: %v", err)
	}
	stmt := signing.InTotoStatement{
		Type: signing.InTotoStatementV1Type,
		Subject: []signing.ResourceDescriptor{
			{
				Name:   "model-bundle:test",
				Digest: map[string]string{"sha256": subjectHex},
			},
		},
		PredicateType: predicateType,
		Predicate:     predBytes,
	}
	stmtBytes, err := json.Marshal(stmt)
	if err != nil {
		t.Fatalf("marshal statement: %v", err)
	}
	env, err := signing.SignDSSE(signing.InTotoPayloadType, stmtBytes, priv)
	if err != nil {
		t.Fatalf("SignDSSE: %v", err)
	}
	out, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		t.Fatalf("marshal env: %v", err)
	}
	return out
}

func TestVerifyUpstreamSLSAV12Provenance(t *testing.T) {
	privPEM, pubPEM, fp, err := signing.GenerateEd25519KeyPairPEM()
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	priv, _ := signing.ParsePrivateKeyPEM(privPEM, "slsa-builder-key")
	pub, _ := signing.ParsePublicKeyPEM(pubPEM, "slsa-builder-key", "Trusted SLSA Builder")
	trustedSigners := []verification.TrustedSignerRule{
		{ID: "slsa-builder-key", Name: "Trusted SLSA Builder", KeyID: "slsa-builder-key", KeyFingerprint: fp, PublicKey: pub},
	}

	validPred := map[string]any{
		"buildDefinition": map[string]any{
			"buildType": "https://slsa.dev/container-based-build/v1",
			"externalParameters": map[string]any{
				"repository": "https://github.com/devenes/ai-model-provenance-gate",
				"workflow":   ".github/workflows/train-lora.yml",
			},
			"internalParameters": map[string]any{
				"runner": "ubuntu-24.04",
			},
			"resolvedDependencies": []map[string]any{
				{
					"uri":  "pkg:huggingface/meta-llama/Llama-3-8B@043235d",
					"name": "base-model",
					"digest": map[string]string{
						"sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
					},
				},
			},
		},
		"runDetails": map[string]any{
			"builder": map[string]any{
				"id": "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v2.0.0",
			},
			"metadata": map[string]any{
				"invocationId": "https://github.com/devenes/ai-model-provenance-gate/actions/runs/10001",
				"startedOn":    "2026-10-31T00:00:00Z",
				"finishedOn":   "2026-10-31T00:05:00Z",
			},
		},
	}

	dir := t.TempDir()

	// 1. Valid SLSA v1.2 provenance -> VERIFIED
	validPath := filepath.Join(dir, "valid-slsa.dsse.json")
	_ = os.WriteFile(validPath, buildSignedSLSAStatement(t, priv, testSLSABundleHex, SLSAV1PredicateType, validPred), 0o600)

	res, err := VerifyUpstreamProvenance(VerifyOptions{
		AttestationPath:             validPath,
		ExpectedBundleID:            testSLSABundleID,
		ExpectedBuilderIDs:          []string{"https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v2.0.0"},
		RequireResolvedDependencies: true,
		TrustedSigners:              trustedSigners,
	})
	if err != nil || res.Status != verification.StatusVerified || res.ResolvedDependencyCount != 1 {
		t.Fatalf("expected valid SLSA v1.2 provenance to pass, got %+v (err=%v)", res, err)
	}

	// 2. Wrong subject digest -> INVALID
	wrongSubjPath := filepath.Join(dir, "wrong-subject.dsse.json")
	_ = os.WriteFile(wrongSubjPath, buildSignedSLSAStatement(t, priv, "2222222222222222222222222222222222222222222222222222222222222222", SLSAV1PredicateType, validPred), 0o600)
	resWrongSubj, err := VerifyUpstreamProvenance(VerifyOptions{
		AttestationPath:  wrongSubjPath,
		ExpectedBundleID: testSLSABundleID,
		TrustedSigners:   trustedSigners,
	})
	if !errors.Is(err, ErrInvalidSLSAProvenance) || resWrongSubj.Status != verification.StatusInvalid {
		t.Fatalf("expected wrong subject digest to fail with StatusInvalid, got %+v (err=%v)", resWrongSubj, err)
	}

	// 3. Untrusted builder ID -> UNTRUSTED
	resUntrustedBuilder, err := VerifyUpstreamProvenance(VerifyOptions{
		AttestationPath:    validPath,
		ExpectedBundleID:   testSLSABundleID,
		ExpectedBuilderIDs: []string{"https://trusted.internal.ci/builder/v1"},
		TrustedSigners:     trustedSigners,
	})
	if !errors.Is(err, ErrInvalidSLSAProvenance) || resUntrustedBuilder.Status != verification.StatusUntrusted {
		t.Fatalf("expected untrusted builder ID to fail with StatusUntrusted, got %+v (err=%v)", resUntrustedBuilder, err)
	}

	// 4. Invalid signature / untrusted signer key -> INVALID / UNTRUSTED
	roguePrivPEM, roguePubPEM, _, _ := signing.GenerateEd25519KeyPairPEM()
	roguePriv, _ := signing.ParsePrivateKeyPEM(roguePrivPEM, "rogue-builder")
	roguePub, _ := signing.ParsePublicKeyPEM(roguePubPEM, "rogue-builder", "Rogue Builder")
	roguePath := filepath.Join(dir, "rogue-slsa.dsse.json")
	_ = os.WriteFile(roguePath, buildSignedSLSAStatement(t, roguePriv, testSLSABundleHex, SLSAV1PredicateType, validPred), 0o600)

	resRogue, err := VerifyUpstreamProvenance(VerifyOptions{
		AttestationPath:        roguePath,
		ExpectedBundleID:       testSLSABundleID,
		TrustedSigners:         trustedSigners,
		CandidateUntrustedKeys: []*signing.PublicKey{roguePub},
	})
	if !errors.Is(err, ErrInvalidSLSAProvenance) || resRogue.Status != verification.StatusUntrusted {
		t.Fatalf("expected rogue signer to fail with StatusUntrusted, got %+v (err=%v)", resRogue, err)
	}

	// 5. Missing materials (resolvedDependencies) when required, or missing externalParameters -> INVALID
	noMaterialsPred := map[string]any{
		"buildDefinition": map[string]any{
			"buildType":          "https://slsa.dev/container-based-build/v1",
			"externalParameters": map[string]any{"workflow": "build.yml"},
		},
		"runDetails": map[string]any{
			"builder": map[string]any{"id": "https://trusted.internal.ci/builder/v1"},
		},
	}
	noMaterialsPath := filepath.Join(dir, "no-materials.dsse.json")
	_ = os.WriteFile(noMaterialsPath, buildSignedSLSAStatement(t, priv, testSLSABundleHex, SLSAV1PredicateType, noMaterialsPred), 0o600)

	resNoMaterials, err := VerifyUpstreamProvenance(VerifyOptions{
		AttestationPath:             noMaterialsPath,
		ExpectedBundleID:            testSLSABundleID,
		RequireResolvedDependencies: true,
		TrustedSigners:              trustedSigners,
	})
	if !errors.Is(err, ErrInvalidSLSAProvenance) || resNoMaterials.Status != verification.StatusInvalid {
		t.Fatalf("expected missing resolvedDependencies to fail when required, got %+v (err=%v)", resNoMaterials, err)
	}

	// 6. Mismatched predicate type -> INVALID
	wrongPredTypePath := filepath.Join(dir, "wrong-pred-type.dsse.json")
	_ = os.WriteFile(wrongPredTypePath, buildSignedSLSAStatement(t, priv, testSLSABundleHex, "https://github.com/devenes/ai-model-provenance-gate/attestation/release-qualification/v1", validPred), 0o600)
	resWrongType, err := VerifyUpstreamProvenance(VerifyOptions{
		AttestationPath:  wrongPredTypePath,
		ExpectedBundleID: testSLSABundleID,
		TrustedSigners:   trustedSigners,
	})
	if !errors.Is(err, ErrInvalidSLSAProvenance) || resWrongType.Status != verification.StatusInvalid {
		t.Fatalf("expected mismatched predicateType to fail with StatusInvalid, got %+v (err=%v)", resWrongType, err)
	}
}
