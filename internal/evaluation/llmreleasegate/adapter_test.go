package llmreleasegate

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/devenes/ai-model-provenance-gate/internal/signing"
	"github.com/devenes/ai-model-provenance-gate/internal/verification"
)

const sampleBundleID = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
const otherBundleID = "sha256:2222222222222222222222222222222222222222222222222222222222222222"

func buildReportJSON(t *testing.T, status GateStatus, quality EvidenceQuality, exitCode int, bundleID string) []byte {
	t.Helper()
	meta := map[string]string{
		"adapter": "support-lora-v2",
	}
	if bundleID != "" {
		meta[MetadataKeyModelBundleID] = bundleID
	}
	rep := RawReport{
		SchemaVersion: ReportSchemaVersion,
		RunID:         "run-test-001",
		Timestamp:     "2026-10-31T00:00:00Z",
		ToolVersion:   "0.1.0",
		Suite: SuiteMetadata{
			Name:    "customer-assistant",
			Version: "1.0.0",
			Digest:  "sha256:aacc5f5bd47e335484803969a97f415f06e00a6c0681c95a056918f8a22e53fb",
		},
		Dataset: DatasetMetadata{
			Digest:    "sha256:c83d9a10096a9d2e4bfaaebb8b8e298f724a185c75c4887a81bfdcb4ecd5323a",
			CaseCount: 3,
		},
		Graders: []GraderIdentity{
			{Type: "exact-match", Version: "1.0.0"},
		},
		Candidate: SubjectIdentity{
			Name:     "customer-assistant-v1",
			Version:  "1.0.0",
			Provider: "fake",
			Model:    "fake-deterministic-v1",
			Digest:   "sha256:96eef63b79a77e33b46dfaf4498e491fb0df4f46b63621bdcb259ee620d06c48",
			Metadata: meta,
		},
		Execution: ExecutionProfile{
			Mode:        "native",
			Timeout:     "15s",
			Concurrency: 1,
			Repetitions: 1,
		},
		Evaluator: EvaluatorIdentity{
			Name:    "llm-release-gate-native",
			Version: "1.0.0",
		},
		Cases: []json.RawMessage{
			json.RawMessage(`{"id":"c1","repetition":1,"status":"passed","required":true,"assertions":[]}`),
		},
		Metrics: AggregateMetrics{
			TotalPlannedCases: 1,
			ExecutedCases:     1,
			PassedCases:       1,
		},
		GateStatus:       status,
		EvidenceQuality:  quality,
		ComparisonStatus: "NOT_APPLICABLE",
		ExitCode:         exitCode,
		DecisionReasons: []DecisionReason{
			{Code: "TEST", Category: "policy", Severity: "info", Message: "test"},
		},
	}
	raw, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	return raw
}

func TestEvaluationEvidenceAcceptanceMatrix(t *testing.T) {
	privPEM, pubPEM, fp, err := signing.GenerateEd25519KeyPairPEM()
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	priv, _ := signing.ParsePrivateKeyPEM(privPEM, "eval-signer-1")
	pub, _ := signing.ParsePublicKeyPEM(pubPEM, "eval-signer-1", "Trusted Evaluator")
	trustedSigners := []verification.TrustedSignerRule{
		{ID: "eval-signer-1", Name: "Trusted Evaluator", KeyID: "eval-signer-1", KeyFingerprint: fp, PublicKey: pub},
	}

	dir := t.TempDir()

	// 1. Matching PASS evidence + trusted signature -> PASS (EligibleForRelease=true)
	passReportPath := filepath.Join(dir, "pass-bound.json")
	if err := os.WriteFile(passReportPath, buildReportJSON(t, GatePass, EvidenceComplete, 0, sampleBundleID), 0o600); err != nil {
		t.Fatalf("write pass report: %v", err)
	}
	attBytes, err := SignEvaluationEvidence(passReportPath, sampleBundleID, priv, "2026-10-31T00:00:00Z")
	if err != nil {
		t.Fatalf("SignEvaluationEvidence: %v", err)
	}
	attPath := filepath.Join(dir, "pass-bound.dsse.json")
	if err := os.WriteFile(attPath, attBytes, 0o600); err != nil {
		t.Fatalf("write att: %v", err)
	}

	sumPass, err := Verify(passReportPath, VerifyOptions{
		ExpectedBundleID:       sampleBundleID,
		AttestationPath:        attPath,
		TrustedSigners:         trustedSigners,
		RequireArtifactBinding: true,
		RequireTrustedEvidence: true,
	})
	if err != nil || !sumPass.EligibleForRelease || sumPass.EffectiveGateStatus != GatePass {
		t.Fatalf("expected PASS & EligibleForRelease=true, got %+v (err=%v)", sumPass, err)
	}

	// 2. Mismatching PASS evidence (different artifact identity) -> FAIL
	sumMismatch, err := Verify(passReportPath, VerifyOptions{
		ExpectedBundleID:       otherBundleID,
		AttestationPath:        attPath,
		TrustedSigners:         trustedSigners,
		RequireArtifactBinding: true,
		RequireTrustedEvidence: true,
	})
	if !errors.Is(err, ErrArtifactMismatch) || sumMismatch.EffectiveGateStatus != GateFail || sumMismatch.BindingStatus != BindingMismatch {
		t.Fatalf("expected ErrArtifactMismatch / FAIL, got %+v (err=%v)", sumMismatch, err)
	}

	// 3. FAIL -> FAIL
	failPath := filepath.Join(dir, "fail.json")
	_ = os.WriteFile(failPath, buildReportJSON(t, GateFail, EvidenceComplete, 1, sampleBundleID), 0o600)
	sumFail, err := Verify(failPath, VerifyOptions{
		ExpectedBundleID:       sampleBundleID,
		RequireArtifactBinding: true,
		RequireTrustedEvidence: false,
	})
	if err == nil || sumFail.EffectiveGateStatus != GateFail {
		t.Fatalf("expected FAIL, got %+v", sumFail)
	}

	// 4. BLOCKED -> BLOCKED
	blockedPath := filepath.Join(dir, "blocked.json")
	_ = os.WriteFile(blockedPath, buildReportJSON(t, GateBlocked, EvidenceLimited, 3, sampleBundleID), 0o600)
	sumBlocked, err := Verify(blockedPath, VerifyOptions{
		ExpectedBundleID:       sampleBundleID,
		RequireArtifactBinding: true,
		RequireTrustedEvidence: false,
	})
	if err == nil || sumBlocked.EffectiveGateStatus != GateBlocked {
		t.Fatalf("expected BLOCKED, got %+v", sumBlocked)
	}

	// 5. NOT_RUN -> BLOCKED
	notRunPath := filepath.Join(dir, "notrun.json")
	_ = os.WriteFile(notRunPath, buildReportJSON(t, GateNotRun, EvidenceLimited, 3, sampleBundleID), 0o600)
	sumNotRun, err := Verify(notRunPath, VerifyOptions{
		ExpectedBundleID:       sampleBundleID,
		RequireArtifactBinding: true,
		RequireTrustedEvidence: false,
	})
	if err == nil || sumNotRun.EffectiveGateStatus != GateBlocked {
		t.Fatalf("expected BLOCKED for NOT_RUN, got %+v", sumNotRun)
	}

	// 6. Missing artifact identity -> UNBOUND / BLOCKED
	unboundPath := filepath.Join(dir, "unbound.json")
	_ = os.WriteFile(unboundPath, buildReportJSON(t, GatePass, EvidenceComplete, 0, ""), 0o600)
	sumUnbound, err := Verify(unboundPath, VerifyOptions{
		ExpectedBundleID:       sampleBundleID,
		RequireArtifactBinding: true,
		RequireTrustedEvidence: false,
	})
	if !errors.Is(err, ErrUnboundEvaluation) || sumUnbound.BindingStatus != BindingUnbound || sumUnbound.EffectiveGateStatus != GateBlocked {
		t.Fatalf("expected UNBOUND / BLOCKED, got %+v (err=%v)", sumUnbound, err)
	}

	// 7. Untrusted evidence (plain unsigned JSON when RequireTrustedEvidence=true) -> BLOCKED
	sumUnsigned, err := Verify(passReportPath, VerifyOptions{
		ExpectedBundleID:       sampleBundleID,
		RequireArtifactBinding: true,
		RequireTrustedEvidence: true,
	})
	if !errors.Is(err, ErrUntrustedEvaluationEvidence) || sumUnsigned.TrustStatus != TrustUnverifiedLocalJSON || sumUnsigned.EffectiveGateStatus != GateBlocked {
		t.Fatalf("expected BLOCKED for unsigned JSON under strict policy, got %+v (err=%v)", sumUnsigned, err)
	}

	// 8. Changed report digest after signing (tampered report) -> FAIL (TrustInvalidOrTampered)
	tamperedReportPath := filepath.Join(dir, "tampered-report.json")
	// Add a trailing comment/whitespace or change runId after signing
	tamperedBytes := buildReportJSON(t, GatePass, EvidenceComplete, 0, sampleBundleID)
	tamperedBytes = append(tamperedBytes, []byte("\n\n")...)
	_ = os.WriteFile(tamperedReportPath, tamperedBytes, 0o600)
	sumTampered, err := Verify(tamperedReportPath, VerifyOptions{
		ExpectedBundleID:       sampleBundleID,
		AttestationPath:        attPath,
		TrustedSigners:         trustedSigners,
		RequireArtifactBinding: true,
		RequireTrustedEvidence: true,
	})
	if !errors.Is(err, ErrUntrustedEvaluationEvidence) || sumTampered.TrustStatus != TrustInvalidOrTampered || sumTampered.EffectiveGateStatus != GateFail {
		t.Fatalf("expected TrustInvalidOrTampered / FAIL on changed report digest, got %+v (err=%v)", sumTampered, err)
	}
	if sumTampered.ReportIntegrityVerified {
		t.Fatalf("expected ReportIntegrityVerified=false on tampered report")
	}

	// Verify all 7 explicit guarantee flags on the valid PASS summary
	if !sumPass.ReportIntegrityVerified || !sumPass.ReportAuthenticityVerified || !sumPass.ProducerIdentityVerified ||
		!sumPass.ArtifactBindingVerified || !sumPass.ExecutionEvidenceVerified || !sumPass.SuiteDatasetIdentityVerified || !sumPass.FreshnessVerified {
		t.Fatalf("expected all 7 evaluation guarantees to be true on valid PASS summary, got %+v", sumPass)
	}
	if sumPass.BindingMode != BindingModeNativeEvaluator || sumPass.AttestationKind != AttestationKindTrustedEvaluator || sumPass.OperatorEndorsementVerified {
		t.Fatalf("expected BindingModeNativeEvaluator & AttestationKindTrustedEvaluator, got %+v", sumPass)
	}

	// 9. Report signed by untrusted key -> FAIL (TrustUntrustedSigner)
	untrustedPrivPEM, untrustedPubPEM, _, _ := signing.GenerateEd25519KeyPairPEM()
	untrustedPriv, _ := signing.ParsePrivateKeyPEM(untrustedPrivPEM, "rogue-signer")
	untrustedPub, _ := signing.ParsePublicKeyPEM(untrustedPubPEM, "rogue-signer", "Rogue Signer")
	untrustedAttBytes, err := SignEvaluationEvidence(passReportPath, sampleBundleID, untrustedPriv, "2026-10-31T00:00:00Z")
	if err != nil {
		t.Fatalf("SignEvaluationEvidence untrusted: %v", err)
	}
	untrustedAttPath := filepath.Join(dir, "untrusted.dsse.json")
	_ = os.WriteFile(untrustedAttPath, untrustedAttBytes, 0o600)

	sumUntrustedKey, err := Verify(passReportPath, VerifyOptions{
		ExpectedBundleID:       sampleBundleID,
		AttestationPath:        untrustedAttPath,
		TrustedSigners:         trustedSigners,
		CandidateUntrustedKeys: []*signing.PublicKey{untrustedPub},
		RequireArtifactBinding: true,
		RequireTrustedEvidence: true,
	})
	if !errors.Is(err, ErrUntrustedEvaluationEvidence) || sumUntrustedKey.TrustStatus != TrustUntrustedSigner || sumUntrustedKey.EffectiveGateStatus != GateFail {
		t.Fatalf("expected TrustUntrustedSigner / FAIL on untrusted key, got %+v (err=%v)", sumUntrustedKey, err)
	}
	if !sumUntrustedKey.ReportAuthenticityVerified || sumUntrustedKey.ProducerIdentityVerified {
		t.Fatalf("expected ReportAuthenticityVerified=true and ProducerIdentityVerified=false on untrusted key, got %+v", sumUntrustedKey)
	}

	// 10. Attestation subject digest modified -> FAIL
	var rawEnv signing.DSSEEnvelope
	_ = json.Unmarshal(attBytes, &rawEnv)
	payloadBytes, _ := base64.StdEncoding.DecodeString(rawEnv.Payload)
	var stmt signing.InTotoStatement
	_ = json.Unmarshal(payloadBytes, &stmt)
	stmt.Subject[0].Digest["sha256"] = "3333333333333333333333333333333333333333333333333333333333333333"
	modStmtBytes, _ := json.Marshal(stmt)
	modEnv, _ := signing.SignDSSE(signing.InTotoPayloadType, modStmtBytes, priv)
	modEnvBytes, _ := json.Marshal(modEnv)
	modSubjectAttPath := filepath.Join(dir, "mod-subject.dsse.json")
	_ = os.WriteFile(modSubjectAttPath, modEnvBytes, 0o600)

	sumModSubj, err := Verify(passReportPath, VerifyOptions{
		ExpectedBundleID:       sampleBundleID,
		AttestationPath:        modSubjectAttPath,
		TrustedSigners:         trustedSigners,
		RequireArtifactBinding: true,
		RequireTrustedEvidence: true,
	})
	if !errors.Is(err, ErrUntrustedEvaluationEvidence) || sumModSubj.TrustStatus != TrustInvalidOrTampered || sumModSubj.EffectiveGateStatus != GateFail {
		t.Fatalf("expected FAIL when attestation subject digest differs from predicate model_bundle_id, got %+v (err=%v)", sumModSubj, err)
	}

	// 11. Stale or replayed report (max_age_hours, expected_suite_digest, expected_dataset_digest) -> FAIL
	sumStale, err := Verify(passReportPath, VerifyOptions{
		ExpectedBundleID:       sampleBundleID,
		AttestationPath:        attPath,
		TrustedSigners:         trustedSigners,
		RequireArtifactBinding: true,
		RequireTrustedEvidence: true,
		MaxAgeHours:            24,
		Now:                    time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC),
	})
	if !errors.Is(err, ErrStaleEvaluationReport) || sumStale.EffectiveGateStatus != GateFail {
		t.Fatalf("expected ErrStaleEvaluationReport / FAIL on stale report, got %+v (err=%v)", sumStale, err)
	}

	sumWrongSuite, err := Verify(passReportPath, VerifyOptions{
		ExpectedBundleID:       sampleBundleID,
		AttestationPath:        attPath,
		TrustedSigners:         trustedSigners,
		RequireArtifactBinding: true,
		RequireTrustedEvidence: true,
		ExpectedSuiteDigest:    "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	})
	if !errors.Is(err, ErrSuiteDigestMismatch) || sumWrongSuite.EffectiveGateStatus != GateFail {
		t.Fatalf("expected ErrSuiteDigestMismatch / FAIL on wrong suite digest, got %+v (err=%v)", sumWrongSuite, err)
	}

	sumWrongDataset, err := Verify(passReportPath, VerifyOptions{
		ExpectedBundleID:       sampleBundleID,
		AttestationPath:        attPath,
		TrustedSigners:         trustedSigners,
		RequireArtifactBinding: true,
		RequireTrustedEvidence: true,
		ExpectedDatasetDigest:  "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	})
	if !errors.Is(err, ErrDatasetDigestMismatch) || sumWrongDataset.EffectiveGateStatus != GateFail {
		t.Fatalf("expected ErrDatasetDigestMismatch / FAIL on wrong dataset digest, got %+v (err=%v)", sumWrongDataset, err)
	}

	// 12. Post-hoc operator binding of an unbound report: rejected in strict mode, allowed only when AllowPostHocBinding=true
	postHocAttBytes, err := SignEvaluationEvidence(unboundPath, sampleBundleID, priv, "2026-10-31T00:00:00Z")
	if err != nil {
		t.Fatalf("SignEvaluationEvidence post-hoc: %v", err)
	}
	postHocAttPath := filepath.Join(dir, "post-hoc.dsse.json")
	_ = os.WriteFile(postHocAttPath, postHocAttBytes, 0o600)

	sumPostHocStrict, err := Verify(unboundPath, VerifyOptions{
		ExpectedBundleID:       sampleBundleID,
		AttestationPath:        postHocAttPath,
		TrustedSigners:         trustedSigners,
		RequireArtifactBinding: true,
		RequireTrustedEvidence: true,
		AllowPostHocBinding:    false,
	})
	if !errors.Is(err, ErrPostHocBindingRejected) || sumPostHocStrict.EffectiveGateStatus != GateBlocked || sumPostHocStrict.BindingMode != BindingModePostHocOperator {
		t.Fatalf("expected ErrPostHocBindingRejected / BLOCKED in strict mode for post-hoc binding, got %+v (err=%v)", sumPostHocStrict, err)
	}

	sumPostHocPermissive, err := Verify(unboundPath, VerifyOptions{
		ExpectedBundleID:       sampleBundleID,
		AttestationPath:        postHocAttPath,
		TrustedSigners:         trustedSigners,
		RequireArtifactBinding: true,
		RequireTrustedEvidence: true,
		AllowPostHocBinding:    true,
	})
	if err != nil || !sumPostHocPermissive.EligibleForRelease || sumPostHocPermissive.BindingMode != BindingModePostHocOperator {
		t.Fatalf("expected post-hoc binding to succeed when AllowPostHocBinding=true with BindingModePostHocOperator, got %+v (err=%v)", sumPostHocPermissive, err)
	}
	if sumPostHocPermissive.ProducerIdentityVerified || !sumPostHocPermissive.OperatorEndorsementVerified {
		t.Fatalf("expected ProducerIdentityVerified=false and OperatorEndorsementVerified=true on post-hoc binding, got %+v", sumPostHocPermissive)
	}

	// 13. Operator endorsement on a bound report (`eval bind` / ProducerRoleOperatorEndorser):
	// Rejected under strict policy unless the signer rule explicitly sets AllowOperatorEndorsement=true,
	// and never represented as proof of trusted evaluator execution (ProducerIdentityVerified=false).
	opEndorseBytes, err := SignEvaluationEvidenceWithRole(passReportPath, sampleBundleID, priv, "2026-10-31T00:00:00Z", ProducerRoleOperatorEndorser)
	if err != nil {
		t.Fatalf("SignEvaluationEvidenceWithRole operator-endorser: %v", err)
	}
	opEndorsePath := filepath.Join(dir, "operator-endorse.dsse.json")
	_ = os.WriteFile(opEndorsePath, opEndorseBytes, 0o600)

	sumOpStrictRejected, err := Verify(passReportPath, VerifyOptions{
		ExpectedBundleID:       sampleBundleID,
		AttestationPath:        opEndorsePath,
		TrustedSigners:         trustedSigners,
		RequireArtifactBinding: true,
		RequireTrustedEvidence: true,
		AllowPostHocBinding:    false,
	})
	if !errors.Is(err, ErrPostHocBindingRejected) || sumOpStrictRejected.EffectiveGateStatus != GateBlocked {
		t.Fatalf("expected operator endorsement to be BLOCKED under strict policy without explicit authorization, got %+v (err=%v)", sumOpStrictRejected, err)
	}

	authorizedOpSigners := []verification.TrustedSignerRule{
		{
			ID:                       "eval-signer-1",
			Name:                     "Authorized Operator Endorser",
			Role:                     ProducerRoleOperatorEndorser,
			AllowOperatorEndorsement: true,
			KeyID:                    "eval-signer-1",
			KeyFingerprint:           fp,
			PublicKey:                pub,
		},
	}
	sumOpAuthorized, err := Verify(passReportPath, VerifyOptions{
		ExpectedBundleID:       sampleBundleID,
		AttestationPath:        opEndorsePath,
		TrustedSigners:         authorizedOpSigners,
		RequireArtifactBinding: true,
		RequireTrustedEvidence: true,
		AllowPostHocBinding:    false,
	})
	if err != nil || !sumOpAuthorized.EligibleForRelease || sumOpAuthorized.ProducerIdentityVerified || !sumOpAuthorized.OperatorEndorsementVerified {
		t.Fatalf("expected authorized operator endorsement to pass while keeping ProducerIdentityVerified=false and OperatorEndorsementVerified=true, got %+v (err=%v)", sumOpAuthorized, err)
	}
}

func TestReadOnlySiblingLLMReleaseGateFixtureCompatibility(t *testing.T) {
	siblingFixture := os.Getenv("LLM_RELEASE_GATE_FIXTURE_PATH")
	if siblingFixture == "" {
		siblingFixture = filepath.Join("..", "..", "..", "..", "llm-release-gate", "examples", "basic", "baselines", "approved.json")
	}
	if _, err := os.Stat(siblingFixture); errors.Is(err, os.ErrNotExist) {
		t.Skip("sibling repository fixture not present on this runner")
	}

	// Read-only verification against the actual unmodified sibling repository fixture:
	// Because the existing sibling fixture has no model_bundle_id in candidate.metadata,
	// our adapter must parse it cleanly and return BindingUnbound + GateBlocked under strict policy.
	sum, err := Verify(siblingFixture, VerifyOptions{
		ExpectedBundleID:       sampleBundleID,
		RequireArtifactBinding: true,
		RequireTrustedEvidence: true,
	})
	if !errors.Is(err, ErrUnboundEvaluation) {
		t.Fatalf("expected ErrUnboundEvaluation on unmodified sibling fixture, got %v", err)
	}
	if sum.BindingStatus != BindingUnbound || sum.EffectiveGateStatus != GateBlocked || sum.EligibleForRelease {
		t.Fatalf("unexpected summary for unmodified sibling fixture: %+v", sum)
	}
}
