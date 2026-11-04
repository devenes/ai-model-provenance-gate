package verify

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/devenes/ai-model-provenance-gate/internal/attestation"
	"github.com/devenes/ai-model-provenance-gate/internal/bom"
	"github.com/devenes/ai-model-provenance-gate/internal/bundle"
	"github.com/devenes/ai-model-provenance-gate/internal/config"
	"github.com/devenes/ai-model-provenance-gate/internal/digest"
	"github.com/devenes/ai-model-provenance-gate/internal/evaluation/llmreleasegate"
	"github.com/devenes/ai-model-provenance-gate/internal/formats/huggingface"
	"github.com/devenes/ai-model-provenance-gate/internal/formats/peft"
	"github.com/devenes/ai-model-provenance-gate/internal/identity"
	"github.com/devenes/ai-model-provenance-gate/internal/inventory"
	"github.com/devenes/ai-model-provenance-gate/internal/manifest"
	"github.com/devenes/ai-model-provenance-gate/internal/oms"
	"github.com/devenes/ai-model-provenance-gate/internal/policy"
	"github.com/devenes/ai-model-provenance-gate/internal/provenance"
	"github.com/devenes/ai-model-provenance-gate/internal/scanner"
	"github.com/devenes/ai-model-provenance-gate/internal/signing"
	"github.com/devenes/ai-model-provenance-gate/internal/verification"
	"github.com/devenes/ai-model-provenance-gate/internal/version"
)

// BuildManifestOptions configures in-memory bundle-manifest.json and CycloneDX BOM construction.
type BuildManifestOptions struct {
	ModelType            string
	Architecture         string
	PrimaryFormat        string
	HasLoRAAdapter       bool
	DeclaredBaseModel    string
	VerifiedBaseBundleID string
	ModelName            string
	Timestamp            string
}

// ReleaseBuildInput holds verified evidence digests and metadata to construct a release-qualification/v1 DSSE envelope.
type ReleaseBuildInput struct {
	Timestamp               string
	Manifest                BundleManifest
	BOMCanonicalDigest      string
	BOMSpecVersion          string
	OMS                     OMSResult
	Evaluation              EvaluationSummary
	RuntimeImage            string
	ServingConfigDigest     string
	QualificationPolicyHash string
	GateStatus              string
}

// GenerateEd25519KeyPairPEM generates an Ed25519 key pair in PKCS#8 / PKIX PEM format and returns its SHA-256 fingerprint.
func GenerateEd25519KeyPairPEM() (privPEM []byte, pubPEM []byte, fingerprint string, err error) {
	return signing.GenerateEd25519KeyPairPEM()
}

func buildInspectionFromDescriptors(observedFiles []FileEntry, opts BuildManifestOptions) (bundle.InspectionResult, error) {
	inv, _, err := buildInventoryFromDescriptors(observedFiles)
	if err != nil {
		return bundle.InspectionResult{}, err
	}
	idRes, err := identity.Compute(inv)
	if err != nil {
		return bundle.InspectionResult{}, err
	}
	primaryFmt := strings.TrimSpace(opts.PrimaryFormat)
	if primaryFmt == "" {
		primaryFmt = "safetensors"
	}
	loraRel := peft.AdapterMetadata{
		IsAdapter:          opts.HasLoRAAdapter,
		VerificationStatus: peft.StatusNone,
	}
	if opts.HasLoRAAdapter {
		loraRel.PEFTType = "LORA"
		loraRel.TaskType = "CAUSAL_LM"
		loraRel.BaseModelNameOrPath = opts.DeclaredBaseModel
		if strings.TrimSpace(opts.VerifiedBaseBundleID) != "" {
			loraRel.VerificationStatus = peft.StatusVerified
			loraRel.VerifiedBaseBundleID = opts.VerifiedBaseBundleID
		} else {
			loraRel.VerificationStatus = peft.StatusDeclaredUnverified
		}
	}

	var modelCfg *huggingface.ModelConfigSummary
	if opts.ModelType != "" || opts.Architecture != "" {
		var archs []string
		if opts.Architecture != "" {
			archs = []string{opts.Architecture}
		}
		modelCfg = &huggingface.ModelConfigSummary{
			Path:          "config.json",
			ModelType:     opts.ModelType,
			Architectures: archs,
		}
	}

	hasSafetensors := false
	hasTokenizer := false
	hasModelConfig := false
	for _, f := range inv.Files {
		if f.Role == inventory.RoleModelWeights || f.Role == inventory.RoleWeightShard || f.Role == inventory.RoleWeightIndex {
			hasSafetensors = true
		}
		if f.Role == inventory.RoleTokenizerConfig || f.Role == inventory.RoleTokenizerVocab || f.Role == inventory.RoleSpecialTokens {
			hasTokenizer = true
		}
		if f.Role == inventory.RoleModelConfig {
			hasModelConfig = true
		}
	}

	m := manifest.BundleManifest{
		SchemaVersion: version.BundleIdentitySchemaVersion,
		BundleID:      idRes.BundleID,
		FileCount:     inv.FileCount,
		TotalBytes:    inv.TotalBytes,
		Files:         inv.Files,
		FormatSummary: manifest.FormatSummary{
			PrimaryFormat:         primaryFmt,
			HasModelConfig:        hasModelConfig,
			HasSafetensorsWeights: hasSafetensors,
			HasTokenizer:          hasTokenizer,
			HasLoRAAdapter:        opts.HasLoRAAdapter,
		},
		ModelConfig:      modelCfg,
		LoRARelationship: loraRel,
	}
	finalized, rawJSON, err := manifest.Finalize(m)
	if err != nil {
		return bundle.InspectionResult{}, err
	}
	return bundle.InspectionResult{
		RootPath:     "model",
		Inventory:    inv,
		Identity:     idRes,
		BundleID:     idRes.BundleID,
		Manifest:     finalized,
		ManifestJSON: rawJSON,
	}, nil
}

// BuildBundleManifestBytes constructs a deterministic bundle-manifest.json byte payload from FileEntry descriptors.
func BuildBundleManifestBytes(observedFiles []FileEntry, opts BuildManifestOptions) ([]byte, BundleManifest, error) {
	insp, err := buildInspectionFromDescriptors(observedFiles, opts)
	if err != nil {
		return nil, BundleManifest{}, err
	}
	bm, err := VerifyBundleManifestBytes(insp.ManifestJSON, observedFiles, ManifestVerifyOptions{
		AllowUnknownFiles:    true,
		ExpectedBaseBundleID: opts.VerifiedBaseBundleID,
	})
	if err != nil {
		return nil, BundleManifest{}, err
	}
	return insp.ManifestJSON, bm, nil
}

// SignOMSBytesFromDescriptors creates a signed OMS v1.0 DSSE envelope in memory over observedFiles.
func SignOMSBytesFromDescriptors(observedFiles []FileEntry, privPEM []byte, keyID string) ([]byte, error) {
	insp, err := buildInspectionFromDescriptors(observedFiles, BuildManifestOptions{})
	if err != nil {
		return nil, err
	}
	priv, err := signing.ParsePrivateKeyPEM(privPEM, keyID)
	if err != nil {
		return nil, err
	}
	return oms.SignBundle(insp, priv, oms.SignOptions{
		Method: "key",
	})
}

// GenerateBOMBytesFromDescriptors generates a CycloneDX 1.7 AI/ML-BOM JSON payload and returns its raw bytes and JCS canonical hash.
func GenerateBOMBytesFromDescriptors(observedFiles []FileEntry, opts BuildManifestOptions) ([]byte, string, error) {
	insp, err := buildInspectionFromDescriptors(observedFiles, opts)
	if err != nil {
		return nil, "", err
	}
	gen, err := bom.Generate(insp, bom.GenerateOptions{
		SpecVersion: bom.SpecVersion1_7,
		Timestamp:   opts.Timestamp,
		ModelName:   opts.ModelName,
	})
	if err != nil {
		return nil, "", err
	}
	return gen.JSON, gen.Digest, nil
}

// SignNativeEvaluationBytes creates a trusted-evaluator (NATIVE_CI_EVALUATOR) evaluation-evidence/v1 DSSE envelope in memory.
func SignNativeEvaluationBytes(rawReport []byte, modelBundleID string, privPEM []byte, keyID string, timestamp string) ([]byte, error) {
	return signEvaluationBytesWithMode(
		rawReport,
		modelBundleID,
		privPEM,
		keyID,
		timestamp,
		llmreleasegate.AttestationKindTrustedEvaluator,
		string(llmreleasegate.BindingModeNativeEvaluator),
	)
}

// SignPostHocEvaluationBytes creates an operator-endorsed (POST_HOC_OPERATOR) evaluation-evidence/v1 DSSE envelope in memory.
func SignPostHocEvaluationBytes(rawReport []byte, modelBundleID string, privPEM []byte, keyID string, timestamp string) ([]byte, error) {
	return signEvaluationBytesWithMode(
		rawReport,
		modelBundleID,
		privPEM,
		keyID,
		timestamp,
		llmreleasegate.AttestationKindOperatorEndorsement,
		string(llmreleasegate.BindingModePostHocOperator),
	)
}

func signEvaluationBytesWithMode(
	rawReport []byte,
	modelBundleID string,
	privPEM []byte,
	keyID string,
	timestamp string,
	attKind string,
	bindingMode string,
) ([]byte, error) {
	if err := digest.Validate(modelBundleID); err != nil {
		return nil, err
	}
	priv, err := signing.ParsePrivateKeyPEM(privPEM, keyID)
	if err != nil {
		return nil, err
	}
	rep, repDigest, err := llmreleasegate.ParseAndValidateReport(rawReport)
	if err != nil {
		return nil, err
	}
	bundleHex, err := digest.TrimPrefix(modelBundleID)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(timestamp) == "" {
		timestamp = time.Now().UTC().Format(time.RFC3339)
	}
	pred := llmreleasegate.EvaluationEvidencePredicate{
		SchemaVersion:       "evaluation-evidence/v1",
		AttestationKind:     attKind,
		Timestamp:           timestamp,
		ModelBundleID:       modelBundleID,
		BindingMode:         bindingMode,
		ReportDigest:        repDigest,
		RunID:               rep.RunID,
		EvaluationTimestamp: rep.Timestamp,
		ToolVersion:         rep.ToolVersion,
		GateStatus:          string(rep.GateStatus),
		EvidenceQuality:     string(rep.EvidenceQuality),
		SuiteDigest:         rep.Suite.Digest,
		DatasetDigest:       rep.Dataset.Digest,
		EvaluatorName:       rep.Evaluator.Name,
		EvaluatorVersion:    rep.Evaluator.Version,
		ExecutionMode:       rep.Execution.Mode,
		CandidateName:       rep.Candidate.Name,
		CandidateDigest:     rep.Candidate.Digest,
		PromptConfigDigest:  rep.Candidate.Digest,
	}
	predBytes, err := json.Marshal(pred)
	if err != nil {
		return nil, err
	}
	stmt := signing.InTotoStatement{
		Type: signing.InTotoStatementV1Type,
		Subject: []signing.ResourceDescriptor{
			{
				Name:   "model-bundle:" + rep.Candidate.Name,
				Digest: map[string]string{"sha256": bundleHex},
			},
		},
		PredicateType: version.EvaluationEvidencePredicateType,
		Predicate:     predBytes,
	}
	stmtBytes, err := json.Marshal(stmt)
	if err != nil {
		return nil, err
	}
	env, err := signing.SignDSSE(signing.InTotoPayloadType, stmtBytes, priv)
	if err != nil {
		return nil, err
	}
	out, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

// SignReleaseQualificationBytes creates a signed release-qualification/v1 DSSE envelope in memory.
func SignReleaseQualificationBytes(in ReleaseBuildInput, privPEM []byte, keyID string) ([]byte, string, error) {
	priv, err := signing.ParsePrivateKeyPEM(privPEM, keyID)
	if err != nil {
		return nil, "", err
	}
	insp, err := buildInspectionFromDescriptors(in.Manifest.Files, BuildManifestOptions{
		PrimaryFormat:        in.Manifest.PrimaryFormat,
		HasLoRAAdapter:       in.Manifest.HasLoRAAdapter,
		DeclaredBaseModel:    in.Manifest.DeclaredBaseModel,
		VerifiedBaseBundleID: in.Manifest.VerifiedBaseBundleID,
	})
	if err != nil {
		return nil, "", err
	}
	insp.Manifest.ManifestDigest = in.Manifest.ManifestDigest

	polDigest := in.QualificationPolicyHash
	if polDigest == "" {
		polDigest = digest.ComputeBytes([]byte("default-qualification-policy"))
	}
	gateStatus := in.GateStatus
	if gateStatus == "" {
		gateStatus = "PASS"
	}
	bomSpec := in.BOMSpecVersion
	if bomSpec == "" {
		bomSpec = "1.7"
	}

	att, err := attestation.BuildAndOptionallySign(attestation.BuildInput{
		Timestamp:  in.Timestamp,
		Inspection: insp,
		BOM: bom.GeneratedBOM{
			Digest: in.BOMCanonicalDigest,
			Document: bom.Document{
				SpecVersion: bomSpec,
			},
		},
		OMS: oms.Result{
			Status:            verification.Status(in.OMS.Status),
			PredicateType:     in.OMS.PredicateType,
			SignerID:          in.OMS.SignerID,
			SignerKeyID:       in.OMS.SignerKeyID,
			SignerFingerprint: in.OMS.SignerFingerprint,
			SignatureDigest:   in.OMS.SignatureDigest,
		},
		HasEvaluation: in.Evaluation.ReportDigest != "",
		Evaluation: llmreleasegate.EvaluationSummary{
			ReportedGateStatus:  llmreleasegate.GateStatus(in.Evaluation.ReportedGateStatus),
			EffectiveGateStatus: llmreleasegate.GateStatus(in.Evaluation.EffectiveGateStatus),
			EvidenceQuality:     llmreleasegate.EvidenceQuality(in.Evaluation.EvidenceQuality),
			BindingStatus:       llmreleasegate.BindingStatus(in.Evaluation.BindingStatus),
			TrustStatus:         llmreleasegate.TrustStatus(in.Evaluation.TrustStatus),
			ReportDigest:        in.Evaluation.ReportDigest,
			AttestationDigest:   in.Evaluation.AttestationDigest,
			SuiteDigest:         in.Evaluation.SuiteDigest,
			DatasetDigest:       in.Evaluation.DatasetDigest,
			RunID:               in.Evaluation.RunID,
			SignerFingerprint:   in.Evaluation.SignerFingerprint,
		},
		Scanner: scanner.Result{
			Status: "NOT_RUN",
		},
		Provenance: provenance.Result{
			Status: verification.StatusNotRun,
		},
		RuntimeImage:        in.RuntimeImage,
		ServingConfigDigest: in.ServingConfigDigest,
		Policy: config.Policy{
			SchemaVersion: config.PolicySchemaVersionV1,
			Name:          "strict-release-policy",
			Digest:        polDigest,
			Release: config.ReleasePolicyConfig{
				DecisionMode: config.DecisionModeStrict,
			},
		},
		Decision: policy.Decision{
			GateStatus: policy.GateStatus(gateStatus),
			ExitCode:   0,
		},
	}, priv)
	if err != nil {
		return nil, "", err
	}
	return att.JSONBytes, att.Digest, nil
}
