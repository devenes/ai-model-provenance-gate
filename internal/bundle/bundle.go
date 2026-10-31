// Package bundle orchestrates safe model bundle inspection, static format validation,
// LoRA relationship analysis, and deterministic bundle-identity/v1 manifest creation.
package bundle

import (
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/devenes/ai-model-provenance-gate/internal/formats/huggingface"
	"github.com/devenes/ai-model-provenance-gate/internal/formats/peft"
	"github.com/devenes/ai-model-provenance-gate/internal/formats/safetensors"
	"github.com/devenes/ai-model-provenance-gate/internal/identity"
	"github.com/devenes/ai-model-provenance-gate/internal/inventory"
	"github.com/devenes/ai-model-provenance-gate/internal/manifest"
	"github.com/devenes/ai-model-provenance-gate/internal/version"
)

var (
	// ErrIncompleteBundle is returned when a bundle is missing required weight files or referenced shards.
	ErrIncompleteBundle = errors.New("incomplete model bundle")
	// ErrUnsupportedFormat is returned when a bundle contains only unsupported or unsafe model weight formats.
	ErrUnsupportedFormat = errors.New("unsupported or unsafe model weight format")
)

// InspectOptions configures model bundle inspection.
type InspectOptions struct {
	InventoryOptions      inventory.Options
	BaseBundlePath        string
	ExpectedBaseBundleID  string
	MaxSafetensorsHeader  uint64
	MaxMetadataBytes      int64
	AllowIncompleteBundle bool
	AllowUnsafeFormats    bool
}

// DefaultInspectOptions returns safe default options for bundle inspection.
func DefaultInspectOptions() InspectOptions {
	return InspectOptions{
		InventoryOptions:     inventory.DefaultOptions(),
		MaxSafetensorsHeader: safetensors.DefaultMaxHeaderBytes,
		MaxMetadataBytes:     huggingface.DefaultMaxConfigBytes,
	}
}

// InspectionResult holds the complete output of inspecting a local model bundle.
type InspectionResult struct {
	RootPath     string                  `json:"root_path"`
	BundleID     string                  `json:"bundle_id"`
	Inventory    inventory.Inventory     `json:"inventory"`
	Identity     identity.Result         `json:"identity"`
	Manifest     manifest.BundleManifest `json:"manifest"`
	ManifestJSON []byte                  `json:"-"`
}

// Inspect inspects a local model bundle directory, validates static format headers,
// and derives the deterministic bundle-identity/v1 manifest.
func Inspect(bundleRoot string, opts InspectOptions) (InspectionResult, error) {
	inv, err := inventory.Build(bundleRoot, opts.InventoryOptions)
	if err != nil {
		return InspectionResult{}, err
	}

	idRes, err := identity.Compute(inv)
	if err != nil {
		return InspectionResult{}, err
	}

	var (
		modelCfg           *huggingface.ModelConfigSummary
		tokSummary         huggingface.TokenizerSummary
		hasTokInfo         bool
		quantMeta          *huggingface.QuantizationMetadata
		stInspections      []safetensors.FileInspection
		stByPath           = make(map[string]safetensors.FileInspection)
		shardIndices       []safetensors.ShardIndex
		adapterMeta        peft.AdapterMetadata
		adapterWeightPaths []string
		unknownFiles       []string
		unsafeFiles        []string
		provRecords        []manifest.ProvenanceRecord
		totalTensors       int
		shardCount         int
	)

	provRecords = append(provRecords, manifest.ProvenanceRecord{
		Field:  "bundle_id",
		Source: "observed",
		Origin: "rfc8785-jcs(bundle-identity/v1)",
	})

	for _, f := range inv.Files {
		absFile := filepath.Join(inv.RootPath, filepath.FromSlash(f.Path))

		switch f.Role {
		case inventory.RoleUnsafePickleArtifact:
			unsafeFiles = append(unsafeFiles, f.Path)

		case inventory.RoleUnknownFile:
			unknownFiles = append(unknownFiles, f.Path)

		case inventory.RoleModelConfig:
			if modelCfg == nil || f.Path == "config.json" {
				cfg, cfgErr := huggingface.InspectModelConfig(absFile, f.Path, opts.MaxMetadataBytes)
				if cfgErr != nil {
					return InspectionResult{}, cfgErr
				}
				modelCfg = &cfg
				provRecords = append(provRecords, manifest.ProvenanceRecord{
					Field:  "model_config",
					Source: "observed",
					Origin: f.Path,
				})
				if cfg.DeclaredNameOrPath != "" {
					provRecords = append(provRecords, manifest.ProvenanceRecord{
						Field:  "model_config.declared_name_or_path",
						Source: "declared_unverified",
						Origin: f.Path + "#_name_or_path",
					})
				}
				if cfg.DeclaredLicense != "" {
					provRecords = append(provRecords, manifest.ProvenanceRecord{
						Field:  "model_config.declared_license",
						Source: "declared_unverified",
						Origin: f.Path + "#license",
					})
				}
				if cfg.Quantization != nil && quantMeta == nil {
					quantMeta = cfg.Quantization
				}
			}

		case inventory.RoleGenerationConfig:
			if err := huggingface.ValidateJSONFile(absFile, f.Path, opts.MaxMetadataBytes); err != nil {
				return InspectionResult{}, err
			}

		case inventory.RoleQuantizationConfig:
			qm, qErr := huggingface.InspectQuantizationFile(absFile, f.Path, opts.MaxMetadataBytes)
			if qErr != nil {
				return InspectionResult{}, qErr
			}
			quantMeta = qm
			provRecords = append(provRecords, manifest.ProvenanceRecord{
				Field:  "quantization",
				Source: "observed",
				Origin: f.Path,
			})

		case inventory.RoleTokenizerConfig:
			ts, tErr := huggingface.InspectTokenizerConfig(absFile, f.Path, opts.MaxMetadataBytes)
			if tErr != nil {
				return InspectionResult{}, tErr
			}
			tokSummary.ConfigPath = ts.ConfigPath
			tokSummary.TokenizerClass = ts.TokenizerClass
			tokSummary.ModelMaxLength = ts.ModelMaxLength
			tokSummary.HasInlineChatTempl = ts.HasInlineChatTempl
			hasTokInfo = true

		case inventory.RoleTokenizerVocab:
			if strings.HasSuffix(strings.ToLower(f.Path), ".json") {
				if err := huggingface.ValidateJSONFile(absFile, f.Path, opts.MaxMetadataBytes); err != nil {
					return InspectionResult{}, err
				}
			}
			if filepath.Base(f.Path) == "tokenizer.json" {
				tokSummary.TokenizerJSONPath = f.Path
			} else {
				tokSummary.VocabFiles = append(tokSummary.VocabFiles, f.Path)
			}
			hasTokInfo = true

		case inventory.RoleSpecialTokens:
			if err := huggingface.ValidateJSONFile(absFile, f.Path, opts.MaxMetadataBytes); err != nil {
				return InspectionResult{}, err
			}
			tokSummary.SpecialTokensPath = f.Path
			hasTokInfo = true

		case inventory.RoleChatTemplate:
			if strings.HasSuffix(strings.ToLower(f.Path), ".json") {
				if err := huggingface.ValidateJSONFile(absFile, f.Path, opts.MaxMetadataBytes); err != nil {
					return InspectionResult{}, err
				}
			}
			tokSummary.ChatTemplatePath = f.Path
			hasTokInfo = true

		case inventory.RoleModelWeights, inventory.RoleWeightShard, inventory.RoleLoRAWeights:
			stInsp, stErr := safetensors.InspectFile(absFile, f.Path, opts.MaxSafetensorsHeader)
			if stErr != nil {
				return InspectionResult{}, stErr
			}
			stInspections = append(stInspections, stInsp)
			stByPath[f.Path] = stInsp
			totalTensors += stInsp.TensorCount
			if f.Role == inventory.RoleWeightShard {
				shardCount++
			}
			if f.Role == inventory.RoleLoRAWeights {
				adapterWeightPaths = append(adapterWeightPaths, f.Path)
			}

		case inventory.RoleWeightIndex, inventory.RoleLoRAIndex:
			idx, idxErr := safetensors.InspectIndexFile(absFile, f.Path, opts.MaxMetadataBytes)
			if idxErr != nil {
				return InspectionResult{}, idxErr
			}
			shardIndices = append(shardIndices, idx)

		case inventory.RoleLoRAConfig:
			am, amErr := peft.InspectAdapterConfig(absFile, f.Path, opts.MaxMetadataBytes)
			if amErr != nil {
				return InspectionResult{}, amErr
			}
			adapterMeta = am
			if am.BaseModelNameOrPath != "" {
				provRecords = append(provRecords, manifest.ProvenanceRecord{
					Field:  "lora_relationship.base_model_name_or_path",
					Source: "declared_unverified",
					Origin: f.Path + "#base_model_name_or_path",
				})
			}
		}
	}

	if len(unsafeFiles) > 0 && !opts.AllowUnsafeFormats {
		return InspectionResult{}, fmt.Errorf(
			"%w: unsafe pickle/executable artifact(s) detected: %s",
			ErrUnsupportedFormat, strings.Join(unsafeFiles, ", "),
		)
	}

	// Verify shard index consistency against inspected .safetensors files.
	for _, idx := range shardIndices {
		if err := safetensors.VerifyIndexConsistency(idx, stByPath); err != nil {
			return InspectionResult{}, fmt.Errorf("%w: %w", ErrIncompleteBundle, err)
		}
	}

	// If sharded weight files exist without an index file, treat as incomplete bundle.
	if shardCount > 0 && len(shardIndices) == 0 && !opts.AllowIncompleteBundle {
		return InspectionResult{}, fmt.Errorf(
			"%w: bundle contains %d weight shard(s) but is missing model.safetensors.index.json",
			ErrIncompleteBundle, shardCount,
		)
	}

	// Inspect optional base model bundle when verifying LoRA relationship.
	var actualBaseBundleID string
	if strings.TrimSpace(opts.BaseBundlePath) != "" {
		baseRes, baseErr := Inspect(opts.BaseBundlePath, InspectOptions{
			InventoryOptions:     inventory.DefaultOptions(),
			MaxSafetensorsHeader: opts.MaxSafetensorsHeader,
			MaxMetadataBytes:     opts.MaxMetadataBytes,
		})
		if baseErr != nil {
			return InspectionResult{}, fmt.Errorf("inspect base model bundle %q: %w", opts.BaseBundlePath, baseErr)
		}
		actualBaseBundleID = baseRes.BundleID
	}

	adapterMeta = peft.EvaluateRelationship(adapterMeta, adapterWeightPaths, actualBaseBundleID, opts.ExpectedBaseBundleID)
	if adapterMeta.VerificationStatus == peft.StatusVerified {
		provRecords = append(provRecords, manifest.ProvenanceRecord{
			Field:  "lora_relationship.verified_base_bundle_id",
			Source: "verified",
			Origin: "cryptographic-bundle-identity",
		})
	}

	// Verify bundle completeness: a valid model bundle must have either base model weights (+ config.json)
	// or a complete LoRA adapter (adapter_config.json + adapter weights).
	hasBaseWeights := inv.RoleCounts[inventory.RoleModelWeights] > 0 || inv.RoleCounts[inventory.RoleWeightShard] > 0
	hasLoRA := adapterMeta.IsAdapter && adapterMeta.ConfigPath != "" && len(adapterMeta.WeightPaths) > 0

	if !opts.AllowIncompleteBundle {
		if !hasBaseWeights && !hasLoRA {
			if len(unsafeFiles) > 0 {
				return InspectionResult{}, fmt.Errorf("%w: no safe model weights found (unsafe files: %v)", ErrUnsupportedFormat, unsafeFiles)
			}
			return InspectionResult{}, fmt.Errorf("%w: bundle contains neither safetensors model weights nor a complete LoRA adapter", ErrIncompleteBundle)
		}
		if hasBaseWeights && modelCfg == nil {
			return InspectionResult{}, fmt.Errorf("%w: bundle contains model weights without config.json", ErrIncompleteBundle)
		}
		if adapterMeta.VerificationStatus == peft.StatusMissing {
			return InspectionResult{}, fmt.Errorf("%w: %s", ErrIncompleteBundle, adapterMeta.VerificationNotes)
		}
	}

	primaryFormat := "unknown"
	switch {
	case hasBaseWeights && hasLoRA:
		primaryFormat = "huggingface-safetensors+peft-lora"
	case hasBaseWeights && shardCount > 0:
		primaryFormat = "huggingface-safetensors-sharded"
	case hasBaseWeights:
		primaryFormat = "huggingface-safetensors"
	case hasLoRA:
		primaryFormat = "huggingface-peft-lora"
	}

	var tokPtr *huggingface.TokenizerSummary
	if hasTokInfo {
		sort.Strings(tokSummary.VocabFiles)
		tokPtr = &tokSummary
	}

	hasChatTempl := inv.RoleCounts[inventory.RoleChatTemplate] > 0 || (tokPtr != nil && tokPtr.HasInlineChatTempl)
	hasRemoteCode := modelCfg != nil && modelCfg.HasAutoMap

	sort.Strings(unknownFiles)
	sort.Strings(unsafeFiles)

	m := manifest.BundleManifest{
		SchemaVersion: version.BundleIdentitySchemaVersion,
		BundleID:      idRes.BundleID,
		FileCount:     inv.FileCount,
		TotalBytes:    inv.TotalBytes,
		Files:         inv.Files,
		FormatSummary: manifest.FormatSummary{
			PrimaryFormat:         primaryFormat,
			HasModelConfig:        modelCfg != nil,
			HasSafetensorsWeights: len(stInspections) > 0,
			IsSharded:             shardCount > 0,
			ShardCount:            shardCount,
			TotalTensors:          totalTensors,
			HasTokenizer:          hasTokInfo,
			HasChatTemplate:       hasChatTempl,
			HasLoRAAdapter:        adapterMeta.IsAdapter,
			HasQuantization:       quantMeta != nil,
			UnknownFileCount:      len(unknownFiles),
			UnsafeArtifactFiles:   unsafeFiles,
		},
		ModelConfig:      modelCfg,
		Tokenizer:        tokPtr,
		Quantization:     quantMeta,
		SafetensorsFiles: stInspections,
		ShardIndices:     shardIndices,
		LoRARelationship: adapterMeta,
		SecurityFlags: manifest.SecurityFlags{
			ContainsSymlinks:        false,
			ContainsUnsafePickle:    len(unsafeFiles) > 0,
			ContainsRemoteCodeHooks: hasRemoteCode,
			UnknownRegularFiles:     unknownFiles,
		},
		MetadataProvenance: provRecords,
	}

	finalManifest, manifestBytes, err := manifest.Finalize(m)
	if err != nil {
		return InspectionResult{}, err
	}

	return InspectionResult{
		RootPath:     inv.RootPath,
		BundleID:     idRes.BundleID,
		Inventory:    inv,
		Identity:     idRes,
		Manifest:     finalManifest,
		ManifestJSON: manifestBytes,
	}, nil
}
