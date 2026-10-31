// Package manifest defines the deterministic bundle-identity/v1 manifest structure and serialization.
package manifest

import (
	"encoding/json"
	"fmt"

	"github.com/devenes/ai-model-provenance-gate/internal/digest"
	"github.com/devenes/ai-model-provenance-gate/internal/formats/huggingface"
	"github.com/devenes/ai-model-provenance-gate/internal/formats/peft"
	"github.com/devenes/ai-model-provenance-gate/internal/formats/safetensors"
	"github.com/devenes/ai-model-provenance-gate/internal/identity"
	"github.com/devenes/ai-model-provenance-gate/internal/inventory"
)

// FormatSummary summarizes the detected model bundle layout and formats.
type FormatSummary struct {
	PrimaryFormat         string   `json:"primary_format"`
	HasModelConfig        bool     `json:"has_model_config"`
	HasSafetensorsWeights bool     `json:"has_safetensors_weights"`
	IsSharded             bool     `json:"is_sharded"`
	ShardCount            int      `json:"shard_count"`
	TotalTensors          int      `json:"total_tensors"`
	HasTokenizer          bool     `json:"has_tokenizer"`
	HasChatTemplate       bool     `json:"has_chat_template"`
	HasLoRAAdapter        bool     `json:"has_lora_adapter"`
	HasQuantization       bool     `json:"has_quantization"`
	UnknownFileCount      int      `json:"unknown_file_count"`
	UnsafeArtifactFiles   []string `json:"unsafe_artifact_files,omitempty"`
}

// SecurityFlags records static security observations made during bundle inspection.
type SecurityFlags struct {
	ContainsSymlinks        bool     `json:"contains_symlinks"`
	ContainsUnsafePickle    bool     `json:"contains_unsafe_pickle"`
	ContainsRemoteCodeHooks bool     `json:"contains_remote_code_hooks"`
	UnknownRegularFiles     []string `json:"unknown_regular_files,omitempty"`
}

// ProvenanceRecord explicitly distinguishes observed vs declared metadata sources.
type ProvenanceRecord struct {
	Field  string `json:"field"`
	Source string `json:"source"` // "observed" or "declared_unverified" or "verified"
	Origin string `json:"origin"`
}

// BundleManifest is the machine-readable bundle-identity/v1 output document.
type BundleManifest struct {
	SchemaVersion      string                            `json:"schema_version"`
	BundleID           string                            `json:"bundle_id"`
	ManifestDigest     string                            `json:"manifest_digest"`
	FileCount          int                               `json:"file_count"`
	TotalBytes         int64                             `json:"total_bytes"`
	Files              []inventory.FileEntry             `json:"files"`
	FormatSummary      FormatSummary                     `json:"format_summary"`
	ModelConfig        *huggingface.ModelConfigSummary   `json:"model_config,omitempty"`
	Tokenizer          *huggingface.TokenizerSummary     `json:"tokenizer,omitempty"`
	Quantization       *huggingface.QuantizationMetadata `json:"quantization,omitempty"`
	SafetensorsFiles   []safetensors.FileInspection      `json:"safetensors_files,omitempty"`
	ShardIndices       []safetensors.ShardIndex          `json:"shard_indices,omitempty"`
	LoRARelationship   peft.AdapterMetadata              `json:"lora_relationship"`
	SecurityFlags      SecurityFlags                     `json:"security_flags"`
	MetadataProvenance []ProvenanceRecord                `json:"metadata_provenance"`
}

// Finalize computes the canonical ManifestDigest over the populated BundleManifest (excluding ManifestDigest itself)
// and returns the completed manifest plus indented JSON bytes.
func Finalize(m BundleManifest) (BundleManifest, []byte, error) {
	m.ManifestDigest = ""
	canon, err := identity.CanonicalizeStruct(m)
	if err != nil {
		return BundleManifest{}, nil, fmt.Errorf("canonicalize manifest: %w", err)
	}
	m.ManifestDigest = digest.ComputeBytes(canon)

	pretty, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return BundleManifest{}, nil, fmt.Errorf("marshal manifest: %w", err)
	}
	pretty = append(pretty, '\n')
	return m, pretty, nil
}
