// Package peft provides static inspection of PEFT / LoRA adapter configurations and base model relationship states.
package peft

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/devenes/ai-model-provenance-gate/internal/formats/huggingface"
)

// VerificationStatus represents the base-model-to-adapter verification state.
type VerificationStatus string

const (
	// StatusNone indicates the bundle does not contain a PEFT/LoRA adapter.
	StatusNone VerificationStatus = "NONE"
	// StatusVerified indicates the base model bundle identity was cryptographically verified.
	StatusVerified VerificationStatus = "VERIFIED"
	// StatusDeclaredUnverified indicates adapter_config.json declares a base model, but the base model files were not cryptographically verified.
	StatusDeclaredUnverified VerificationStatus = "DECLARED_UNVERIFIED"
	// StatusMissing indicates adapter weights or config exist, but base_model_name_or_path or adapter config is missing.
	StatusMissing VerificationStatus = "MISSING"
	// StatusMismatch indicates the supplied base model bundle identity or architecture conflicts with the adapter.
	StatusMismatch VerificationStatus = "MISMATCH"
)

var (
	// ErrInvalidAdapterConfig is returned when adapter_config.json is malformed.
	ErrInvalidAdapterConfig = errors.New("invalid PEFT adapter_config.json")
)

// AdapterMetadata holds static metadata extracted from adapter_config.json and adapter weight files.
type AdapterMetadata struct {
	IsAdapter            bool               `json:"is_adapter"`
	ConfigPath           string             `json:"config_path,omitempty"`
	WeightPaths          []string           `json:"weight_paths,omitempty"`
	PEFTType             string             `json:"peft_type,omitempty"`
	TaskType             string             `json:"task_type,omitempty"`
	BaseModelNameOrPath  string             `json:"base_model_name_or_path,omitempty"`
	Revision             string             `json:"revision,omitempty"`
	Rank                 int                `json:"r,omitempty"`
	LoraAlpha            float64            `json:"lora_alpha,omitempty"`
	LoraDropout          float64            `json:"lora_dropout,omitempty"`
	TargetModules        []string           `json:"target_modules,omitempty"`
	VerificationStatus   VerificationStatus `json:"verification_status"`
	VerifiedBaseBundleID string             `json:"verified_base_bundle_id,omitempty"`
	ExpectedBaseBundleID string             `json:"expected_base_bundle_id,omitempty"`
	VerificationNotes    string             `json:"verification_notes,omitempty"`
}

// InspectAdapterConfig statically parses adapter_config.json without executing code.
func InspectAdapterConfig(path string, relPath string, maxBytes int64) (AdapterMetadata, error) {
	if maxBytes <= 0 {
		maxBytes = huggingface.DefaultMaxConfigBytes
	}
	st, err := os.Stat(path)
	if err != nil {
		return AdapterMetadata{}, fmt.Errorf("stat %q: %w", relPath, err)
	}
	if st.Size() > maxBytes {
		return AdapterMetadata{}, fmt.Errorf("%w: %q size %d exceeds limit %d", huggingface.ErrMetadataTooLarge, relPath, st.Size(), maxBytes)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return AdapterMetadata{}, fmt.Errorf("read %q: %w", relPath, err)
	}
	if err := huggingface.ScanForSecrets(raw, relPath); err != nil {
		return AdapterMetadata{}, err
	}

	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(raw, &rawMap); err != nil {
		return AdapterMetadata{}, fmt.Errorf("%w in %q: %v", ErrInvalidAdapterConfig, relPath, err)
	}

	meta := AdapterMetadata{
		IsAdapter:  true,
		ConfigPath: relPath,
	}

	if v, ok := rawMap["peft_type"]; ok {
		_ = json.Unmarshal(v, &meta.PEFTType)
	}
	if v, ok := rawMap["task_type"]; ok {
		_ = json.Unmarshal(v, &meta.TaskType)
	}
	if v, ok := rawMap["base_model_name_or_path"]; ok {
		_ = json.Unmarshal(v, &meta.BaseModelNameOrPath)
	}
	if v, ok := rawMap["revision"]; ok {
		_ = json.Unmarshal(v, &meta.Revision)
	}
	if v, ok := rawMap["r"]; ok {
		_ = json.Unmarshal(v, &meta.Rank)
	}
	if v, ok := rawMap["lora_alpha"]; ok {
		_ = json.Unmarshal(v, &meta.LoraAlpha)
	}
	if v, ok := rawMap["lora_dropout"]; ok {
		_ = json.Unmarshal(v, &meta.LoraDropout)
	}
	if v, ok := rawMap["target_modules"]; ok {
		var list []string
		if err := json.Unmarshal(v, &list); err == nil {
			sort.Strings(list)
			meta.TargetModules = list
		} else {
			var single string
			if err := json.Unmarshal(bytes.TrimSpace(v), &single); err == nil && single != "" {
				meta.TargetModules = []string{single}
			}
		}
	}

	return meta, nil
}

// EvaluateRelationship determines the LoRA base-model verification status (`VERIFIED`, `DECLARED_UNVERIFIED`, `MISSING`, `MISMATCH`, or `NONE`).
func EvaluateRelationship(
	meta AdapterMetadata,
	adapterWeightPaths []string,
	actualBaseBundleID string,
	expectedBaseBundleID string,
) AdapterMetadata {
	meta.WeightPaths = append([]string(nil), adapterWeightPaths...)
	sort.Strings(meta.WeightPaths)
	meta.ExpectedBaseBundleID = strings.TrimSpace(expectedBaseBundleID)
	actualBaseBundleID = strings.TrimSpace(actualBaseBundleID)

	if !meta.IsAdapter && len(meta.WeightPaths) == 0 {
		meta.VerificationStatus = StatusNone
		return meta
	}

	meta.IsAdapter = true
	if meta.ConfigPath == "" {
		meta.VerificationStatus = StatusMissing
		meta.VerificationNotes = "adapter weight files exist without adapter_config.json"
		return meta
	}
	if len(meta.WeightPaths) == 0 {
		meta.VerificationStatus = StatusMissing
		meta.VerificationNotes = "adapter_config.json exists without adapter weight files"
		return meta
	}
	if strings.TrimSpace(meta.BaseModelNameOrPath) == "" {
		meta.VerificationStatus = StatusMissing
		meta.VerificationNotes = "adapter_config.json does not declare base_model_name_or_path"
		return meta
	}

	// If an actual base model bundle was inspected alongside the adapter:
	if actualBaseBundleID != "" {
		if meta.ExpectedBaseBundleID != "" && actualBaseBundleID != meta.ExpectedBaseBundleID {
			meta.VerificationStatus = StatusMismatch
			meta.VerifiedBaseBundleID = actualBaseBundleID
			meta.VerificationNotes = fmt.Sprintf(
				"inspected base model bundle identity %s does not match expected base bundle identity %s",
				actualBaseBundleID, meta.ExpectedBaseBundleID,
			)
			return meta
		}
		meta.VerificationStatus = StatusVerified
		meta.VerifiedBaseBundleID = actualBaseBundleID
		meta.VerificationNotes = fmt.Sprintf(
			"base model bundle identity %s cryptographically verified alongside adapter",
			actualBaseBundleID,
		)
		return meta
	}

	// If an expected base bundle ID was required, but no base model bundle was supplied to verify it:
	if meta.ExpectedBaseBundleID != "" {
		meta.VerificationStatus = StatusMismatch
		meta.VerificationNotes = fmt.Sprintf(
			"expected base model bundle %s, but no base model bundle was supplied for cryptographic verification",
			meta.ExpectedBaseBundleID,
		)
		return meta
	}

	// Otherwise, base_model_name_or_path is a declared string without cryptographic verification of base model weights.
	meta.VerificationStatus = StatusDeclaredUnverified
	meta.VerificationNotes = fmt.Sprintf(
		"base_model_name_or_path=%q (revision=%q) is declared in adapter_config.json without cryptographic verification of base model weights",
		meta.BaseModelNameOrPath, meta.Revision,
	)
	return meta
}
