// Package huggingface provides static inspection of Hugging Face model, tokenizer, and quantization configuration files.
package huggingface

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
)

const (
	// DefaultMaxConfigBytes caps JSON metadata files at 32 MiB to prevent memory exhaustion DoS.
	DefaultMaxConfigBytes int64 = 32 * 1024 * 1024
)

var (
	// ErrMetadataTooLarge is returned when a configuration file exceeds MaxConfigBytes.
	ErrMetadataTooLarge = errors.New("huggingface metadata file exceeds maximum allowed byte size")
	// ErrInvalidConfigJSON is returned when a configuration file is not valid JSON.
	ErrInvalidConfigJSON = errors.New("invalid huggingface JSON configuration")
	// ErrSensitiveMetadataDetected is returned when secret/token patterns are detected inside model metadata.
	ErrSensitiveMetadataDetected = errors.New("sensitive credential or token pattern detected in model metadata")

	secretPatterns = []*regexp.Regexp{
		regexp.MustCompile(`hf_[A-Za-z0-9]{20,}`),
		regexp.MustCompile(`sk-[A-Za-z0-9]{20,}`),
		regexp.MustCompile(`ghp_[A-Za-z0-9]{20,}`),
		regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----`),
	}
)

// QuantizationMetadata captures observed quantization settings from config.json or quantization_config.json.
type QuantizationMetadata struct {
	QuantMethod string `json:"quant_method,omitempty"`
	Bits        int    `json:"bits,omitempty"`
	GroupSize   int    `json:"group_size,omitempty"`
	ZeroPoint   *bool  `json:"zero_point,omitempty"`
	Format      string `json:"format,omitempty"`
	Source      string `json:"source"`
}

// ModelConfigSummary captures observed fields from config.json without inventing absent metadata.
type ModelConfigSummary struct {
	Path                string                `json:"path"`
	ModelType           string                `json:"model_type,omitempty"`
	Architectures       []string              `json:"architectures,omitempty"`
	TorchDType          string                `json:"torch_dtype,omitempty"`
	TransformersVersion string                `json:"transformers_version,omitempty"`
	VocabSize           int                   `json:"vocab_size,omitempty"`
	HiddenSize          int                   `json:"hidden_size,omitempty"`
	NumHiddenLayers     int                   `json:"num_hidden_layers,omitempty"`
	NumAttentionHeads   int                   `json:"num_attention_heads,omitempty"`
	DeclaredNameOrPath  string                `json:"declared_name_or_path,omitempty"`
	DeclaredLicense     string                `json:"declared_license,omitempty"`
	HasAutoMap          bool                  `json:"has_auto_map"`
	AutoMapKeys         []string              `json:"auto_map_keys,omitempty"`
	Quantization        *QuantizationMetadata `json:"quantization,omitempty"`
	UnknownFields       []string              `json:"unknown_fields,omitempty"`
}

// TokenizerSummary captures observed fields from tokenizer_config.json, tokenizer.json, and chat templates.
type TokenizerSummary struct {
	ConfigPath         string   `json:"config_path,omitempty"`
	TokenizerJSONPath  string   `json:"tokenizer_json_path,omitempty"`
	SpecialTokensPath  string   `json:"special_tokens_path,omitempty"`
	ChatTemplatePath   string   `json:"chat_template_path,omitempty"`
	TokenizerClass     string   `json:"tokenizer_class,omitempty"`
	ModelMaxLength     int64    `json:"model_max_length,omitempty"`
	HasInlineChatTempl bool     `json:"has_inline_chat_template"`
	VocabFiles         []string `json:"vocab_files,omitempty"`
}

// InspectModelConfig statically parses config.json with strict size and secret checks.
func InspectModelConfig(path string, relPath string, maxBytes int64) (ModelConfigSummary, error) {
	raw, err := readBoundedJSONFile(path, relPath, maxBytes)
	if err != nil {
		return ModelConfigSummary{}, err
	}
	if err := ScanForSecrets(raw, relPath); err != nil {
		return ModelConfigSummary{}, err
	}

	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(raw, &rawMap); err != nil {
		return ModelConfigSummary{}, fmt.Errorf("%w in %q: %v", ErrInvalidConfigJSON, relPath, err)
	}

	knownKeys := map[string]bool{
		"model_type": true, "architectures": true, "torch_dtype": true,
		"transformers_version": true, "vocab_size": true, "hidden_size": true,
		"num_hidden_layers": true, "num_attention_heads": true, "_name_or_path": true,
		"license": true, "auto_map": true, "quantization_config": true,
	}

	summary := ModelConfigSummary{
		Path: relPath,
	}

	if v, ok := rawMap["model_type"]; ok {
		_ = json.Unmarshal(v, &summary.ModelType)
	}
	if v, ok := rawMap["architectures"]; ok {
		_ = json.Unmarshal(v, &summary.Architectures)
	}
	if v, ok := rawMap["torch_dtype"]; ok {
		_ = json.Unmarshal(v, &summary.TorchDType)
	}
	if v, ok := rawMap["transformers_version"]; ok {
		_ = json.Unmarshal(v, &summary.TransformersVersion)
	}
	if v, ok := rawMap["vocab_size"]; ok {
		_ = json.Unmarshal(v, &summary.VocabSize)
	}
	if v, ok := rawMap["hidden_size"]; ok {
		_ = json.Unmarshal(v, &summary.HiddenSize)
	}
	if v, ok := rawMap["num_hidden_layers"]; ok {
		_ = json.Unmarshal(v, &summary.NumHiddenLayers)
	}
	if v, ok := rawMap["num_attention_heads"]; ok {
		_ = json.Unmarshal(v, &summary.NumAttentionHeads)
	}
	if v, ok := rawMap["_name_or_path"]; ok {
		_ = json.Unmarshal(v, &summary.DeclaredNameOrPath)
	}
	if v, ok := rawMap["license"]; ok {
		_ = json.Unmarshal(v, &summary.DeclaredLicense)
	}
	if v, ok := rawMap["auto_map"]; ok {
		var autoMap map[string]any
		if err := json.Unmarshal(v, &autoMap); err == nil && len(autoMap) > 0 {
			summary.HasAutoMap = true
			for k := range autoMap {
				summary.AutoMapKeys = append(summary.AutoMapKeys, k)
			}
			sort.Strings(summary.AutoMapKeys)
		}
	}
	if v, ok := rawMap["quantization_config"]; ok {
		q, err := parseQuantizationJSON(v, relPath+"#quantization_config")
		if err == nil && q != nil {
			summary.Quantization = q
		}
	}

	for k := range rawMap {
		if !knownKeys[k] {
			summary.UnknownFields = append(summary.UnknownFields, k)
		}
	}
	sort.Strings(summary.UnknownFields)

	return summary, nil
}

// InspectQuantizationFile parses a standalone quantization_config.json or quantize_config.json file.
func InspectQuantizationFile(path string, relPath string, maxBytes int64) (*QuantizationMetadata, error) {
	raw, err := readBoundedJSONFile(path, relPath, maxBytes)
	if err != nil {
		return nil, err
	}
	if err := ScanForSecrets(raw, relPath); err != nil {
		return nil, err
	}
	return parseQuantizationJSON(raw, relPath)
}

func parseQuantizationJSON(raw []byte, source string) (*QuantizationMetadata, error) {
	var parsed struct {
		QuantMethod string `json:"quant_method"`
		Bits        int    `json:"bits"`
		WBits       int    `json:"w_bit"`
		GroupSize   int    `json:"group_size"`
		QGroupSize  int    `json:"q_group_size"`
		ZeroPoint   *bool  `json:"zero_point"`
		Format      string `json:"format"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, fmt.Errorf("%w in %q: %v", ErrInvalidConfigJSON, source, err)
	}
	bits := parsed.Bits
	if bits == 0 && parsed.WBits > 0 {
		bits = parsed.WBits
	}
	groupSize := parsed.GroupSize
	if groupSize == 0 && parsed.QGroupSize > 0 {
		groupSize = parsed.QGroupSize
	}
	return &QuantizationMetadata{
		QuantMethod: parsed.QuantMethod,
		Bits:        bits,
		GroupSize:   groupSize,
		ZeroPoint:   parsed.ZeroPoint,
		Format:      parsed.Format,
		Source:      source,
	}, nil
}

// InspectTokenizerConfig statically parses tokenizer_config.json.
func InspectTokenizerConfig(path string, relPath string, maxBytes int64) (TokenizerSummary, error) {
	raw, err := readBoundedJSONFile(path, relPath, maxBytes)
	if err != nil {
		return TokenizerSummary{}, err
	}
	if err := ScanForSecrets(raw, relPath); err != nil {
		return TokenizerSummary{}, err
	}
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(raw, &rawMap); err != nil {
		return TokenizerSummary{}, fmt.Errorf("%w in %q: %v", ErrInvalidConfigJSON, relPath, err)
	}
	summary := TokenizerSummary{
		ConfigPath: relPath,
	}
	if v, ok := rawMap["tokenizer_class"]; ok {
		_ = json.Unmarshal(v, &summary.TokenizerClass)
	}
	if v, ok := rawMap["model_max_length"]; ok {
		var maxLen int64
		if err := json.Unmarshal(v, &maxLen); err == nil && maxLen > 0 && maxLen < 1_000_000_000 {
			summary.ModelMaxLength = maxLen
		}
	}
	if v, ok := rawMap["chat_template"]; ok && len(bytes.TrimSpace(v)) > 0 && string(bytes.TrimSpace(v)) != "null" {
		summary.HasInlineChatTempl = true
	}
	return summary, nil
}

// ValidateJSONFile verifies that a JSON file (such as tokenizer.json, special_tokens_map.json, or generation_config.json)
// is bounded, free of secret patterns, and valid JSON syntax.
func ValidateJSONFile(path string, relPath string, maxBytes int64) error {
	raw, err := readBoundedJSONFile(path, relPath, maxBytes)
	if err != nil {
		return err
	}
	if err := ScanForSecrets(raw, relPath); err != nil {
		return err
	}
	var anyObj map[string]any
	if err := json.Unmarshal(raw, &anyObj); err != nil {
		return fmt.Errorf("%w in %q: %v", ErrInvalidConfigJSON, relPath, err)
	}
	return nil
}

// ScanForSecrets checks raw metadata bytes for embedded credential tokens or private keys.
func ScanForSecrets(raw []byte, relPath string) error {
	for _, pat := range secretPatterns {
		if loc := pat.FindIndex(raw); loc != nil {
			matched := string(raw[loc[0]:loc[1]])
			prefix := matched
			if len(prefix) > 6 {
				prefix = prefix[:6] + "***REDACTED***"
			}
			return fmt.Errorf("%w in %q (matched pattern %q)", ErrSensitiveMetadataDetected, relPath, prefix)
		}
	}
	return nil
}

// IsUnsafePickleExtension returns true if a file extension corresponds to an executable/pickle serialization format.
func IsUnsafePickleExtension(relPath string) bool {
	lower := strings.ToLower(relPath)
	for _, ext := range []string{".pkl", ".pickle", ".pt", ".pth", ".bin", ".ckpt", ".joblib", ".dill"} {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

func readBoundedJSONFile(path string, relPath string, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxConfigBytes
	}
	st, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat %q: %w", relPath, err)
	}
	if st.Size() > maxBytes {
		return nil, fmt.Errorf("%w: %q is %d bytes (limit %d)", ErrMetadataTooLarge, relPath, st.Size(), maxBytes)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %q: %w", relPath, err)
	}
	return raw, nil
}
