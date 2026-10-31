package bom

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/devenes/ai-model-provenance-gate/internal/bundle"
	"github.com/devenes/ai-model-provenance-gate/internal/formats/safetensors"
)

func TestBOMAcceptanceCriteria(t *testing.T) {
	// 1. Valid model bundle with multiple shards, LoRA adapter, missing license, unknown metadata
	dir := filepath.Join(t.TempDir(), "sharded-lora-bundle")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	// config.json WITHOUT license and WITH unknown custom field
	cfgJSON := `{
  "architectures": ["LlamaForCausalLM"],
  "model_type": "llama",
  "torch_dtype": "bfloat16",
  "custom_vendor_flag": "experimental-v2",
  "quantization_config": {
    "quant_method": "gptq",
    "bits": 4,
    "group_size": 128
  }
}`
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(cfgJSON), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	shard1, err := safetensors.BuildSyntheticSafetensors([]safetensors.SyntheticTensor{
		{Name: "model.embed_tokens.weight", DType: "BF16", Shape: []int64{4, 4}},
	}, map[string]string{"format": "pt"})
	if err != nil {
		t.Fatalf("shard1: %v", err)
	}
	shard2, err := safetensors.BuildSyntheticSafetensors([]safetensors.SyntheticTensor{
		{Name: "model.layers.0.weight", DType: "BF16", Shape: []int64{4, 4}},
	}, map[string]string{"format": "pt"})
	if err != nil {
		t.Fatalf("shard2: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "model-00001-of-00002.safetensors"), shard1, 0o600); err != nil {
		t.Fatalf("write s1: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "model-00002-of-00002.safetensors"), shard2, 0o600); err != nil {
		t.Fatalf("write s2: %v", err)
	}
	indexJSON := `{
  "metadata": {"total_size": 64},
  "weight_map": {
    "model.embed_tokens.weight": "model-00001-of-00002.safetensors",
    "model.layers.0.weight": "model-00002-of-00002.safetensors"
  }
}`
	if err := os.WriteFile(filepath.Join(dir, "model.safetensors.index.json"), []byte(indexJSON), 0o600); err != nil {
		t.Fatalf("write index: %v", err)
	}

	// LoRA adapter
	adapterCfg := `{
  "peft_type": "LORA",
  "task_type": "CAUSAL_LM",
  "base_model_name_or_path": "meta-llama/Llama-3-8B",
  "revision": "043235d",
  "r": 16,
  "lora_alpha": 32,
  "target_modules": ["q_proj", "v_proj"]
}`
	if err := os.WriteFile(filepath.Join(dir, "adapter_config.json"), []byte(adapterCfg), 0o600); err != nil {
		t.Fatalf("write adapter_config: %v", err)
	}
	adapterW, err := safetensors.BuildSyntheticSafetensors([]safetensors.SyntheticTensor{
		{Name: "base_model.model.layers.0.lora_A.weight", DType: "F16", Shape: []int64{2, 4}},
	}, nil)
	if err != nil {
		t.Fatalf("build adapter weights: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "adapter_model.safetensors"), adapterW, 0o600); err != nil {
		t.Fatalf("write adapter weights: %v", err)
	}

	// Inspect bundle (note: no tokenizer files in this bundle -> tests missing tokenizer case too)
	insp, err := bundle.Inspect(dir, bundle.DefaultInspectOptions())
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}

	// Generate CycloneDX 1.7 BOM
	gen17, err := Generate(insp, GenerateOptions{
		SpecVersion: SpecVersion1_7,
		Timestamp:   "2026-10-31T00:00:00Z",
	})
	if err != nil {
		t.Fatalf("Generate 1.7: %v", err)
	}
	if gen17.Document.SpecVersion != "1.7" || gen17.Document.Schema != SchemaURI1_7 {
		t.Fatalf("unexpected 1.7 schema header: %s / %s", gen17.Document.SpecVersion, gen17.Document.Schema)
	}

	// Verify missing license is NOT fabricated
	if len(gen17.Document.Metadata.Component.Licenses) != 0 {
		t.Fatalf("expected 0 licenses when missing from bundle, got %d", len(gen17.Document.Metadata.Component.Licenses))
	}
	if !hasProperty(gen17.Document.Metadata.Component.Properties, "provenance:license_status", "missing") {
		t.Fatalf("expected provenance:license_status=missing property")
	}

	// Verify missing tokenizer is recorded accurately
	if !hasProperty(gen17.Document.Metadata.Component.Properties, "provenance:has_tokenizer", "false") {
		t.Fatalf("expected provenance:has_tokenizer=false property")
	}

	// Verify unknown metadata key preserved
	if !hasProperty(gen17.Document.Metadata.Component.Properties, "huggingface:preserved_unknown_config_keys", "custom_vendor_flag") {
		t.Fatalf("expected unknown config key custom_vendor_flag to be preserved")
	}

	// Verify LoRA pedigree & DECLARED_UNVERIFIED status
	if gen17.Document.Metadata.Component.Pedigree == nil || len(gen17.Document.Metadata.Component.Pedigree.Ancestors) != 1 {
		t.Fatalf("expected 1 pedigree ancestor for LoRA base model")
	}
	anc := gen17.Document.Metadata.Component.Pedigree.Ancestors[0]
	if !hasProperty(anc.Properties, "provenance:verification_status", "DECLARED_UNVERIFIED") {
		t.Fatalf("expected DECLARED_UNVERIFIED on ancestor")
	}

	// Generate CycloneDX 1.6 BOM and validate
	gen16, err := Generate(insp, GenerateOptions{
		SpecVersion: SpecVersion1_6,
		Timestamp:   "2026-10-31T00:00:00Z",
	})
	if err != nil {
		t.Fatalf("Generate 1.6: %v", err)
	}
	if gen16.Document.SpecVersion != "1.6" || gen16.Document.Schema != SchemaURI1_6 {
		t.Fatalf("unexpected 1.6 schema header")
	}

	// Tamper with a file hash in BOM JSON and confirm inventory/BOM consistency check fails
	tamperedJSON := strings.Replace(string(gen17.JSON), gen17.Document.Components[0].Hashes[0].Content, strings.Repeat("0", 64), 1)
	if err := Validate([]byte(tamperedJSON), &insp); !errors.Is(err, ErrInvalidBOM) {
		t.Fatalf("expected ErrInvalidBOM on tampered file hash, got %v", err)
	}
}

func hasProperty(props []Property, name, val string) bool {
	for _, p := range props {
		if p.Name == name && p.Value == val {
			return true
		}
	}
	return false
}

func TestCycloneDX17OfficialSchemaAndNegativeCases(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cdx17-bundle")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	cfgJSON := `{
  "architectures": ["MistralForCausalLM"],
  "model_type": "mistral",
  "torch_dtype": "bfloat16",
  "license": "apache-2.0"
}`
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(cfgJSON), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	stBytes, err := safetensors.BuildSyntheticSafetensors([]safetensors.SyntheticTensor{
		{Name: "model.layers.0.weight", DType: "BF16", Shape: []int64{4, 4}},
	}, map[string]string{"format": "pt"})
	if err != nil {
		t.Fatalf("safetensors: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "model.safetensors"), stBytes, 0o600); err != nil {
		t.Fatalf("write model: %v", err)
	}
	adapterCfg := `{
  "peft_type": "LORA",
  "task_type": "CAUSAL_LM",
  "base_model_name_or_path": "mistralai/Mistral-7B-v0.1",
  "revision": "26bca36",
  "r": 8,
  "lora_alpha": 16,
  "target_modules": ["q_proj"]
}`
	if err := os.WriteFile(filepath.Join(dir, "adapter_config.json"), []byte(adapterCfg), 0o600); err != nil {
		t.Fatalf("write adapter_config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "adapter_model.safetensors"), stBytes, 0o600); err != nil {
		t.Fatalf("write adapter_model: %v", err)
	}

	insp, err := bundle.Inspect(dir, bundle.DefaultInspectOptions())
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}

	// 1. Valid 1.7 BOM + SPDX license normalization ("apache-2.0" -> "Apache-2.0")
	gen, err := Generate(insp, GenerateOptions{
		SpecVersion: SpecVersion1_7,
		Timestamp:   "2026-10-31T00:00:00Z",
	})
	if err != nil {
		t.Fatalf("Generate 1.7: %v", err)
	}
	if len(gen.Document.Metadata.Component.Licenses) != 1 || gen.Document.Metadata.Component.Licenses[0].License.ID != "Apache-2.0" {
		t.Fatalf("expected SPDX normalized license ID Apache-2.0, got %+v", gen.Document.Metadata.Component.Licenses)
	}
	if gen.Document.SerialNumber == insp.BundleID || strings.HasPrefix(gen.Document.SerialNumber, "sha256:") {
		t.Fatalf("serialNumber %q must not be confused with model_bundle_id %q", gen.Document.SerialNumber, insp.BundleID)
	}

	cloneDoc := func() Document {
		var d Document
		if err := json.Unmarshal(gen.JSON, &d); err != nil {
			t.Fatalf("unmarshal base doc: %v", err)
		}
		return d
	}
	mustFail := func(name string, raw []byte) {
		t.Helper()
		if err := Validate(raw, &insp); !errors.Is(err, ErrInvalidBOM) {
			t.Fatalf("[%s] expected ErrInvalidBOM, got %v", name, err)
		}
	}

	// 2. Invalid required fields (missing bomFormat / missing metadata.timestamp)
	{
		d := cloneDoc()
		d.BOMFormat = ""
		b, _ := json.Marshal(d)
		mustFail("missing bomFormat", b)

		d2 := cloneDoc()
		d2.Metadata.Timestamp = ""
		b2, _ := json.Marshal(d2)
		mustFail("missing metadata.timestamp", b2)
	}

	// 3. Unknown properties
	{
		var rawMap map[string]any
		_ = json.Unmarshal(gen.JSON, &rawMap)
		rawMap["unexpectedCustomField"] = "disallowed"
		b, _ := json.Marshal(rawMap)
		mustFail("unknown property", b)
	}

	// 4. Invalid component types
	{
		d := cloneDoc()
		d.Components[0].Type = "invalid-component-type"
		b, _ := json.Marshal(d)
		mustFail("invalid component type", b)
	}

	// 5. Missing file component
	{
		d := cloneDoc()
		var filtered []Component
		var keepRef string
		for _, c := range d.Components {
			if c.Type == "file" && keepRef == "" {
				keepRef = c.BOMRef
				continue // drop one file component
			}
			filtered = append(filtered, c)
		}
		d.Components = filtered
		for i := range d.Dependencies {
			var deps []string
			for _, ref := range d.Dependencies[i].DependsOn {
				if ref != keepRef {
					deps = append(deps, ref)
				}
			}
			d.Dependencies[i].DependsOn = deps
		}
		b, _ := json.Marshal(d)
		mustFail("missing file component", b)
	}

	// 6. Extra file component
	{
		d := cloneDoc()
		extraRef := "file:extra.safetensors"
		d.Components = append(d.Components, Component{
			Type:   "file",
			BOMRef: extraRef,
			Name:   "extra.safetensors",
			Hashes: []Hash{{Alg: "SHA-256", Content: strings.Repeat("a", 64)}},
		})
		d.Dependencies[0].DependsOn = append(d.Dependencies[0].DependsOn, extraRef)
		b, _ := json.Marshal(d)
		mustFail("extra file component", b)
	}

	// 7. Wrong digest
	{
		d := cloneDoc()
		for i := range d.Components {
			if d.Components[i].Type == "file" {
				d.Components[i].Hashes[0].Content = strings.Repeat("b", 64)
				break
			}
		}
		b, _ := json.Marshal(d)
		mustFail("wrong file digest", b)
	}

	// 8. Invalid pedigree (wrong base model name, missing ancestor, or non-ML ancestor type)
	{
		d := cloneDoc()
		d.Metadata.Component.Pedigree.Ancestors[0].Name = "tampered/wrong-base-model"
		b, _ := json.Marshal(d)
		mustFail("wrong pedigree ancestor name", b)

		d2 := cloneDoc()
		d2.Metadata.Component.Pedigree.Ancestors[0].Type = "file"
		b2, _ := json.Marshal(d2)
		mustFail("invalid pedigree ancestor type", b2)

		d3 := cloneDoc()
		d3.Metadata.Component.Pedigree = nil
		b3, _ := json.Marshal(d3)
		mustFail("missing pedigree for PEFT bundle", b3)
	}

	// 9. Incorrect model metadata (wrong modelArchitecture or modelCard on file component)
	{
		d := cloneDoc()
		d.Metadata.Component.ModelCard.ModelParameters.ModelArchitecture = "GPT2LMHeadModel"
		b, _ := json.Marshal(d)
		mustFail("mismatched modelCard modelArchitecture", b)

		d2 := cloneDoc()
		d2.Components[0].ModelCard = &ModelCard{
			ModelParameters: &ModelParameters{Task: "CAUSAL_LM"},
		}
		b2, _ := json.Marshal(d2)
		mustFail("modelCard on file component", b2)
	}

	// 10. Official CycloneDX 1.7 schema validation failure & serialNumber/bundle_id confusion
	{
		d := cloneDoc()
		d.Metadata.Component.Licenses = []LicenseChoice{
			{
				License: &License{
					ID: "NOT-A-VALID-SPDX-LICENSE-IDENTIFIER",
				},
			},
		}
		b, _ := json.Marshal(d)
		mustFail("official spdx.schema.json license ID rejection", b)

		d2 := cloneDoc()
		d2.SerialNumber = insp.BundleID
		b2, _ := json.Marshal(d2)
		mustFail("serialNumber confused with model_bundle_id", b2)
	}

	// 11. Invalid relationship (dangling dependsOn reference or unlinked component)
	{
		d := cloneDoc()
		d.Dependencies[0].DependsOn[0] = "file:nonexistent-target.safetensors"
		b, _ := json.Marshal(d)
		mustFail("dangling dependency target", b)

		d2 := cloneDoc()
		d2.Dependencies[0].DependsOn = d2.Dependencies[0].DependsOn[1:]
		b2, _ := json.Marshal(d2)
		mustFail("unlinked component in root dependencies", b2)
	}

	// 12. Malformed JSON
	{
		mustFail("malformed JSON", []byte("{invalid-json"))
	}
}
