package bundle

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/devenes/ai-model-provenance-gate/internal/digest"
	"github.com/devenes/ai-model-provenance-gate/internal/formats/peft"
	"github.com/devenes/ai-model-provenance-gate/internal/formats/safetensors"
	"github.com/devenes/ai-model-provenance-gate/internal/inventory"
)

func writeSyntheticBundle(t *testing.T, dir string, weightByte byte, tokContent string, cfgArch string, loraRank string, includeUnknown bool) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	cfg := `{
  "architectures": ["` + cfgArch + `"],
  "model_type": "llama",
  "torch_dtype": "bfloat16",
  "vocab_size": 32000,
  "hidden_size": 4096,
  "num_hidden_layers": 32,
  "num_attention_heads": 32,
  "license": "apache-2.0",
  "quantization_config": {
    "quant_method": "awq",
    "bits": 4,
    "group_size": 128
  }
}`
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(cfg), 0o600); err != nil {
		t.Fatalf("write config.json: %v", err)
	}

	weights, err := safetensors.BuildSyntheticSafetensors([]safetensors.SyntheticTensor{
		{
			Name:  "model.layers.0.self_attn.q_proj.weight",
			DType: "BF16",
			Shape: []int64{4, 4},
			Data:  repeatByte(weightByte, 32),
		},
	}, map[string]string{"format": "pt"})
	if err != nil {
		t.Fatalf("build safetensors: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "model.safetensors"), weights, 0o600); err != nil {
		t.Fatalf("write model.safetensors: %v", err)
	}

	tokCfg := `{
  "tokenizer_class": "PreTrainedTokenizerFast",
  "model_max_length": 8192
}`
	if err := os.WriteFile(filepath.Join(dir, "tokenizer_config.json"), []byte(tokCfg), 0o600); err != nil {
		t.Fatalf("write tokenizer_config.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tokenizer.json"), []byte(tokContent), 0o600); err != nil {
		t.Fatalf("write tokenizer.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "special_tokens_map.json"), []byte(`{"bos_token":"<s>","eos_token":"</s>"}`), 0o600); err != nil {
		t.Fatalf("write special_tokens_map.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "chat_template.jinja"), []byte("{{ bos_token }}{% for m in messages %}{{ m['content'] }}{% endfor %}"), 0o600); err != nil {
		t.Fatalf("write chat_template.jinja: %v", err)
	}

	if loraRank != "" {
		adapterCfg := `{
  "peft_type": "LORA",
  "task_type": "CAUSAL_LM",
  "base_model_name_or_path": "meta-llama/Llama-3-8B",
  "revision": "main",
  "r": ` + loraRank + `,
  "lora_alpha": 16,
  "lora_dropout": 0.05,
  "target_modules": ["q_proj", "v_proj"]
}`
		if err := os.WriteFile(filepath.Join(dir, "adapter_config.json"), []byte(adapterCfg), 0o600); err != nil {
			t.Fatalf("write adapter_config.json: %v", err)
		}
		adapterWeights, err := safetensors.BuildSyntheticSafetensors([]safetensors.SyntheticTensor{
			{
				Name:  "base_model.model.layers.0.lora_A.weight",
				DType: "F16",
				Shape: []int64{2, 4},
				Data:  repeatByte(weightByte^0x11, 16),
			},
		}, map[string]string{"format": "pt"})
		if err != nil {
			t.Fatalf("build adapter safetensors: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, "adapter_model.safetensors"), adapterWeights, 0o600); err != nil {
			t.Fatalf("write adapter_model.safetensors: %v", err)
		}
	}

	if includeUnknown {
		if err := os.WriteFile(filepath.Join(dir, "custom_notes.dat"), []byte("extra regular file"), 0o600); err != nil {
			t.Fatalf("write custom_notes.dat: %v", err)
		}
	}
}

func repeatByte(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func TestIdentityAcceptanceCriteria(t *testing.T) {
	baseTok := `{"version":"1.0","model":{"type":"BPE","vocab":{"<s>":0,"</s>":1,"hello":2}}}`

	// 1. Same bundle -> same identity & 6. Different enumeration order -> same identity
	dirA := filepath.Join(t.TempDir(), "bundle-a")
	dirB := filepath.Join(t.TempDir(), "bundle-b")
	writeSyntheticBundle(t, dirA, 0x2A, baseTok, "LlamaForCausalLM", "8", false)
	writeSyntheticBundle(t, dirB, 0x2A, baseTok, "LlamaForCausalLM", "8", false)

	resA, err := Inspect(dirA, DefaultInspectOptions())
	if err != nil {
		t.Fatalf("Inspect dirA: %v", err)
	}
	optsRev := DefaultInspectOptions()
	optsRev.InventoryOptions.ReverseEnumerationOrder = true
	resB, err := Inspect(dirB, optsRev)
	if err != nil {
		t.Fatalf("Inspect dirB reversed: %v", err)
	}
	if resA.BundleID != resB.BundleID {
		t.Fatalf("same bundle / reversed order produced different bundle_id: %s vs %s", resA.BundleID, resB.BundleID)
	}
	if resA.Manifest.ManifestDigest != resB.Manifest.ManifestDigest {
		t.Fatalf("same bundle produced different manifest_digest: %s vs %s", resA.Manifest.ManifestDigest, resB.Manifest.ManifestDigest)
	}

	// 2. Different weight -> different identity
	dirDiffWeight := filepath.Join(t.TempDir(), "diff-weight")
	writeSyntheticBundle(t, dirDiffWeight, 0x3B, baseTok, "LlamaForCausalLM", "8", false)
	resDiffWeight, err := Inspect(dirDiffWeight, DefaultInspectOptions())
	if err != nil {
		t.Fatalf("Inspect diff-weight: %v", err)
	}
	if resDiffWeight.BundleID == resA.BundleID {
		t.Fatalf("expected different bundle_id when weight bytes change")
	}

	// 3. Different tokenizer -> different identity
	dirDiffTok := filepath.Join(t.TempDir(), "diff-tok")
	altTok := `{"version":"1.0","model":{"type":"BPE","vocab":{"<s>":0,"</s>":1,"tampered":2}}}`
	writeSyntheticBundle(t, dirDiffTok, 0x2A, altTok, "LlamaForCausalLM", "8", false)
	resDiffTok, err := Inspect(dirDiffTok, DefaultInspectOptions())
	if err != nil {
		t.Fatalf("Inspect diff-tok: %v", err)
	}
	if resDiffTok.BundleID == resA.BundleID {
		t.Fatalf("expected different bundle_id when tokenizer changes")
	}

	// 4. Different adapter -> different identity
	dirDiffAdapter := filepath.Join(t.TempDir(), "diff-adapter")
	writeSyntheticBundle(t, dirDiffAdapter, 0x2A, baseTok, "LlamaForCausalLM", "16", false)
	resDiffAdapter, err := Inspect(dirDiffAdapter, DefaultInspectOptions())
	if err != nil {
		t.Fatalf("Inspect diff-adapter: %v", err)
	}
	if resDiffAdapter.BundleID == resA.BundleID {
		t.Fatalf("expected different bundle_id when LoRA adapter changes")
	}

	// 5. Different config -> different identity
	dirDiffCfg := filepath.Join(t.TempDir(), "diff-cfg")
	writeSyntheticBundle(t, dirDiffCfg, 0x2A, baseTok, "MistralForCausalLM", "8", false)
	resDiffCfg, err := Inspect(dirDiffCfg, DefaultInspectOptions())
	if err != nil {
		t.Fatalf("Inspect diff-cfg: %v", err)
	}
	if resDiffCfg.BundleID == resA.BundleID {
		t.Fatalf("expected different bundle_id when config.json changes")
	}

	// 15. Unknown regular file preserved in inventory and changes identity
	dirUnknown := filepath.Join(t.TempDir(), "unknown-file")
	writeSyntheticBundle(t, dirUnknown, 0x2A, baseTok, "LlamaForCausalLM", "8", true)
	resUnknown, err := Inspect(dirUnknown, DefaultInspectOptions())
	if err != nil {
		t.Fatalf("Inspect unknown-file: %v", err)
	}
	if resUnknown.BundleID == resA.BundleID {
		t.Fatalf("expected unknown regular file to change bundle_id")
	}
	if resUnknown.Manifest.FormatSummary.UnknownFileCount != 1 {
		t.Fatalf("expected UnknownFileCount=1, got %d", resUnknown.Manifest.FormatSummary.UnknownFileCount)
	}
}

func TestBundleErrorAndAdversarialCases(t *testing.T) {
	baseTok := `{"version":"1.0","model":{"type":"BPE","vocab":{"<s>":0}}}`

	// 7 & 8. Missing file / Incomplete bundle (config.json without weights)
	dirIncomplete := filepath.Join(t.TempDir(), "incomplete")
	if err := os.MkdirAll(dirIncomplete, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dirIncomplete, "config.json"), []byte(`{"model_type":"llama"}`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if _, err := Inspect(dirIncomplete, DefaultInspectOptions()); !errors.Is(err, ErrIncompleteBundle) {
		t.Fatalf("expected ErrIncompleteBundle, got %v", err)
	}

	// 10. File mutation during hashing (TOCTOU)
	dirMut := filepath.Join(t.TempDir(), "mutating")
	writeSyntheticBundle(t, dirMut, 0x2A, baseTok, "LlamaForCausalLM", "", false)
	optsMut := DefaultInspectOptions()
	mutated := false
	optsMut.InventoryOptions.OnChunkRead = func(relPath string, _ int64) error {
		if relPath == "model.safetensors" && !mutated {
			mutated = true
			p := filepath.Join(dirMut, "model.safetensors")
			f, err := os.OpenFile(p, os.O_WRONLY|os.O_APPEND, 0o600)
			if err != nil {
				return err
			}
			_, _ = f.Write([]byte("tamper"))
			_ = f.Close()
		}
		return nil
	}
	if _, err := Inspect(dirMut, optsMut); !errors.Is(err, digest.ErrConcurrentMutation) {
		t.Fatalf("expected ErrConcurrentMutation, got %v", err)
	}

	// 11. Symbolic link escape rejected
	dirSym := filepath.Join(t.TempDir(), "symlink-bundle")
	writeSyntheticBundle(t, dirSym, 0x2A, baseTok, "LlamaForCausalLM", "", false)
	secretFile := filepath.Join(t.TempDir(), "outside-secret.txt")
	if err := os.WriteFile(secretFile, []byte("secret"), 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}
	if err := os.Symlink(secretFile, filepath.Join(dirSym, "escaped.txt")); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if _, err := Inspect(dirSym, DefaultInspectOptions()); !errors.Is(err, inventory.ErrSymlinkRejected) {
		t.Fatalf("expected ErrSymlinkRejected, got %v", err)
	}

	// 12. Path traversal validation
	if _, err := inventory.NormalizeAndValidateRelPath("../etc/passwd"); !errors.Is(err, inventory.ErrInvalidRelativePath) {
		t.Fatalf("expected ErrInvalidRelativePath for ../etc/passwd, got %v", err)
	}

	// 13. Path normalization collision (NFC vs NFD & case-folding collision)
	// "e\u0301.json" (NFD) vs "\u00e9.json" (NFC)
	if err := inventory.CheckPathCollision([]string{"e\u0301.json", "\u00e9.json"}); !errors.Is(err, inventory.ErrPathCollision) {
		t.Fatalf("expected ErrPathCollision for NFD/NFC collision, got %v", err)
	}
	if err := inventory.CheckPathCollision([]string{"Config.json", "config.json"}); !errors.Is(err, inventory.ErrPathCollision) {
		t.Fatalf("expected ErrPathCollision for case-folding collision, got %v", err)
	}

	// 14. Unsupported / unsafe format (.pkl / .pt)
	dirUnsafe := filepath.Join(t.TempDir(), "unsafe-pickle")
	if err := os.MkdirAll(dirUnsafe, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dirUnsafe, "pytorch_model.bin"), []byte("\x80\x04pkl"), 0o600); err != nil {
		t.Fatalf("write pkl: %v", err)
	}
	if _, err := Inspect(dirUnsafe, DefaultInspectOptions()); !errors.Is(err, ErrUnsupportedFormat) {
		t.Fatalf("expected ErrUnsupportedFormat, got %v", err)
	}

	// Output directory inside bundle rejected
	bundleRootDir := dirAName(t)
	optsInside := DefaultInspectOptions()
	optsInside.InventoryOptions.OutputPath = filepath.Join(bundleRootDir, "sub-out")
	if err := inventory.ValidateOutputOutsideBundle(bundleRootDir, optsInside.InventoryOptions.OutputPath); !errors.Is(err, inventory.ErrOutputInsideBundle) {
		t.Fatalf("expected ErrOutputInsideBundle, got %v", err)
	}

	// Comprehensive path syntax rejections (../, /abs, backslash, ./, //, trailing /, Windows drive prefixes, Windows reserved names)
	badPaths := []string{
		"../etc/passwd",
		"sub/../../etc/passwd",
		"/etc/passwd",
		`sub\config.json`,
		"./config.json",
		"sub//config.json",
		"config.json/",
		"config\x00.json",
		"C:/models/config.json",
		"D:config.json",
		"sub/CON",
		"CON.json",
		"sub/aux.txt",
		"PRN",
		"NUL.safetensors",
		"COM1.json",
		"sub/lpt9.bin",
		"trailing-dot./config.json",
		"trailing-space /config.json",
	}
	for _, bp := range badPaths {
		if _, err := inventory.NormalizeAndValidateRelPath(bp); !errors.Is(err, inventory.ErrInvalidRelativePath) {
			t.Fatalf("expected ErrInvalidRelativePath for %q, got %v", bp, err)
		}
	}

	// Symlinked bundle root rejected
	symRoot := filepath.Join(t.TempDir(), "symlink-root")
	if err := os.Symlink(dirSym, symRoot); err == nil {
		if _, err := Inspect(symRoot, DefaultInspectOptions()); !errors.Is(err, inventory.ErrSymlinkRejected) {
			t.Fatalf("expected ErrSymlinkRejected for symlinked bundle root, got %v", err)
		}
	}

	// Hard-linked file rejected
	dirHard := filepath.Join(t.TempDir(), "hardlink-bundle")
	writeSyntheticBundle(t, dirHard, 0x2A, baseTok, "LlamaForCausalLM", "", false)
	extTarget := filepath.Join(t.TempDir(), "external-target.txt")
	if err := os.WriteFile(extTarget, []byte("hardlinked content"), 0o600); err == nil {
		if err := os.Link(extTarget, filepath.Join(dirHard, "linked.txt")); err == nil {
			if _, err := Inspect(dirHard, DefaultInspectOptions()); !errors.Is(err, inventory.ErrHardLinkRejected) {
				t.Fatalf("expected ErrHardLinkRejected for hard-linked file, got %v", err)
			}
		}
	}

	// Duplicate path collision
	if err := inventory.CheckPathCollision([]string{"config.json", "config.json"}); !errors.Is(err, inventory.ErrPathCollision) {
		t.Fatalf("expected ErrPathCollision for duplicate path, got %v", err)
	}

	// FIFO special file rejected
	dirFIFO := filepath.Join(t.TempDir(), "fifo-bundle")
	writeSyntheticBundle(t, dirFIFO, 0x2A, baseTok, "LlamaForCausalLM", "", false)
	fifoPath := filepath.Join(dirFIFO, "named.pipe")
	if err := syscall.Mkfifo(fifoPath, 0o600); err == nil {
		if _, err := Inspect(dirFIFO, DefaultInspectOptions()); !errors.Is(err, inventory.ErrSpecialFileRejected) {
			t.Fatalf("expected ErrSpecialFileRejected for FIFO, got %v", err)
		}
	}
}

func dirAName(t *testing.T) string {
	t.Helper()
	d := filepath.Join(t.TempDir(), "bundle-root")
	_ = os.MkdirAll(d, 0o755)
	return d
}

func TestLoRARelationshipStates(t *testing.T) {
	baseTok := `{"version":"1.0","model":{"type":"BPE","vocab":{"<s>":0}}}`
	baseDir := filepath.Join(t.TempDir(), "base-model")
	writeSyntheticBundle(t, baseDir, 0x10, baseTok, "LlamaForCausalLM", "", false)
	baseRes, err := Inspect(baseDir, DefaultInspectOptions())
	if err != nil {
		t.Fatalf("Inspect base: %v", err)
	}
	if baseRes.Manifest.LoRARelationship.VerificationStatus != peft.StatusNone {
		t.Fatalf("expected StatusNone for pure base model, got %s", baseRes.Manifest.LoRARelationship.VerificationStatus)
	}

	loraDir := filepath.Join(t.TempDir(), "lora-bundle")
	writeSyntheticBundle(t, loraDir, 0x10, baseTok, "LlamaForCausalLM", "8", false)

	// DECLARED_UNVERIFIED when no base bundle is provided
	loraUnverified, err := Inspect(loraDir, DefaultInspectOptions())
	if err != nil {
		t.Fatalf("Inspect lora unverified: %v", err)
	}
	if loraUnverified.Manifest.LoRARelationship.VerificationStatus != peft.StatusDeclaredUnverified {
		t.Fatalf("expected DECLARED_UNVERIFIED, got %s", loraUnverified.Manifest.LoRARelationship.VerificationStatus)
	}

	// VERIFIED when matching base bundle is provided
	optsVerified := DefaultInspectOptions()
	optsVerified.BaseBundlePath = baseDir
	optsVerified.ExpectedBaseBundleID = baseRes.BundleID
	loraVerified, err := Inspect(loraDir, optsVerified)
	if err != nil {
		t.Fatalf("Inspect lora verified: %v", err)
	}
	if loraVerified.Manifest.LoRARelationship.VerificationStatus != peft.StatusVerified {
		t.Fatalf("expected VERIFIED, got %s", loraVerified.Manifest.LoRARelationship.VerificationStatus)
	}

	// MISMATCH when wrong expected base bundle ID is provided
	optsMismatch := DefaultInspectOptions()
	optsMismatch.BaseBundlePath = baseDir
	optsMismatch.ExpectedBaseBundleID = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	loraMismatch, err := Inspect(loraDir, optsMismatch)
	if err != nil {
		t.Fatalf("Inspect lora mismatch: %v", err)
	}
	if loraMismatch.Manifest.LoRARelationship.VerificationStatus != peft.StatusMismatch {
		t.Fatalf("expected MISMATCH, got %s", loraMismatch.Manifest.LoRARelationship.VerificationStatus)
	}
}
