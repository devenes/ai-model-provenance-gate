// Package inventory implements safe model bundle traversal, path normalization, collision detection,
// component classification, and streaming SHA-256 hashing.
package inventory

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"

	"github.com/devenes/ai-model-provenance-gate/internal/digest"
	"github.com/devenes/ai-model-provenance-gate/internal/formats/huggingface"
)

// ComponentRole classifies the role of a file inside a model bundle.
type ComponentRole string

const (
	RoleModelConfig          ComponentRole = "model_config"
	RoleGenerationConfig     ComponentRole = "generation_config"
	RoleModelWeights         ComponentRole = "model_weights"
	RoleWeightShard          ComponentRole = "weight_shard"
	RoleWeightIndex          ComponentRole = "weight_index"
	RoleTokenizerConfig      ComponentRole = "tokenizer_config"
	RoleTokenizerVocab       ComponentRole = "tokenizer_vocab"
	RoleSpecialTokens        ComponentRole = "special_tokens"
	RoleChatTemplate         ComponentRole = "chat_template"
	RoleLoRAConfig           ComponentRole = "lora_config"
	RoleLoRAWeights          ComponentRole = "lora_weights"
	RoleLoRAIndex            ComponentRole = "lora_index"
	RoleQuantizationConfig   ComponentRole = "quantization_config"
	RoleLicense              ComponentRole = "license"
	RoleDocumentation        ComponentRole = "documentation"
	RoleUnsafePickleArtifact ComponentRole = "unsafe_pickle_artifact"
	RoleUnknownFile          ComponentRole = "unknown_file"
)

var (
	// ErrEmptyBundle is returned when a model bundle directory contains zero files.
	ErrEmptyBundle = errors.New("model bundle directory contains no regular files")
	// ErrSymlinkRejected is returned when a symbolic link is encountered inside the bundle.
	ErrSymlinkRejected = errors.New("symbolic link encountered in model bundle")
	// ErrHardLinkRejected is returned when a hard-linked regular file (nlink > 1) is encountered inside the bundle.
	ErrHardLinkRejected = errors.New("hard-linked file encountered in model bundle")
	// ErrSpecialFileRejected is returned when a FIFO, socket, device, or irregular file is encountered.
	ErrSpecialFileRejected = errors.New("unsupported non-regular file encountered in model bundle")
	// ErrInvalidRelativePath is returned when a path is invalid UTF-8, contains control characters, or traverses upward.
	ErrInvalidRelativePath = errors.New("invalid or unsafe relative file path")
	// ErrPathCollision is returned when two files collide after Unicode NFC normalization or case folding.
	ErrPathCollision = errors.New("normalized path collision detected in model bundle")
	// ErrOutputInsideBundle is returned when the requested output directory resides inside the inspected bundle root.
	ErrOutputInsideBundle = errors.New("output path must reside outside the inspected model bundle root")

	shardFilePattern     = regexp.MustCompile(`(?i)^model-[0-9]{5}-of-[0-9]{5}\.safetensors$`)
	loraShardFilePattern = regexp.MustCompile(`(?i)^adapter_model-[0-9]{5}-of-[0-9]{5}\.safetensors$`)
)

// FileEntry represents a single verified regular file in the model bundle inventory.
type FileEntry struct {
	Path               string        `json:"path"`
	Size               int64         `json:"size"`
	SHA256             string        `json:"sha256"`
	Role               ComponentRole `json:"role"`
	MetadataProvenance string        `json:"metadata_provenance"`
}

// Options configures bundle traversal and hashing rules.
type Options struct {
	// RejectSymlinks rejects any symbolic link in or at the bundle root (default true).
	RejectSymlinks bool
	// OutputPath, if non-empty, is checked to ensure it does not reside inside BundleRoot.
	OutputPath string
	// MaxFileBytes optionally caps individual file size (0 = unlimited).
	MaxFileBytes int64
	// ReverseEnumerationOrder reverses directory read order (used in tests to prove enumeration independence).
	ReverseEnumerationOrder bool
	// OnChunkRead is forwarded to digest.StreamFile for TOCTOU testing.
	OnChunkRead func(relPath string, bytesRead int64) error
}

// DefaultOptions returns the strict default traversal options.
func DefaultOptions() Options {
	return Options{
		RejectSymlinks: true,
	}
}

// Inventory holds the complete sorted file inventory of a model bundle.
type Inventory struct {
	RootPath   string                `json:"-"`
	Files      []FileEntry           `json:"files"`
	TotalBytes int64                 `json:"total_bytes"`
	FileCount  int                   `json:"file_count"`
	RoleCounts map[ComponentRole]int `json:"role_counts"`
}

// ValidateOutputOutsideBundle ensures that outputPath is not inside or equal to bundleRoot.
func ValidateOutputOutsideBundle(bundleRoot string, outputPath string) error {
	if strings.TrimSpace(outputPath) == "" {
		return nil
	}
	absBundle, err := resolveCanonicalPath(bundleRoot)
	if err != nil {
		return fmt.Errorf("resolve bundle path: %w", err)
	}
	absOut, err := resolveCanonicalPath(outputPath)
	if err != nil {
		return fmt.Errorf("resolve output path: %w", err)
	}
	rel, err := filepath.Rel(absBundle, absOut)
	if err == nil {
		cleanRel := filepath.ToSlash(filepath.Clean(rel))
		if cleanRel == "." || (!strings.HasPrefix(cleanRel, "../") && cleanRel != "..") {
			return fmt.Errorf("%w: output %q is inside bundle %q", ErrOutputInsideBundle, outputPath, bundleRoot)
		}
	}
	return nil
}

func resolveCanonicalPath(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	if realP, evalErr := filepath.EvalSymlinks(abs); evalErr == nil {
		return realP, nil
	}
	// If the leaf path does not exist yet, resolve symlinks on the nearest existing ancestor.
	cur := abs
	var tail []string
	for {
		parent := filepath.Dir(cur)
		base := filepath.Base(cur)
		tail = append([]string{base}, tail...)
		if realParent, evalErr := filepath.EvalSymlinks(parent); evalErr == nil {
			elems := append([]string{realParent}, tail...)
			return filepath.Join(elems...), nil
		}
		if parent == cur {
			return abs, nil
		}
		cur = parent
	}
}

// NormalizeAndValidateRelPath validates a relative path and normalizes it to POSIX slashes and Unicode NFC.
func NormalizeAndValidateRelPath(rel string) (string, error) {
	if rel == "" {
		return "", fmt.Errorf("%w: empty relative path", ErrInvalidRelativePath)
	}
	if !utf8.ValidString(rel) {
		return "", fmt.Errorf("%w: non-UTF8 path %q", ErrInvalidRelativePath, rel)
	}
	for _, r := range rel {
		if r < 0x20 || r == 0x7f {
			return "", fmt.Errorf("%w: control character in path %q", ErrInvalidRelativePath, rel)
		}
	}
	if strings.ContainsRune(rel, '\\') {
		return "", fmt.Errorf("%w: backslash separator not allowed in path %q", ErrInvalidRelativePath, rel)
	}
	if strings.ContainsRune(rel, ':') {
		return "", fmt.Errorf("%w: colon or Windows drive prefix not allowed in path %q", ErrInvalidRelativePath, rel)
	}
	if strings.HasPrefix(rel, "/") {
		return "", fmt.Errorf("%w: absolute path %q not allowed", ErrInvalidRelativePath, rel)
	}
	segments := strings.Split(rel, "/")
	for _, seg := range segments {
		if seg == "" || seg == "." || seg == ".." {
			return "", fmt.Errorf("%w: invalid path segment %q in %q", ErrInvalidRelativePath, seg, rel)
		}
		if strings.HasSuffix(seg, " ") || strings.HasSuffix(seg, ".") {
			return "", fmt.Errorf("%w: path segment %q cannot end with space or dot in %q", ErrInvalidRelativePath, seg, rel)
		}
		if isWindowsReservedDeviceName(seg) {
			return "", fmt.Errorf("%w: Windows reserved device name %q in %q", ErrInvalidRelativePath, seg, rel)
		}
	}
	cleaned := filepath.ToSlash(filepath.Clean(rel))
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") || strings.HasPrefix(cleaned, "/") {
		return "", fmt.Errorf("%w: path traversal in %q", ErrInvalidRelativePath, rel)
	}
	nfc := norm.NFC.String(cleaned)
	return nfc, nil
}

func isWindowsReservedDeviceName(seg string) bool {
	stem := seg
	if idx := strings.IndexByte(seg, '.'); idx >= 0 {
		stem = seg[:idx]
	}
	switch strings.ToUpper(stem) {
	case "CON", "PRN", "AUX", "NUL",
		"COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
		"LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9":
		return true
	default:
		return false
	}
}

// ClassifyFile deterministically classifies a normalized relative path into a ComponentRole.
func ClassifyFile(relPath string) ComponentRole {
	base := filepath.Base(relPath)
	lowerBase := strings.ToLower(base)

	if huggingface.IsUnsafePickleExtension(lowerBase) {
		return RoleUnsafePickleArtifact
	}

	switch lowerBase {
	case "config.json":
		return RoleModelConfig
	case "generation_config.json":
		return RoleGenerationConfig
	case "model.safetensors":
		return RoleModelWeights
	case "model.safetensors.index.json":
		return RoleWeightIndex
	case "adapter_config.json":
		return RoleLoRAConfig
	case "adapter_model.safetensors":
		return RoleLoRAWeights
	case "adapter_model.safetensors.index.json":
		return RoleLoRAIndex
	case "tokenizer_config.json":
		return RoleTokenizerConfig
	case "tokenizer.json", "tokenizer.model", "vocab.json", "vocab.txt", "merges.txt", "spiece.model", "added_tokens.json":
		return RoleTokenizerVocab
	case "special_tokens_map.json":
		return RoleSpecialTokens
	case "chat_template.jinja", "chat_template.json", "chat_template.txt":
		return RoleChatTemplate
	case "quantization_config.json", "quantize_config.json":
		return RoleQuantizationConfig
	case "license", "license.txt", "license.md", "notice", "notice.txt":
		return RoleLicense
	case "readme.md", "readme.txt", "model_card.md":
		return RoleDocumentation
	}

	if shardFilePattern.MatchString(base) {
		return RoleWeightShard
	}
	if loraShardFilePattern.MatchString(base) {
		return RoleLoRAWeights
	}
	if strings.HasSuffix(lowerBase, ".safetensors") {
		if strings.Contains(lowerBase, "adapter") || strings.Contains(lowerBase, "lora") {
			return RoleLoRAWeights
		}
		return RoleModelWeights
	}
	if strings.HasSuffix(lowerBase, ".jinja") {
		return RoleChatTemplate
	}

	return RoleUnknownFile
}

// Build scans bundleRoot, validates filesystem safety, streams SHA-256 digests, and returns a deterministically sorted Inventory.
func Build(bundleRoot string, opts Options) (Inventory, error) {
	if strings.TrimSpace(bundleRoot) == "" {
		return Inventory{}, errors.New("bundle root path is required")
	}
	if err := ValidateOutputOutsideBundle(bundleRoot, opts.OutputPath); err != nil {
		return Inventory{}, err
	}

	absRoot, err := filepath.Abs(bundleRoot)
	if err != nil {
		return Inventory{}, fmt.Errorf("resolve bundle root %q: %w", bundleRoot, err)
	}

	rootInfo, err := os.Lstat(absRoot)
	if err != nil {
		return Inventory{}, fmt.Errorf("lstat bundle root %q: %w", bundleRoot, err)
	}
	if rootInfo.Mode()&fs.ModeSymlink != 0 {
		if opts.RejectSymlinks {
			return Inventory{}, fmt.Errorf("%w: bundle root %q is a symbolic link", ErrSymlinkRejected, bundleRoot)
		}
	}
	if !rootInfo.IsDir() {
		return Inventory{}, fmt.Errorf("bundle root %q is not a directory", bundleRoot)
	}

	var entries []FileEntry
	seenNFC := make(map[string]string)
	seenFolded := make(map[string]string)

	var walkDir func(currentAbs string, currentRel string) error
	walkDir = func(currentAbs string, currentRel string) error {
		dirEntries, readErr := os.ReadDir(currentAbs)
		if readErr != nil {
			return fmt.Errorf("readdir %q: %w", currentRel, readErr)
		}
		if opts.ReverseEnumerationOrder {
			for i, j := 0, len(dirEntries)-1; i < j; i, j = i+1, j-1 {
				dirEntries[i], dirEntries[j] = dirEntries[j], dirEntries[i]
			}
		}

		for _, de := range dirEntries {
			name := de.Name()
			childRel := name
			if currentRel != "" {
				childRel = currentRel + "/" + name
			}
			childAbs := filepath.Join(currentAbs, name)

			info, lstatErr := os.Lstat(childAbs)
			if lstatErr != nil {
				return fmt.Errorf("lstat %q: %w", childRel, lstatErr)
			}

			mode := info.Mode()
			if mode&fs.ModeSymlink != 0 {
				if opts.RejectSymlinks {
					return fmt.Errorf("%w: %q", ErrSymlinkRejected, childRel)
				}
				continue
			}

			normRel, normErr := NormalizeAndValidateRelPath(childRel)
			if normErr != nil {
				return normErr
			}

			if prevRaw, exists := seenNFC[normRel]; exists {
				return fmt.Errorf("%w: %q and %q normalize to %q", ErrPathCollision, prevRaw, childRel, normRel)
			}
			seenNFC[normRel] = childRel

			folded := strings.ToLower(normRel)
			if prevRaw, exists := seenFolded[folded]; exists {
				return fmt.Errorf("%w: case-folding collision between %q and %q", ErrPathCollision, prevRaw, childRel)
			}
			seenFolded[folded] = childRel

			if mode.IsDir() {
				if err := walkDir(childAbs, normRel); err != nil {
					return err
				}
				continue
			}

			if !mode.IsRegular() {
				return fmt.Errorf("%w: %q has mode %s", ErrSpecialFileRejected, normRel, mode.String())
			}
			if opts.RejectSymlinks && isHardLinkedFile(info) {
				return fmt.Errorf("%w: %q has multiple hard links (nlink > 1)", ErrHardLinkRejected, normRel)
			}

			var chunkHook func(int64) error
			if opts.OnChunkRead != nil {
				relCopy := normRel
				chunkHook = func(n int64) error {
					return opts.OnChunkRead(relCopy, n)
				}
			}

			fd, hashErr := digest.StreamFile(childAbs, digest.StreamOptions{
				MaxBytes:    opts.MaxFileBytes,
				OnChunkRead: chunkHook,
			})
			if hashErr != nil {
				return fmt.Errorf("hash %q: %w", normRel, hashErr)
			}

			entries = append(entries, FileEntry{
				Path:               normRel,
				Size:               fd.Size,
				SHA256:             fd.SHA256,
				Role:               ClassifyFile(normRel),
				MetadataProvenance: "observed",
			})
		}
		return nil
	}

	if err := walkDir(absRoot, ""); err != nil {
		return Inventory{}, err
	}

	if len(entries) == 0 {
		return Inventory{}, ErrEmptyBundle
	}

	// Deterministic lexicographical UTF-8 byte order sort by normalized relative path.
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Path < entries[j].Path
	})

	roleCounts := make(map[ComponentRole]int)
	var totalBytes int64
	for _, e := range entries {
		totalBytes += e.Size
		roleCounts[e.Role]++
	}

	return Inventory{
		RootPath:   absRoot,
		Files:      entries,
		TotalBytes: totalBytes,
		FileCount:  len(entries),
		RoleCounts: roleCounts,
	}, nil
}

// CheckPathCollision checks a candidate list of relative paths for NFC or case-folding collisions.
func CheckPathCollision(paths []string) error {
	seenNFC := make(map[string]string, len(paths))
	seenFolded := make(map[string]string, len(paths))
	for _, raw := range paths {
		normRel, err := NormalizeAndValidateRelPath(raw)
		if err != nil {
			return err
		}
		if prev, ok := seenNFC[normRel]; ok {
			return fmt.Errorf("%w: %q and %q normalize to %q", ErrPathCollision, prev, raw, normRel)
		}
		seenNFC[normRel] = raw

		folded := strings.ToLower(normRel)
		if prev, ok := seenFolded[folded]; ok {
			return fmt.Errorf("%w: case-folding collision between %q and %q", ErrPathCollision, prev, raw)
		}
		seenFolded[folded] = raw
	}
	return nil
}
