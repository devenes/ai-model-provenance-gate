// Package identity implements RFC 8785 (JCS) canonical JSON serialization and deterministic
// Model Bundle Identity (bundle-identity/v1) derivation.
package identity

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"unicode/utf16"

	"github.com/devenes/ai-model-provenance-gate/internal/digest"
	"github.com/devenes/ai-model-provenance-gate/internal/inventory"
	"github.com/devenes/ai-model-provenance-gate/internal/version"
)

// CanonicalFileEntry is the canonical file descriptor inside bundle-identity/v1.
type CanonicalFileEntry struct {
	Path   string                  `json:"path"`
	Role   inventory.ComponentRole `json:"role"`
	SHA256 string                  `json:"sha256"`
	Size   int64                   `json:"size"`
}

// CanonicalDocument is the exact RFC 8785 canonical input for deriving a Model Bundle Identity.
type CanonicalDocument struct {
	Files         []CanonicalFileEntry `json:"files"`
	SchemaVersion string               `json:"schema_version"`
}

// Result contains the computed deterministic Model Bundle Identity and its canonical JCS bytes.
type Result struct {
	SchemaVersion string            `json:"schema_version"`
	BundleID      string            `json:"bundle_id"`
	CanonicalJSON []byte            `json:"-"`
	Document      CanonicalDocument `json:"document"`
}

// Compute derives the deterministic bundle-identity/v1 digest from an Inventory.
func Compute(inv inventory.Inventory) (Result, error) {
	if len(inv.Files) == 0 {
		return Result{}, inventory.ErrEmptyBundle
	}

	files := make([]CanonicalFileEntry, len(inv.Files))
	for i, f := range inv.Files {
		if err := digest.Validate(f.SHA256); err != nil {
			return Result{}, fmt.Errorf("invalid digest for %q: %w", f.Path, err)
		}
		files[i] = CanonicalFileEntry{
			Path:   f.Path,
			Role:   f.Role,
			SHA256: f.SHA256,
			Size:   f.Size,
		}
	}

	// Ensure deterministic path ordering regardless of caller order.
	sort.Slice(files, func(i, j int) bool {
		return files[i].Path < files[j].Path
	})

	doc := CanonicalDocument{
		Files:         files,
		SchemaVersion: version.BundleIdentitySchemaVersion,
	}

	canonicalBytes, err := CanonicalizeStruct(doc)
	if err != nil {
		return Result{}, fmt.Errorf("canonicalize bundle identity document: %w", err)
	}

	bundleID := digest.ComputeBytes(canonicalBytes)
	return Result{
		SchemaVersion: version.BundleIdentitySchemaVersion,
		BundleID:      bundleID,
		CanonicalJSON: canonicalBytes,
		Document:      doc,
	}, nil
}

// CanonicalizeStruct marshals v to JSON and transforms it into RFC 8785 (JCS) canonical JSON bytes.
func CanonicalizeStruct(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return CanonicalizeJSON(raw)
}

// CanonicalizeJSON transforms arbitrary valid UTF-8 JSON bytes into RFC 8785 (JCS) canonical bytes.
func CanonicalizeJSON(raw []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var val any
	if err := dec.Decode(&val); err != nil {
		return nil, fmt.Errorf("decode JSON for canonicalization: %w", err)
	}
	var buf bytes.Buffer
	if err := writeCanonicalValue(&buf, val); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeCanonicalValue(buf *bytes.Buffer, v any) error {
	switch val := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if val {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		writeCanonicalString(buf, val)
	case json.Number:
		s := val.String()
		if i, err := strconv.ParseInt(s, 10, 64); err == nil {
			buf.WriteString(strconv.FormatInt(i, 10))
			return nil
		}
		f, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return fmt.Errorf("invalid JSON number %q: %w", s, err)
		}
		if f == 0 {
			buf.WriteString("0")
			return nil
		}
		buf.WriteString(strconv.FormatFloat(f, 'g', -1, 64))
	case []any:
		buf.WriteByte('[')
		for i, elem := range val {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonicalValue(buf, elem); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		// RFC 8785 Section 3.2.3: Sort object properties lexicographically by UTF-16 code units.
		sort.Slice(keys, func(i, j int) bool {
			return compareUTF16(keys[i], keys[j]) < 0
		})
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeCanonicalString(buf, k)
			buf.WriteByte(':')
			if err := writeCanonicalValue(buf, val[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("unsupported JSON value type %T", v)
	}
	return nil
}

// writeCanonicalString encodes a UTF-8 string per RFC 8785 Section 3.2.2.2 (without HTML escaping).
func writeCanonicalString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			if r < 0x20 {
				_, _ = fmt.Fprintf(buf, `\u%04x`, r)
			} else {
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
}

func compareUTF16(a, b string) int {
	ua := utf16.Encode([]rune(a))
	ub := utf16.Encode([]rune(b))
	minLen := len(ua)
	if len(ub) < minLen {
		minLen = len(ub)
	}
	for i := 0; i < minLen; i++ {
		if ua[i] < ub[i] {
			return -1
		}
		if ua[i] > ub[i] {
			return 1
		}
	}
	if len(ua) < len(ub) {
		return -1
	}
	if len(ua) > len(ub) {
		return 1
	}
	return 0
}
