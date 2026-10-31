package safetensors

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestInspectValidSafetensorsAndShards(t *testing.T) {
	dir := t.TempDir()
	shard1Bytes, err := BuildSyntheticSafetensors([]SyntheticTensor{
		{Name: "model.embed_tokens.weight", DType: "F16", Shape: []int64{4, 4}},
	}, map[string]string{"format": "pt"})
	if err != nil {
		t.Fatalf("build shard1: %v", err)
	}
	shard2Bytes, err := BuildSyntheticSafetensors([]SyntheticTensor{
		{Name: "model.layers.0.weight", DType: "BF16", Shape: []int64{2, 4}},
	}, map[string]string{"format": "pt"})
	if err != nil {
		t.Fatalf("build shard2: %v", err)
	}

	s1Path := filepath.Join(dir, "model-00001-of-00002.safetensors")
	s2Path := filepath.Join(dir, "model-00002-of-00002.safetensors")
	if err := os.WriteFile(s1Path, shard1Bytes, 0o600); err != nil {
		t.Fatalf("write shard1: %v", err)
	}
	if err := os.WriteFile(s2Path, shard2Bytes, 0o600); err != nil {
		t.Fatalf("write shard2: %v", err)
	}

	i1, err := InspectFile(s1Path, "model-00001-of-00002.safetensors", 0)
	if err != nil {
		t.Fatalf("InspectFile s1: %v", err)
	}
	i2, err := InspectFile(s2Path, "model-00002-of-00002.safetensors", 0)
	if err != nil {
		t.Fatalf("InspectFile s2: %v", err)
	}

	indexJSON := `{
  "metadata": {"total_size": 48},
  "weight_map": {
    "model.embed_tokens.weight": "model-00001-of-00002.safetensors",
    "model.layers.0.weight": "model-00002-of-00002.safetensors"
  }
}`
	idxPath := filepath.Join(dir, "model.safetensors.index.json")
	if err := os.WriteFile(idxPath, []byte(indexJSON), 0o600); err != nil {
		t.Fatalf("write index: %v", err)
	}

	idx, err := InspectIndexFile(idxPath, "model.safetensors.index.json", 0)
	if err != nil {
		t.Fatalf("InspectIndexFile: %v", err)
	}
	byPath := map[string]FileInspection{
		i1.Path: i1,
		i2.Path: i2,
	}
	if err := VerifyIndexConsistency(idx, byPath); err != nil {
		t.Fatalf("VerifyIndexConsistency: %v", err)
	}

	// Missing shard detection
	delete(byPath, i2.Path)
	if err := VerifyIndexConsistency(idx, byPath); !errors.Is(err, ErrInvalidShardIndex) {
		t.Fatalf("expected ErrInvalidShardIndex for missing shard, got %v", err)
	}
}

func TestInspectRejectsDisguisedPickleAndOversizedHeader(t *testing.T) {
	dir := t.TempDir()
	pklPath := filepath.Join(dir, "evil.safetensors")
	// Pickle protocol 4 header (\x80\x04) padded to 16 bytes
	if err := os.WriteFile(pklPath, []byte("\x80\x04\x95\x05\x00\x00\x00\x00\x00\x00\x00cos\nsystem\n"), 0o600); err != nil {
		t.Fatalf("write pkl: %v", err)
	}
	if _, err := InspectFile(pklPath, "evil.safetensors", 0); !errors.Is(err, ErrDisguisedFormat) {
		t.Fatalf("expected ErrDisguisedFormat, got %v", err)
	}

	validBytes, err := BuildSyntheticSafetensors([]SyntheticTensor{
		{Name: "w", DType: "F32", Shape: []int64{2, 2}},
	}, nil)
	if err != nil {
		t.Fatalf("build valid: %v", err)
	}
	validPath := filepath.Join(dir, "valid.safetensors")
	if err := os.WriteFile(validPath, validBytes, 0o600); err != nil {
		t.Fatalf("write valid: %v", err)
	}
	if _, err := InspectFile(validPath, "valid.safetensors", 10); !errors.Is(err, ErrHeaderTooLarge) {
		t.Fatalf("expected ErrHeaderTooLarge, got %v", err)
	}
}

func writeRawSafetensorsHeaderAndData(t *testing.T, dir, name string, header []byte, data []byte) string {
	t.Helper()
	var buf bytes.Buffer
	var lenBuf [8]byte
	binary.LittleEndian.PutUint64(lenBuf[:], uint64(len(header)))
	_, _ = buf.Write(lenBuf[:])
	_, _ = buf.Write(header)
	_, _ = buf.Write(data)
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return p
}

func TestSafetensorsAdversarialHeadersAndOffsets(t *testing.T) {
	dir := t.TempDir()

	// 1. File < 8 bytes (truncated length prefix)
	shortPath := filepath.Join(dir, "short.safetensors")
	_ = os.WriteFile(shortPath, []byte{1, 2, 3}, 0o600)
	if _, err := InspectFile(shortPath, "short.safetensors", 0); !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("expected ErrInvalidHeader for <8 byte file, got %v", err)
	}

	// 2. Zero header length
	zeroLenPath := filepath.Join(dir, "zero.safetensors")
	_ = os.WriteFile(zeroLenPath, make([]byte, 16), 0o600)
	if _, err := InspectFile(zeroLenPath, "zero.safetensors", 0); !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("expected ErrInvalidHeader for zero header length, got %v", err)
	}

	// 3. Truncated header (headerLen > fileSize - 8)
	truncPath := filepath.Join(dir, "trunc.safetensors")
	var truncBuf [12]byte
	binary.LittleEndian.PutUint64(truncBuf[:8], 1024)
	_ = os.WriteFile(truncPath, truncBuf[:], 0o600)
	if _, err := InspectFile(truncPath, "trunc.safetensors", 0); !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("expected ErrInvalidHeader for truncated header, got %v", err)
	}

	// 4. Invalid UTF-8 in header
	badUTF8Path := writeRawSafetensorsHeaderAndData(t, dir, "badutf8.safetensors", []byte{'{', 0xff, 0xfe, '}'}, nil)
	if _, err := InspectFile(badUTF8Path, "badutf8.safetensors", 0); !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("expected ErrInvalidHeader for invalid UTF-8 header, got %v", err)
	}

	// 5. Non-object JSON header
	arrPath := writeRawSafetensorsHeaderAndData(t, dir, "array.safetensors", []byte(`[1, 2, 3]`), nil)
	if _, err := InspectFile(arrPath, "array.safetensors", 0); !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("expected ErrInvalidHeader for JSON array header, got %v", err)
	}

	// 6. Negative tensor offsets
	negOffsetPath := writeRawSafetensorsHeaderAndData(t, dir, "neg.safetensors",
		[]byte(`{"t1":{"dtype":"F32","shape":[1],"data_offsets":[-4,0]}}`), make([]byte, 4))
	if _, err := InspectFile(negOffsetPath, "neg.safetensors", 0); !errors.Is(err, ErrInvalidTensorOffsets) {
		t.Fatalf("expected ErrInvalidTensorOffsets for negative offset, got %v", err)
	}

	// 7. Overlapping tensor offsets
	overlapPath := writeRawSafetensorsHeaderAndData(t, dir, "overlap.safetensors",
		[]byte(`{"t1":{"dtype":"F32","shape":[2],"data_offsets":[0,8]},"t2":{"dtype":"F32","shape":[2],"data_offsets":[4,12]}}`),
		make([]byte, 12))
	if _, err := InspectFile(overlapPath, "overlap.safetensors", 0); !errors.Is(err, ErrInvalidTensorOffsets) {
		t.Fatalf("expected ErrInvalidTensorOffsets for overlapping tensors, got %v", err)
	}

	// 8. Gap between tensor offsets
	gapPath := writeRawSafetensorsHeaderAndData(t, dir, "gap.safetensors",
		[]byte(`{"t1":{"dtype":"F32","shape":[1],"data_offsets":[0,4]},"t2":{"dtype":"F32","shape":[1],"data_offsets":[8,12]}}`),
		make([]byte, 12))
	if _, err := InspectFile(gapPath, "gap.safetensors", 0); !errors.Is(err, ErrInvalidTensorOffsets) {
		t.Fatalf("expected ErrInvalidTensorOffsets for gap between tensors, got %v", err)
	}

	// 9. Trailing unaccounted bytes in data buffer
	trailingPath := writeRawSafetensorsHeaderAndData(t, dir, "trailing.safetensors",
		[]byte(`{"t1":{"dtype":"F32","shape":[1],"data_offsets":[0,4]}}`),
		make([]byte, 8))
	if _, err := InspectFile(trailingPath, "trailing.safetensors", 0); !errors.Is(err, ErrInvalidTensorOffsets) {
		t.Fatalf("expected ErrInvalidTensorOffsets for trailing bytes, got %v", err)
	}

	// 10. Integer overflow in shape product
	overflowPath := writeRawSafetensorsHeaderAndData(t, dir, "overflow.safetensors",
		[]byte(`{"t1":{"dtype":"F32","shape":[3037000500,3037000500],"data_offsets":[0,4]}}`),
		make([]byte, 4))
	if _, err := InspectFile(overflowPath, "overflow.safetensors", 0); !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("expected ErrInvalidHeader for shape product overflow, got %v", err)
	}

	// 11. Disguised ZIP archive header
	zipPath := filepath.Join(dir, "zip.safetensors")
	_ = os.WriteFile(zipPath, []byte("PK\x03\x04\x14\x00\x00\x00\x08\x00extra"), 0o600)
	if _, err := InspectFile(zipPath, "zip.safetensors", 0); !errors.Is(err, ErrDisguisedFormat) {
		t.Fatalf("expected ErrDisguisedFormat for ZIP header, got %v", err)
	}
}
