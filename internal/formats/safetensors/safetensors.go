// Package safetensors provides safe static inspection of Safetensors binary headers and shard index files
// without loading model weights into memory or executing untrusted code.
package safetensors

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"
)

const (
	// DefaultMaxHeaderBytes caps the Safetensors JSON header at 100 MiB (matching official specification).
	DefaultMaxHeaderBytes uint64 = 100 * 1024 * 1024
	// DefaultMaxIndexBytes caps model.safetensors.index.json at 32 MiB.
	DefaultMaxIndexBytes int64 = 32 * 1024 * 1024
)

var (
	// ErrInvalidHeader is returned when a Safetensors file header is malformed or truncated.
	ErrInvalidHeader = errors.New("invalid safetensors binary header")
	// ErrHeaderTooLarge is returned when the 8-byte header size exceeds MaxHeaderBytes.
	ErrHeaderTooLarge = errors.New("safetensors header exceeds maximum allowed byte size")
	// ErrDisguisedFormat is returned when a file with .safetensors extension starts with Pickle or ZIP magic bytes.
	ErrDisguisedFormat = errors.New("disguised pickle or archive magic bytes detected in safetensors file")
	// ErrInvalidTensorOffsets is returned when tensor data_offsets are out-of-bounds, overlapping, or incomplete.
	ErrInvalidTensorOffsets = errors.New("invalid safetensors tensor data_offsets")
	// ErrInvalidShardIndex is returned when a safetensors shard index file is malformed or inconsistent with shards.
	ErrInvalidShardIndex = errors.New("invalid safetensors shard index")
)

// dtypeByteSizes maps official Safetensors dtype identifiers to their element size in bytes.
var dtypeByteSizes = map[string]int64{
	"BOOL":    1,
	"U8":      1,
	"I8":      1,
	"F8_E5M2": 1,
	"F8_E4M3": 1,
	"I16":     2,
	"U16":     2,
	"F16":     2,
	"BF16":    2,
	"I32":     4,
	"U32":     4,
	"F32":     4,
	"F64":     8,
	"I64":     8,
	"U64":     8,
	"C64":     8,
}

// TensorDescriptor represents a single tensor entry inside a Safetensors JSON header.
type TensorDescriptor struct {
	Name        string   `json:"name"`
	DType       string   `json:"dtype"`
	Shape       []int64  `json:"shape"`
	DataOffsets [2]int64 `json:"data_offsets"`
	ByteLength  int64    `json:"byte_length"`
}

// FileInspection summarizes the static inspection of a single .safetensors file.
type FileInspection struct {
	Path        string             `json:"path"`
	FileSize    int64              `json:"file_size"`
	HeaderBytes uint64             `json:"header_bytes"`
	DataBytes   int64              `json:"data_bytes"`
	TensorCount int                `json:"tensor_count"`
	DTypes      []string           `json:"dtypes"`
	Metadata    map[string]string  `json:"metadata,omitempty"`
	Tensors     []TensorDescriptor `json:"tensors,omitempty"`
}

// ShardIndex represents a parsed model.safetensors.index.json or adapter_model.safetensors.index.json file.
type ShardIndex struct {
	Path       string            `json:"path"`
	TotalSize  int64             `json:"total_size,omitempty"`
	WeightMap  map[string]string `json:"weight_map"`
	ShardFiles []string          `json:"shard_files"`
}

// InspectFile performs static validation of a .safetensors file header without reading tensor data into memory.
func InspectFile(path string, relPath string, maxHeaderBytes uint64) (FileInspection, error) {
	if maxHeaderBytes == 0 {
		maxHeaderBytes = DefaultMaxHeaderBytes
	}

	f, err := os.Open(path)
	if err != nil {
		return FileInspection{}, fmt.Errorf("open safetensors %q: %w", relPath, err)
	}
	defer func() {
		_ = f.Close()
	}()

	st, err := f.Stat()
	if err != nil {
		return FileInspection{}, fmt.Errorf("stat safetensors %q: %w", relPath, err)
	}
	fileSize := st.Size()
	if fileSize < 8 {
		return FileInspection{}, fmt.Errorf("%w: %q is only %d bytes (< 8 bytes)", ErrInvalidHeader, relPath, fileSize)
	}

	var lenBuf [8]byte
	if _, err := io.ReadFull(f, lenBuf[:]); err != nil {
		return FileInspection{}, fmt.Errorf("%w: read header length of %q: %v", ErrInvalidHeader, relPath, err)
	}

	// Defense-in-depth: detect disguised Pickle (\x80\x02..\x80\x05) or ZIP/PyTorch (PK\x03\x04) magic bytes.
	if lenBuf[0] == 0x80 && lenBuf[1] >= 2 && lenBuf[1] <= 5 {
		return FileInspection{}, fmt.Errorf("%w: pickle protocol %d signature in %q", ErrDisguisedFormat, lenBuf[1], relPath)
	}
	if bytes.HasPrefix(lenBuf[:], []byte("PK\x03\x04")) || bytes.HasPrefix(lenBuf[:], []byte("PK\x05\x06")) {
		return FileInspection{}, fmt.Errorf("%w: zip archive signature in %q", ErrDisguisedFormat, relPath)
	}

	headerLen := binary.LittleEndian.Uint64(lenBuf[:])
	if headerLen == 0 {
		return FileInspection{}, fmt.Errorf("%w: zero header length in %q", ErrInvalidHeader, relPath)
	}
	if headerLen > maxHeaderBytes {
		return FileInspection{}, fmt.Errorf("%w: header length %d in %q exceeds limit %d", ErrHeaderTooLarge, headerLen, relPath, maxHeaderBytes)
	}
	if headerLen > uint64(fileSize-8) {
		return FileInspection{}, fmt.Errorf("%w: header length %d in %q exceeds file size %d", ErrInvalidHeader, headerLen, relPath, fileSize)
	}

	headerBytes := make([]byte, headerLen)
	if _, err := io.ReadFull(f, headerBytes); err != nil {
		return FileInspection{}, fmt.Errorf("%w: read header bytes of %q: %v", ErrInvalidHeader, relPath, err)
	}
	if !utf8.Valid(headerBytes) {
		return FileInspection{}, fmt.Errorf("%w: header in %q is not valid UTF-8", ErrInvalidHeader, relPath)
	}
	trimmed := bytes.TrimLeft(headerBytes, " \t\r\n")
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return FileInspection{}, fmt.Errorf("%w: header in %q does not start with JSON object", ErrInvalidHeader, relPath)
	}

	var rawMap map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(headerBytes))
	dec.UseNumber()
	if err := dec.Decode(&rawMap); err != nil {
		return FileInspection{}, fmt.Errorf("%w: decode JSON header in %q: %v", ErrInvalidHeader, relPath, err)
	}

	dataRegionSize := fileSize - 8 - int64(headerLen)
	metadata := make(map[string]string)
	var tensors []TensorDescriptor
	dtypeSet := make(map[string]struct{})

	for key, rawVal := range rawMap {
		if key == "__metadata__" {
			var metaMap map[string]string
			if err := json.Unmarshal(rawVal, &metaMap); err != nil {
				return FileInspection{}, fmt.Errorf("%w: __metadata__ in %q must be map[string]string: %v", ErrInvalidHeader, relPath, err)
			}
			for mk, mv := range metaMap {
				metadata[mk] = mv
			}
			continue
		}

		var entry struct {
			DType       string  `json:"dtype"`
			Shape       []int64 `json:"shape"`
			DataOffsets []int64 `json:"data_offsets"`
		}
		entryDec := json.NewDecoder(bytes.NewReader(rawVal))
		entryDec.DisallowUnknownFields()
		if err := entryDec.Decode(&entry); err != nil {
			return FileInspection{}, fmt.Errorf("%w: tensor %q in %q: %v", ErrInvalidHeader, key, relPath, err)
		}

		elemBytes, ok := dtypeByteSizes[entry.DType]
		if !ok {
			return FileInspection{}, fmt.Errorf("%w: unsupported dtype %q for tensor %q in %q", ErrInvalidHeader, entry.DType, key, relPath)
		}
		if len(entry.DataOffsets) != 2 {
			return FileInspection{}, fmt.Errorf("%w: tensor %q in %q must have 2 data_offsets", ErrInvalidTensorOffsets, key, relPath)
		}
		begin, end := entry.DataOffsets[0], entry.DataOffsets[1]
		if begin < 0 || end < begin || end > dataRegionSize {
			return FileInspection{}, fmt.Errorf(
				"%w: tensor %q offsets [%d, %d] out of bounds (data region %d) in %q",
				ErrInvalidTensorOffsets, key, begin, end, dataRegionSize, relPath,
			)
		}

		expectedElems := int64(1)
		for _, dim := range entry.Shape {
			if dim < 0 {
				return FileInspection{}, fmt.Errorf("%w: negative dimension %d in tensor %q of %q", ErrInvalidHeader, dim, key, relPath)
			}
			if dim == 0 {
				expectedElems = 0
				break
			}
			// Overflow guard
			if expectedElems > (1<<62)/dim {
				return FileInspection{}, fmt.Errorf("%w: dimension overflow in tensor %q of %q", ErrInvalidHeader, key, relPath)
			}
			expectedElems *= dim
		}
		expectedBytes := expectedElems * elemBytes
		actualBytes := end - begin
		if expectedBytes != actualBytes {
			return FileInspection{}, fmt.Errorf(
				"%w: tensor %q in %q byte length %d != shape*dtype %d",
				ErrInvalidTensorOffsets, key, relPath, actualBytes, expectedBytes,
			)
		}

		dtypeSet[entry.DType] = struct{}{}
		tensors = append(tensors, TensorDescriptor{
			Name:        key,
			DType:       entry.DType,
			Shape:       entry.Shape,
			DataOffsets: [2]int64{begin, end},
			ByteLength:  actualBytes,
		})
	}

	// Verify tensor offset contiguity and absence of overlaps/gaps across the data buffer.
	sort.Slice(tensors, func(i, j int) bool {
		if tensors[i].DataOffsets[0] == tensors[j].DataOffsets[0] {
			return tensors[i].Name < tensors[j].Name
		}
		return tensors[i].DataOffsets[0] < tensors[j].DataOffsets[0]
	})
	var cursor int64
	for _, td := range tensors {
		if td.DataOffsets[0] != cursor {
			return FileInspection{}, fmt.Errorf(
				"%w: tensor %q starts at %d, expected contiguous offset %d in %q",
				ErrInvalidTensorOffsets, td.Name, td.DataOffsets[0], cursor, relPath,
			)
		}
		cursor = td.DataOffsets[1]
	}
	if cursor != dataRegionSize {
		return FileInspection{}, fmt.Errorf(
			"%w: tensors in %q end at offset %d, but data buffer size is %d (trailing/unaccounted bytes)",
			ErrInvalidTensorOffsets, relPath, cursor, dataRegionSize,
		)
	}

	// Sort tensors by name for deterministic manifest output.
	sort.Slice(tensors, func(i, j int) bool {
		return tensors[i].Name < tensors[j].Name
	})

	dtypes := make([]string, 0, len(dtypeSet))
	for dt := range dtypeSet {
		dtypes = append(dtypes, dt)
	}
	sort.Strings(dtypes)

	return FileInspection{
		Path:        relPath,
		FileSize:    fileSize,
		HeaderBytes: headerLen,
		DataBytes:   dataRegionSize,
		TensorCount: len(tensors),
		DTypes:      dtypes,
		Metadata:    metadata,
		Tensors:     tensors,
	}, nil
}

// InspectIndexFile parses a model.safetensors.index.json file safely.
func InspectIndexFile(path string, relPath string, maxBytes int64) (ShardIndex, error) {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxIndexBytes
	}
	st, err := os.Stat(path)
	if err != nil {
		return ShardIndex{}, fmt.Errorf("stat index %q: %w", relPath, err)
	}
	if st.Size() > maxBytes {
		return ShardIndex{}, fmt.Errorf("%w: %q size %d exceeds limit %d", ErrInvalidShardIndex, relPath, st.Size(), maxBytes)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return ShardIndex{}, fmt.Errorf("read index %q: %w", relPath, err)
	}

	var parsed struct {
		Metadata  map[string]any    `json:"metadata"`
		WeightMap map[string]string `json:"weight_map"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&parsed); err != nil {
		return ShardIndex{}, fmt.Errorf("%w: parse %q: %v", ErrInvalidShardIndex, relPath, err)
	}
	if len(parsed.WeightMap) == 0 {
		return ShardIndex{}, fmt.Errorf("%w: %q has empty weight_map", ErrInvalidShardIndex, relPath)
	}

	indexDir := filepath.Dir(relPath)
	if indexDir == "." {
		indexDir = ""
	}
	shardSet := make(map[string]struct{})
	normalizedWeightMap := make(map[string]string, len(parsed.WeightMap))
	for tensorName, shardFile := range parsed.WeightMap {
		cleanShard := filepath.ToSlash(filepath.Clean(shardFile))
		if strings.HasPrefix(cleanShard, "../") || strings.HasPrefix(cleanShard, "/") || cleanShard == ".." {
			return ShardIndex{}, fmt.Errorf("%w: invalid shard path %q in %q", ErrInvalidShardIndex, shardFile, relPath)
		}
		if indexDir != "" {
			cleanShard = indexDir + "/" + cleanShard
		}
		shardSet[cleanShard] = struct{}{}
		normalizedWeightMap[tensorName] = cleanShard
	}

	shards := make([]string, 0, len(shardSet))
	for s := range shardSet {
		shards = append(shards, s)
	}
	sort.Strings(shards)

	var totalSize int64
	if parsed.Metadata != nil {
		if ts, ok := parsed.Metadata["total_size"].(float64); ok && ts > 0 {
			totalSize = int64(ts)
		}
	}

	return ShardIndex{
		Path:       relPath,
		TotalSize:  totalSize,
		WeightMap:  normalizedWeightMap,
		ShardFiles: shards,
	}, nil
}

// VerifyIndexConsistency checks that every shard file referenced by an index exists in inspectedFiles
// and contains the mapped tensor names.
func VerifyIndexConsistency(idx ShardIndex, inspectedByPath map[string]FileInspection) error {
	for _, shardPath := range idx.ShardFiles {
		if _, ok := inspectedByPath[shardPath]; !ok {
			return fmt.Errorf("%w: index %q references missing shard %q", ErrInvalidShardIndex, idx.Path, shardPath)
		}
	}
	for tensorName, shardPath := range idx.WeightMap {
		insp := inspectedByPath[shardPath]
		found := false
		for _, td := range insp.Tensors {
			if td.Name == tensorName {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf(
				"%w: index %q maps tensor %q to shard %q, but tensor is missing from shard header",
				ErrInvalidShardIndex, idx.Path, tensorName, shardPath,
			)
		}
	}
	return nil
}

// SyntheticTensor describes a tensor for building deterministic synthetic .safetensors test fixtures.
type SyntheticTensor struct {
	Name  string
	DType string
	Shape []int64
	Data  []byte
}

// BuildSyntheticSafetensors serializes a valid, deterministic .safetensors binary payload for testing.
func BuildSyntheticSafetensors(tensors []SyntheticTensor, metadata map[string]string) ([]byte, error) {
	headerObj := make(map[string]any)
	if len(metadata) > 0 {
		headerObj["__metadata__"] = metadata
	}
	var dataBuf bytes.Buffer
	var offset int64
	for _, t := range tensors {
		elemSize, ok := dtypeByteSizes[t.DType]
		if !ok {
			return nil, fmt.Errorf("unsupported dtype %q", t.DType)
		}
		expected := elemSize
		for _, d := range t.Shape {
			expected *= d
		}
		data := t.Data
		if len(data) == 0 && expected > 0 {
			data = bytes.Repeat([]byte{0x01}, int(expected))
		}
		if int64(len(data)) != expected {
			return nil, fmt.Errorf("tensor %q data len %d != expected %d", t.Name, len(data), expected)
		}
		start := offset
		end := offset + expected
		offset = end
		_, _ = dataBuf.Write(data)
		headerObj[t.Name] = map[string]any{
			"dtype":        t.DType,
			"shape":        t.Shape,
			"data_offsets": []int64{start, end},
		}
	}

	headerJSON, err := json.Marshal(headerObj)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	var lenBuf [8]byte
	binary.LittleEndian.PutUint64(lenBuf[:], uint64(len(headerJSON)))
	_, _ = out.Write(lenBuf[:])
	_, _ = out.Write(headerJSON)
	_, _ = out.Write(dataBuf.Bytes())
	return out.Bytes(), nil
}
