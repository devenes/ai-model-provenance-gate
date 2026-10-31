// Package digest provides streaming SHA-256 computation with TOCTOU concurrent mutation detection.
package digest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"regexp"
	"strings"
)

const (
	// Prefix is the standard digest algorithm prefix.
	Prefix = "sha256:"
	// DefaultBufferSize is the streaming read chunk size (64 KiB).
	DefaultBufferSize = 64 * 1024
)

var (
	// ErrConcurrentMutation is returned when a file changes size, mode, or mtime while being hashed.
	ErrConcurrentMutation = errors.New("concurrent file mutation detected during streaming digest (TOCTOU)")
	// ErrSymlinkRejected is returned when attempting to hash a symbolic link.
	ErrSymlinkRejected = errors.New("symbolic link rejected by digest engine")
	// ErrNonRegularFile is returned when attempting to hash a non-regular file.
	ErrNonRegularFile = errors.New("non-regular file rejected by digest engine")
	// ErrFileTooLarge is returned when a file exceeds the configured maximum byte limit.
	ErrFileTooLarge = errors.New("file exceeds maximum allowed byte limit")
	// ErrInvalidDigestFormat is returned when a digest string does not match sha256:<64-lowercase-hex>.
	ErrInvalidDigestFormat = errors.New("invalid sha256 digest format (expected sha256:<64-lowercase-hex>)")

	sha256Pattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// FileDigest holds the verified SHA-256 digest and observed size of a streamed file.
type FileDigest struct {
	SHA256 string `json:"sha256"`
	Hex    string `json:"hex"`
	Size   int64  `json:"size"`
}

// StreamOptions configures streaming SHA-256 behavior.
type StreamOptions struct {
	// MaxBytes is the optional maximum allowed file size (0 means unlimited).
	MaxBytes int64
	// BufferSize overrides the default 64 KiB read buffer size if > 0.
	BufferSize int
	// OnChunkRead is an optional hook invoked after each read chunk (used for deterministic TOCTOU testing).
	OnChunkRead func(bytesReadSoFar int64) error
}

// ComputeBytes computes the "sha256:<64-hex>" digest of an in-memory byte slice.
func ComputeBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return Prefix + hex.EncodeToString(sum[:])
}

// ComputeHexBytes computes the raw 64-character lowercase hex SHA-256 of data.
func ComputeHexBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// ComputeNormalizedText computes the "sha256:<64-hex>" digest after normalizing CRLF (\r\n) to LF (\n).
func ComputeNormalizedText(data []byte) string {
	normalized := bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
	return ComputeBytes(normalized)
}

// Validate checks whether s conforms to "sha256:<64-lowercase-hex>".
func Validate(s string) error {
	if !sha256Pattern.MatchString(s) {
		return fmt.Errorf("%w: %q", ErrInvalidDigestFormat, s)
	}
	return nil
}

// TrimPrefix returns the 64-character hex portion of a valid "sha256:<hex>" string.
func TrimPrefix(s string) (string, error) {
	if err := Validate(s); err != nil {
		return "", err
	}
	return strings.TrimPrefix(s, Prefix), nil
}

// StreamFile computes the SHA-256 digest of a regular file using bounded memory while verifying
// that the file is not a symlink and did not mutate during hashing.
func StreamFile(path string, opts StreamOptions) (FileDigest, error) {
	preLstat, err := os.Lstat(path)
	if err != nil {
		return FileDigest{}, fmt.Errorf("lstat %q before hashing: %w", path, err)
	}
	if preLstat.Mode()&fs.ModeSymlink != 0 {
		return FileDigest{}, fmt.Errorf("%w: %q", ErrSymlinkRejected, path)
	}
	if !preLstat.Mode().IsRegular() {
		return FileDigest{}, fmt.Errorf("%w: %q (mode %s)", ErrNonRegularFile, path, preLstat.Mode())
	}
	if opts.MaxBytes > 0 && preLstat.Size() > opts.MaxBytes {
		return FileDigest{}, fmt.Errorf("%w: %q has size %d > limit %d", ErrFileTooLarge, path, preLstat.Size(), opts.MaxBytes)
	}

	f, err := os.Open(path)
	if err != nil {
		return FileDigest{}, fmt.Errorf("open %q for hashing: %w", path, err)
	}
	defer func() {
		_ = f.Close()
	}()

	openStat, err := f.Stat()
	if err != nil {
		return FileDigest{}, fmt.Errorf("fstat %q before hashing: %w", path, err)
	}
	if !openStat.Mode().IsRegular() {
		return FileDigest{}, fmt.Errorf("%w: %q", ErrNonRegularFile, path)
	}
	if !os.SameFile(preLstat, openStat) {
		return FileDigest{}, fmt.Errorf("%w: %q inode replaced between lstat and open", ErrConcurrentMutation, path)
	}
	if openStat.Size() != preLstat.Size() || !openStat.ModTime().Equal(preLstat.ModTime()) {
		return FileDigest{}, fmt.Errorf("%w: %q changed before read start", ErrConcurrentMutation, path)
	}

	bufSize := opts.BufferSize
	if bufSize <= 0 {
		bufSize = DefaultBufferSize
	}
	buf := make([]byte, bufSize)
	hasher := sha256.New()
	var totalRead int64

	for {
		n, readErr := f.Read(buf)
		if n > 0 {
			totalRead += int64(n)
			if opts.MaxBytes > 0 && totalRead > opts.MaxBytes {
				return FileDigest{}, fmt.Errorf("%w: %q exceeded %d bytes during read", ErrFileTooLarge, path, opts.MaxBytes)
			}
			_, _ = hasher.Write(buf[:n])
			if opts.OnChunkRead != nil {
				if hookErr := opts.OnChunkRead(totalRead); hookErr != nil {
					return FileDigest{}, hookErr
				}
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return FileDigest{}, fmt.Errorf("read %q during hashing: %w", path, readErr)
		}
	}

	postFstat, err := f.Stat()
	if err != nil {
		return FileDigest{}, fmt.Errorf("fstat %q after hashing: %w", path, err)
	}
	postLstat, err := os.Lstat(path)
	if err != nil {
		return FileDigest{}, fmt.Errorf("lstat %q after hashing: %w", path, err)
	}

	if !os.SameFile(preLstat, postLstat) || !os.SameFile(openStat, postFstat) {
		return FileDigest{}, fmt.Errorf("%w: %q replaced during hashing", ErrConcurrentMutation, path)
	}
	if totalRead != preLstat.Size() || postFstat.Size() != preLstat.Size() || postLstat.Size() != preLstat.Size() {
		return FileDigest{}, fmt.Errorf(
			"%w: %q byte count mismatch (expected %d, read %d, post-stat %d)",
			ErrConcurrentMutation, path, preLstat.Size(), totalRead, postLstat.Size(),
		)
	}
	if !postFstat.ModTime().Equal(preLstat.ModTime()) || !postLstat.ModTime().Equal(preLstat.ModTime()) {
		return FileDigest{}, fmt.Errorf("%w: %q modification time changed during hashing", ErrConcurrentMutation, path)
	}

	hexSum := hex.EncodeToString(hasher.Sum(nil))
	return FileDigest{
		SHA256: Prefix + hexSum,
		Hex:    hexSum,
		Size:   totalRead,
	}, nil
}
