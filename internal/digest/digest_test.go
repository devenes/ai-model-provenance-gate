package digest

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestStreamFileAndDeterminism(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "weights.bin")
	payload := bytes.Repeat([]byte("abcd1234"), 16384) // 128 KiB (> 64 KiB buffer)
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	d1, err := StreamFile(path, StreamOptions{BufferSize: 4096})
	if err != nil {
		t.Fatalf("StreamFile d1: %v", err)
	}
	d2, err := StreamFile(path, StreamOptions{BufferSize: 65536})
	if err != nil {
		t.Fatalf("StreamFile d2: %v", err)
	}

	if d1.SHA256 != d2.SHA256 {
		t.Fatalf("expected identical digests across buffer sizes, got %s vs %s", d1.SHA256, d2.SHA256)
	}
	if d1.SHA256 != ComputeBytes(payload) {
		t.Fatalf("expected %s, got %s", ComputeBytes(payload), d1.SHA256)
	}
	if d1.Size != int64(len(payload)) {
		t.Fatalf("expected size %d, got %d", len(payload), d1.Size)
	}
}

func TestStreamFileDetectsConcurrentMutation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mutating.bin")
	payload := bytes.Repeat([]byte("x"), 32768)
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	mutated := false
	_, err := StreamFile(path, StreamOptions{
		BufferSize: 4096,
		OnChunkRead: func(_ int64) error {
			if !mutated {
				mutated = true
				f, openErr := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
				if openErr != nil {
					return openErr
				}
				_, _ = f.Write([]byte("extra-bytes"))
				_ = f.Close()
			}
			return nil
		},
	})
	if !errors.Is(err, ErrConcurrentMutation) {
		t.Fatalf("expected ErrConcurrentMutation, got %v", err)
	}
}

func TestStreamFileRejectsSymlinkAndOversized(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.bin")
	if err := os.WriteFile(target, []byte("hello"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	link := filepath.Join(dir, "link.bin")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	if _, err := StreamFile(link, StreamOptions{}); !errors.Is(err, ErrSymlinkRejected) {
		t.Fatalf("expected ErrSymlinkRejected, got %v", err)
	}

	if _, err := StreamFile(target, StreamOptions{MaxBytes: 3}); !errors.Is(err, ErrFileTooLarge) {
		t.Fatalf("expected ErrFileTooLarge, got %v", err)
	}
}
