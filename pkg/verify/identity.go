package verify

import (
	"fmt"
	"sort"
	"strings"

	"github.com/devenes/ai-model-provenance-gate/internal/digest"
	"github.com/devenes/ai-model-provenance-gate/internal/identity"
	"github.com/devenes/ai-model-provenance-gate/internal/inventory"
)

// ClassifyFileRole validates a relative path and returns its canonical bundle-identity/v1 component role.
func ClassifyFileRole(relPath string) (string, error) {
	normPath, err := inventory.NormalizeAndValidateRelPath(relPath)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidInventory, err)
	}
	return string(inventory.ClassifyFile(normPath)), nil
}

// ComputeBundleIdentityFromDescriptors derives the deterministic bundle-identity/v1 digest from an OCI
// layer descriptor inventory without touching the filesystem.
func ComputeBundleIdentityFromDescriptors(files []FileEntry) (IdentityResult, error) {
	inv, normEntries, err := buildInventoryFromDescriptors(files)
	if err != nil {
		return IdentityResult{}, err
	}
	idRes, err := identity.Compute(inv)
	if err != nil {
		return IdentityResult{}, fmt.Errorf("%w: %v", ErrInvalidInventory, err)
	}
	return IdentityResult{
		SchemaVersion: idRes.SchemaVersion,
		BundleID:      idRes.BundleID,
		FileCount:     inv.FileCount,
		TotalBytes:    inv.TotalBytes,
		Files:         normEntries,
		CanonicalJSON: idRes.CanonicalJSON,
	}, nil
}

func buildInventoryFromDescriptors(files []FileEntry) (inventory.Inventory, []FileEntry, error) {
	if len(files) == 0 {
		return inventory.Inventory{}, nil, fmt.Errorf("%w: file descriptor list is empty", ErrInvalidInventory)
	}

	seenNFC := make(map[string]string, len(files))
	seenFolded := make(map[string]string, len(files))
	invEntries := make([]inventory.FileEntry, 0, len(files))
	roleCounts := make(map[inventory.ComponentRole]int)
	var totalBytes int64

	for _, f := range files {
		normPath, err := inventory.NormalizeAndValidateRelPath(f.Path)
		if err != nil {
			return inventory.Inventory{}, nil, fmt.Errorf("%w: %v", ErrInvalidInventory, err)
		}
		if normPath != f.Path {
			return inventory.Inventory{}, nil, fmt.Errorf("%w: path %q is not in canonical normalized POSIX form %q", ErrInvalidInventory, f.Path, normPath)
		}
		if prev, exists := seenNFC[normPath]; exists {
			return inventory.Inventory{}, nil, fmt.Errorf("%w: duplicate path %q (conflicts with %q)", ErrInvalidInventory, normPath, prev)
		}
		seenNFC[normPath] = f.Path

		folded := strings.ToLower(normPath)
		if prev, exists := seenFolded[folded]; exists {
			return inventory.Inventory{}, nil, fmt.Errorf("%w: case-folding path collision between %q and %q", ErrInvalidInventory, normPath, prev)
		}
		seenFolded[folded] = normPath

		if f.Size < 0 {
			return inventory.Inventory{}, nil, fmt.Errorf("%w: negative size %d for %q", ErrInvalidInventory, f.Size, normPath)
		}
		if err := digest.Validate(f.SHA256); err != nil {
			return inventory.Inventory{}, nil, fmt.Errorf("%w: file %q has invalid digest %q: %v", ErrInvalidInventory, normPath, f.SHA256, err)
		}

		expectedRole := inventory.ClassifyFile(normPath)
		if strings.TrimSpace(f.Role) != "" && inventory.ComponentRole(f.Role) != expectedRole {
			return inventory.Inventory{}, nil, fmt.Errorf(
				"%w: file %q declared role %q does not match canonical role %q",
				ErrInvalidInventory, normPath, f.Role, expectedRole,
			)
		}

		invEntries = append(invEntries, inventory.FileEntry{
			Path:               normPath,
			Size:               f.Size,
			SHA256:             f.SHA256,
			Role:               expectedRole,
			MetadataProvenance: "observed",
		})
		roleCounts[expectedRole]++
		totalBytes += f.Size
	}

	sort.Slice(invEntries, func(i, j int) bool {
		return invEntries[i].Path < invEntries[j].Path
	})

	normFiles := make([]FileEntry, len(invEntries))
	for i, e := range invEntries {
		normFiles[i] = FileEntry{
			Path:   e.Path,
			Role:   string(e.Role),
			SHA256: e.SHA256,
			Size:   e.Size,
		}
	}

	return inventory.Inventory{
		Files:      invEntries,
		TotalBytes: totalBytes,
		FileCount:  len(invEntries),
		RoleCounts: roleCounts,
	}, normFiles, nil
}
