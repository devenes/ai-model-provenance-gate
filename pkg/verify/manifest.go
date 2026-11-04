package verify

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/devenes/ai-model-provenance-gate/internal/bundle"
	"github.com/devenes/ai-model-provenance-gate/internal/digest"
	"github.com/devenes/ai-model-provenance-gate/internal/formats/peft"
	"github.com/devenes/ai-model-provenance-gate/internal/manifest"
	"github.com/devenes/ai-model-provenance-gate/internal/version"
)

// VerifyBundleManifestBytes parses bundle-manifest.json bytes, verifies its internal RFC 8785 JCS manifest_digest,
// recomputes bundle-identity/v1 from observedFiles (OCI layer descriptors), and enforces 1-to-1 correspondence
// and static security flags without downloading model weights.
func VerifyBundleManifestBytes(
	manifestJSON []byte,
	observedFiles []FileEntry,
	opts ManifestVerifyOptions,
) (BundleManifest, error) {
	if len(bytes.TrimSpace(manifestJSON)) == 0 {
		return BundleManifest{}, fmt.Errorf("%w: empty bundle-manifest.json bytes", ErrInvalidBundleManifest)
	}
	configBlobDigest := digest.ComputeBytes(manifestJSON)

	var m manifest.BundleManifest
	dec := json.NewDecoder(bytes.NewReader(manifestJSON))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return BundleManifest{}, fmt.Errorf("%w: decode JSON: %v", ErrInvalidBundleManifest, err)
	}

	if m.SchemaVersion != version.BundleIdentitySchemaVersion {
		return BundleManifest{}, fmt.Errorf("%w: schema_version %q != %q", ErrInvalidBundleManifest, m.SchemaVersion, version.BundleIdentitySchemaVersion)
	}
	if err := digest.Validate(m.BundleID); err != nil {
		return BundleManifest{}, fmt.Errorf("%w: invalid bundle_id: %v", ErrInvalidBundleManifest, err)
	}
	if err := digest.Validate(m.ManifestDigest); err != nil {
		return BundleManifest{}, fmt.Errorf("%w: invalid manifest_digest: %v", ErrInvalidBundleManifest, err)
	}

	// 1. Recompute canonical JCS manifest_digest (with ManifestDigest="") and verify integrity.
	declaredManifestDigest := m.ManifestDigest
	finalized, _, err := manifest.Finalize(m)
	if err != nil {
		return BundleManifest{}, fmt.Errorf("%w: recompute manifest_digest: %v", ErrInvalidBundleManifest, err)
	}
	if finalized.ManifestDigest != declaredManifestDigest {
		return BundleManifest{}, fmt.Errorf(
			"%w: recomputed JCS manifest_digest %s does not match declared %s (manifest tampered)",
			ErrInvalidBundleManifest, finalized.ManifestDigest, declaredManifestDigest,
		)
	}

	// 2. Recompute bundle-identity/v1 from observed OCI descriptors and check 1-to-1 correspondence.
	idRes, err := ComputeBundleIdentityFromDescriptors(observedFiles)
	if err != nil {
		return BundleManifest{}, err
	}
	if idRes.BundleID != m.BundleID {
		return BundleManifest{}, fmt.Errorf(
			"%w: OCI descriptor bundle_id %s does not match manifest bundle_id %s",
			ErrInvalidBundleManifest, idRes.BundleID, m.BundleID,
		)
	}
	if m.FileCount != len(idRes.Files) || m.TotalBytes != idRes.TotalBytes || len(m.Files) != len(idRes.Files) {
		return BundleManifest{}, fmt.Errorf(
			"%w: manifest file count/bytes (%d files, %d bytes) does not match OCI descriptors (%d files, %d bytes)",
			ErrInvalidBundleManifest, m.FileCount, m.TotalBytes, len(idRes.Files), idRes.TotalBytes,
		)
	}

	manifestFilesByPath := make(map[string]FileEntry, len(m.Files))
	for _, mf := range m.Files {
		manifestFilesByPath[mf.Path] = FileEntry{
			Path:   mf.Path,
			Role:   string(mf.Role),
			SHA256: mf.SHA256,
			Size:   mf.Size,
		}
	}
	for _, of := range idRes.Files {
		mf, ok := manifestFilesByPath[of.Path]
		if !ok {
			return BundleManifest{}, fmt.Errorf("%w: OCI descriptor file %q is missing from bundle-manifest.json", ErrInvalidBundleManifest, of.Path)
		}
		if mf.SHA256 != of.SHA256 || mf.Size != of.Size || mf.Role != of.Role {
			return BundleManifest{}, fmt.Errorf(
				"%w: descriptor mismatch for %q: manifest=(%s, %d, %s) vs observed=(%s, %d, %s)",
				ErrInvalidBundleManifest, of.Path, mf.SHA256, mf.Size, mf.Role, of.SHA256, of.Size, of.Role,
			)
		}
	}

	// 3. Enforce static bundle security flags.
	if m.SecurityFlags.ContainsSymlinks {
		return BundleManifest{}, fmt.Errorf("%w: bundle contains forbidden symlinks", ErrInvalidBundleManifest)
	}
	if m.SecurityFlags.ContainsUnsafePickle || len(m.FormatSummary.UnsafeArtifactFiles) > 0 {
		return BundleManifest{}, fmt.Errorf("%w: bundle contains unsafe pickle/executable artifacts: %v", ErrInvalidBundleManifest, m.FormatSummary.UnsafeArtifactFiles)
	}
	if m.SecurityFlags.ContainsRemoteCodeHooks || (m.ModelConfig != nil && m.ModelConfig.HasAutoMap) {
		return BundleManifest{}, fmt.Errorf("%w: bundle config.json contains remote code execution hooks (auto_map)", ErrInvalidBundleManifest)
	}
	if !opts.AllowUnknownFiles && (m.FormatSummary.UnknownFileCount > 0 || len(m.SecurityFlags.UnknownRegularFiles) > 0) {
		return BundleManifest{}, fmt.Errorf("%w: bundle contains forbidden unknown regular files: %v", ErrInvalidBundleManifest, m.SecurityFlags.UnknownRegularFiles)
	}
	if opts.ExpectedBaseBundleID != "" {
		if !m.LoRARelationship.IsAdapter {
			return BundleManifest{}, fmt.Errorf("%w: expected LoRA adapter bound to base model %s, but bundle is not an adapter", ErrInvalidBundleManifest, opts.ExpectedBaseBundleID)
		}
		if m.LoRARelationship.VerificationStatus != peft.StatusVerified || m.LoRARelationship.VerifiedBaseBundleID != opts.ExpectedBaseBundleID {
			return BundleManifest{}, fmt.Errorf(
				"%w: LoRA adapter base bundle ID %q (status=%s) does not match expected %q",
				ErrInvalidBundleManifest, m.LoRARelationship.VerifiedBaseBundleID, m.LoRARelationship.VerificationStatus, opts.ExpectedBaseBundleID,
			)
		}
	}

	return BundleManifest{
		SchemaVersion:           m.SchemaVersion,
		BundleID:                m.BundleID,
		ManifestDigest:          m.ManifestDigest,
		ConfigBlobDigest:        configBlobDigest,
		FileCount:               m.FileCount,
		TotalBytes:              m.TotalBytes,
		PrimaryFormat:           m.FormatSummary.PrimaryFormat,
		HasLoRAAdapter:          m.FormatSummary.HasLoRAAdapter,
		LoRAVerificationStatus:  string(m.LoRARelationship.VerificationStatus),
		VerifiedBaseBundleID:    m.LoRARelationship.VerifiedBaseBundleID,
		DeclaredBaseModel:       m.LoRARelationship.BaseModelNameOrPath,
		ContainsSymlinks:        m.SecurityFlags.ContainsSymlinks,
		ContainsUnsafePickle:    m.SecurityFlags.ContainsUnsafePickle,
		ContainsRemoteCodeHooks: m.SecurityFlags.ContainsRemoteCodeHooks,
		UnknownRegularFiles:     m.SecurityFlags.UnknownRegularFiles,
		Files:                   idRes.Files,
		RawJSON:                 manifestJSON,
	}, nil
}

func reconstructInspectionResult(bm *BundleManifest, observedFiles []FileEntry) (*bundle.InspectionResult, error) {
	inv, _, err := buildInventoryFromDescriptors(observedFiles)
	if err != nil {
		return nil, err
	}
	idRes, err := ComputeBundleIdentityFromDescriptors(observedFiles)
	if err != nil {
		return nil, err
	}
	var m manifest.BundleManifest
	if bm != nil && len(bm.RawJSON) > 0 {
		dec := json.NewDecoder(bytes.NewReader(bm.RawJSON))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&m); err != nil {
			return nil, fmt.Errorf("%w: decode raw manifest: %v", ErrInvalidBundleManifest, err)
		}
		if m.BundleID != idRes.BundleID {
			return nil, fmt.Errorf("%w: manifest bundle_id %s != observed bundle_id %s", ErrInvalidBundleManifest, m.BundleID, idRes.BundleID)
		}
	} else {
		m = manifest.BundleManifest{
			SchemaVersion: version.BundleIdentitySchemaVersion,
			BundleID:      idRes.BundleID,
			FileCount:     inv.FileCount,
			TotalBytes:    inv.TotalBytes,
			Files:         inv.Files,
		}
	}
	return &bundle.InspectionResult{
		BundleID:  idRes.BundleID,
		Inventory: inv,
		Manifest:  m,
	}, nil
}
