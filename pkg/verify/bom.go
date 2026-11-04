package verify

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/devenes/ai-model-provenance-gate/internal/bom"
	"github.com/devenes/ai-model-provenance-gate/internal/digest"
	"github.com/devenes/ai-model-provenance-gate/internal/identity"
)

// VerifyBOMBytes validates raw CycloneDX 1.6/1.7 AI/ML-BOM JSON bytes against the official CycloneDX JSON Schema,
// the cyclonedx-go SDK, the ML-BOM profile schema, and strict 1-to-1 file and metadata correspondence against
// the verified BundleManifest and OCI layer descriptors.
// It returns BOMResult containing CanonicalHash (RFC 8785 JCS SHA-256 matching ReleaseQualificationPredicate.BOM.Digest).
func VerifyBOMBytes(
	rawBOM []byte,
	expectedManifest *BundleManifest,
	observedFiles []FileEntry,
) (BOMResult, error) {
	if len(bytes.TrimSpace(rawBOM)) == 0 {
		return BOMResult{
			Status: StatusMissing,
			Reason: "empty CycloneDX AI/ML-BOM bytes",
		}, fmt.Errorf("%w: empty BOM bytes", ErrInvalidBOM)
	}
	rawDigest := digest.ComputeBytes(rawBOM)

	expectedInsp, err := reconstructInspectionResult(expectedManifest, observedFiles)
	if err != nil {
		return BOMResult{
			Status:        StatusInvalid,
			RawBlobDigest: rawDigest,
			Reason:        err.Error(),
		}, err
	}

	if err := bom.Validate(rawBOM, expectedInsp); err != nil {
		return BOMResult{
			Status:        StatusInvalid,
			RawBlobDigest: rawDigest,
			Reason:        err.Error(),
		}, fmt.Errorf("%w: %v", ErrInvalidBOM, err)
	}

	canonBytes, err := identity.CanonicalizeJSON(rawBOM)
	if err != nil {
		return BOMResult{
			Status:        StatusInvalid,
			RawBlobDigest: rawDigest,
			Reason:        err.Error(),
		}, fmt.Errorf("%w: canonicalize BOM JSON: %v", ErrInvalidBOM, err)
	}
	canonHash := digest.ComputeBytes(canonBytes)

	var doc bom.Document
	_ = json.Unmarshal(rawBOM, &doc)

	return BOMResult{
		Status:        StatusVerified,
		CanonicalHash: canonHash,
		RawBlobDigest: rawDigest,
		SpecVersion:   doc.SpecVersion,
		SerialNumber:  doc.SerialNumber,
		BundleID:      expectedInsp.BundleID,
		Reason:        fmt.Sprintf("verified CycloneDX %s AI/ML-BOM (%s) matching bundle %s", doc.SpecVersion, canonHash, expectedInsp.BundleID),
	}, nil
}
