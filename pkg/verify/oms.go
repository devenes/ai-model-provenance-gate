package verify

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/devenes/ai-model-provenance-gate/internal/digest"
	"github.com/devenes/ai-model-provenance-gate/internal/oms"
	"github.com/devenes/ai-model-provenance-gate/internal/signing"
)

// VerifyOMSBytes verifies an OpenSSF Model Signing (OMS v1.0) DSSE or Sigstore bundle envelope in memory
// against the OCI descriptor file inventory and the modelSigners trust domain.
func VerifyOMSBytes(
	rawEnvelope []byte,
	observedFiles []FileEntry,
	opts OMSVerifyOptions,
) (OMSResult, error) {
	inv, _, err := buildInventoryFromDescriptors(observedFiles)
	if err != nil {
		return OMSResult{
			Status: StatusInvalid,
			Reason: err.Error(),
		}, err
	}

	trusted, err := resolveSignerRules(opts.TrustedModelSigners)
	if err != nil {
		return OMSResult{
			Status: StatusBlocked,
			Reason: err.Error(),
		}, err
	}
	untrusted := resolveUntrustedCandidateKeys(trusted, opts.UntrustedCandidates)

	fileMap := make(map[string]string, len(inv.Files))
	for _, f := range inv.Files {
		fileMap[f.Path] = f.SHA256
	}

	res, err := oms.VerifyBytesAgainstFileMap(rawEnvelope, fileMap, oms.VerifyOptions{
		Mode:                   oms.ModeNative,
		Method:                 "key",
		TrustedSigners:         trusted,
		CandidateUntrustedKeys: untrusted,
		IgnoreUnsignedFiles:    opts.IgnoreUnsignedFiles,
	})

	var rootDigest string
	if env, _, pErr := signing.ParseDSSEOrSigstoreBundle(rawEnvelope); pErr == nil {
		var stmt signing.InTotoStatement
		if rawPayload, dErr := decodeDSSEPayload(env.Payload); dErr == nil {
			if json.Unmarshal(rawPayload, &stmt) == nil && len(stmt.Subject) == 1 {
				if hexSum := stmt.Subject[0].Digest["sha256"]; len(hexSum) == 64 {
					rootDigest = digest.Prefix + hexSum
				}
			}
		}
	}

	out := OMSResult{
		Status:                Status(res.Status),
		SignatureDigest:       res.SignatureDigest,
		PredicateType:         res.PredicateType,
		RootDigest:            rootDigest,
		IsSigstoreBundle:      res.IsSigstoreBundle,
		SignerID:              res.SignerID,
		SignerKeyID:           res.SignerKeyID,
		SignerFingerprint:     res.SignerFingerprint,
		Algorithm:             res.Algorithm,
		VerifiedFileCount:     res.VerifiedFileCount,
		DigestsMatchInventory: res.DigestsMatchInventory,
		MismatchedFiles:       res.MismatchedFiles,
		MissingSignedFiles:    res.MissingSignedFiles,
		UnsignedBundleFiles:   res.UnsignedBundleFiles,
		Reason:                res.Reason,
	}
	if err != nil {
		if out.Status == StatusUntrusted {
			return out, fmt.Errorf("%w: %s", ErrUntrustedSigner, out.Reason)
		}
		return out, fmt.Errorf("%w: %v", ErrInvalidOMSSignature, err)
	}
	return out, nil
}

func decodeDSSEPayload(b64 string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(b64)
}
