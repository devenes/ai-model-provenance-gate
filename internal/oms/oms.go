// Package oms implements OpenSSF Model Signing (OMS v1.0 and v0.1) signing and verification,
// including offline DSSE/Sigstore-bundle cryptographic verification, X.509 certificate chains,
// Sigstore keyless Fulcio/Rekor verification, signer trust evaluation, 1-to-1 file inventory
// digest correspondence, and an optional external model_signing CLI adapter.
package oms

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/devenes/ai-model-provenance-gate/internal/bundle"
	"github.com/devenes/ai-model-provenance-gate/internal/digest"
	"github.com/devenes/ai-model-provenance-gate/internal/inventory"
	"github.com/devenes/ai-model-provenance-gate/internal/signing"
	"github.com/devenes/ai-model-provenance-gate/internal/verification"
)

const (
	// PredicateTypeOMSV1 is the official OpenSSF Model Signing v1.0 predicate URI.
	PredicateTypeOMSV1 = "https://model_signing/signature/v1.0"
	// PredicateTypeOMSV01 is the legacy OpenSSF Model Signing v0.1 predicate URI (case-insensitive Digests/v0.1).
	PredicateTypeOMSV01 = "https://model_signing/digests/v0.1"
	// PredicateTypeOMSV01Canonical is the legacy Go v0.2.0 predicate URI with capital D.
	PredicateTypeOMSV01Canonical = "https://model_signing/Digests/v0.1"
	// DefaultCLITimeout bounds external model_signing CLI execution.
	DefaultCLITimeout = 30 * time.Second
)

// AdapterMode selects the OMS verification execution backend.
type AdapterMode string

const (
	// ModeNative uses Go's standard library DSSE/PKIX verifier and in-toto OMS v1.0 parser (default).
	ModeNative AdapterMode = "native"
	// ModeExternalCLI invokes the external Python `model_signing` CLI binary via exec.CommandContext.
	ModeExternalCLI AdapterMode = "external-cli"
)

var (
	// ErrInvalidOMSSignature is returned when an OMS signature or statement is invalid or tampered.
	ErrInvalidOMSSignature = errors.New("invalid OpenSSF Model Signing signature")
	// ErrComponentDigestMismatch is returned when OMS subject file digests do not match the bundle inventory.
	ErrComponentDigestMismatch = errors.New("OMS component digest correspondence failure")
	// ErrExternalCLIUnavailable is returned when ModeExternalCLI is requested and `model_signing` is not found on PATH.
	ErrExternalCLIUnavailable = errors.New("external model_signing CLI binary is not installed on PATH")
)

// ResourceDescriptorV1 represents an entry in OMS v1.0 predicate.resources.
type ResourceDescriptorV1 struct {
	Name      string `json:"name"`
	Algorithm string `json:"algorithm"`
	Digest    string `json:"digest"`
}

// SerializationConfig represents the OMS v1.0 predicate.serialization object.
type SerializationConfig struct {
	Method        string   `json:"method"`
	HashType      string   `json:"hash_type"`
	ShardSize     int64    `json:"shard_size,omitempty"`
	AllowSymlinks bool     `json:"allow_symlinks"`
	IgnorePaths   []string `json:"ignore_paths,omitempty"`
}

// PredicateV1 represents the OpenSSF Model Signing v1.0 predicate structure.
type PredicateV1 struct {
	Serialization SerializationConfig    `json:"serialization"`
	Resources     []ResourceDescriptorV1 `json:"resources"`
}

// SignOptions configures OMS v1.0 bundle signing.
type SignOptions struct {
	AsSigstoreBundle bool
	Method           string // "key" (default) or "certificate"
	SigningCertPath  string
	CertChainPaths   []string
	IgnorePaths      []string
	OutputBundlePath string
}

// VerifyOptions configures OMS v1.0 bundle verification.
type VerifyOptions struct {
	Mode                    AdapterMode
	ExternalBinary          string
	Timeout                 time.Duration
	Method                  string // "key" (default), "certificate", or "sigstore"
	TrustedSigners          []verification.TrustedSignerRule
	PublicKeyPaths          []string
	CandidateUntrustedKeys  []*signing.PublicKey
	CertChainPaths          []string
	TrustAnchorCerts        []*x509.Certificate
	CertificateIdentity     string
	CertificateOIDCIssuer   string
	SigstoreTrustedRootJSON []byte
	IgnorePaths             []string
	IgnoreUnsignedFiles     bool
}

// Result captures the structured result of OpenSSF Model Signing verification.
type Result struct {
	Status                verification.Status `json:"status"`
	Mode                  AdapterMode         `json:"mode"`
	SignaturePath         string              `json:"signature_path,omitempty"`
	SignatureDigest       string              `json:"signature_digest,omitempty"`
	PredicateType         string              `json:"predicate_type,omitempty"`
	IsSigstoreBundle      bool                `json:"is_sigstore_bundle"`
	SignerID              string              `json:"signer_id,omitempty"`
	SignerKeyID           string              `json:"signer_key_id,omitempty"`
	SignerFingerprint     string              `json:"signer_fingerprint,omitempty"`
	Algorithm             string              `json:"algorithm,omitempty"`
	VerifiedFileCount     int                 `json:"verified_file_count"`
	DigestsMatchInventory bool                `json:"digests_match_inventory"`
	MismatchedFiles       []string            `json:"mismatched_files,omitempty"`
	MissingSignedFiles    []string            `json:"missing_signed_files,omitempty"`
	UnsignedBundleFiles   []string            `json:"unsigned_bundle_files,omitempty"`
	Reason                string              `json:"reason"`
}

// ComputeRootDigest computes the OMS v1.0 §6.5.1 root subject digest from predicate.resources:
// Sort resources ascending by Name, decode each resource's hex digest into raw bytes,
// and compute SHA-256 over the concatenated raw digest bytes.
func ComputeRootDigest(resources []ResourceDescriptorV1) (string, error) {
	if len(resources) == 0 {
		return "", fmt.Errorf("%w: resources array cannot be empty", ErrInvalidOMSSignature)
	}
	sorted := make([]ResourceDescriptorV1, len(resources))
	copy(sorted, resources)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Name < sorted[j].Name
	})

	h := sha256.New()
	for _, r := range sorted {
		if r.Algorithm != "sha256" {
			return "", fmt.Errorf("%w: unsupported resource digest algorithm %q for %q", ErrInvalidOMSSignature, r.Algorithm, r.Name)
		}
		hexStr := strings.ToLower(strings.TrimSpace(r.Digest))
		if len(hexStr) != 64 {
			return "", fmt.Errorf("%w: invalid sha256 digest length for %q", ErrInvalidOMSSignature, r.Name)
		}
		rawBytes, err := hex.DecodeString(hexStr)
		if err != nil {
			return "", fmt.Errorf("%w: invalid hex digest for %q: %v", ErrInvalidOMSSignature, r.Name, err)
		}
		h.Write(rawBytes)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// SignBundle generates a standards-compliant OMS v1.0 (`https://model_signing/signature/v1.0`)
// in-toto Statement v1 over every file in insp.Inventory.Files and signs it in a DSSE envelope
// (or Sigstore v0.3 JSON bundle when opts.AsSigstoreBundle is true).
func SignBundle(insp bundle.InspectionResult, priv *signing.PrivateKey, opts SignOptions) ([]byte, error) {
	if priv == nil {
		return nil, signing.ErrInvalidKeyMaterial
	}
	if len(insp.Inventory.Files) == 0 {
		return nil, inventory.ErrEmptyBundle
	}

	resources := make([]ResourceDescriptorV1, 0, len(insp.Inventory.Files))
	for _, f := range insp.Inventory.Files {
		hexSum, err := digest.TrimPrefix(f.SHA256)
		if err != nil {
			return nil, fmt.Errorf("file %q digest: %w", f.Path, err)
		}
		resources = append(resources, ResourceDescriptorV1{
			Name:      f.Path,
			Algorithm: "sha256",
			Digest:    hexSum,
		})
	}
	subjectName := filepath.Base(insp.RootPath)
	if subjectName == "" || subjectName == "." || subjectName == "/" {
		subjectName = "model"
	}
	return buildAndSignOMSStatement(subjectName, resources, nil, priv, opts)
}

// SignModelPath enumerates a model directory or single-file model according to OMS v1.0 §6.1–6.2
// and signs it using either bare-key (`method: key`) or X.509 certificate (`method: certificate`).
func SignModelPath(modelPath string, priv *signing.PrivateKey, opts SignOptions) ([]byte, error) {
	if priv == nil {
		return nil, signing.ErrInvalidKeyMaterial
	}
	subjectName, _, files, relIgnored, err := EnumerateOMSModelFiles(modelPath, opts.IgnorePaths, opts.OutputBundlePath)
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("%w: model path %q contains 0 signable files after exclusions", inventory.ErrEmptyBundle, modelPath)
	}

	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	resources := make([]ResourceDescriptorV1, 0, len(paths))
	for _, p := range paths {
		hexSum, err := digest.TrimPrefix(files[p])
		if err != nil {
			return nil, err
		}
		resources = append(resources, ResourceDescriptorV1{
			Name:      p,
			Algorithm: "sha256",
			Digest:    hexSum,
		})
	}
	opts.AsSigstoreBundle = true
	return buildAndSignOMSStatement(subjectName, resources, relIgnored, priv, opts)
}

func buildAndSignOMSStatement(
	subjectName string,
	resources []ResourceDescriptorV1,
	ignorePaths []string,
	priv *signing.PrivateKey,
	opts SignOptions,
) ([]byte, error) {
	sort.Slice(resources, func(i, j int) bool {
		return resources[i].Name < resources[j].Name
	})
	rootDigestHex, err := ComputeRootDigest(resources)
	if err != nil {
		return nil, err
	}

	pred := PredicateV1{
		Serialization: SerializationConfig{
			Method:        "files",
			HashType:      "sha256",
			AllowSymlinks: false,
			IgnorePaths:   ignorePaths,
		},
		Resources: resources,
	}
	predBytes, err := json.Marshal(pred)
	if err != nil {
		return nil, fmt.Errorf("marshal OMS predicate: %w", err)
	}

	stmt := signing.InTotoStatement{
		Type: signing.InTotoStatementV1Type,
		Subject: []signing.ResourceDescriptor{
			{
				Name: subjectName,
				Digest: map[string]string{
					"sha256": rootDigestHex,
				},
			},
		},
		PredicateType: PredicateTypeOMSV1,
		Predicate:     predBytes,
	}
	stmtBytes, err := json.Marshal(stmt)
	if err != nil {
		return nil, fmt.Errorf("marshal OMS in-toto statement: %w", err)
	}

	method := strings.ToLower(strings.TrimSpace(opts.Method))
	if method == "" {
		method = "key"
	}

	var certChain []*x509.Certificate
	if method == "certificate" {
		if strings.TrimSpace(opts.SigningCertPath) == "" {
			return nil, fmt.Errorf("%w: --signing-cert is required for certificate signing", signing.ErrInvalidKeyMaterial)
		}
		leafRaw, err := os.ReadFile(opts.SigningCertPath)
		if err != nil {
			return nil, fmt.Errorf("read signing certificate %q: %w", opts.SigningCertPath, err)
		}
		leafCerts, err := signing.ParseCertificatesPEM(leafRaw)
		if err != nil {
			return nil, err
		}
		var extraCerts []*x509.Certificate
		if len(leafCerts) > 1 {
			extraCerts = append(extraCerts, leafCerts[1:]...)
		}
		for _, cp := range opts.CertChainPaths {
			rawC, err := os.ReadFile(cp)
			if err != nil {
				return nil, fmt.Errorf("read certificate chain %q: %w", cp, err)
			}
			parsedC, err := signing.ParseCertificatesPEM(rawC)
			if err != nil {
				return nil, err
			}
			extraCerts = append(extraCerts, parsedC...)
		}
		certChain, err = signing.ValidateSigningCertificate(leafCerts[0], extraCerts, priv, time.Now().UTC())
		if err != nil {
			return nil, err
		}
	} else if method != "key" {
		return nil, fmt.Errorf("%w: unsupported OMS signing method %q", ErrInvalidOMSSignature, method)
	}

	env, err := signing.SignDSSE(signing.InTotoPayloadType, stmtBytes, priv)
	if err != nil {
		return nil, fmt.Errorf("sign OMS DSSE envelope: %w", err)
	}

	var out []byte
	if method == "certificate" {
		b, bErr := signing.WrapInSigstoreCertificateBundle(env, certChain)
		if bErr != nil {
			return nil, bErr
		}
		out, err = json.MarshalIndent(b, "", "  ")
	} else if opts.AsSigstoreBundle {
		hintHex := strings.TrimPrefix(priv.Fingerprint, "sha256:")
		b := signing.WrapInSigstoreBundle(env, hintHex)
		out, err = json.MarshalIndent(b, "", "  ")
	} else {
		out, err = json.MarshalIndent(env, "", "  ")
	}
	if err != nil {
		return nil, err
	}
	out = append(out, '\n')
	return out, nil
}

// VerifyBundle verifies an OpenSSF Model Signing signature against the inspected model bundle
// and configured trusted signers.
func VerifyBundle(ctx context.Context, insp bundle.InspectionResult, sigPath string, opts VerifyOptions) (Result, error) {
	inventoryFiles := make(map[string]string, len(insp.Inventory.Files))
	for _, f := range insp.Inventory.Files {
		inventoryFiles[f.Path] = f.SHA256
	}
	return verifyAgainstFileMap(ctx, insp.RootPath, false, inventoryFiles, sigPath, opts)
}

// VerifyModelPath verifies an OpenSSF Model Signing signature against a model directory or single-file model on disk.
func VerifyModelPath(ctx context.Context, modelPath string, sigPath string, opts VerifyOptions) (Result, error) {
	_, isSingleFile, files, _, err := EnumerateOMSModelFiles(modelPath, opts.IgnorePaths, sigPath)
	if err != nil {
		return Result{
			Status:        verification.StatusInvalid,
			Mode:          ModeNative,
			SignaturePath: sigPath,
			Reason:        err.Error(),
		}, err
	}
	return verifyAgainstFileMap(ctx, modelPath, isSingleFile, files, sigPath, opts)
}

func verifyAgainstFileMap(
	ctx context.Context,
	rootPath string,
	isSingleFile bool,
	inventoryFiles map[string]string,
	sigPath string,
	opts VerifyOptions,
) (Result, error) {
	mode := opts.Mode
	if mode == "" {
		mode = ModeNative
	}
	sigPath = strings.TrimSpace(sigPath)
	if sigPath == "" {
		return Result{
			Status: verification.StatusMissing,
			Mode:   mode,
			Reason: "no OpenSSF Model Signing signature path provided",
		}, fmt.Errorf("%w: missing signature path", ErrInvalidOMSSignature)
	}

	rawSig, err := os.ReadFile(sigPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Result{
				Status:        verification.StatusMissing,
				Mode:          mode,
				SignaturePath: sigPath,
				Reason:        fmt.Sprintf("OMS signature file %q does not exist", sigPath),
			}, fmt.Errorf("%w: %v", ErrInvalidOMSSignature, err)
		}
		return Result{
			Status:        verification.StatusBlocked,
			Mode:          mode,
			SignaturePath: sigPath,
			Reason:        fmt.Sprintf("read OMS signature %q: %v", sigPath, err),
		}, err
	}

	sigDigest := digest.ComputeBytes(rawSig)

	if mode == ModeExternalCLI {
		return verifyViaExternalCLI(ctx, rootPath, isSingleFile, inventoryFiles, sigPath, sigDigest, rawSig, opts)
	}

	method := strings.ToLower(strings.TrimSpace(opts.Method))
	if method == "" {
		method = "key"
	}

	var envVer verification.EnvelopeVerification
	switch method {
	case "key":
		envVer, err = verification.VerifyInTotoDSSE(rawSig, opts.TrustedSigners, opts.CandidateUntrustedKeys)
	case "certificate":
		anchors := append([]*x509.Certificate(nil), opts.TrustAnchorCerts...)
		for _, cp := range opts.CertChainPaths {
			rawC, rErr := os.ReadFile(cp)
			if rErr != nil {
				return Result{
					Status:        verification.StatusInvalid,
					Mode:          mode,
					SignaturePath: sigPath,
					Reason:        fmt.Sprintf("read certificate chain %q: %v", cp, rErr),
				}, rErr
			}
			parsedC, pErr := signing.ParseCertificatesPEM(rawC)
			if pErr != nil {
				return Result{
					Status:        verification.StatusInvalid,
					Mode:          mode,
					SignaturePath: sigPath,
					Reason:        pErr.Error(),
				}, pErr
			}
			anchors = append(anchors, parsedC...)
		}
		envVer, err = verification.VerifyInTotoCertificateBundle(rawSig, anchors, time.Now().UTC())
	case "sigstore":
		envVer, err = verification.VerifyInTotoSigstoreBundle(rawSig, opts.CertificateIdentity, opts.CertificateOIDCIssuer, opts.SigstoreTrustedRootJSON)
	default:
		reason := fmt.Sprintf("unsupported OMS verification method %q", method)
		return Result{
			Status:        verification.StatusInvalid,
			Mode:          mode,
			SignaturePath: sigPath,
			Reason:        reason,
		}, fmt.Errorf("%w: %s", ErrInvalidOMSSignature, reason)
	}

	if err != nil {
		return Result{
			Status:            envVer.Status,
			Mode:              mode,
			SignaturePath:     sigPath,
			SignatureDigest:   sigDigest,
			IsSigstoreBundle:  envVer.IsSigstoreBundle,
			SignerKeyID:       envVer.SignerKeyID,
			SignerFingerprint: envVer.SignerFingerprint,
			Algorithm:         envVer.Algorithm,
			Reason:            envVer.Reason,
		}, err
	}

	return verifyStatementCorrespondence(isSingleFile, rootPath, inventoryFiles, sigPath, sigDigest, mode, envVer, opts.IgnoreUnsignedFiles)
}

// VerifyBytesAgainstFileMap verifies an in-memory OpenSSF Model Signing envelope against an observed file digest map
// without performing any filesystem I/O.
func VerifyBytesAgainstFileMap(
	rawSig []byte,
	inventoryFiles map[string]string,
	opts VerifyOptions,
) (Result, error) {
	if len(bytes.TrimSpace(rawSig)) == 0 {
		return Result{
			Status: verification.StatusMissing,
			Mode:   ModeNative,
			Reason: "empty OpenSSF Model Signing signature bytes",
		}, fmt.Errorf("%w: empty signature bytes", ErrInvalidOMSSignature)
	}
	sigDigest := digest.ComputeBytes(rawSig)

	method := strings.ToLower(strings.TrimSpace(opts.Method))
	if method == "" {
		method = "key"
	}

	var envVer verification.EnvelopeVerification
	var err error
	switch method {
	case "key":
		envVer, err = verification.VerifyInTotoDSSE(rawSig, opts.TrustedSigners, opts.CandidateUntrustedKeys)
	case "certificate":
		envVer, err = verification.VerifyInTotoCertificateBundle(rawSig, opts.TrustAnchorCerts, time.Now().UTC())
	case "sigstore":
		envVer, err = verification.VerifyInTotoSigstoreBundle(rawSig, opts.CertificateIdentity, opts.CertificateOIDCIssuer, opts.SigstoreTrustedRootJSON)
	default:
		reason := fmt.Sprintf("unsupported OMS verification method %q", method)
		return Result{
			Status:          verification.StatusInvalid,
			Mode:            ModeNative,
			SignatureDigest: sigDigest,
			Reason:          reason,
		}, fmt.Errorf("%w: %s", ErrInvalidOMSSignature, reason)
	}

	if err != nil {
		return Result{
			Status:            envVer.Status,
			Mode:              ModeNative,
			SignatureDigest:   sigDigest,
			IsSigstoreBundle:  envVer.IsSigstoreBundle,
			SignerKeyID:       envVer.SignerKeyID,
			SignerFingerprint: envVer.SignerFingerprint,
			Algorithm:         envVer.Algorithm,
			Reason:            envVer.Reason,
		}, err
	}

	return verifyStatementCorrespondence(false, "", inventoryFiles, "", sigDigest, ModeNative, envVer, opts.IgnoreUnsignedFiles)
}

func verifyStatementCorrespondence(
	isSingleFile bool,
	rootPath string,
	inventoryFiles map[string]string,
	sigPath string,
	sigDigest string,
	mode AdapterMode,
	envVer verification.EnvelopeVerification,
	ignoreUnsignedFiles bool,
) (Result, error) {
	stmt := envVer.Statement
	isV1 := stmt.PredicateType == PredicateTypeOMSV1
	isV01 := strings.EqualFold(stmt.PredicateType, PredicateTypeOMSV01)

	if !isV1 && !isV01 {
		reason := fmt.Sprintf(
			"unsupported OMS predicateType %q (expected %q or %q)",
			stmt.PredicateType, PredicateTypeOMSV1, PredicateTypeOMSV01Canonical,
		)
		return Result{
			Status:            verification.StatusInvalid,
			Mode:              mode,
			SignaturePath:     sigPath,
			SignatureDigest:   sigDigest,
			PredicateType:     stmt.PredicateType,
			IsSigstoreBundle:  envVer.IsSigstoreBundle,
			SignerID:          envVer.MatchedSignerID,
			SignerKeyID:       envVer.SignerKeyID,
			SignerFingerprint: envVer.SignerFingerprint,
			Algorithm:         envVer.Algorithm,
			Reason:            reason,
		}, fmt.Errorf("%w: %s", ErrInvalidOMSSignature, reason)
	}

	signedFiles := make(map[string]string)

	if isV1 {
		if len(stmt.Subject) != 1 {
			reason := fmt.Sprintf("OMS v1.0 statement requires exactly 1 subject entry, got %d", len(stmt.Subject))
			return Result{
				Status:          verification.StatusInvalid,
				Mode:            mode,
				SignaturePath:   sigPath,
				SignatureDigest: sigDigest,
				PredicateType:   stmt.PredicateType,
				Reason:          reason,
			}, fmt.Errorf("%w: %s", ErrInvalidOMSSignature, reason)
		}
		subjRootHex := strings.ToLower(strings.TrimSpace(stmt.Subject[0].Digest["sha256"]))
		if err := digest.Validate(digest.Prefix + subjRootHex); err != nil {
			reason := fmt.Sprintf("invalid subject sha256 root digest %q in OMS v1.0 statement", subjRootHex)
			return Result{
				Status:          verification.StatusInvalid,
				Mode:            mode,
				SignaturePath:   sigPath,
				SignatureDigest: sigDigest,
				PredicateType:   stmt.PredicateType,
				Reason:          reason,
			}, fmt.Errorf("%w: %s", ErrInvalidOMSSignature, reason)
		}

		if len(bytes.TrimSpace(stmt.Predicate)) == 0 {
			reason := "OMS v1.0 statement predicate is empty"
			return Result{
				Status:          verification.StatusInvalid,
				Mode:            mode,
				SignaturePath:   sigPath,
				SignatureDigest: sigDigest,
				PredicateType:   stmt.PredicateType,
				Reason:          reason,
			}, fmt.Errorf("%w: %s", ErrInvalidOMSSignature, reason)
		}

		var pred PredicateV1
		dec := json.NewDecoder(bytes.NewReader(stmt.Predicate))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&pred); err != nil {
			reason := fmt.Sprintf("invalid OMS v1.0 predicate structure: %v", err)
			return Result{
				Status:          verification.StatusInvalid,
				Mode:            mode,
				SignaturePath:   sigPath,
				SignatureDigest: sigDigest,
				PredicateType:   stmt.PredicateType,
				Reason:          reason,
			}, fmt.Errorf("%w: %s", ErrInvalidOMSSignature, reason)
		}

		if (pred.Serialization.Method != "files" && pred.Serialization.Method != "shards") || pred.Serialization.HashType != "sha256" {
			reason := fmt.Sprintf("missing or invalid OMS v1.0 predicate.serialization (method=%q, hash_type=%q)", pred.Serialization.Method, pred.Serialization.HashType)
			return Result{
				Status:          verification.StatusInvalid,
				Mode:            mode,
				SignaturePath:   sigPath,
				SignatureDigest: sigDigest,
				PredicateType:   stmt.PredicateType,
				Reason:          reason,
			}, fmt.Errorf("%w: %s", ErrInvalidOMSSignature, reason)
		}

		if len(pred.Resources) == 0 {
			reason := "OMS v1.0 predicate.resources array is empty"
			return Result{
				Status:          verification.StatusInvalid,
				Mode:            mode,
				SignaturePath:   sigPath,
				SignatureDigest: sigDigest,
				PredicateType:   stmt.PredicateType,
				Reason:          reason,
			}, fmt.Errorf("%w: %s", ErrInvalidOMSSignature, reason)
		}

		computedRootHex, err := ComputeRootDigest(pred.Resources)
		if err != nil {
			return Result{
				Status:          verification.StatusInvalid,
				Mode:            mode,
				SignaturePath:   sigPath,
				SignatureDigest: sigDigest,
				PredicateType:   stmt.PredicateType,
				Reason:          err.Error(),
			}, err
		}
		if computedRootHex != subjRootHex {
			reason := fmt.Sprintf("OMS v1.0 root subject digest mismatch: subject=%s computed=%s", subjRootHex, computedRootHex)
			return Result{
				Status:          verification.StatusInvalid,
				Mode:            mode,
				SignaturePath:   sigPath,
				SignatureDigest: sigDigest,
				PredicateType:   stmt.PredicateType,
				Reason:          reason,
			}, fmt.Errorf("%w: %s", ErrInvalidOMSSignature, reason)
		}

		for _, r := range pred.Resources {
			var normPath string
			if isSingleFile && r.Name == "." {
				normPath = filepath.Base(rootPath)
			} else {
				var normErr error
				normPath, normErr = inventory.NormalizeAndValidateRelPath(r.Name)
				if normErr != nil {
					reason := fmt.Sprintf("invalid resource path %q in OMS v1.0 predicate: %v", r.Name, normErr)
					return Result{
						Status:          verification.StatusInvalid,
						Mode:            mode,
						SignaturePath:   sigPath,
						SignatureDigest: sigDigest,
						PredicateType:   stmt.PredicateType,
						Reason:          reason,
					}, fmt.Errorf("%w: %s", ErrInvalidOMSSignature, reason)
				}
			}
			shaHex := strings.ToLower(strings.TrimSpace(r.Digest))
			if err := digest.Validate(digest.Prefix + shaHex); err != nil {
				reason := fmt.Sprintf("invalid sha256 digest %q for resource %q", shaHex, normPath)
				return Result{
					Status:          verification.StatusInvalid,
					Mode:            mode,
					SignaturePath:   sigPath,
					SignatureDigest: sigDigest,
					PredicateType:   stmt.PredicateType,
					Reason:          reason,
				}, fmt.Errorf("%w: %s", ErrInvalidOMSSignature, reason)
			}
			signedFiles[normPath] = digest.Prefix + shaHex
		}
	} else {
		// Legacy v0.1 ("https://model_signing/Digests/v0.1"): per-file digests are in stmt.Subject.
		for _, desc := range stmt.Subject {
			var normPath string
			if isSingleFile && desc.Name == "." {
				normPath = filepath.Base(rootPath)
			} else {
				var normErr error
				normPath, normErr = inventory.NormalizeAndValidateRelPath(desc.Name)
				if normErr != nil {
					reason := fmt.Sprintf("invalid subject path %q in OMS v0.1 statement: %v", desc.Name, normErr)
					return Result{
						Status:          verification.StatusInvalid,
						Mode:            mode,
						SignaturePath:   sigPath,
						SignatureDigest: sigDigest,
						PredicateType:   stmt.PredicateType,
						Reason:          reason,
					}, fmt.Errorf("%w: %s", ErrInvalidOMSSignature, reason)
				}
			}
			shaHex := strings.ToLower(strings.TrimSpace(desc.Digest["sha256"]))
			if err := digest.Validate(digest.Prefix + shaHex); err != nil {
				reason := fmt.Sprintf("invalid sha256 digest %q for subject %q in OMS v0.1 statement", shaHex, normPath)
				return Result{
					Status:          verification.StatusInvalid,
					Mode:            mode,
					SignaturePath:   sigPath,
					SignatureDigest: sigDigest,
					PredicateType:   stmt.PredicateType,
					Reason:          reason,
				}, fmt.Errorf("%w: %s", ErrInvalidOMSSignature, reason)
			}
			signedFiles[normPath] = digest.Prefix + shaHex
		}
	}

	var mismatched []string
	var missingSigned []string
	var unsignedBundle []string

	for path, expectedDigest := range signedFiles {
		actualDigest, exists := inventoryFiles[path]
		if !exists {
			missingSigned = append(missingSigned, path)
			continue
		}
		if actualDigest != expectedDigest {
			mismatched = append(mismatched, path)
		}
	}

	for path := range inventoryFiles {
		if _, signed := signedFiles[path]; !signed {
			unsignedBundle = append(unsignedBundle, path)
		}
	}

	sort.Strings(mismatched)
	sort.Strings(missingSigned)
	sort.Strings(unsignedBundle)

	hasExtraFailure := len(unsignedBundle) > 0 && !ignoreUnsignedFiles
	if len(mismatched) > 0 || len(missingSigned) > 0 || hasExtraFailure {
		reason := fmt.Sprintf(
			"OMS component digest mismatch (mismatched=%v, missing_signed=%v, unsigned_extra=%v)",
			mismatched, missingSigned, unsignedBundle,
		)
		return Result{
			Status:                verification.StatusInvalid,
			Mode:                  mode,
			SignaturePath:         sigPath,
			SignatureDigest:       sigDigest,
			PredicateType:         stmt.PredicateType,
			IsSigstoreBundle:      envVer.IsSigstoreBundle,
			SignerID:              envVer.MatchedSignerID,
			SignerKeyID:           envVer.SignerKeyID,
			SignerFingerprint:     envVer.SignerFingerprint,
			Algorithm:             envVer.Algorithm,
			DigestsMatchInventory: false,
			MismatchedFiles:       mismatched,
			MissingSignedFiles:    missingSigned,
			UnsignedBundleFiles:   unsignedBundle,
			Reason:                reason,
		}, fmt.Errorf("%w: %s", ErrComponentDigestMismatch, reason)
	}

	return Result{
		Status:                verification.StatusVerified,
		Mode:                  mode,
		SignaturePath:         sigPath,
		SignatureDigest:       sigDigest,
		PredicateType:         stmt.PredicateType,
		IsSigstoreBundle:      envVer.IsSigstoreBundle,
		SignerID:              envVer.MatchedSignerID,
		SignerKeyID:           envVer.SignerKeyID,
		SignerFingerprint:     envVer.SignerFingerprint,
		Algorithm:             envVer.Algorithm,
		VerifiedFileCount:     len(signedFiles),
		DigestsMatchInventory: true,
		UnsignedBundleFiles:   unsignedBundle,
		Reason:                fmt.Sprintf("verified OMS %s signature and %d component file digests", stmt.PredicateType, len(signedFiles)),
	}, nil
}

// EnumerateOMSModelFiles walks a model directory or single-file model according to OMS v1.0 §6.1–6.2,
// applying default exclusions, caller --ignore-paths, and auto-exclusion of the signature bundle if inside modelPath.
func EnumerateOMSModelFiles(
	modelPath string,
	ignorePaths []string,
	autoIgnoreSigPath string,
) (subjectName string, isSingleFile bool, files map[string]string, relIgnored []string, err error) {
	cleanedModel := filepath.Clean(modelPath)
	fi, err := os.Lstat(cleanedModel)
	if err != nil {
		return "", false, nil, nil, fmt.Errorf("stat model path %q: %w", cleanedModel, err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return "", false, nil, nil, fmt.Errorf("%w: model path %q cannot be a symlink", digest.ErrSymlinkRejected, cleanedModel)
	}

	subjectName = filepath.Base(cleanedModel)
	if !fi.IsDir() {
		if !fi.Mode().IsRegular() {
			return "", false, nil, nil, fmt.Errorf("model path %q is not a regular file", cleanedModel)
		}
		fd, dErr := digest.StreamFile(cleanedModel, digest.StreamOptions{})
		if dErr != nil {
			return "", false, nil, nil, dErr
		}
		return subjectName, true, map[string]string{subjectName: fd.SHA256}, nil, nil
	}

	absRoot, err := canonicalPathPreservingFinal(cleanedModel)
	if err != nil {
		return "", false, nil, nil, err
	}

	ignoredSet := map[string]bool{
		".git":           true,
		".gitignore":     true,
		".gitattributes": true,
		".github":        true,
	}

	addIgnoreCandidate := func(raw string) {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return
		}
		if absCand, cErr := canonicalPathPreservingFinal(raw); cErr == nil {
			if rel, rErr := filepath.Rel(absRoot, absCand); rErr == nil {
				relPosix := filepath.ToSlash(rel)
				if relPosix != "." && relPosix != ".." && !strings.HasPrefix(relPosix, "../") {
					ignoredSet[relPosix] = true
					return
				}
			}
		}
		// Also accept relative POSIX paths directly relative to modelPath.
		if !filepath.IsAbs(raw) {
			relPosix := strings.TrimPrefix(filepath.ToSlash(filepath.Clean(raw)), "./")
			if relPosix != "" && relPosix != "." && relPosix != ".." && !strings.HasPrefix(relPosix, "../") {
				ignoredSet[relPosix] = true
			}
		}
	}

	for _, ip := range ignorePaths {
		addIgnoreCandidate(ip)
	}
	if autoIgnoreSigPath != "" {
		addIgnoreCandidate(autoIgnoreSigPath)
	}

	isIgnoredRel := func(relPosix string) bool {
		if ignoredSet[relPosix] {
			return true
		}
		for ig := range ignoredSet {
			if strings.HasPrefix(relPosix, ig+"/") {
				return true
			}
		}
		return false
	}

	files = make(map[string]string)
	var walkDir func(currDir, relPrefix string) error
	walkDir = func(currDir, relPrefix string) error {
		entries, rErr := os.ReadDir(currDir)
		if rErr != nil {
			return fmt.Errorf("read directory %q: %w", currDir, rErr)
		}
		for _, entry := range entries {
			name := entry.Name()
			relPosix := name
			if relPrefix != "" {
				relPosix = relPrefix + "/" + name
			}
			// Exclude any .git directory at any nesting level, plus any path matching ignoredSet.
			if name == ".git" || isIgnoredRel(relPosix) {
				continue
			}

			fullPath := filepath.Join(currDir, name)
			lfi, lErr := os.Lstat(fullPath)
			if lErr != nil {
				return fmt.Errorf("lstat %q: %w", fullPath, lErr)
			}
			if lfi.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("%w: symlink %q is not permitted in OMS model bundle", digest.ErrSymlinkRejected, relPosix)
			}
			if lfi.IsDir() {
				if err := walkDir(fullPath, relPosix); err != nil {
					return err
				}
				continue
			}
			if !lfi.Mode().IsRegular() {
				return fmt.Errorf("irregular file %q in model bundle", relPosix)
			}
			if _, normErr := inventory.NormalizeAndValidateRelPath(relPosix); normErr != nil {
				return normErr
			}
			fd, dErr := digest.StreamFile(fullPath, digest.StreamOptions{})
			if dErr != nil {
				return dErr
			}
			files[relPosix] = fd.SHA256
		}
		return nil
	}

	if err := walkDir(absRoot, ""); err != nil {
		return "", false, nil, nil, err
	}

	for k := range ignoredSet {
		relIgnored = append(relIgnored, k)
	}
	sort.Strings(relIgnored)
	return subjectName, false, files, relIgnored, nil
}

func canonicalPathPreservingFinal(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	parent := filepath.Dir(abs)
	base := filepath.Base(abs)
	if evalParent, err := filepath.EvalSymlinks(parent); err == nil {
		return filepath.Join(evalParent, base), nil
	}
	return abs, nil
}

func verifyViaExternalCLI(
	ctx context.Context,
	rootPath string,
	isSingleFile bool,
	inventoryFiles map[string]string,
	sigPath string,
	sigDigest string,
	rawSig []byte,
	opts VerifyOptions,
) (Result, error) {
	bin := strings.TrimSpace(opts.ExternalBinary)
	if bin == "" {
		bin = "model_signing"
	}
	resolvedBin, err := exec.LookPath(bin)
	if err != nil {
		return Result{
			Status:          verification.StatusBlocked,
			Mode:            ModeExternalCLI,
			SignaturePath:   sigPath,
			SignatureDigest: sigDigest,
			Reason:          fmt.Sprintf("%s: %q not found on PATH", ErrExternalCLIUnavailable.Error(), bin),
		}, fmt.Errorf("%w: %v", ErrExternalCLIUnavailable, err)
	}

	if len(opts.PublicKeyPaths) == 0 {
		return Result{
			Status:          verification.StatusBlocked,
			Mode:            ModeExternalCLI,
			SignaturePath:   sigPath,
			SignatureDigest: sigDigest,
			Reason:          verification.ErrMissingVerificationMaterial.Error(),
		}, verification.ErrMissingVerificationMaterial
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultCLITimeout
	}
	cmdCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Use explicit argument array (no shell interpolation).
	args := []string{
		"verify", "key",
		rootPath,
		"--signature", sigPath,
		"--public-key", opts.PublicKeyPaths[0],
	}
	cmd := exec.CommandContext(cmdCtx, resolvedBin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if runErr := cmd.Run(); runErr != nil {
		outMsg := strings.TrimSpace(stderr.String() + " " + stdout.String())
		reason := fmt.Sprintf("external %s verify failed: %v (%s)", bin, runErr, outMsg)
		return Result{
			Status:          verification.StatusInvalid,
			Mode:            ModeExternalCLI,
			SignaturePath:   sigPath,
			SignatureDigest: sigDigest,
			Reason:          reason,
		}, fmt.Errorf("%w: %s", ErrInvalidOMSSignature, reason)
	}

	// Even when external CLI succeeds, also run our native signer-trust & inventory correspondence check.
	envVer, verErr := verification.VerifyInTotoDSSE(rawSig, opts.TrustedSigners, opts.CandidateUntrustedKeys)
	if verErr != nil {
		return Result{
			Status:          envVer.Status,
			Mode:            ModeExternalCLI,
			SignaturePath:   sigPath,
			SignatureDigest: sigDigest,
			Reason:          envVer.Reason,
		}, verErr
	}
	return verifyStatementCorrespondence(isSingleFile, rootPath, inventoryFiles, sigPath, sigDigest, ModeExternalCLI, envVer, opts.IgnoreUnsignedFiles)
}
