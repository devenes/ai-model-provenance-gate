// Package provenance verifies optional upstream SLSA v1.0 / v1.1 / v1.2 build provenance attestations
// (`https://slsa.dev/provenance/v1`) while strictly distinguishing upstream build provenance
// from post-hoc release qualification.
package provenance

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/devenes/ai-model-provenance-gate/internal/digest"
	"github.com/devenes/ai-model-provenance-gate/internal/signing"
	"github.com/devenes/ai-model-provenance-gate/internal/verification"
)

const (
	// SLSAV1PredicateType is the official SLSA v1.0 / v1.1 / v1.2 build provenance predicate URI.
	SLSAV1PredicateType = "https://slsa.dev/provenance/v1"
)

var (
	// ErrInvalidSLSAProvenance is returned when an upstream SLSA provenance attestation is invalid or mismatches the bundle.
	ErrInvalidSLSAProvenance = errors.New("invalid or untrusted upstream SLSA build provenance")
)

// SLSAResourceDescriptor represents a dependency/material entry in SLSA v1.2 buildDefinition.resolvedDependencies.
type SLSAResourceDescriptor struct {
	URI              string            `json:"uri,omitempty"`
	Digest           map[string]string `json:"digest,omitempty"`
	Name             string            `json:"name,omitempty"`
	DownloadLocation string            `json:"downloadLocation,omitempty"`
	MediaType        string            `json:"mediaType,omitempty"`
	Content          string            `json:"content,omitempty"`
	Annotations      map[string]any    `json:"annotations,omitempty"`
}

// SLSAPredicate represents the official SLSA v1.0 / v1.1 / v1.2 provenance predicate structure.
type SLSAPredicate struct {
	BuildDefinition struct {
		BuildType            string                   `json:"buildType"`
		ExternalParameters   map[string]any           `json:"externalParameters"`
		InternalParameters   map[string]any           `json:"internalParameters,omitempty"`
		ResolvedDependencies []SLSAResourceDescriptor `json:"resolvedDependencies,omitempty"`
	} `json:"buildDefinition"`
	RunDetails struct {
		Builder struct {
			ID                  string                   `json:"id"`
			BuilderDependencies []SLSAResourceDescriptor `json:"builderDependencies,omitempty"`
			Version             map[string]string        `json:"version,omitempty"`
		} `json:"builder"`
		Metadata *struct {
			InvocationID string `json:"invocationId,omitempty"`
			StartedOn    string `json:"startedOn,omitempty"`
			FinishedOn   string `json:"finishedOn,omitempty"`
		} `json:"metadata,omitempty"`
		Byproducts []SLSAResourceDescriptor `json:"byproducts,omitempty"`
	} `json:"runDetails"`
}

// VerifyOptions configures upstream SLSA provenance verification.
type VerifyOptions struct {
	AttestationPath             string
	ExpectedBundleID            string
	ExpectedBuilderIDs          []string
	RequireResolvedDependencies bool
	TrustedSigners              []verification.TrustedSignerRule
	CandidateUntrustedKeys      []*signing.PublicKey
}

// Result summarizes upstream SLSA build provenance verification.
type Result struct {
	Status                  verification.Status `json:"status"`
	AttestationPath         string              `json:"attestation_path,omitempty"`
	AttestationDigest       string              `json:"attestation_digest,omitempty"`
	BuilderID               string              `json:"builder_id,omitempty"`
	BuildType               string              `json:"build_type,omitempty"`
	ResolvedDependencyCount int                 `json:"resolved_dependency_count,omitempty"`
	SignerID                string              `json:"signer_id,omitempty"`
	SignerFingerprint       string              `json:"signer_fingerprint,omitempty"`
	Reason                  string              `json:"reason"`
}

// VerifyUpstreamProvenance verifies an optional upstream SLSA v1.0/v1.1 DSSE provenance statement
// against trusted builder keys and the inspected model bundle identity.
func VerifyUpstreamProvenance(opts VerifyOptions) (Result, error) {
	path := strings.TrimSpace(opts.AttestationPath)
	if path == "" {
		return Result{
			Status: verification.StatusNotRun,
			Reason: "no upstream SLSA build provenance attestation supplied",
		}, nil
	}

	rawBytes, err := os.ReadFile(path)
	if err != nil {
		return Result{
			Status:          verification.StatusBlocked,
			AttestationPath: path,
			Reason:          fmt.Sprintf("read upstream provenance %q: %v", path, err),
		}, err
	}
	attDigest := digest.ComputeBytes(rawBytes)

	envVer, err := verification.VerifyInTotoDSSE(rawBytes, opts.TrustedSigners, opts.CandidateUntrustedKeys)
	if err != nil {
		return Result{
			Status:            envVer.Status,
			AttestationPath:   path,
			AttestationDigest: attDigest,
			SignerFingerprint: envVer.SignerFingerprint,
			Reason:            envVer.Reason,
		}, fmt.Errorf("%w: %v", ErrInvalidSLSAProvenance, err)
	}

	if envVer.Statement.PredicateType != SLSAV1PredicateType {
		reason := fmt.Sprintf("unexpected predicateType %q (expected %q)", envVer.Statement.PredicateType, SLSAV1PredicateType)
		return Result{
			Status:            verification.StatusInvalid,
			AttestationPath:   path,
			AttestationDigest: attDigest,
			Reason:            reason,
		}, fmt.Errorf("%w: %s", ErrInvalidSLSAProvenance, reason)
	}

	expectedHex, err := digest.TrimPrefix(opts.ExpectedBundleID)
	if err != nil {
		return Result{}, err
	}
	matchedSubject := false
	for _, s := range envVer.Statement.Subject {
		if strings.EqualFold(s.Digest["sha256"], expectedHex) {
			matchedSubject = true
			break
		}
	}
	if !matchedSubject {
		reason := fmt.Sprintf("SLSA provenance subject digest does not match model bundle %s", opts.ExpectedBundleID)
		return Result{
			Status:            verification.StatusInvalid,
			AttestationPath:   path,
			AttestationDigest: attDigest,
			Reason:            reason,
		}, fmt.Errorf("%w: %s", ErrInvalidSLSAProvenance, reason)
	}

	var pred SLSAPredicate
	dec := json.NewDecoder(bytes.NewReader(envVer.Statement.Predicate))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&pred); err != nil {
		reason := fmt.Sprintf("decode SLSA v1.2 predicate: %v", err)
		return Result{
			Status:            verification.StatusInvalid,
			AttestationPath:   path,
			AttestationDigest: attDigest,
			Reason:            reason,
		}, fmt.Errorf("%w: %s", ErrInvalidSLSAProvenance, reason)
	}

	builderID := strings.TrimSpace(pred.RunDetails.Builder.ID)
	buildType := strings.TrimSpace(pred.BuildDefinition.BuildType)
	if builderID == "" || buildType == "" {
		reason := "SLSA predicate missing runDetails.builder.id or buildDefinition.buildType"
		return Result{
			Status:            verification.StatusInvalid,
			AttestationPath:   path,
			AttestationDigest: attDigest,
			Reason:            reason,
		}, fmt.Errorf("%w: %s", ErrInvalidSLSAProvenance, reason)
	}
	if pred.BuildDefinition.ExternalParameters == nil {
		reason := "SLSA predicate missing required buildDefinition.externalParameters object"
		return Result{
			Status:            verification.StatusInvalid,
			AttestationPath:   path,
			AttestationDigest: attDigest,
			Reason:            reason,
		}, fmt.Errorf("%w: %s", ErrInvalidSLSAProvenance, reason)
	}
	if opts.RequireResolvedDependencies && len(pred.BuildDefinition.ResolvedDependencies) == 0 {
		reason := "SLSA predicate missing required buildDefinition.resolvedDependencies (materials)"
		return Result{
			Status:            verification.StatusInvalid,
			AttestationPath:   path,
			AttestationDigest: attDigest,
			Reason:            reason,
		}, fmt.Errorf("%w: %s", ErrInvalidSLSAProvenance, reason)
	}
	for i, dep := range pred.BuildDefinition.ResolvedDependencies {
		if strings.TrimSpace(dep.URI) == "" && strings.TrimSpace(dep.Name) == "" && len(dep.Digest) == 0 {
			reason := fmt.Sprintf("SLSA resolvedDependencies[%d] must specify uri, name, or digest", i)
			return Result{
				Status:            verification.StatusInvalid,
				AttestationPath:   path,
				AttestationDigest: attDigest,
				Reason:            reason,
			}, fmt.Errorf("%w: %s", ErrInvalidSLSAProvenance, reason)
		}
		if shaHex, ok := dep.Digest["sha256"]; ok {
			if err := digest.Validate(digest.Prefix + strings.ToLower(strings.TrimSpace(shaHex))); err != nil {
				reason := fmt.Sprintf("SLSA resolvedDependencies[%d] has invalid sha256 digest %q", i, shaHex)
				return Result{
					Status:            verification.StatusInvalid,
					AttestationPath:   path,
					AttestationDigest: attDigest,
					Reason:            reason,
				}, fmt.Errorf("%w: %s", ErrInvalidSLSAProvenance, reason)
			}
		}
	}

	if len(opts.ExpectedBuilderIDs) > 0 {
		allowed := false
		for _, exp := range opts.ExpectedBuilderIDs {
			if exp == builderID {
				allowed = true
				break
			}
		}
		if !allowed {
			reason := fmt.Sprintf("SLSA builder.id %q is not in policy trusted builders %v", builderID, opts.ExpectedBuilderIDs)
			return Result{
				Status:                  verification.StatusUntrusted,
				AttestationPath:         path,
				AttestationDigest:       attDigest,
				BuilderID:               builderID,
				BuildType:               buildType,
				ResolvedDependencyCount: len(pred.BuildDefinition.ResolvedDependencies),
				Reason:                  reason,
			}, fmt.Errorf("%w: %s", ErrInvalidSLSAProvenance, reason)
		}
	}

	return Result{
		Status:                  verification.StatusVerified,
		AttestationPath:         path,
		AttestationDigest:       attDigest,
		BuilderID:               builderID,
		BuildType:               buildType,
		ResolvedDependencyCount: len(pred.BuildDefinition.ResolvedDependencies),
		SignerID:                envVer.MatchedSignerID,
		SignerFingerprint:       envVer.SignerFingerprint,
		Reason:                  fmt.Sprintf("verified upstream SLSA v1.2 provenance from builder %q", builderID),
	}, nil
}
