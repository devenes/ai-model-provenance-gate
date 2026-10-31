// Package deployment implements local Deployment Composition Identity (deployment-composition/v1)
// derivation and pre-deployment verification against a signed Release Qualification Attestation.
package deployment

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/devenes/ai-model-provenance-gate/internal/attestation"
	"github.com/devenes/ai-model-provenance-gate/internal/bundle"
	"github.com/devenes/ai-model-provenance-gate/internal/config"
	"github.com/devenes/ai-model-provenance-gate/internal/digest"
	"github.com/devenes/ai-model-provenance-gate/internal/identity"
	"github.com/devenes/ai-model-provenance-gate/internal/policy"
	"github.com/devenes/ai-model-provenance-gate/internal/signing"
	"github.com/devenes/ai-model-provenance-gate/internal/verification"
	"github.com/devenes/ai-model-provenance-gate/internal/version"
)

var (
	// ErrInvalidDeploymentDescriptor is returned when a deployment YAML/JSON descriptor is malformed.
	ErrInvalidDeploymentDescriptor = errors.New("invalid deployment composition descriptor")
	// ErrDeploymentVerificationFailed is returned when deployment composition verification fails.
	ErrDeploymentVerificationFailed = errors.New("deployment composition verification failed")
)

// Descriptor represents a local deployment composition descriptor (deployment.yaml).
type Descriptor struct {
	SchemaVersion       string            `yaml:"schema_version" json:"schema_version"`
	Name                string            `yaml:"name,omitempty" json:"name,omitempty"`
	ModelBundleID       string            `yaml:"model_bundle_id" json:"model_bundle_id"`
	BaseModelBundleID   string            `yaml:"base_model_bundle_id,omitempty" json:"base_model_bundle_id,omitempty"`
	RuntimeImage        string            `yaml:"runtime_image" json:"runtime_image"`
	RuntimeProfile      string            `yaml:"runtime_profile,omitempty" json:"runtime_profile,omitempty"`
	ServingConfigPath   string            `yaml:"serving_config_path,omitempty" json:"serving_config_path,omitempty"`
	ServingConfigDigest string            `yaml:"serving_config_digest,omitempty" json:"serving_config_digest,omitempty"`
	ActiveAdapters      []string          `yaml:"active_adapters,omitempty" json:"active_adapters,omitempty"`
	ServingParameters   map[string]string `yaml:"serving_parameters,omitempty" json:"serving_parameters,omitempty"`

	// BaseDir is the directory containing the descriptor file for resolving relative serving_config_path.
	BaseDir string `yaml:"-" json:"-"`
}

// CanonicalCompositionDocument is the RFC 8785 (JCS) payload used to derive the Deployment Composition Identity.
type CanonicalCompositionDocument struct {
	ActiveAdapters      []string          `json:"active_adapters,omitempty"`
	BaseModelBundleID   string            `json:"base_model_bundle_id,omitempty"`
	ModelBundleID       string            `json:"model_bundle_id"`
	RuntimeImage        string            `json:"runtime_image"`
	RuntimeProfile      string            `json:"runtime_profile,omitempty"`
	SchemaVersion       string            `json:"schema_version"`
	ServingConfigDigest string            `json:"serving_config_digest,omitempty"`
	ServingParameters   map[string]string `json:"serving_parameters,omitempty"`
}

// LoadDescriptor reads and strictly parses a deployment YAML/JSON descriptor file.
func LoadDescriptor(path string) (Descriptor, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Descriptor{}, fmt.Errorf("read deployment descriptor %q: %w", path, err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	var d Descriptor
	if err := dec.Decode(&d); err != nil {
		return Descriptor{}, fmt.Errorf("%w (%q): %v", ErrInvalidDeploymentDescriptor, path, err)
	}
	d.BaseDir = filepath.Dir(path)
	if d.SchemaVersion != version.DeploymentCompositionSchemaVersion {
		return Descriptor{}, fmt.Errorf(
			"%w: schema_version must be %q, got %q",
			ErrInvalidDeploymentDescriptor, version.DeploymentCompositionSchemaVersion, d.SchemaVersion,
		)
	}
	return d, nil
}

// ComputeCompositionID derives the deterministic deployment-composition/v1 digest (distinct from bundle-identity/v1).
func ComputeCompositionID(d Descriptor) (string, []byte, error) {
	adapters := append([]string(nil), d.ActiveAdapters...)
	sort.Strings(adapters)

	doc := CanonicalCompositionDocument{
		SchemaVersion:       version.DeploymentCompositionSchemaVersion,
		ModelBundleID:       d.ModelBundleID,
		BaseModelBundleID:   d.BaseModelBundleID,
		RuntimeImage:        d.RuntimeImage,
		RuntimeProfile:      d.RuntimeProfile,
		ServingConfigDigest: d.ServingConfigDigest,
		ActiveAdapters:      adapters,
		ServingParameters:   d.ServingParameters,
	}
	canon, err := identity.CanonicalizeStruct(doc)
	if err != nil {
		return "", nil, fmt.Errorf("canonicalize deployment composition: %w", err)
	}
	return digest.ComputeBytes(canon), canon, nil
}

// VerifyOptions configures pre-deployment composition verification (`release verify`).
type VerifyOptions struct {
	BundlePath             string
	BaseBundlePath         string
	DescriptorPath         string
	AttestationPath        string
	Policy                 config.Policy
	TrustedSigners         []verification.TrustedSignerRule
	CandidateUntrustedKeys []*signing.PublicKey
}

// VerificationResult holds the complete outcome of `release verify`.
type VerificationResult struct {
	GateStatus                  policy.GateStatus                 `json:"gate_status"`
	ExitCode                    int                               `json:"exit_code"`
	BundleID                    string                            `json:"bundle_id"`
	CompositionID               string                            `json:"composition_id,omitempty"`
	AttestedBundleID            string                            `json:"attested_bundle_id,omitempty"`
	DescriptorBundleID          string                            `json:"descriptor_bundle_id,omitempty"`
	RuntimeImage                string                            `json:"runtime_image,omitempty"`
	RuntimeImageImmutable       bool                              `json:"runtime_image_immutable"`
	ExpectedServingConfigDigest string                            `json:"expected_serving_config_digest,omitempty"`
	ObservedServingConfigDigest string                            `json:"observed_serving_config_digest,omitempty"`
	ActiveAdapters              []string                          `json:"active_adapters,omitempty"`
	QualificationVerification   attestation.VerifiedQualification `json:"qualification_verification"`
	Reasons                     []policy.DecisionReason           `json:"reasons"`
	ScopeLimitation             string                            `json:"scope_limitation"`
}

const deploymentScopeDisclaimer = "Verifies local deployment descriptor and local model bundle contents offline; does NOT query or verify live Kubernetes workloads or cloud control planes."

// Verify executes pre-deployment verification of a model bundle, signed release qualification attestation,
// and optional deployment composition descriptor.
func Verify(opts VerifyOptions) (VerificationResult, error) {
	var reasons []policy.DecisionReason
	hasFail := false
	hasBlocked := false

	addReason := func(code, category string, st policy.GateStatus, msg string) {
		sev := "info"
		switch st {
		case policy.StatusFail:
			hasFail = true
			sev = "error"
		case policy.StatusBlocked:
			hasBlocked = true
			sev = "error"
		}
		reasons = append(reasons, policy.DecisionReason{
			Code:     code,
			Category: category,
			Severity: sev,
			Status:   string(st),
			Message:  msg,
		})
	}

	// 1. Re-inspect the deployment model bundle directory to compute its actual current bundle-identity/v1.
	inspOpts := bundle.DefaultInspectOptions()
	inspOpts.BaseBundlePath = opts.BaseBundlePath
	insp, err := bundle.Inspect(opts.BundlePath, inspOpts)
	if err != nil {
		addReason("DEPLOYMENT_BUNDLE_INSPECTION_FAILED", "bundle", policy.StatusFail, err.Error())
		return VerificationResult{
			GateStatus:      policy.StatusFail,
			ExitCode:        policy.ExitFail,
			Reasons:         reasons,
			ScopeLimitation: deploymentScopeDisclaimer,
		}, err
	}
	addReason(
		"DEPLOYMENT_BUNDLE_INSPECTED",
		"bundle",
		policy.StatusPass,
		fmt.Sprintf("re-computed live model bundle identity %s (%d files, %d bytes)", insp.BundleID, insp.Manifest.FileCount, insp.Manifest.TotalBytes),
	)

	// 2. Verify the signed Release Qualification Attestation against trusted release signers and the live bundle ID.
	qualVer, qualErr := attestation.VerifyQualificationFile(
		opts.AttestationPath,
		insp.BundleID,
		opts.TrustedSigners,
		opts.CandidateUntrustedKeys,
	)
	if qualErr != nil {
		switch qualVer.Status {
		case verification.StatusMissing, verification.StatusBlocked:
			addReason("RELEASE_ATTESTATION_BLOCKED", "attestation", policy.StatusBlocked, qualVer.Reason)
		case verification.StatusUntrusted:
			addReason("RELEASE_ATTESTATION_UNTRUSTED_SIGNER", "attestation", policy.StatusFail, qualVer.Reason)
		default:
			if qualVer.SubjectBundleID != "" && qualVer.SubjectBundleID != insp.BundleID {
				addReason("DEPLOYMENT_ARTIFACT_TAMPERED", "attestation", policy.StatusFail, qualVer.Reason)
			} else {
				addReason("RELEASE_ATTESTATION_INVALID", "attestation", policy.StatusFail, qualVer.Reason)
			}
		}
	} else {
		addReason(
			"RELEASE_ATTESTATION_VERIFIED",
			"attestation",
			policy.StatusPass,
			fmt.Sprintf("verified signed release qualification attestation (%s) matching bundle %s", qualVer.SignerFingerprint, insp.BundleID),
		)
	}

	res := VerificationResult{
		BundleID:                  insp.BundleID,
		AttestedBundleID:          qualVer.SubjectBundleID,
		QualificationVerification: qualVer,
		ScopeLimitation:           deploymentScopeDisclaimer,
	}

	// 3. If a deployment descriptor (`--deployment`) is supplied, verify all composition bindings.
	if strings.TrimSpace(opts.DescriptorPath) != "" {
		desc, dErr := LoadDescriptor(opts.DescriptorPath)
		if dErr != nil {
			addReason("DEPLOYMENT_DESCRIPTOR_INVALID", "deployment", policy.StatusBlocked, dErr.Error())
		} else {
			res.DescriptorBundleID = desc.ModelBundleID
			res.RuntimeImage = desc.RuntimeImage
			res.ExpectedServingConfigDigest = desc.ServingConfigDigest
			res.ActiveAdapters = desc.ActiveAdapters

			// 3a. Verify descriptor model_bundle_id matches live bundle_id.
			if strings.TrimSpace(desc.ModelBundleID) == "" {
				addReason("DEPLOYMENT_MISSING_MODEL_BUNDLE_ID", "deployment", policy.StatusBlocked, "deployment descriptor is missing model_bundle_id")
			} else if desc.ModelBundleID != insp.BundleID {
				addReason(
					"DEPLOYMENT_DESCRIPTOR_BUNDLE_MISMATCH",
					"deployment",
					policy.StatusFail,
					fmt.Sprintf("deployment descriptor model_bundle_id %s does not match live bundle %s", desc.ModelBundleID, insp.BundleID),
				)
			} else {
				addReason("DEPLOYMENT_DESCRIPTOR_BUNDLE_MATCHED", "deployment", policy.StatusPass, "deployment descriptor model_bundle_id matches live bundle")
			}

			// 3b. Verify runtime image immutability and correspondence with attestation runtime if recorded.
			if strings.TrimSpace(desc.RuntimeImage) == "" {
				addReason("DEPLOYMENT_MISSING_RUNTIME_IMAGE", "deployment", policy.StatusBlocked, "deployment descriptor is missing runtime_image")
			} else {
				immutable := policy.IsImmutableOCIRef(desc.RuntimeImage)
				res.RuntimeImageImmutable = immutable
				if opts.Policy.Deployment.RequireImmutableImage && !immutable {
					addReason(
						"DEPLOYMENT_RUNTIME_IMAGE_MUTABLE",
						"deployment",
						policy.StatusFail,
						fmt.Sprintf("deployment runtime_image %q uses a mutable tag without an immutable @sha256:<64-hex> digest", desc.RuntimeImage),
					)
				} else if qualVer.Predicate.Runtime != nil && qualVer.Predicate.Runtime.RuntimeImage != "" && qualVer.Predicate.Runtime.RuntimeImage != desc.RuntimeImage {
					addReason(
						"DEPLOYMENT_RUNTIME_IMAGE_CHANGED",
						"deployment",
						policy.StatusFail,
						fmt.Sprintf("deployment runtime_image %q differs from attested runtime_image %q", desc.RuntimeImage, qualVer.Predicate.Runtime.RuntimeImage),
					)
				} else {
					addReason(
						"DEPLOYMENT_RUNTIME_IMAGE_VERIFIED",
						"deployment",
						policy.StatusPass,
						fmt.Sprintf("verified deployment runtime image %q", desc.RuntimeImage),
					)
				}
			}

			// 3c. Verify serving configuration file and digest.
			if opts.Policy.Deployment.RequireServingConfig && strings.TrimSpace(desc.ServingConfigDigest) == "" && strings.TrimSpace(desc.ServingConfigPath) == "" {
				addReason(
					"DEPLOYMENT_SERVING_CONFIG_MISSING",
					"deployment",
					policy.StatusBlocked,
					"policy requires serving configuration verification, but serving_config_path / serving_config_digest is missing",
				)
			} else if strings.TrimSpace(desc.ServingConfigPath) != "" {
				cfgPath := desc.ServingConfigPath
				if !filepath.IsAbs(cfgPath) && desc.BaseDir != "" {
					cfgPath = filepath.Join(desc.BaseDir, cfgPath)
				}
				rawCfg, readErr := os.ReadFile(cfgPath)
				if readErr != nil {
					addReason(
						"DEPLOYMENT_SERVING_CONFIG_MISSING",
						"deployment",
						policy.StatusBlocked,
						fmt.Sprintf("required serving configuration file %q could not be read: %v", cfgPath, readErr),
					)
				} else {
					obsDigest := digest.ComputeNormalizedText(rawCfg)
					res.ObservedServingConfigDigest = obsDigest
					if desc.ServingConfigDigest != "" && obsDigest != desc.ServingConfigDigest {
						addReason(
							"DEPLOYMENT_SERVING_CONFIG_MODIFIED",
							"deployment",
							policy.StatusFail,
							fmt.Sprintf("serving configuration %q digest %s does not match expected %s", desc.ServingConfigPath, obsDigest, desc.ServingConfigDigest),
						)
					} else if qualVer.Predicate.Runtime != nil && qualVer.Predicate.Runtime.ServingConfigDigest != "" && obsDigest != qualVer.Predicate.Runtime.ServingConfigDigest {
						addReason(
							"DEPLOYMENT_SERVING_CONFIG_MODIFIED",
							"deployment",
							policy.StatusFail,
							fmt.Sprintf("serving configuration %q digest %s differs from attested serving_config_digest %s", desc.ServingConfigPath, obsDigest, qualVer.Predicate.Runtime.ServingConfigDigest),
						)
					} else {
						desc.ServingConfigDigest = obsDigest
						addReason(
							"DEPLOYMENT_SERVING_CONFIG_VERIFIED",
							"deployment",
							policy.StatusPass,
							fmt.Sprintf("verified serving configuration digest %s", obsDigest),
						)
					}
				}
			}

			// 3d. Verify active LoRA adapters against policy allowed_adapters if configured.
			if len(opts.Policy.Deployment.AllowedAdapters) > 0 {
				allowedSet := make(map[string]bool, len(opts.Policy.Deployment.AllowedAdapters))
				for _, a := range opts.Policy.Deployment.AllowedAdapters {
					allowedSet[a] = true
				}
				for _, active := range desc.ActiveAdapters {
					if !allowedSet[active] {
						addReason(
							"DEPLOYMENT_ADAPTER_NOT_ALLOWED",
							"deployment",
							policy.StatusFail,
							fmt.Sprintf("active adapter %q is not in policy.deployment.allowed_adapters %v", active, opts.Policy.Deployment.AllowedAdapters),
						)
					}
				}
			}

			// 3e. Compute deterministic Deployment Composition Identity (deployment-composition/v1).
			compID, _, compErr := ComputeCompositionID(desc)
			if compErr == nil {
				res.CompositionID = compID
				if res.CompositionID == res.BundleID {
					addReason("DEPLOYMENT_IDENTITY_COLLISION", "deployment", policy.StatusFail, "composition_id must never equal bundle_id")
				}
			}
		}
	}

	finalStatus := policy.StatusPass
	switch {
	case hasFail:
		finalStatus = policy.StatusFail
	case hasBlocked:
		finalStatus = policy.StatusBlocked
	}
	res.GateStatus = finalStatus
	res.ExitCode = policy.ExitCodeForStatus(finalStatus)
	res.Reasons = reasons

	if finalStatus != policy.StatusPass {
		return res, fmt.Errorf("%w: gate_status=%s", ErrDeploymentVerificationFailed, finalStatus)
	}
	return res, nil
}

// WriteCompositionManifest writes the canonical deployment-composition/v1 manifest JSON file.
func WriteCompositionManifest(path string, res VerificationResult) error {
	pretty, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		return err
	}
	pretty = append(pretty, '\n')
	return os.WriteFile(path, pretty, 0o600)
}
