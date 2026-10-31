// Package config parses and validates release qualification policies (policy.yaml)
// and resolves trusted signer public keys.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/devenes/ai-model-provenance-gate/internal/digest"
	"github.com/devenes/ai-model-provenance-gate/internal/signing"
	"github.com/devenes/ai-model-provenance-gate/internal/verification"
)

const (
	// PolicySchemaVersionV1 is the versioned identifier for policy.yaml.
	PolicySchemaVersionV1 = "v1"
	// DecisionModeStrict enforces fail-closed evaluation with no policy exceptions.
	DecisionModeStrict = "strict"
	// DecisionModeAudit evaluates all fail-closed policy rules without exceptions while recording audit mode.
	DecisionModeAudit = "audit"
	// DecisionModePermissive allows explicit, auditable policy exceptions.
	DecisionModePermissive = "permissive"
)

var (
	// ErrInvalidPolicy is returned when a policy YAML file fails schema or semantic validation.
	ErrInvalidPolicy = errors.New("invalid release policy configuration")
)

// TrustedSignerConfig declares an authorized public key in policy.yaml.
type TrustedSignerConfig struct {
	ID                       string `yaml:"id" json:"id"`
	Name                     string `yaml:"name,omitempty" json:"name,omitempty"`
	Role                     string `yaml:"role,omitempty" json:"role,omitempty"`
	AllowOperatorEndorsement bool   `yaml:"allow_operator_endorsement,omitempty" json:"allow_operator_endorsement,omitempty"`
	KeyID                    string `yaml:"key_id,omitempty" json:"key_id,omitempty"`
	KeyFingerprint           string `yaml:"key_fingerprint,omitempty" json:"key_fingerprint,omitempty"`
	PublicKeyPath            string `yaml:"public_key_path" json:"public_key_path"`
}

// BundlePolicyConfig configures model bundle hygiene and LoRA verification rules.
type BundlePolicyConfig struct {
	RejectSymlinks               bool  `yaml:"reject_symlinks" json:"reject_symlinks"`
	RequireDeterministicIdentity bool  `yaml:"require_deterministic_identity" json:"require_deterministic_identity"`
	AllowUnknownFiles            *bool `yaml:"allow_unknown_files,omitempty" json:"allow_unknown_files,omitempty"`
	RequireVerifiedLoRABase      bool  `yaml:"require_verified_lora_base,omitempty" json:"require_verified_lora_base,omitempty"`
}

// SigningPolicyConfig configures OpenSSF Model Signing (OMS) verification rules.
type SigningPolicyConfig struct {
	RequireOMS     bool                  `yaml:"require_oms" json:"require_oms"`
	OMSMode        string                `yaml:"oms_mode,omitempty" json:"oms_mode,omitempty"`
	TrustedSigners []TrustedSignerConfig `yaml:"trusted_signers" json:"trusted_signers"`
}

// EvaluationPolicyConfig configures LLM Release Gate evaluation binding and authenticity rules.
type EvaluationPolicyConfig struct {
	Required               *bool                 `yaml:"required,omitempty" json:"required,omitempty"`
	RequiredStatus         string                `yaml:"required_status" json:"required_status"`
	RequireArtifactBinding bool                  `yaml:"require_artifact_binding" json:"require_artifact_binding"`
	RequireTrustedEvidence bool                  `yaml:"require_trusted_evidence" json:"require_trusted_evidence"`
	AllowPostHocBinding    bool                  `yaml:"allow_post_hoc_binding,omitempty" json:"allow_post_hoc_binding,omitempty"`
	MaxAgeHours            int                   `yaml:"max_age_hours,omitempty" json:"max_age_hours,omitempty"`
	ExpectedSuiteDigest    string                `yaml:"expected_suite_digest,omitempty" json:"expected_suite_digest,omitempty"`
	ExpectedDatasetDigest  string                `yaml:"expected_dataset_digest,omitempty" json:"expected_dataset_digest,omitempty"`
	TrustedSigners         []TrustedSignerConfig `yaml:"trusted_signers,omitempty" json:"trusted_signers,omitempty"`
}

// ProvenancePolicyConfig configures optional upstream SLSA build provenance verification.
type ProvenancePolicyConfig struct {
	RequireUpstreamSLSA bool                  `yaml:"require_upstream_slsa,omitempty" json:"require_upstream_slsa,omitempty"`
	TrustedBuilders     []string              `yaml:"trusted_builders,omitempty" json:"trusted_builders,omitempty"`
	TrustedSigners      []TrustedSignerConfig `yaml:"trusted_signers,omitempty" json:"trusted_signers,omitempty"`
}

// ScannerPolicyConfig configures optional ModelScan serialization scanning.
type ScannerPolicyConfig struct {
	Required bool `yaml:"required" json:"required"`
}

// DeploymentPolicyConfig configures deployment composition verification rules.
type DeploymentPolicyConfig struct {
	RequireImmutableImage bool     `yaml:"require_immutable_image" json:"require_immutable_image"`
	RequireServingConfig  bool     `yaml:"require_serving_config,omitempty" json:"require_serving_config,omitempty"`
	AllowedAdapters       []string `yaml:"allowed_adapters,omitempty" json:"allowed_adapters,omitempty"`
}

// PolicyException defines an explicit, auditable exception to a policy rule.
type PolicyException struct {
	ID         string `yaml:"id" json:"id"`
	Rule       string `yaml:"rule" json:"rule"`
	Reason     string `yaml:"reason" json:"reason"`
	ApprovedBy string `yaml:"approved_by" json:"approved_by"`
	ExpiresAt  string `yaml:"expires_at,omitempty" json:"expires_at,omitempty"`
}

// ReleasePolicyConfig configures the overall decision mode and release attestation signers.
type ReleasePolicyConfig struct {
	DecisionMode               string                `yaml:"decision_mode" json:"decision_mode"`
	RequireSignedQualification bool                  `yaml:"require_signed_qualification,omitempty" json:"require_signed_qualification,omitempty"`
	TrustedSigners             []TrustedSignerConfig `yaml:"trusted_signers,omitempty" json:"trusted_signers,omitempty"`
	Exceptions                 []PolicyException     `yaml:"exceptions,omitempty" json:"exceptions,omitempty"`
}

// Policy represents a parsed and validated release policy.
type Policy struct {
	SchemaVersion string                 `yaml:"schema_version" json:"schema_version"`
	Name          string                 `yaml:"name,omitempty" json:"name,omitempty"`
	Bundle        BundlePolicyConfig     `yaml:"bundle" json:"bundle"`
	Signing       SigningPolicyConfig    `yaml:"signing" json:"signing"`
	Evaluation    EvaluationPolicyConfig `yaml:"evaluation" json:"evaluation"`
	Provenance    ProvenancePolicyConfig `yaml:"provenance,omitempty" json:"provenance,omitempty"`
	Scanner       ScannerPolicyConfig    `yaml:"scanner" json:"scanner"`
	Deployment    DeploymentPolicyConfig `yaml:"deployment" json:"deployment"`
	Release       ReleasePolicyConfig    `yaml:"release" json:"release"`

	// Computed fields
	Digest  string `yaml:"-" json:"digest"`
	BaseDir string `yaml:"-" json:"-"`
}

// StrictDefaultPolicy returns the fail-closed default policy when no policy file is provided.
func StrictDefaultPolicy() Policy {
	t := true
	p := Policy{
		SchemaVersion: PolicySchemaVersionV1,
		Name:          "strict-default",
		Bundle: BundlePolicyConfig{
			RejectSymlinks:               true,
			RequireDeterministicIdentity: true,
			AllowUnknownFiles:            &t,
		},
		Signing: SigningPolicyConfig{
			RequireOMS:     true,
			OMSMode:        "native",
			TrustedSigners: nil,
		},
		Evaluation: EvaluationPolicyConfig{
			Required:               &t,
			RequiredStatus:         "PASS",
			RequireArtifactBinding: true,
			RequireTrustedEvidence: true,
		},
		Scanner: ScannerPolicyConfig{
			Required: false,
		},
		Deployment: DeploymentPolicyConfig{
			RequireImmutableImage: true,
		},
		Release: ReleasePolicyConfig{
			DecisionMode: DecisionModeStrict,
		},
	}
	raw, _ := yaml.Marshal(p)
	p.Digest = digest.ComputeNormalizedText(raw)
	return p
}

// LoadPolicy reads, strictly decodes (`KnownFields(true)`), and validates a policy YAML file.
func LoadPolicy(path string) (Policy, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Policy{}, fmt.Errorf("read policy %q: %w", path, err)
	}
	p, err := ParsePolicyBytes(raw, filepath.Dir(path))
	if err != nil {
		return Policy{}, fmt.Errorf("policy %q: %w", path, err)
	}
	return p, nil
}

// ParsePolicyBytes parses and validates YAML policy bytes.
func ParsePolicyBytes(raw []byte, baseDir string) (Policy, error) {
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	var p Policy
	if err := dec.Decode(&p); err != nil {
		return Policy{}, fmt.Errorf("%w: %v", ErrInvalidPolicy, err)
	}
	p.Digest = digest.ComputeNormalizedText(raw)
	p.BaseDir = baseDir
	if err := p.Validate(); err != nil {
		return Policy{}, err
	}
	return p, nil
}

// Validate checks semantic invariants of the Policy.
func (p *Policy) Validate() error {
	if p.SchemaVersion != PolicySchemaVersionV1 {
		return fmt.Errorf("%w: schema_version must be %q, got %q", ErrInvalidPolicy, PolicySchemaVersionV1, p.SchemaVersion)
	}
	if !p.Bundle.RequireDeterministicIdentity {
		return fmt.Errorf("%w: bundle.require_deterministic_identity must be true", ErrInvalidPolicy)
	}
	if p.Signing.OMSMode != "" && p.Signing.OMSMode != "native" && p.Signing.OMSMode != "external-cli" {
		return fmt.Errorf("%w: unsupported signing.oms_mode %q", ErrInvalidPolicy, p.Signing.OMSMode)
	}
	if p.Evaluation.RequiredStatus != "PASS" {
		return fmt.Errorf("%w: evaluation.required_status must be \"PASS\", got %q", ErrInvalidPolicy, p.Evaluation.RequiredStatus)
	}
	if p.Evaluation.MaxAgeHours < 0 {
		return fmt.Errorf("%w: evaluation.max_age_hours must be >= 0, got %d", ErrInvalidPolicy, p.Evaluation.MaxAgeHours)
	}
	if p.Evaluation.ExpectedSuiteDigest != "" {
		if err := digest.Validate(p.Evaluation.ExpectedSuiteDigest); err != nil {
			return fmt.Errorf("%w: evaluation.expected_suite_digest: %v", ErrInvalidPolicy, err)
		}
	}
	if p.Evaluation.ExpectedDatasetDigest != "" {
		if err := digest.Validate(p.Evaluation.ExpectedDatasetDigest); err != nil {
			return fmt.Errorf("%w: evaluation.expected_dataset_digest: %v", ErrInvalidPolicy, err)
		}
	}
	switch p.Release.DecisionMode {
	case DecisionModeStrict, DecisionModeAudit, DecisionModePermissive:
	default:
		return fmt.Errorf("%w: release.decision_mode must be %q, %q, or %q, got %q", ErrInvalidPolicy, DecisionModeStrict, DecisionModeAudit, DecisionModePermissive, p.Release.DecisionMode)
	}
	if (p.Release.DecisionMode == DecisionModeStrict || p.Release.DecisionMode == DecisionModeAudit) && len(p.Release.Exceptions) > 0 {
		return fmt.Errorf("%w: policy exceptions are not permitted when release.decision_mode is %q", ErrInvalidPolicy, p.Release.DecisionMode)
	}
	if (p.Release.DecisionMode == DecisionModeStrict || p.Release.DecisionMode == DecisionModeAudit) && p.Evaluation.AllowPostHocBinding {
		return fmt.Errorf("%w: evaluation.allow_post_hoc_binding is not permitted when release.decision_mode is %q", ErrInvalidPolicy, p.Release.DecisionMode)
	}
	for _, ex := range p.Release.Exceptions {
		if strings.TrimSpace(ex.ID) == "" || strings.TrimSpace(ex.Rule) == "" || strings.TrimSpace(ex.Reason) == "" || strings.TrimSpace(ex.ApprovedBy) == "" {
			return fmt.Errorf("%w: policy exception requires id, rule, reason, and approved_by", ErrInvalidPolicy)
		}
		if strings.TrimSpace(ex.ExpiresAt) != "" {
			if _, err := time.Parse(time.RFC3339, strings.TrimSpace(ex.ExpiresAt)); err != nil {
				return fmt.Errorf("%w: policy exception %q expires_at must be valid RFC3339 timestamp: %v", ErrInvalidPolicy, ex.ID, err)
			}
		}
	}
	allSigners := append([]TrustedSignerConfig{}, p.Signing.TrustedSigners...)
	allSigners = append(allSigners, p.Evaluation.TrustedSigners...)
	allSigners = append(allSigners, p.Provenance.TrustedSigners...)
	allSigners = append(allSigners, p.Release.TrustedSigners...)
	for _, ts := range allSigners {
		if strings.TrimSpace(ts.ID) == "" || strings.TrimSpace(ts.PublicKeyPath) == "" {
			return fmt.Errorf("%w: trusted_signer requires id and public_key_path", ErrInvalidPolicy)
		}
		if ts.KeyFingerprint != "" {
			if err := digest.Validate(ts.KeyFingerprint); err != nil {
				return fmt.Errorf("%w: trusted_signer %q key_fingerprint: %v", ErrInvalidPolicy, ts.ID, err)
			}
		}
	}
	return nil
}

// IsEvaluationRequired returns whether evaluation evidence is required (defaults to true).
func (p Policy) IsEvaluationRequired() bool {
	if p.Evaluation.Required == nil {
		return true
	}
	return *p.Evaluation.Required
}

// IsUnknownFileAllowed returns whether unknown regular files are permitted in the bundle (defaults to true).
func (p Policy) IsUnknownFileAllowed() bool {
	if p.Bundle.AllowUnknownFiles == nil {
		return true
	}
	return *p.Bundle.AllowUnknownFiles
}

// FindException returns the matching non-expired PolicyException for ruleCode when in permissive mode.
func (p Policy) FindException(ruleCode string) (PolicyException, bool) {
	return p.FindExceptionAt(ruleCode, time.Now().UTC())
}

// FindExceptionAt returns the matching non-expired PolicyException for ruleCode at the specified timestamp.
func (p Policy) FindExceptionAt(ruleCode string, now time.Time) (PolicyException, bool) {
	if p.Release.DecisionMode != DecisionModePermissive {
		return PolicyException{}, false
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	for _, ex := range p.Release.Exceptions {
		if ex.Rule != ruleCode {
			continue
		}
		if strings.TrimSpace(ex.ExpiresAt) != "" {
			expTime, err := time.Parse(time.RFC3339, strings.TrimSpace(ex.ExpiresAt))
			if err != nil || now.After(expTime) {
				continue
			}
		}
		return ex, true
	}
	return PolicyException{}, false
}

// FindExpiredException returns an expired PolicyException for ruleCode if one exists in permissive mode.
func (p Policy) FindExpiredException(ruleCode string, now time.Time) (PolicyException, bool) {
	if p.Release.DecisionMode != DecisionModePermissive {
		return PolicyException{}, false
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	for _, ex := range p.Release.Exceptions {
		if ex.Rule != ruleCode || strings.TrimSpace(ex.ExpiresAt) == "" {
			continue
		}
		expTime, err := time.Parse(time.RFC3339, strings.TrimSpace(ex.ExpiresAt))
		if err != nil || now.After(expTime) {
			return ex, true
		}
	}
	return PolicyException{}, false
}

// ResolveTrustedSigners loads PEM public keys for a slice of TrustedSignerConfig entries.
func ResolveTrustedSigners(configs []TrustedSignerConfig, baseDir string, extraPublicKeyPaths []string) ([]verification.TrustedSignerRule, error) {
	var rules []verification.TrustedSignerRule
	for _, cfg := range configs {
		keyPath := cfg.PublicKeyPath
		if !filepath.IsAbs(keyPath) && baseDir != "" {
			keyPath = filepath.Join(baseDir, keyPath)
		}
		pub, err := signing.LoadPublicKeyFile(keyPath, cfg.KeyID, cfg.Name)
		if err != nil {
			return nil, fmt.Errorf("load trusted signer %q public key %q: %w", cfg.ID, keyPath, err)
		}
		rules = append(rules, verification.TrustedSignerRule{
			ID:                       cfg.ID,
			Name:                     cfg.Name,
			Role:                     cfg.Role,
			AllowOperatorEndorsement: cfg.AllowOperatorEndorsement,
			KeyID:                    cfg.KeyID,
			KeyFingerprint:           cfg.KeyFingerprint,
			PublicKey:                pub,
		})
	}
	for i, p := range extraPublicKeyPaths {
		if strings.TrimSpace(p) == "" {
			continue
		}
		id := fmt.Sprintf("cli-public-key-%d", i+1)
		pub, err := signing.LoadPublicKeyFile(p, "", id)
		if err != nil {
			return nil, fmt.Errorf("load CLI public key %q: %w", p, err)
		}
		rules = append(rules, verification.TrustedSignerRule{
			ID:             id,
			Name:           p,
			KeyFingerprint: pub.Fingerprint,
			PublicKey:      pub,
		})
	}
	return rules, nil
}
