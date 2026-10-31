// Package bom generates and validates CycloneDX 1.6 and 1.7 AI/ML-BOM documents
// from inspected model bundles without inventing unobserved metadata.
package bom

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/CycloneDX/cyclonedx-go"

	"github.com/devenes/ai-model-provenance-gate/internal/bundle"
	"github.com/devenes/ai-model-provenance-gate/internal/digest"
	"github.com/devenes/ai-model-provenance-gate/internal/formats/peft"
	"github.com/devenes/ai-model-provenance-gate/internal/formats/safetensors"
	"github.com/devenes/ai-model-provenance-gate/internal/identity"
	"github.com/devenes/ai-model-provenance-gate/internal/inventory"
	"github.com/devenes/ai-model-provenance-gate/internal/version"
)

const (
	// SpecVersion1_6 is CycloneDX specification version 1.6.
	SpecVersion1_6 = "1.6"
	// SpecVersion1_7 is CycloneDX specification version 1.7 (default).
	SpecVersion1_7 = "1.7"

	// SchemaURI1_6 is the official JSON schema URI for CycloneDX 1.6.
	SchemaURI1_6 = "http://cyclonedx.org/schema/bom-1.6.schema.json"
	// SchemaURI1_7 is the official JSON schema URI for CycloneDX 1.7.
	SchemaURI1_7 = "http://cyclonedx.org/schema/bom-1.7.schema.json"
)

var (
	// ErrInvalidBOM is returned when a CycloneDX BOM fails schema or inventory consistency checks.
	ErrInvalidBOM = errors.New("invalid CycloneDX AI/ML-BOM")

	uuidURNPattern = regexp.MustCompile(`^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	hex64Pattern   = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// GenerateOptions configures CycloneDX AI/ML-BOM generation.
type GenerateOptions struct {
	// SpecVersion is "1.6" or "1.7" (defaults to "1.7").
	SpecVersion string
	// Timestamp overrides the metadata timestamp (defaults to current UTC time; use fixed timestamp for deterministic fixtures).
	Timestamp string
	// ModelName overrides the display name of the root model component if non-empty.
	ModelName string
}

// Property represents a CycloneDX name-value property.
type Property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Hash represents a CycloneDX cryptographic hash entry.
type Hash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

// LicenseChoice represents a CycloneDX license entry.
type LicenseChoice struct {
	License *License `json:"license,omitempty"`
}

// License represents a CycloneDX license expression or name.
type License struct {
	ID         string     `json:"id,omitempty"`
	Name       string     `json:"name,omitempty"`
	Properties []Property `json:"properties,omitempty"`
}

// ExternalReference represents a CycloneDX external reference.
type ExternalReference struct {
	Type    string `json:"type"`
	URL     string `json:"url"`
	Comment string `json:"comment,omitempty"`
}

// ModelParameters represents CycloneDX modelCard.modelParameters.
type ModelParameters struct {
	ArchitectureFamily string `json:"architectureFamily,omitempty"`
	ModelArchitecture  string `json:"modelArchitecture,omitempty"`
	Task               string `json:"task,omitempty"`
}

// ModelCard represents a CycloneDX ML model card attached to a machine-learning-model component.
type ModelCard struct {
	ModelParameters *ModelParameters `json:"modelParameters,omitempty"`
	Properties      []Property       `json:"properties,omitempty"`
}

// Pedigree represents CycloneDX component lineage (e.g., base model ancestors for a LoRA adapter).
type Pedigree struct {
	Ancestors []Component `json:"ancestors,omitempty"`
	Notes     string      `json:"notes,omitempty"`
}

// Component represents a CycloneDX component (machine-learning-model, file, data, or application).
type Component struct {
	Type               string              `json:"type"`
	BOMRef             string              `json:"bom-ref,omitempty"`
	Name               string              `json:"name"`
	Version            string              `json:"version,omitempty"`
	PURL               string              `json:"purl,omitempty"`
	Hashes             []Hash              `json:"hashes,omitempty"`
	Licenses           []LicenseChoice     `json:"licenses,omitempty"`
	ExternalReferences []ExternalReference `json:"externalReferences,omitempty"`
	ModelCard          *ModelCard          `json:"modelCard,omitempty"`
	Pedigree           *Pedigree           `json:"pedigree,omitempty"`
	Properties         []Property          `json:"properties,omitempty"`
}

// ToolMetadata represents CycloneDX 1.6/1.7 metadata.tools.
type ToolMetadata struct {
	Components []Component `json:"components"`
}

// Metadata represents the CycloneDX top-level metadata block.
type Metadata struct {
	Timestamp  string       `json:"timestamp"`
	Tools      ToolMetadata `json:"tools"`
	Component  Component    `json:"component"`
	Properties []Property   `json:"properties,omitempty"`
}

// Dependency represents a CycloneDX dependency graph edge.
type Dependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn"`
}

// Document represents a CycloneDX 1.6 / 1.7 AI/ML-BOM JSON document.
type Document struct {
	Schema       string       `json:"$schema"`
	BOMFormat    string       `json:"bomFormat"`
	SpecVersion  string       `json:"specVersion"`
	SerialNumber string       `json:"serialNumber"`
	Version      int          `json:"version"`
	Metadata     Metadata     `json:"metadata"`
	Components   []Component  `json:"components"`
	Dependencies []Dependency `json:"dependencies"`
}

// GeneratedBOM holds the structured CycloneDX Document, its serialized JSON bytes, and its SHA-256 digest.
type GeneratedBOM struct {
	Document Document `json:"document"`
	JSON     []byte   `json:"-"`
	Digest   string   `json:"digest"`
}

// Generate creates a standards-compliant CycloneDX AI/ML-BOM from a bundle InspectionResult.
func Generate(insp bundle.InspectionResult, opts GenerateOptions) (GeneratedBOM, error) {
	specVer := strings.TrimSpace(opts.SpecVersion)
	if specVer == "" {
		specVer = SpecVersion1_7
	}
	var schemaURI string
	switch specVer {
	case SpecVersion1_6:
		schemaURI = SchemaURI1_6
	case SpecVersion1_7:
		schemaURI = SchemaURI1_7
	default:
		return GeneratedBOM{}, fmt.Errorf("%w: unsupported CycloneDX specVersion %q (supported: 1.6, 1.7)", ErrInvalidBOM, specVer)
	}

	ts := strings.TrimSpace(opts.Timestamp)
	if ts == "" {
		ts = time.Now().UTC().Format(time.RFC3339)
	}

	bundleHex, err := digest.TrimPrefix(insp.BundleID)
	if err != nil {
		return GeneratedBOM{}, fmt.Errorf("extract bundle hex: %w", err)
	}

	rootRef := "model-bundle:" + bundleHex[:16]
	modelName := strings.TrimSpace(opts.ModelName)
	if modelName == "" {
		modelName = "local-model-bundle-" + bundleHex[:12]
	}

	rootProps := []Property{
		{Name: "provenance:model_bundle_id", Value: insp.BundleID},
		{Name: "provenance:manifest_digest", Value: insp.Manifest.ManifestDigest},
		{Name: "provenance:bundle_schema_version", Value: insp.Manifest.SchemaVersion},
		{Name: "provenance:primary_format", Value: insp.Manifest.FormatSummary.PrimaryFormat},
		{Name: "provenance:file_count", Value: strconv.Itoa(insp.Manifest.FileCount)},
		{Name: "provenance:total_bytes", Value: strconv.FormatInt(insp.Manifest.TotalBytes, 10)},
		{Name: "provenance:has_tokenizer", Value: strconv.FormatBool(insp.Manifest.FormatSummary.HasTokenizer)},
		{Name: "provenance:has_lora_adapter", Value: strconv.FormatBool(insp.Manifest.FormatSummary.HasLoRAAdapter)},
		{Name: "provenance:lora_verification_status", Value: string(insp.Manifest.LoRARelationship.VerificationStatus)},
	}

	var modelCard *ModelCard
	var licenses []LicenseChoice
	var extRefs []ExternalReference

	if cfg := insp.Manifest.ModelConfig; cfg != nil {
		mp := &ModelParameters{}
		hasParams := false
		if cfg.ModelType != "" {
			mp.ArchitectureFamily = cfg.ModelType
			hasParams = true
			rootProps = append(rootProps, Property{Name: "huggingface:model_type", Value: cfg.ModelType})
		}
		if len(cfg.Architectures) > 0 {
			mp.ModelArchitecture = cfg.Architectures[0]
			hasParams = true
			rootProps = append(rootProps, Property{Name: "huggingface:architecture", Value: cfg.Architectures[0]})
		}
		if cfg.TorchDType != "" {
			rootProps = append(rootProps, Property{Name: "huggingface:torch_dtype", Value: cfg.TorchDType})
		}
		if cfg.VocabSize > 0 {
			rootProps = append(rootProps, Property{Name: "huggingface:vocab_size", Value: strconv.Itoa(cfg.VocabSize)})
		}
		if cfg.DeclaredNameOrPath != "" {
			rootProps = append(rootProps,
				Property{Name: "huggingface:declared_name_or_path", Value: cfg.DeclaredNameOrPath},
				Property{Name: "provenance:declared_name_or_path_source", Value: "declared_unverified"},
			)
		}
		if cfg.HasAutoMap {
			rootProps = append(rootProps, Property{Name: "security:contains_remote_code_auto_map", Value: "true"})
		}
		if len(cfg.UnknownFields) > 0 {
			rootProps = append(rootProps, Property{
				Name:  "huggingface:preserved_unknown_config_keys",
				Value: strings.Join(cfg.UnknownFields, ","),
			})
		}
		if cfg.DeclaredLicense != "" {
			lic := &License{
				Properties: []Property{
					{Name: "provenance:license_verification", Value: "declared_unverified"},
					{Name: "provenance:license_origin", Value: cfg.Path + "#license"},
				},
			}
			if spdxID, ok := NormalizeSPDXLicense(cfg.DeclaredLicense); ok {
				lic.ID = spdxID
			} else {
				lic.Name = cfg.DeclaredLicense
			}
			licenses = append(licenses, LicenseChoice{License: lic})
			rootProps = append(rootProps, Property{Name: "provenance:license_status", Value: "declared_unverified"})
		} else {
			rootProps = append(rootProps, Property{Name: "provenance:license_status", Value: "missing"})
		}
		if hasParams {
			modelCard = &ModelCard{
				ModelParameters: mp,
				Properties: []Property{
					{Name: "provenance:source", Value: "observed"},
				},
			}
		}
	} else {
		rootProps = append(rootProps, Property{Name: "provenance:license_status", Value: "missing"})
	}

	if q := insp.Manifest.Quantization; q != nil {
		if q.QuantMethod != "" {
			rootProps = append(rootProps, Property{Name: "quantization:method", Value: q.QuantMethod})
		}
		if q.Bits > 0 {
			rootProps = append(rootProps, Property{Name: "quantization:bits", Value: strconv.Itoa(q.Bits)})
		}
		if q.GroupSize > 0 {
			rootProps = append(rootProps, Property{Name: "quantization:group_size", Value: strconv.Itoa(q.GroupSize)})
		}
		rootProps = append(rootProps, Property{Name: "quantization:source", Value: q.Source})
	}

	var pedigree *Pedigree
	if lora := insp.Manifest.LoRARelationship; lora.IsAdapter {
		if modelCard == nil {
			modelCard = &ModelCard{ModelParameters: &ModelParameters{}}
		}
		if modelCard.ModelParameters.Task == "" && lora.TaskType != "" {
			modelCard.ModelParameters.Task = lora.TaskType
		}
		ancestorProps := []Property{
			{Name: "provenance:verification_status", Value: string(lora.VerificationStatus)},
		}
		if lora.Revision != "" {
			ancestorProps = append(ancestorProps, Property{Name: "huggingface:declared_revision", Value: lora.Revision})
		}
		if lora.VerifiedBaseBundleID != "" {
			ancestorProps = append(ancestorProps, Property{Name: "provenance:verified_base_bundle_id", Value: lora.VerifiedBaseBundleID})
		}
		ancestorName := lora.BaseModelNameOrPath
		if ancestorName == "" {
			ancestorName = "undeclared-base-model"
		}
		var ancestorHashes []Hash
		if lora.VerificationStatus == peft.StatusVerified && lora.VerifiedBaseBundleID != "" {
			if baseHex, hErr := digest.TrimPrefix(lora.VerifiedBaseBundleID); hErr == nil {
				ancestorHashes = []Hash{{Alg: "SHA-256", Content: baseHex}}
			}
		}
		pedigree = &Pedigree{
			Ancestors: []Component{
				{
					Type:       "machine-learning-model",
					BOMRef:     "base-model:" + sanitizeRef(ancestorName),
					Name:       ancestorName,
					Version:    lora.Revision,
					Hashes:     ancestorHashes,
					Properties: ancestorProps,
				},
			},
			Notes: lora.VerificationNotes,
		}
		if strings.Contains(lora.BaseModelNameOrPath, "/") && !strings.HasPrefix(lora.BaseModelNameOrPath, ".") && !strings.HasPrefix(lora.BaseModelNameOrPath, "/") {
			extRefs = append(extRefs, ExternalReference{
				Type:    "distribution",
				URL:     "https://huggingface.co/" + lora.BaseModelNameOrPath,
				Comment: "declared_unverified base_model_name_or_path in adapter_config.json",
			})
		}
	}

	sortProperties(rootProps)

	rootComponent := Component{
		Type:               "machine-learning-model",
		BOMRef:             rootRef,
		Name:               modelName,
		Version:            bundleHex[:12],
		Hashes:             []Hash{{Alg: "SHA-256", Content: bundleHex}},
		Licenses:           licenses,
		ExternalReferences: extRefs,
		ModelCard:          modelCard,
		Pedigree:           pedigree,
		Properties:         rootProps,
	}

	stByPath := make(map[string]safetensors.FileInspection, len(insp.Manifest.SafetensorsFiles))
	for _, st := range insp.Manifest.SafetensorsFiles {
		stByPath[st.Path] = st
	}

	var components []Component
	var rootDependsOn []string
	var loraDependsOn []string

	for _, f := range insp.Inventory.Files {
		fHex, fErr := digest.TrimPrefix(f.SHA256)
		if fErr != nil {
			return GeneratedBOM{}, fErr
		}
		compRef := "file:" + f.Path
		props := []Property{
			{Name: "provenance:role", Value: string(f.Role)},
			{Name: "provenance:size_bytes", Value: strconv.FormatInt(f.Size, 10)},
			{Name: "provenance:source", Value: f.MetadataProvenance},
		}
		if st, ok := stByPath[f.Path]; ok {
			props = append(props,
				Property{Name: "safetensors:tensor_count", Value: strconv.Itoa(st.TensorCount)},
				Property{Name: "safetensors:header_bytes", Value: strconv.FormatUint(st.HeaderBytes, 10)},
				Property{Name: "safetensors:dtypes", Value: strings.Join(st.DTypes, ",")},
			)
		}
		sortProperties(props)

		components = append(components, Component{
			Type:   "file",
			BOMRef: compRef,
			Name:   f.Path,
			Hashes: []Hash{
				{Alg: "SHA-256", Content: fHex},
			},
			Properties: props,
		})

		if f.Role == inventory.RoleLoRAConfig || f.Role == inventory.RoleLoRAWeights || f.Role == inventory.RoleLoRAIndex {
			loraDependsOn = append(loraDependsOn, compRef)
		}
		rootDependsOn = append(rootDependsOn, compRef)
	}

	var dependencies []Dependency

	// If a PEFT/LoRA adapter is present, represent it as an explicit machine-learning-model sub-component.
	if lora := insp.Manifest.LoRARelationship; lora.IsAdapter {
		loraRef := "component:lora-adapter"
		loraProps := []Property{
			{Name: "peft:type", Value: lora.PEFTType},
			{Name: "peft:task_type", Value: lora.TaskType},
			{Name: "peft:rank", Value: strconv.Itoa(lora.Rank)},
			{Name: "peft:lora_alpha", Value: strconv.FormatFloat(lora.LoraAlpha, 'f', -1, 64)},
			{Name: "peft:target_modules", Value: strings.Join(lora.TargetModules, ",")},
			{Name: "provenance:base_model_verification_status", Value: string(lora.VerificationStatus)},
			{Name: "provenance:declared_base_model", Value: lora.BaseModelNameOrPath},
		}
		if lora.Revision != "" {
			loraProps = append(loraProps, Property{Name: "provenance:declared_base_revision", Value: lora.Revision})
		}
		if lora.VerifiedBaseBundleID != "" {
			loraProps = append(loraProps, Property{Name: "provenance:verified_base_bundle_id", Value: lora.VerifiedBaseBundleID})
		}
		sortProperties(loraProps)

		components = append(components, Component{
			Type:       "machine-learning-model",
			BOMRef:     loraRef,
			Name:       "peft-lora-adapter",
			Properties: loraProps,
		})
		rootDependsOn = append(rootDependsOn, loraRef)
		sort.Strings(loraDependsOn)
		dependencies = append(dependencies, Dependency{
			Ref:       loraRef,
			DependsOn: loraDependsOn,
		})
	}

	sort.Strings(rootDependsOn)
	dependencies = append([]Dependency{
		{
			Ref:       rootRef,
			DependsOn: rootDependsOn,
		},
	}, dependencies...)

	// Derive a deterministic UUID v5-style URN from the canonical bundle ID and specVersion.
	serialURN := deterministicUUIDURN(insp.BundleID + ":" + specVer)

	verMeta := version.Get()
	doc := Document{
		Schema:       schemaURI,
		BOMFormat:    "CycloneDX",
		SpecVersion:  specVer,
		SerialNumber: serialURN,
		Version:      1,
		Metadata: Metadata{
			Timestamp: ts,
			Tools: ToolMetadata{
				Components: []Component{
					{
						Type:    "application",
						BOMRef:  "tool:" + verMeta.Name,
						Name:    verMeta.Name,
						Version: verMeta.Version,
					},
				},
			},
			Component: rootComponent,
		},
		Components:   components,
		Dependencies: dependencies,
	}

	rawJSON, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return GeneratedBOM{}, fmt.Errorf("marshal CycloneDX BOM: %w", err)
	}
	rawJSON = append(rawJSON, '\n')

	if err := Validate(rawJSON, &insp); err != nil {
		return GeneratedBOM{}, err
	}

	canonBytes, err := identity.CanonicalizeJSON(rawJSON)
	if err != nil {
		return GeneratedBOM{}, err
	}

	return GeneratedBOM{
		Document: doc,
		JSON:     rawJSON,
		Digest:   digest.ComputeBytes(canonBytes),
	}, nil
}

// Validate validates raw CycloneDX JSON bytes against the official CycloneDX 1.6/1.7 JSON Schema,
// the cyclonedx-go v0.12.0 SDK decoder, the project ML-BOM profile schema, and semantic/cryptographic
// inventory rules (including 1-to-1 file consistency against an InspectionResult when supplied).
func Validate(rawJSON []byte, expectedInsp *bundle.InspectionResult) error {
	var doc Document
	dec := json.NewDecoder(bytes.NewReader(rawJSON))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return fmt.Errorf("%w: schema parse error: %v", ErrInvalidBOM, err)
	}

	if doc.BOMFormat != "CycloneDX" {
		return fmt.Errorf("%w: bomFormat must be \"CycloneDX\", got %q", ErrInvalidBOM, doc.BOMFormat)
	}
	var expectedCDXSpec cyclonedx.SpecVersion
	switch doc.SpecVersion {
	case SpecVersion1_6:
		expectedCDXSpec = cyclonedx.SpecVersion1_6
		if doc.Schema != SchemaURI1_6 {
			return fmt.Errorf("%w: specVersion 1.6 requires $schema %q, got %q", ErrInvalidBOM, SchemaURI1_6, doc.Schema)
		}
	case SpecVersion1_7:
		expectedCDXSpec = cyclonedx.SpecVersion1_7
		if doc.Schema != SchemaURI1_7 {
			return fmt.Errorf("%w: specVersion 1.7 requires $schema %q, got %q", ErrInvalidBOM, SchemaURI1_7, doc.Schema)
		}
	default:
		return fmt.Errorf("%w: unsupported specVersion %q", ErrInvalidBOM, doc.SpecVersion)
	}

	// Validate against the official CycloneDX 1.7 / 1.6 JSON Schema and project profile schema.
	if err := ValidateOfficialCycloneDXSchema(rawJSON, doc.SpecVersion); err != nil {
		return err
	}

	// Validate round-trip decoding with the official cyclonedx-go v0.12.0 SDK.
	var cdxBOM cyclonedx.BOM
	if err := cyclonedx.NewBOMDecoder(bytes.NewReader(rawJSON), cyclonedx.BOMFileFormatJSON).Decode(&cdxBOM); err != nil {
		return fmt.Errorf("%w: cyclonedx-go SDK decode failed: %v", ErrInvalidBOM, err)
	}
	if cdxBOM.SpecVersion != expectedCDXSpec {
		return fmt.Errorf("%w: cyclonedx-go parsed specVersion %s, expected %s", ErrInvalidBOM, cdxBOM.SpecVersion, expectedCDXSpec)
	}

	if !uuidURNPattern.MatchString(doc.SerialNumber) {
		return fmt.Errorf("%w: invalid serialNumber URN %q", ErrInvalidBOM, doc.SerialNumber)
	}
	if strings.HasPrefix(doc.SerialNumber, digest.Prefix) {
		return fmt.Errorf("%w: serialNumber %q must be a UUID URN and never confused with model_bundle_id", ErrInvalidBOM, doc.SerialNumber)
	}
	if doc.Version < 1 {
		return fmt.Errorf("%w: version must be >= 1", ErrInvalidBOM)
	}
	if strings.TrimSpace(doc.Metadata.Timestamp) == "" {
		return fmt.Errorf("%w: metadata.timestamp is required", ErrInvalidBOM)
	}
	if doc.Metadata.Component.Type != "machine-learning-model" {
		return fmt.Errorf("%w: metadata.component.type must be \"machine-learning-model\", got %q", ErrInvalidBOM, doc.Metadata.Component.Type)
	}
	if doc.Metadata.Component.BOMRef == "" || doc.Metadata.Component.Name == "" {
		return fmt.Errorf("%w: metadata.component requires bom-ref and name", ErrInvalidBOM)
	}
	if err := validateHashes(doc.Metadata.Component.Hashes, "metadata.component"); err != nil {
		return err
	}
	expectedRootBundleID := digest.Prefix + doc.Metadata.Component.Hashes[0].Content
	declaredBundleIDProp := getPropertyValue(doc.Metadata.Component.Properties, "provenance:model_bundle_id")
	if declaredBundleIDProp == "" {
		return fmt.Errorf("%w: metadata.component missing required provenance:model_bundle_id property", ErrInvalidBOM)
	}
	if declaredBundleIDProp != expectedRootBundleID {
		return fmt.Errorf("%w: provenance:model_bundle_id %q does not match metadata.component hash %q", ErrInvalidBOM, declaredBundleIDProp, expectedRootBundleID)
	}
	if doc.SerialNumber == declaredBundleIDProp {
		return fmt.Errorf("%w: serialNumber and model_bundle_id must be distinct", ErrInvalidBOM)
	}

	if err := validateModelCard(doc.Metadata.Component.ModelCard, "metadata.component"); err != nil {
		return err
	}

	knownRefs := map[string]bool{
		doc.Metadata.Component.BOMRef: true,
	}
	if err := validatePedigree(doc.Metadata.Component.Pedigree, "metadata.component", knownRefs); err != nil {
		return err
	}

	if len(doc.Components) == 0 {
		return fmt.Errorf("%w: components array cannot be empty", ErrInvalidBOM)
	}

	bomFileHashes := make(map[string]string)

	for _, c := range doc.Components {
		if c.BOMRef == "" || c.Name == "" {
			return fmt.Errorf("%w: component missing bom-ref or name", ErrInvalidBOM)
		}
		if knownRefs[c.BOMRef] {
			return fmt.Errorf("%w: duplicate bom-ref %q", ErrInvalidBOM, c.BOMRef)
		}
		knownRefs[c.BOMRef] = true
		switch c.Type {
		case "file":
			if c.ModelCard != nil {
				return fmt.Errorf("%w: file component %q cannot have a modelCard", ErrInvalidBOM, c.BOMRef)
			}
			if err := validateHashes(c.Hashes, c.BOMRef); err != nil {
				return err
			}
			bomFileHashes[c.Name] = digest.Prefix + c.Hashes[0].Content
		case "machine-learning-model":
			if len(c.Hashes) > 0 {
				if err := validateHashes(c.Hashes, c.BOMRef); err != nil {
					return err
				}
			}
			if err := validateModelCard(c.ModelCard, c.BOMRef); err != nil {
				return err
			}
			if err := validatePedigree(c.Pedigree, c.BOMRef, knownRefs); err != nil {
				return err
			}
		case "data", "application":
			if c.ModelCard != nil {
				return fmt.Errorf("%w: component %q of type %q cannot have a modelCard", ErrInvalidBOM, c.BOMRef, c.Type)
			}
			if len(c.Hashes) > 0 {
				if err := validateHashes(c.Hashes, c.BOMRef); err != nil {
					return err
				}
			}
		default:
			return fmt.Errorf("%w: unsupported component type %q", ErrInvalidBOM, c.Type)
		}
	}

	if len(doc.Dependencies) == 0 {
		return fmt.Errorf("%w: dependencies array cannot be empty", ErrInvalidBOM)
	}
	rootDepTargets := make(map[string]bool)
	hasRootDep := false
	for _, dep := range doc.Dependencies {
		if !knownRefs[dep.Ref] {
			return fmt.Errorf("%w: dependency ref %q does not match any component", ErrInvalidBOM, dep.Ref)
		}
		for _, target := range dep.DependsOn {
			if !knownRefs[target] {
				return fmt.Errorf("%w: dependency target %q does not match any component", ErrInvalidBOM, target)
			}
			if target == dep.Ref {
				return fmt.Errorf("%w: component %q cannot depend on itself", ErrInvalidBOM, dep.Ref)
			}
			if dep.Ref == doc.Metadata.Component.BOMRef {
				rootDepTargets[target] = true
			}
		}
		if dep.Ref == doc.Metadata.Component.BOMRef {
			hasRootDep = true
		}
	}
	if !hasRootDep {
		return fmt.Errorf("%w: dependencies missing root component ref %q", ErrInvalidBOM, doc.Metadata.Component.BOMRef)
	}
	for _, c := range doc.Components {
		if !rootDepTargets[c.BOMRef] {
			return fmt.Errorf("%w: component %q is not referenced in root component dependencies", ErrInvalidBOM, c.BOMRef)
		}
	}

	// If an InspectionResult is supplied, verify strict 1-to-1 correspondence between BOM files, metadata, pedigree, and bundle inventory.
	if expectedInsp != nil {
		expectedHex, err := digest.TrimPrefix(expectedInsp.BundleID)
		if err != nil {
			return err
		}
		if doc.Metadata.Component.Hashes[0].Content != expectedHex {
			return fmt.Errorf(
				"%w: root component hash %s does not match bundle_id %s",
				ErrInvalidBOM, doc.Metadata.Component.Hashes[0].Content, expectedHex,
			)
		}
		if len(bomFileHashes) != len(expectedInsp.Inventory.Files) {
			return fmt.Errorf(
				"%w: BOM has %d file components, but bundle inventory has %d files",
				ErrInvalidBOM, len(bomFileHashes), len(expectedInsp.Inventory.Files),
			)
		}
		for _, f := range expectedInsp.Inventory.Files {
			gotDigest, ok := bomFileHashes[f.Path]
			if !ok {
				return fmt.Errorf("%w: inventory file %q is missing from BOM components", ErrInvalidBOM, f.Path)
			}
			if gotDigest != f.SHA256 {
				return fmt.Errorf(
					"%w: BOM hash for %q is %s, expected %s",
					ErrInvalidBOM, f.Path, gotDigest, f.SHA256,
				)
			}
		}

		// Validate observed model metadata consistency against expectedInsp.Manifest.ModelConfig.
		if cfg := expectedInsp.Manifest.ModelConfig; cfg != nil {
			if cfg.ModelType != "" || len(cfg.Architectures) > 0 {
				if doc.Metadata.Component.ModelCard == nil || doc.Metadata.Component.ModelCard.ModelParameters == nil {
					return fmt.Errorf("%w: metadata.component.modelCard.modelParameters is required when config.json model metadata is present", ErrInvalidBOM)
				}
				mp := doc.Metadata.Component.ModelCard.ModelParameters
				if cfg.ModelType != "" && mp.ArchitectureFamily != cfg.ModelType {
					return fmt.Errorf("%w: modelCard architectureFamily %q does not match observed model_type %q", ErrInvalidBOM, mp.ArchitectureFamily, cfg.ModelType)
				}
				if len(cfg.Architectures) > 0 && mp.ModelArchitecture != cfg.Architectures[0] {
					return fmt.Errorf("%w: modelCard modelArchitecture %q does not match observed architecture %q", ErrInvalidBOM, mp.ModelArchitecture, cfg.Architectures[0])
				}
			}
		}

		// Validate PEFT/LoRA pedigree consistency against expectedInsp.Manifest.LoRARelationship.
		if lora := expectedInsp.Manifest.LoRARelationship; lora.IsAdapter {
			if doc.Metadata.Component.Pedigree == nil || len(doc.Metadata.Component.Pedigree.Ancestors) == 0 {
				return fmt.Errorf("%w: PEFT/LoRA bundle requires metadata.component.pedigree.ancestors", ErrInvalidBOM)
			}
			anc := doc.Metadata.Component.Pedigree.Ancestors[0]
			expectedAncName := lora.BaseModelNameOrPath
			if expectedAncName == "" {
				expectedAncName = "undeclared-base-model"
			}
			if anc.Name != expectedAncName {
				return fmt.Errorf("%w: pedigree ancestor name %q does not match declared base model %q", ErrInvalidBOM, anc.Name, expectedAncName)
			}
			if anc.Version != lora.Revision {
				return fmt.Errorf("%w: pedigree ancestor version %q does not match declared base revision %q", ErrInvalidBOM, anc.Version, lora.Revision)
			}
			gotStatus := getPropertyValue(anc.Properties, "provenance:verification_status")
			if gotStatus != string(lora.VerificationStatus) {
				return fmt.Errorf("%w: pedigree ancestor verification_status %q does not match %q", ErrInvalidBOM, gotStatus, lora.VerificationStatus)
			}
		}
	}

	return nil
}

func getPropertyValue(props []Property, name string) string {
	for _, p := range props {
		if p.Name == name {
			return p.Value
		}
	}
	return ""
}

func validateModelCard(mc *ModelCard, owner string) error {
	if mc == nil {
		return nil
	}
	if mc.ModelParameters == nil {
		return fmt.Errorf("%w: %s.modelCard requires modelParameters", ErrInvalidBOM, owner)
	}
	mp := mc.ModelParameters
	if strings.TrimSpace(mp.Task) == "" && strings.TrimSpace(mp.ArchitectureFamily) == "" && strings.TrimSpace(mp.ModelArchitecture) == "" {
		return fmt.Errorf("%w: %s.modelCard.modelParameters must specify at least one of task, architectureFamily, or modelArchitecture", ErrInvalidBOM, owner)
	}
	return nil
}

func validatePedigree(ped *Pedigree, owner string, knownRefs map[string]bool) error {
	if ped == nil {
		return nil
	}
	if len(ped.Ancestors) == 0 {
		return fmt.Errorf("%w: %s.pedigree.ancestors cannot be empty", ErrInvalidBOM, owner)
	}
	for _, anc := range ped.Ancestors {
		if anc.Type != "machine-learning-model" {
			return fmt.Errorf("%w: %s.pedigree ancestor %q must have type \"machine-learning-model\", got %q", ErrInvalidBOM, owner, anc.BOMRef, anc.Type)
		}
		if strings.TrimSpace(anc.BOMRef) == "" || strings.TrimSpace(anc.Name) == "" {
			return fmt.Errorf("%w: %s.pedigree ancestor requires non-empty bom-ref and name", ErrInvalidBOM, owner)
		}
		if knownRefs[anc.BOMRef] {
			return fmt.Errorf("%w: duplicate bom-ref %q in %s.pedigree", ErrInvalidBOM, anc.BOMRef, owner)
		}
		knownRefs[anc.BOMRef] = true
		if len(anc.Hashes) > 0 {
			if err := validateHashes(anc.Hashes, anc.BOMRef); err != nil {
				return err
			}
		}
		verStatus := getPropertyValue(anc.Properties, "provenance:verification_status")
		if verStatus != string(peft.StatusDeclaredUnverified) && verStatus != string(peft.StatusVerified) {
			return fmt.Errorf("%w: %s.pedigree ancestor %q requires valid provenance:verification_status property, got %q", ErrInvalidBOM, owner, anc.BOMRef, verStatus)
		}
	}
	return nil
}

func validateHashes(hashes []Hash, owner string) error {
	if len(hashes) == 0 {
		return fmt.Errorf("%w: %s requires at least one SHA-256 hash", ErrInvalidBOM, owner)
	}
	for _, h := range hashes {
		if h.Alg != "SHA-256" {
			return fmt.Errorf("%w: %s has unsupported hash alg %q", ErrInvalidBOM, owner, h.Alg)
		}
		if !hex64Pattern.MatchString(h.Content) {
			return fmt.Errorf("%w: %s has invalid SHA-256 hex %q", ErrInvalidBOM, owner, h.Content)
		}
	}
	return nil
}

func sortProperties(props []Property) {
	sort.Slice(props, func(i, j int) bool {
		if props[i].Name == props[j].Name {
			return props[i].Value < props[j].Value
		}
		return props[i].Name < props[j].Name
	})
}

func sanitizeRef(s string) string {
	s = strings.TrimSpace(s)
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' || r == '/' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}

func deterministicUUIDURN(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	b := sum[:16]
	// Set RFC 4122 version 5 and variant bits
	b[6] = (b[6] & 0x0f) | 0x50
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf(
		"urn:uuid:%s-%s-%s-%s-%s",
		hex.EncodeToString(b[0:4]),
		hex.EncodeToString(b[4:6]),
		hex.EncodeToString(b[6:8]),
		hex.EncodeToString(b[8:10]),
		hex.EncodeToString(b[10:16]),
	)
}
