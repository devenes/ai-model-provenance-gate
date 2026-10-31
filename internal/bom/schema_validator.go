package bom

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

//go:embed schemas/*.schema.json
var embeddedSchemas embed.FS

var (
	schemaOnce        sync.Once
	schemaInitErr     error
	officialSchema1_7 *jsonschema.Schema
	officialSchema1_6 *jsonschema.Schema
	profileSchema     *jsonschema.Schema
	spdxLicenseLookup map[string]string
)

func initSchemas() {
	schemaOnce.Do(func() {
		compiler := jsonschema.NewCompiler()

		loadRes := func(filename, fallbackURL string) error {
			raw, err := embeddedSchemas.ReadFile("schemas/" + filename)
			if err != nil {
				return fmt.Errorf("read embedded schema %s: %w", filename, err)
			}
			doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
			if err != nil {
				return fmt.Errorf("unmarshal embedded schema %s: %w", filename, err)
			}
			if err := compiler.AddResource(fallbackURL, doc); err != nil {
				return fmt.Errorf("register schema resource %s: %w", fallbackURL, err)
			}
			return nil
		}

		if err := loadRes("spdx.schema.json", "http://cyclonedx.org/schema/spdx.schema.json"); err != nil {
			schemaInitErr = err
			return
		}
		if err := loadRes("jsf-0.82.schema.json", "http://cyclonedx.org/schema/jsf-0.82.schema.json"); err != nil {
			schemaInitErr = err
			return
		}
		if err := loadRes("cryptography-defs.schema.json", "http://cyclonedx.org/schema/cryptography-defs.schema.json"); err != nil {
			schemaInitErr = err
			return
		}
		if err := loadRes("bom-1.7.schema.json", SchemaURI1_7); err != nil {
			schemaInitErr = err
			return
		}
		if err := loadRes("bom-1.6.schema.json", SchemaURI1_6); err != nil {
			schemaInitErr = err
			return
		}
		if err := loadRes("cyclonedx-mlbom-profile.schema.json", "https://github.com/devenes/ai-model-provenance-gate/schemas/reports/cyclonedx-mlbom-profile.schema.json"); err != nil {
			schemaInitErr = err
			return
		}

		var err error
		officialSchema1_7, err = compiler.Compile(SchemaURI1_7)
		if err != nil {
			schemaInitErr = fmt.Errorf("compile official CycloneDX 1.7 schema: %w", err)
			return
		}
		officialSchema1_6, err = compiler.Compile(SchemaURI1_6)
		if err != nil {
			schemaInitErr = fmt.Errorf("compile official CycloneDX 1.6 schema: %w", err)
			return
		}
		profileSchema, err = compiler.Compile("https://github.com/devenes/ai-model-provenance-gate/schemas/reports/cyclonedx-mlbom-profile.schema.json")
		if err != nil {
			schemaInitErr = fmt.Errorf("compile project ML-BOM profile schema: %w", err)
			return
		}

		// Parse official SPDX license IDs for case-insensitive canonical normalization.
		spdxRaw, err := embeddedSchemas.ReadFile("schemas/spdx.schema.json")
		if err != nil {
			schemaInitErr = err
			return
		}
		var spdxDoc struct {
			Enum []string `json:"enum"`
		}
		if err := json.Unmarshal(spdxRaw, &spdxDoc); err != nil {
			schemaInitErr = err
			return
		}
		spdxLicenseLookup = make(map[string]string, len(spdxDoc.Enum))
		for _, id := range spdxDoc.Enum {
			spdxLicenseLookup[strings.ToLower(id)] = id
		}
	})
}

// ValidateOfficialCycloneDXSchema validates raw JSON bytes against the official CycloneDX 1.7 or 1.6 JSON Schema,
// as well as the project's strict ML-BOM profile schema.
func ValidateOfficialCycloneDXSchema(rawJSON []byte, specVer string) error {
	initSchemas()
	if schemaInitErr != nil {
		return fmt.Errorf("%w: schema compiler initialization error: %v", ErrInvalidBOM, schemaInitErr)
	}

	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(rawJSON))
	if err != nil {
		return fmt.Errorf("%w: invalid JSON syntax: %v", ErrInvalidBOM, err)
	}

	switch specVer {
	case SpecVersion1_7:
		if err := officialSchema1_7.Validate(inst); err != nil {
			return fmt.Errorf("%w: official CycloneDX 1.7 JSON Schema validation failed: %v", ErrInvalidBOM, err)
		}
	case SpecVersion1_6:
		if err := officialSchema1_6.Validate(inst); err != nil {
			return fmt.Errorf("%w: official CycloneDX 1.6 JSON Schema validation failed: %v", ErrInvalidBOM, err)
		}
	default:
		return fmt.Errorf("%w: unsupported CycloneDX specVersion %q", ErrInvalidBOM, specVer)
	}

	if err := profileSchema.Validate(inst); err != nil {
		return fmt.Errorf("%w: project ML-BOM profile schema validation failed: %v", ErrInvalidBOM, err)
	}
	return nil
}

// NormalizeSPDXLicense checks if rawLicense matches an official SPDX license identifier
// (case-insensitively) and returns (canonicalSPDXID, true). Otherwise returns ("", false).
func NormalizeSPDXLicense(rawLicense string) (string, bool) {
	initSchemas()
	if spdxLicenseLookup == nil {
		return "", false
	}
	trimmed := strings.TrimSpace(rawLicense)
	if trimmed == "" {
		return "", false
	}
	id, ok := spdxLicenseLookup[strings.ToLower(trimmed)]
	return id, ok
}
