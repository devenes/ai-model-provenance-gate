# CycloneDX 1.7 Standards Compliance Report (`docs/audit/CYCLONEDX_COMPLIANCE.md`)

**Component:** [`internal/bom`](../../internal/bom/bom.go), [`internal/bom/schema_validator.go`](../../internal/bom/schema_validator.go)  
**SDK Version:** `github.com/CycloneDX/cyclonedx-go v0.12.0`  
**Schema Compiler:** `github.com/santhosh-tekuri/jsonschema/v6 v6.0.3`  
**Evidence Artifact:** [`artifacts/final-audit/cyclonedx-validation.json`](../../artifacts/final-audit/cyclonedx-validation.json)

---

## 1. Standards Audit & SDK Verification

- **Specification Version:** CycloneDX `1.7` (`http://cyclonedx.org/schema/bom-1.7.schema.json`) is the default generated specification version; CycloneDX `1.6` (`http://cyclonedx.org/schema/bom-1.6.schema.json`) is also supported for backward compatibility.
- **Maintained Go SDK:** Upgraded to `github.com/CycloneDX/cyclonedx-go v0.12.0` (`cyclonedx.SpecVersion1_7`), verified to round-trip decode generated BOM documents without loss or version downgrade.
- **Official Schema Validation:** `bom.Validate()` compiles and enforces the official CycloneDX 1.7 and 1.6 JSON Schemas embedded in [`internal/bom/schemas/`](../../internal/bom/schemas/) and mirrored in [`schemas/cyclonedx/`](../../schemas/cyclonedx/):
  - `bom-1.7.schema.json`
  - `bom-1.6.schema.json`
  - `spdx.schema.json`
  - `jsf-0.82.schema.json`
  - `cryptography-defs.schema.json`
- **Supplementary Project Profile:** [`schemas/reports/cyclonedx-mlbom-profile.schema.json`](../../schemas/reports/cyclonedx-mlbom-profile.schema.json) is enforced as an additional profile check after official CycloneDX 1.7 schema validation succeeds.

---

## 2. Semantic & Cryptographic Inventory Invariants

1. **Identity Separation (`serialNumber` vs. `model_bundle_id`):**
   - `serialNumber` is a deterministic `urn:uuid:<uuid>` URN and is strictly validated never to equal or start with `sha256:`.
   - The canonical `bundle-identity/v1` digest is recorded in `metadata.component.hashes[0]` (`alg: "SHA-256"`) and `metadata.component.properties` (`provenance:model_bundle_id`).
2. **1-to-1 File Component Correspondence:**
   - Every regular file in the inspected model bundle is represented as a `type: "file"` component with its exact `SHA-256` digest, byte size, role, and Safetensors header summary (`tensor_count`, `header_bytes`, `dtypes`).
   - Missing file components, extra file components, or mismatched SHA-256 digests fail validation with `ErrInvalidBOM`.
3. **Observed vs. Declared Metadata:**
   - Missing licenses are never fabricated (`provenance:license_status = "missing"`).
   - Observed license strings in `config.json` (e.g., `"apache-2.0"`) are normalized to valid SPDX case (`"Apache-2.0"`) when matching the official `spdx.schema.json` enum, or emitted under `license.name` when custom/non-SPDX, and explicitly tagged `declared_unverified`.
   - PEFT/LoRA base model references in `adapter_config.json` are recorded under `metadata.component.pedigree.ancestors` with `provenance:verification_status = "DECLARED_UNVERIFIED"` unless cryptographically verified against `--base-bundle` (`"VERIFIED"`).
4. **Dependency Graph Integrity:**
   - Every `dependencies` entry must reference known `bom-ref` identifiers, cannot self-reference, and the root `machine-learning-model` component must declare dependency edges covering all bundle components.

---

## 3. Executed Test Matrix (`go test -v -race ./internal/bom/...`)

| Test ID | Scenario | Expected | Observed |
|---|---|---|---|
| `CDX-01` | Valid CycloneDX 1.7 BOM generation & official schema validation | `PASS` | `PASS` |
| `CDX-02` | Valid CycloneDX 1.6 BOM backward-compatibility validation | `PASS` | `PASS` |
| `CDX-03` | Missing required fields (`bomFormat`, `metadata.timestamp`) | `FAIL` (`ErrInvalidBOM`) | `PASS` (Rejected) |
| `CDX-04` | Unknown top-level or nested JSON properties | `FAIL` (`ErrInvalidBOM`) | `PASS` (Rejected) |
| `CDX-05` | Invalid component type (`"invalid-component-type"`) | `FAIL` (`ErrInvalidBOM`) | `PASS` (Rejected) |
| `CDX-06` | Missing file component vs. bundle inventory | `FAIL` (`ErrInvalidBOM`) | `PASS` (Rejected) |
| `CDX-07` | Extra file component not in bundle inventory | `FAIL` (`ErrInvalidBOM`) | `PASS` (Rejected) |
| `CDX-08` | Wrong file SHA-256 digest | `FAIL` (`ErrInvalidBOM`) | `PASS` (Rejected) |
| `CDX-09` | Invalid PEFT/LoRA pedigree (tampered ancestor name, wrong type, or missing pedigree) | `FAIL` (`ErrInvalidBOM`) | `PASS` (Rejected) |
| `CDX-10` | Incorrect model metadata (`modelCard` architecture mismatch or `modelCard` on `file` component) | `FAIL` (`ErrInvalidBOM`) | `PASS` (Rejected) |
| `CDX-11` | Invalid dependency relationship (dangling `dependsOn` ref or unlinked component) | `FAIL` (`ErrInvalidBOM`) | `PASS` (Rejected) |
| `CDX-12` | Official `spdx.schema.json` invalid license ID & `serialNumber == model_bundle_id` confusion | `FAIL` (`ErrInvalidBOM`) | `PASS` (Rejected) |
| `CDX-13` | Malformed JSON input (`{invalid-json`) | `FAIL` (`ErrInvalidBOM`) | `PASS` (Rejected) |
