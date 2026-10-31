# Acceptance Criteria & Verification Matrix

Every required test case across Identity, CycloneDX BOM, Signature & Provenance, Evaluation Binding, and Deployment Composition is implemented and verified by automated tests (`go test -v -race ./...`).

---

## 1. Identity Tests (`internal/bundle/bundle_test.go`, `internal/digest/digest_test.go`)

| # | Test Scenario | Input | Expected Status | Actual Status | Verified By |Result |
|---|---|---|---|---|---|---|
| 1 | Same bundle, same identity | Two identical model bundles | Identical `bundle_id` (`sha256:...`) | Identical `bundle_id` | `TestIdentityAcceptanceCriteria` | **PASS** |
| 2 | Different weight, different identity | Modified byte in `model.safetensors` | Different `bundle_id` | Different `bundle_id` | `TestIdentityAcceptanceCriteria` | **PASS** |
| 3 | Different tokenizer, different identity | Modified vocab entry in `tokenizer.json` | Different `bundle_id` | Different `bundle_id` | `TestIdentityAcceptanceCriteria` | **PASS** |
| 4 | Different adapter, different identity | Modified LoRA rank/weights in `adapter_*` | Different `bundle_id` | Different `bundle_id` | `TestIdentityAcceptanceCriteria` | **PASS** |
| 5 | Different config, different identity | Modified `architectures` in `config.json` | Different `bundle_id` | Different `bundle_id` | `TestIdentityAcceptanceCriteria` | **PASS** |
| 6 | Different enumeration order, same identity | `ReverseEnumerationOrder: true` vs normal | Identical `bundle_id` & `manifest_digest` | Identical `bundle_id` & `manifest_digest` | `TestIdentityAcceptanceCriteria` | **PASS** |
| 7 | Missing file, verification failure | Shard referenced in `model.safetensors.index.json` deleted | `ErrInvalidShardIndex` / `ErrIncompleteBundle` | Rejected with `ErrInvalidShardIndex` | `TestInspectValidSafetensorsAndShards` | **PASS** |
| 8 | Incomplete bundle | `config.json` only (no weights or adapter) | `ErrIncompleteBundle` | Rejected with `ErrIncompleteBundle` | `TestBundleErrorAndAdversarialCases` | **PASS** |
| 9 | Large file streaming | 128 KiB payload across 4 KiB & 64 KiB chunk buffers | Identical streaming `SHA256` | Identical `SHA256` | `TestStreamFileAndDeterminism` | **PASS** |
| 10 | File mutation during hashing (TOCTOU) | Concurrent append during `OnChunkRead` | `ErrConcurrentMutation` | Rejected with `ErrConcurrentMutation` | `TestStreamFileDetectsConcurrentMutation`, `TestBundleErrorAndAdversarialCases` | **PASS** |
| 11 | Symbolic link escape | Symlink pointing outside bundle root | `ErrSymlinkRejected` | Rejected with `ErrSymlinkRejected` | `TestBundleErrorAndAdversarialCases` | **PASS** |
| 12 | Path traversal | `../etc/passwd` relative path | `ErrInvalidRelativePath` | Rejected with `ErrInvalidRelativePath` | `TestBundleErrorAndAdversarialCases` | **PASS** |
| 13 | Path normalization collision | NFD `e\u0301.json` vs NFC `\u00e9.json` & `Config.json` vs `config.json` | `ErrPathCollision` | Rejected with `ErrPathCollision` | `TestBundleErrorAndAdversarialCases` | **PASS** |
| 14 | Unsupported / unsafe format | `pytorch_model.bin` / disguised `.pkl` in `.safetensors` | `ErrUnsupportedFormat` / `ErrDisguisedFormat` | Rejected with `ErrUnsupportedFormat` / `ErrDisguisedFormat` | `TestBundleErrorAndAdversarialCases`, `TestInspectRejectsDisguisedPickleAndOversizedHeader` | **PASS** |
| 15 | Unknown regular file | `custom_notes.dat` inside bundle | Included as `role: "unknown_file"`, changes `bundle_id` | Included (`UnknownFileCount=1`), changes `bundle_id` | `TestIdentityAcceptanceCriteria` | **PASS** |

---

## 2. CycloneDX AI/ML-BOM Tests (`internal/bom/bom_test.go`)

| # | Test Scenario | Input | Expected Status | Actual Status | Verified By | Result |
|---|---|---|---|---|---|---|
| 1 | Valid model bundle | Base + sharded + LoRA bundle | Valid CycloneDX BOM generated | Valid BOM generated | `TestBOMAcceptanceCriteria` | **PASS** |
| 2 | Multiple weight shards | `model-00001-of-00002.safetensors`, `model-00002-of-00002.safetensors`, index | All shards & tensor counts in `components` | Verified in `components` | `TestBOMAcceptanceCriteria` | **PASS** |
| 3 | LoRA adapter | `adapter_config.json` + `adapter_model.safetensors` | `component:lora-adapter` + `pedigree.ancestors` with `DECLARED_UNVERIFIED` | Verified in `components` & `pedigree` | `TestBOMAcceptanceCriteria` | **PASS** |
| 4 | Missing tokenizer | Bundle without `tokenizer.json` | `provenance:has_tokenizer=false`, no invented tokenizer component | Verified | `TestBOMAcceptanceCriteria` | **PASS** |
| 5 | Missing license | `config.json` without `license` | `licenses` empty, `provenance:license_status=missing` | Verified | `TestBOMAcceptanceCriteria` | **PASS** |
| 6 | Unknown metadata | `custom_vendor_flag` in `config.json` | Preserved in `huggingface:preserved_unknown_config_keys` | Verified | `TestBOMAcceptanceCriteria` | **PASS** |
| 7 | Correct schema version | `SpecVersion: "1.7"` and `"1.6"` | `$schema` matches official 1.7 / 1.6 URI | Verified | `TestBOMAcceptanceCriteria` | **PASS** |
| 8 | Schema validation | `bom.Validate(rawJSON, &insp)` | Passes valid BOM, rejects unknown/invalid fields | Verified | `TestBOMAcceptanceCriteria` | **PASS** |
| 9 | Inventory/BOM consistency | Tampered file hash in BOM JSON | Rejected with `ErrInvalidBOM` | Rejected with `ErrInvalidBOM` | `TestBOMAcceptanceCriteria` | **PASS** |

---

## 3. Signature and Provenance Tests (`internal/oms/oms_test.go`, `internal/deployment/deployment_test.go`)

| # | Test Scenario | Input | Expected Status | Actual Status | Verified By | Result |
|---|---|---|---|---|---|---|
| 1 | Valid trusted signature | OMS v1.0 Sigstore bundle signed by trusted Ed25519 key | `VERIFIED` (`PASS`) | `VERIFIED` (`PASS`) | `TestOMSSigningAndVerificationMatrix` | **PASS** |
| 2 | Invalid signature | Corrupted base64 signature bytes | `INVALID` (`FAIL`) | `INVALID` (`FAIL`) | `TestOMSSigningAndVerificationMatrix` | **PASS** |
| 3 | Missing signature | Empty signature path when OMS required | `MISSING` (`BLOCKED`) | `MISSING` (`BLOCKED`) | `TestOMSSigningAndVerificationMatrix` | **PASS** |
| 4 | Unknown signer | Signed by key not in `trusted_signers` | `UNTRUSTED` (`FAIL`) | `UNTRUSTED` (`FAIL`) | `TestOMSSigningAndVerificationMatrix` | **PASS** |
| 5 | Altered attestation | Modified predicate inside DSSE envelope | `INVALID` (`FAIL`) | `INVALID` (`FAIL`) | `TestPolicyAttestationAndDeploymentMatrix` | **PASS** |
| 6 | Wrong subject digest | Modified `tokenizer.json` after OMS signing | `INVALID` (`ErrComponentDigestMismatch`) | `INVALID` (`FAIL`) | `TestOMSSigningAndVerificationMatrix` | **PASS** |
| 7 | Offline verification | Local PEM public key verification without network | `VERIFIED` (`PASS`) | `VERIFIED` (`PASS`) | `TestOMSSigningAndVerificationMatrix` | **PASS** |
| 8 | Missing verification material | Offline verify with zero public keys | `BLOCKED` (`ErrMissingVerificationMaterial`) | `BLOCKED` | `TestOMSSigningAndVerificationMatrix` | **PASS** |
| 9 | Unavailable external OMS CLI | `ModeExternalCLI` when `model_signing` is absent | `BLOCKED` (`ErrExternalCLIUnavailable`) | `BLOCKED` | `TestOMSSigningAndVerificationMatrix` | **PASS** |

---

## 4. Evaluation Evidence Tests (`internal/evaluation/llmreleasegate/adapter_test.go`)

| # | Test Scenario | Input | Expected Status | Actual Status | Verified By | Result |
|---|---|---|---|---|---|---|
| 1 | Matching `PASS` + trusted signature | Bound `model_bundle_id` + signed `evaluation-evidence/v1` | `PASS` (`EligibleForRelease=true`) | `PASS` | `TestEvaluationEvidenceAcceptanceMatrix` | **PASS** |
| 2 | Mismatching `PASS` evidence | `PASS` report bound to `otherBundleID` | `FAIL` (`BindingMismatch`) | `FAIL` | `TestEvaluationEvidenceAcceptanceMatrix` | **PASS** |
| 3 | `FAIL` evaluation report | `gateStatus: "FAIL"` | `FAIL` | `FAIL` | `TestEvaluationEvidenceAcceptanceMatrix` | **PASS** |
| 4 | `BLOCKED` evaluation report | `gateStatus: "BLOCKED"` | `BLOCKED` | `BLOCKED` | `TestEvaluationEvidenceAcceptanceMatrix` | **PASS** |
| 5 | `NOT_RUN` evaluation report | `gateStatus: "NOT_RUN"` | `BLOCKED` | `BLOCKED` | `TestEvaluationEvidenceAcceptanceMatrix` | **PASS** |
| 6 | Missing artifact identity (including live sibling fixture) | Report without `candidate.metadata["model_bundle_id"]` | `UNBOUND` / `BLOCKED` | `UNBOUND` / `BLOCKED` | `TestEvaluationEvidenceAcceptanceMatrix`, `TestReadOnlySiblingLLMReleaseGateFixtureCompatibility` | **PASS** |
| 7 | Untrusted evidence (plain JSON) | Unsigned `report.json` under `require_trusted_evidence: true` | `BLOCKED` (`UNVERIFIED_LOCAL_JSON`) | `BLOCKED` | `TestEvaluationEvidenceAcceptanceMatrix` | **PASS** |
| 8 | Changed report digest | `report.json` modified after `evaluation-evidence/v1` signing | `FAIL` (`INVALID_OR_TAMPERED`) | `FAIL` | `TestEvaluationEvidenceAcceptanceMatrix` | **PASS** |

---

## 5. Deployment Composition Tests (`internal/deployment/deployment_test.go`, `internal/cli/cli_test.go`)

| # | Test Scenario | Input | Expected Status | Actual Status | Verified By | Result |
|---|---|---|---|---|---|---|
| 1 | Matching model bundle & descriptor | Unmodified bundle + immutable image + valid serving config | `PASS` (exit `0`) | `PASS` (exit `0`) | `TestPolicyAttestationAndDeploymentMatrix`, `TestEndToEndProductThesisLifecycle` | **PASS** |
| 2 | Modified weights | 1 byte changed in `model.safetensors` | `FAIL` (exit `1`) | `FAIL` (exit `1`) | `TestPolicyAttestationAndDeploymentMatrix` | **PASS** |
| 3 | Modified tokenizer | Modified vocab in `tokenizer.json` | `FAIL` (exit `1`) | `FAIL` (exit `1`) | `TestPolicyAttestationAndDeploymentMatrix`, `TestEndToEndProductThesisLifecycle` | **PASS** |
| 4 | Different LoRA | Modified LoRA rank/weights | `FAIL` (exit `1`) | `FAIL` (exit `1`) | `TestPolicyAttestationAndDeploymentMatrix` | **PASS** |
| 5 | Changed runtime image digest | Different `@sha256:...` than qualified runtime | `FAIL` (exit `1`) | `FAIL` (exit `1`) | `TestPolicyAttestationAndDeploymentMatrix` | **PASS** |
| 6 | Mutable image tag | `ghcr.io/vllm/vllm-openai:latest` | `FAIL` (exit `1`) | `FAIL` (exit `1`) | `TestPolicyAttestationAndDeploymentMatrix` | **PASS** |
| 7 | Changed serving configuration | Modified `serving-config.yaml` | `FAIL` (exit `1`) | `FAIL` (exit `1`) | `TestPolicyAttestationAndDeploymentMatrix` | **PASS** |
| 8 | Missing required configuration | Missing `serving_config_path` when required | `BLOCKED` (exit `3`) | `BLOCKED` (exit `3`) | `TestPolicyAttestationAndDeploymentMatrix` | **PASS** |
