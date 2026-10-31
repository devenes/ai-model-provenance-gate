# in-toto Attestation Framework Standard Reference

## 1. Official Sources
- **in-toto Homepage:** https://in-toto.io/
- **in-toto Attestation Specification:** https://github.com/in-toto/attestation
- **Statement v1 Spec:** https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md
- **DSSE (Dead Simple Signing Envelope) Spec:** https://github.com/secure-systems-lab/dsse

## 2. Statement v1 Structure (`https://in-toto.io/Statement/v1`)
All release qualification and evaluation attestations produced or verified by `ai-model-provenance-gate` conform to the in-toto Statement v1 specification:

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
      "name": "model-bundle:customer-support-llama",
      "digest": {
        "sha256": "<64-hex-model-bundle-identity>"
      }
    }
  ],
  "predicateType": "https://github.com/devenes/ai-model-provenance-gate/attestation/release-qualification/v1",
  "predicate": { ... }
}
```

## 3. Project-Owned Predicate Types

### 3.1 Release Qualification Predicate (`release-qualification/v1`)
- **URI:** `https://github.com/devenes/ai-model-provenance-gate/attestation/release-qualification/v1`
- **Purpose:** Records the post-inspection, post-evaluation release qualification decision for a specific `bundle-identity/v1` subject digest.
- **Required Predicate Fields:**
  - `schema_version`: `"release-qualification/v1"`
  - `timestamp`: RFC 3339 UTC timestamp
  - `tool`: `{ "name": "ai-model-provenance-gate", "version": "...", "git_commit": "..." }`
  - `bundle`: `{ "bundle_id": "sha256:...", "manifest_digest": "sha256:...", "file_count": int, "total_bytes": int, "primary_format": "...", "lora_status": "..." }`
  - `bom`: `{ "digest": "sha256:...", "spec_version": "1.7" }`
  - `oms_verification`: `{ "status": "VERIFIED"|"INVALID"|"UNTRUSTED"|"MISSING"|"BLOCKED"|"NOT_RUN", "signer_key_id": "...", "signer_fingerprint": "sha256:...", "signature_digest": "sha256:..." }`
  - `evaluation`: `{ "status": "PASS"|"FAIL"|"BLOCKED"|"NOT_RUN", "binding_status": "MATCHED"|"MISMATCH"|"UNBOUND", "trust_status": "VERIFIED_TRUSTED"|"UNVERIFIED_LOCAL_JSON"|"INVALID_SIGNATURE", "report_digest": "sha256:...", "suite_digest": "sha256:...", "dataset_digest": "sha256:...", "run_id": "..." }`
  - `scanner`: `{ "status": "PASS"|"FAIL"|"BLOCKED"|"NOT_RUN", "tool": "...", "report_digest": "sha256:..." }`
  - `policy`: `{ "schema_version": "v1", "digest": "sha256:...", "decision_mode": "strict"|"permissive", "exceptions_applied": [...] }`
  - `decision`: `{ "gate_status": "PASS"|"FAIL"|"BLOCKED"|"NOT_RUN"|"ERROR", "reasons": [...] }`

### 3.2 Evaluation Evidence Attestation Predicate (`evaluation-evidence/v1`)
- **URI:** `https://github.com/devenes/ai-model-provenance-gate/attestation/evaluation-evidence/v1`
- **Purpose:** Cryptographically binds an `llm-release-gate.report/v1` JSON report digest (`sha256:...`) to a specific `model_bundle_id` (`sha256:...`) and signs it with an authorized evaluator key inside a DSSE envelope.

## 4. DSSE v1.0 Pre-Authentication Encoding (PAE)
Signatures in DSSE envelopes are never computed over raw payload bytes alone (to prevent confusion attacks between payload types). They are computed over the exact ASCII/byte sequence:
```text
"DSSEv1 " + ASCII_DECIMAL(LEN(payloadType)) + " " + payloadType + " " + ASCII_DECIMAL(LEN(payload)) + " " + payload
```
where `payloadType` is `"application/vnd.in-toto+json"` and `payload` is the raw UTF-8 JSON bytes of the in-toto Statement (before Base64 encoding).
