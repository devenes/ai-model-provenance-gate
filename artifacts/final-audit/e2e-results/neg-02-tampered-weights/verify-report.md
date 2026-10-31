# AI Model Provenance Gate Report (`release-verify`)

- **Gate Status:** `FAIL` (Exit Code `1`)
- **Timestamp:** `2026-10-30T23:17:04Z`
- **Tool Version:** `0.1.0` (`darwin/arm64`)
- **Model Bundle Identity (`bundle-identity/v1`):** ``
- **Policy:** `final-audit-strict-policy` (mode=`strict`, digest=`sha256:8d03a624eeb133833230c14056f6df039be455e3e49b811e2c8bfd2bad996434`)

---

## 1. Security Guarantee Separation Matrix

| Security Guarantee | Observed / Verified Status |
|---|---|
| **Artifact Integrity** | OBSERVED () |
| **Artifact Authenticity** | ATTESTATION_ |
| **Signer Trust** | SIGNER= () |
| **Artifact Provenance** | BOUND_VIA_RELEASE_ATTESTATION |
| **Security Scan Evidence** | RECORDED_IN_ATTESTATION |
| **Model Behavioral Evaluation** | RECORDED_IN_ATTESTATION |
| **Release Qualification** |  (subject=) |
| **Deployment Identity** | REJECTED (FAIL) |

> **Note:** Each security guarantee is evaluated independently. A SHA-256 digest does not prove origin; a valid BOM or signature does not prove behavioral safety; an unbound evaluation `PASS` does not qualify a model bundle.

## 3. Decision Reasons

| Status | Severity | Category | Code | Message |
|---|---|---|---|---|
| `FAIL` | `error` | `bundle` | `DEPLOYMENT_BUNDLE_INSPECTION_FAILED` | invalid safetensors tensor data_offsets: tensors in "model.safetensors" end at offset 32, but data buffer size is 33 (trailing/unaccounted bytes) |

