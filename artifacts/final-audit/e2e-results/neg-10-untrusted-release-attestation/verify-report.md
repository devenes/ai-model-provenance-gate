# AI Model Provenance Gate Report (`release-verify`)

- **Gate Status:** `FAIL` (Exit Code `1`)
- **Timestamp:** `2026-10-30T23:17:04Z`
- **Tool Version:** `0.1.0` (`darwin/arm64`)
- **Model Bundle Identity (`bundle-identity/v1`):** `sha256:5cf4da3cb4001a33d87d0dcd06439061bf9b293ad2bcdcf7fc7ba4411887e61a`
- **Deployment Composition Identity (`deployment-composition/v1`):** `sha256:e65bd90789bf5847156a7ca7b4b272f331f139e40271406ef806526dfe8c9a72`
- **Release Qualification Attestation Digest:** `sha256:f6895e4598e291d8a88bd01ea2652f1e29d9418cda121032968f295296499b0d`
- **Policy:** `final-audit-strict-policy` (mode=`strict`, digest=`sha256:8d03a624eeb133833230c14056f6df039be455e3e49b811e2c8bfd2bad996434`)

---

## 1. Security Guarantee Separation Matrix

| Security Guarantee | Observed / Verified Status |
|---|---|
| **Artifact Integrity** | OBSERVED (sha256:5cf4da3cb4001a33d87d0dcd06439061bf9b293ad2bcdcf7fc7ba4411887e61a) |
| **Artifact Authenticity** | ATTESTATION_UNTRUSTED |
| **Signer Trust** | SIGNER= () |
| **Artifact Provenance** | BOUND_VIA_RELEASE_ATTESTATION |
| **Security Scan Evidence** | RECORDED_IN_ATTESTATION |
| **Model Behavioral Evaluation** | RECORDED_IN_ATTESTATION |
| **Release Qualification** | UNTRUSTED (subject=) |
| **Deployment Identity** | REJECTED (FAIL) |

> **Note:** Each security guarantee is evaluated independently. A SHA-256 digest does not prove origin; a valid BOM or signature does not prove behavioral safety; an unbound evaluation `PASS` does not qualify a model bundle.

## 3. Decision Reasons

| Status | Severity | Category | Code | Message |
|---|---|---|---|---|
| `PASS` | `info` | `bundle` | `DEPLOYMENT_BUNDLE_INSPECTED` | re-computed live model bundle identity sha256:5cf4da3cb4001a33d87d0dcd06439061bf9b293ad2bcdcf7fc7ba4411887e61a (8 files, 1194 bytes) |
| `FAIL` | `error` | `attestation` | `RELEASE_ATTESTATION_UNTRUSTED_SIGNER` | signature keyid/hint "untrusted-signer-1" does not match any configured trusted signer (1 trusted signers checked) |
| `PASS` | `info` | `deployment` | `DEPLOYMENT_DESCRIPTOR_BUNDLE_MATCHED` | deployment descriptor model_bundle_id matches live bundle |
| `PASS` | `info` | `deployment` | `DEPLOYMENT_RUNTIME_IMAGE_VERIFIED` | verified deployment runtime image "ghcr.io/vllm/vllm-openai@sha256:7777777777777777777777777777777777777777777777777777777777777777" |
| `PASS` | `info` | `deployment` | `DEPLOYMENT_SERVING_CONFIG_VERIFIED` | verified serving configuration digest sha256:51ceb1fe36b786d1d57dcd52c22ca444ae0e81adab31243be4ee5b80a8fb0675 |

