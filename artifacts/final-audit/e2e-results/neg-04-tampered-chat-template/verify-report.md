# AI Model Provenance Gate Report (`release-verify`)

- **Gate Status:** `FAIL` (Exit Code `1`)
- **Timestamp:** `2026-10-30T23:17:04Z`
- **Tool Version:** `0.1.0` (`darwin/arm64`)
- **Model Bundle Identity (`bundle-identity/v1`):** `sha256:7dcd071d6de5e755fa2c3bade8cdff812f1a2438fffed3d375209291618d18bf`
- **Deployment Composition Identity (`deployment-composition/v1`):** `sha256:e65bd90789bf5847156a7ca7b4b272f331f139e40271406ef806526dfe8c9a72`
- **Release Qualification Attestation Digest:** `sha256:5672afb6d05fb875d4dad3ee80b044ead9b562f2eca137ce2e1dd8eb5c9dd6d6`
- **Policy:** `final-audit-strict-policy` (mode=`strict`, digest=`sha256:8d03a624eeb133833230c14056f6df039be455e3e49b811e2c8bfd2bad996434`)

---

## 1. Security Guarantee Separation Matrix

| Security Guarantee | Observed / Verified Status |
|---|---|
| **Artifact Integrity** | OBSERVED (sha256:7dcd071d6de5e755fa2c3bade8cdff812f1a2438fffed3d375209291618d18bf) |
| **Artifact Authenticity** | ATTESTATION_INVALID |
| **Signer Trust** | SIGNER=test-release-signer-1 (sha256:6387843b1d3507615d31cf66e2c33e558d780cb5bec210c19aff5377becb0d65) |
| **Artifact Provenance** | BOUND_VIA_RELEASE_ATTESTATION |
| **Security Scan Evidence** | RECORDED_IN_ATTESTATION |
| **Model Behavioral Evaluation** | RECORDED_IN_ATTESTATION |
| **Release Qualification** | INVALID (subject=sha256:5cf4da3cb4001a33d87d0dcd06439061bf9b293ad2bcdcf7fc7ba4411887e61a) |
| **Deployment Identity** | REJECTED (FAIL) |

> **Note:** Each security guarantee is evaluated independently. A SHA-256 digest does not prove origin; a valid BOM or signature does not prove behavioral safety; an unbound evaluation `PASS` does not qualify a model bundle.

## 3. Decision Reasons

| Status | Severity | Category | Code | Message |
|---|---|---|---|---|
| `PASS` | `info` | `bundle` | `DEPLOYMENT_BUNDLE_INSPECTED` | re-computed live model bundle identity sha256:7dcd071d6de5e755fa2c3bade8cdff812f1a2438fffed3d375209291618d18bf (8 files, 1130 bytes) |
| `FAIL` | `error` | `attestation` | `DEPLOYMENT_ARTIFACT_TAMPERED` | inspected model bundle identity sha256:7dcd071d6de5e755fa2c3bade8cdff812f1a2438fffed3d375209291618d18bf does not match attested release subject sha256:5cf4da3cb4001a33d87d0dcd06439061bf9b293ad2bcdcf7fc7ba4411887e61a (artifact modified or substituted) |
| `FAIL` | `error` | `deployment` | `DEPLOYMENT_DESCRIPTOR_BUNDLE_MISMATCH` | deployment descriptor model_bundle_id sha256:5cf4da3cb4001a33d87d0dcd06439061bf9b293ad2bcdcf7fc7ba4411887e61a does not match live bundle sha256:7dcd071d6de5e755fa2c3bade8cdff812f1a2438fffed3d375209291618d18bf |
| `PASS` | `info` | `deployment` | `DEPLOYMENT_RUNTIME_IMAGE_VERIFIED` | verified deployment runtime image "ghcr.io/vllm/vllm-openai@sha256:7777777777777777777777777777777777777777777777777777777777777777" |
| `PASS` | `info` | `deployment` | `DEPLOYMENT_SERVING_CONFIG_VERIFIED` | verified serving configuration digest sha256:51ceb1fe36b786d1d57dcd52c22ca444ae0e81adab31243be4ee5b80a8fb0675 |

