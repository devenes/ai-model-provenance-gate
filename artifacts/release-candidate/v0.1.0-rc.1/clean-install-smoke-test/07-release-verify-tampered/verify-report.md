# AI Model Provenance Gate Report (`release-verify`)

- **Gate Status:** `FAIL` (Exit Code `1`)
- **Timestamp:** `2026-10-31T05:42:27Z`
- **Tool Version:** `0.1.0-rc.1` (`darwin/arm64`)
- **Model Bundle Identity (`bundle-identity/v1`):** `sha256:5de71f31053cdbb2a052ddaa37cd9aa6ff9f6d849e54d1f8987937812a1139bf`
- **Deployment Composition Identity (`deployment-composition/v1`):** `sha256:928cfc44decf9e6d0b63e1c8bda069aed0030b7601a173495940008514f3df6a`
- **Release Qualification Attestation Digest:** `sha256:5b7ad472598459972ff17765bf7197881cb36b75f1d98478f419cd2295829976`
- **Policy:** `rc1-strict-policy` (mode=`strict`, digest=`sha256:9b24240cc0267d6915786785ebc02cac0afbe374fe2e8e8a8406b4d75e2ce95b`)

---

## 1. Security Guarantee Separation Matrix

| Security Guarantee | Observed / Verified Status |
|---|---|
| **Artifact Integrity** | OBSERVED (sha256:5de71f31053cdbb2a052ddaa37cd9aa6ff9f6d849e54d1f8987937812a1139bf) |
| **Artifact Authenticity** | ATTESTATION_INVALID |
| **Signer Trust** | SIGNER=release-signer-1 (sha256:ef385f7bc28ac44e805a621e0da4a753b65475ad40d1b64473ac280c2a0c07c1) |
| **Artifact Provenance** | BOUND_VIA_RELEASE_ATTESTATION |
| **Security Scan Evidence** | RECORDED_IN_ATTESTATION |
| **Model Behavioral Evaluation** | RECORDED_IN_ATTESTATION |
| **Release Qualification** | INVALID (subject=sha256:2c5f9757efe8c44d095cb3969c166928ccfaefc7cf80fc2b1ef8639505347adb) |
| **Deployment Identity** | REJECTED (FAIL) |

> **Note:** Each security guarantee is evaluated independently. A SHA-256 digest does not prove origin; a valid BOM or signature does not prove behavioral safety; an unbound evaluation `PASS` does not qualify a model bundle.

## 3. Decision Reasons

| Status | Severity | Category | Code | Message |
|---|---|---|---|---|
| `PASS` | `info` | `bundle` | `DEPLOYMENT_BUNDLE_INSPECTED` | re-computed live model bundle identity sha256:5de71f31053cdbb2a052ddaa37cd9aa6ff9f6d849e54d1f8987937812a1139bf (9 files, 1170 bytes) |
| `FAIL` | `error` | `attestation` | `DEPLOYMENT_ARTIFACT_TAMPERED` | inspected model bundle identity sha256:5de71f31053cdbb2a052ddaa37cd9aa6ff9f6d849e54d1f8987937812a1139bf does not match attested release subject sha256:2c5f9757efe8c44d095cb3969c166928ccfaefc7cf80fc2b1ef8639505347adb (artifact modified or substituted) |
| `FAIL` | `error` | `deployment` | `DEPLOYMENT_DESCRIPTOR_BUNDLE_MISMATCH` | deployment descriptor model_bundle_id sha256:2c5f9757efe8c44d095cb3969c166928ccfaefc7cf80fc2b1ef8639505347adb does not match live bundle sha256:5de71f31053cdbb2a052ddaa37cd9aa6ff9f6d849e54d1f8987937812a1139bf |
| `PASS` | `info` | `deployment` | `DEPLOYMENT_RUNTIME_IMAGE_VERIFIED` | verified deployment runtime image "ghcr.io/vllm/vllm-openai@sha256:7777777777777777777777777777777777777777777777777777777777777777" |
| `PASS` | `info` | `deployment` | `DEPLOYMENT_SERVING_CONFIG_VERIFIED` | verified serving configuration digest sha256:51ceb1fe36b786d1d57dcd52c22ca444ae0e81adab31243be4ee5b80a8fb0675 |

