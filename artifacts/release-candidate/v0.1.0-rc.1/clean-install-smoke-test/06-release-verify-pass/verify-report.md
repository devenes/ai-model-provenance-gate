# AI Model Provenance Gate Report (`release-verify`)

- **Gate Status:** `PASS` (Exit Code `0`)
- **Timestamp:** `2026-10-31T05:42:27Z`
- **Tool Version:** `0.1.0-rc.1` (`darwin/arm64`)
- **Model Bundle Identity (`bundle-identity/v1`):** `sha256:2c5f9757efe8c44d095cb3969c166928ccfaefc7cf80fc2b1ef8639505347adb`
- **Deployment Composition Identity (`deployment-composition/v1`):** `sha256:928cfc44decf9e6d0b63e1c8bda069aed0030b7601a173495940008514f3df6a`
- **Release Qualification Attestation Digest:** `sha256:5b7ad472598459972ff17765bf7197881cb36b75f1d98478f419cd2295829976`
- **Policy:** `rc1-strict-policy` (mode=`strict`, digest=`sha256:9b24240cc0267d6915786785ebc02cac0afbe374fe2e8e8a8406b4d75e2ce95b`)

---

## 1. Security Guarantee Separation Matrix

| Security Guarantee | Observed / Verified Status |
|---|---|
| **Artifact Integrity** | OBSERVED (sha256:2c5f9757efe8c44d095cb3969c166928ccfaefc7cf80fc2b1ef8639505347adb) |
| **Artifact Authenticity** | ATTESTATION_VERIFIED |
| **Signer Trust** | SIGNER=release-signer-1 (sha256:ef385f7bc28ac44e805a621e0da4a753b65475ad40d1b64473ac280c2a0c07c1) |
| **Artifact Provenance** | BOUND_VIA_RELEASE_ATTESTATION |
| **Security Scan Evidence** | RECORDED_IN_ATTESTATION |
| **Model Behavioral Evaluation** | RECORDED_IN_ATTESTATION |
| **Release Qualification** | VERIFIED (subject=sha256:2c5f9757efe8c44d095cb3969c166928ccfaefc7cf80fc2b1ef8639505347adb) |
| **Deployment Identity** | VERIFIED (composition_id=sha256:928cfc44decf9e6d0b63e1c8bda069aed0030b7601a173495940008514f3df6a, immutable_image=true) |

> **Note:** Each security guarantee is evaluated independently. A SHA-256 digest does not prove origin; a valid BOM or signature does not prove behavioral safety; an unbound evaluation `PASS` does not qualify a model bundle.

## 3. Decision Reasons

| Status | Severity | Category | Code | Message |
|---|---|---|---|---|
| `PASS` | `info` | `bundle` | `DEPLOYMENT_BUNDLE_INSPECTED` | re-computed live model bundle identity sha256:2c5f9757efe8c44d095cb3969c166928ccfaefc7cf80fc2b1ef8639505347adb (8 files, 1104 bytes) |
| `PASS` | `info` | `attestation` | `RELEASE_ATTESTATION_VERIFIED` | verified signed release qualification attestation (sha256:ef385f7bc28ac44e805a621e0da4a753b65475ad40d1b64473ac280c2a0c07c1) matching bundle sha256:2c5f9757efe8c44d095cb3969c166928ccfaefc7cf80fc2b1ef8639505347adb |
| `PASS` | `info` | `deployment` | `DEPLOYMENT_DESCRIPTOR_BUNDLE_MATCHED` | deployment descriptor model_bundle_id matches live bundle |
| `PASS` | `info` | `deployment` | `DEPLOYMENT_RUNTIME_IMAGE_VERIFIED` | verified deployment runtime image "ghcr.io/vllm/vllm-openai@sha256:7777777777777777777777777777777777777777777777777777777777777777" |
| `PASS` | `info` | `deployment` | `DEPLOYMENT_SERVING_CONFIG_VERIFIED` | verified serving configuration digest sha256:51ceb1fe36b786d1d57dcd52c22ca444ae0e81adab31243be4ee5b80a8fb0675 |

