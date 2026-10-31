# AI Model Provenance Gate Report (`release-verify`)

- **Gate Status:** `FAIL` (Exit Code `1`)
- **Timestamp:** `2026-10-31T05:35:58Z`
- **Tool Version:** `0.1.0-rc.1` (`darwin/arm64`)
- **Model Bundle Identity (`bundle-identity/v1`):** `sha256:b870647c39f9d299b394f48d1c67752a186e7aab6dd0368b1d884decd7ec40b5`
- **Deployment Composition Identity (`deployment-composition/v1`):** `sha256:45d9afad2900c634bc75152d08bc2176a8d1743dc5baf982c6360f70fac986b9`
- **Release Qualification Attestation Digest:** `sha256:0c7b4ab6a930dbb5bfa21a947c1ea6a4e0e9e3a74e08b5ebd85abaafa0e942d0`
- **Policy:** `e2e-test-strict-policy` (mode=`strict`, digest=`sha256:86ebc584bed2b313d49771f1ce3db1789dabdb97b5b0ed8143c5e64dc48a930a`)

---

## 1. Security Guarantee Separation Matrix

| Security Guarantee | Observed / Verified Status |
|---|---|
| **Artifact Integrity** | OBSERVED (sha256:b870647c39f9d299b394f48d1c67752a186e7aab6dd0368b1d884decd7ec40b5) |
| **Artifact Authenticity** | ATTESTATION_INVALID |
| **Signer Trust** | SIGNER=test-release-signer-1 (sha256:2d19512cc4f6f51004a898b2dcbfd76f0a0f0b453dface80b70e808b4030fa55) |
| **Artifact Provenance** | BOUND_VIA_RELEASE_ATTESTATION |
| **Security Scan Evidence** | RECORDED_IN_ATTESTATION |
| **Model Behavioral Evaluation** | RECORDED_IN_ATTESTATION |
| **Release Qualification** | INVALID (subject=sha256:c0a72555e7a14d64e27e5f559b14a2c564d502064043e8a2e5cbca8130d9a3e4) |
| **Deployment Identity** | REJECTED (FAIL) |

> **Note:** Each security guarantee is evaluated independently. A SHA-256 digest does not prove origin; a valid BOM or signature does not prove behavioral safety; an unbound evaluation `PASS` does not qualify a model bundle.

## 3. Decision Reasons

| Status | Severity | Category | Code | Message |
|---|---|---|---|---|
| `PASS` | `info` | `bundle` | `DEPLOYMENT_BUNDLE_INSPECTED` | re-computed live model bundle identity sha256:b870647c39f9d299b394f48d1c67752a186e7aab6dd0368b1d884decd7ec40b5 (8 files, 1194 bytes) |
| `FAIL` | `error` | `attestation` | `DEPLOYMENT_ARTIFACT_TAMPERED` | inspected model bundle identity sha256:b870647c39f9d299b394f48d1c67752a186e7aab6dd0368b1d884decd7ec40b5 does not match attested release subject sha256:c0a72555e7a14d64e27e5f559b14a2c564d502064043e8a2e5cbca8130d9a3e4 (artifact modified or substituted) |
| `FAIL` | `error` | `deployment` | `DEPLOYMENT_DESCRIPTOR_BUNDLE_MISMATCH` | deployment descriptor model_bundle_id sha256:c0a72555e7a14d64e27e5f559b14a2c564d502064043e8a2e5cbca8130d9a3e4 does not match live bundle sha256:b870647c39f9d299b394f48d1c67752a186e7aab6dd0368b1d884decd7ec40b5 |
| `PASS` | `info` | `deployment` | `DEPLOYMENT_RUNTIME_IMAGE_VERIFIED` | verified deployment runtime image "ghcr.io/vllm/vllm-openai@sha256:7777777777777777777777777777777777777777777777777777777777777777" |
| `PASS` | `info` | `deployment` | `DEPLOYMENT_SERVING_CONFIG_VERIFIED` | verified serving configuration digest sha256:2952fe8adb1568081442c08415913b5c97739eb630b64dfdc1b13beb95a963f4 |

