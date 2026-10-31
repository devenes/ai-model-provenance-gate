# SLSA (Supply-chain Levels for Software Artifacts) Standard Reference

## 1. Official Sources
- **SLSA Homepage:** https://slsa.dev/
- **SLSA v1.0 Specification:** https://slsa.dev/spec/v1.0/
- **SLSA v1.1 Specification:** https://slsa.dev/spec/v1.1/
- **SLSA Provenance Predicate:** `https://slsa.dev/provenance/v1`
- **SLSA Verification Summary Attestation (VSA):** `https://slsa.dev/verification_summary/v1`

## 2. Critical Distinction: Build Provenance vs. Release Qualification

`ai-model-provenance-gate` enforces a strict architectural separation between **SLSA Build/Training Provenance** and **Release Qualification Attestations**:

1. **SLSA Provenance (`https://slsa.dev/provenance/v1`)** must be generated **during the build or training execution** by a trusted builder/training control plane that isolated and observed the build inputs (`buildDefinition.externalParameters`, `resolvedDependencies`) and emitted the provenance statement (`runDetails.builder.id`).
2. **An in-toto Statement is NOT automatically SLSA Provenance.** Wrapping a local file inventory in `https://in-toto.io/Statement/v1` does **not** achieve SLSA Build L1/L2/L3 compliance unless a genuine build/training system produced `https://slsa.dev/provenance/v1`.
3. **`ai-model-provenance-gate` is a Verifier and Release Qualification Gate, not a Model Training Builder.**
   - Therefore, `ai-model-provenance-gate` **never** emits `https://slsa.dev/provenance/v1` for model bundles it inspects post-hoc.
   - Instead, it emits its own explicitly scoped predicate:
     `https://github.com/devenes/ai-model-provenance-gate/attestation/release-qualification/v1`.
   - When an upstream training/build pipeline supplies a signed `https://slsa.dev/provenance/v1` DSSE attestation for the model bundle, `ai-model-provenance-gate` can verify its DSSE signature, builder ID, and subject digest correspondence as optional upstream provenance evidence.
