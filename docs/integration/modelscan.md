# Protect AI ModelScan Integration Guide

## 1. Overview & Purpose
[Protect AI ModelScan](https://github.com/protectai/modelscan) is an open-source scanner that inspects serialized machine learning model files for unsafe operators and embedded code execution payloads (e.g., Python `pickle` opcodes in `.pkl`/`.pt`/`.bin`, `Lambda` layers in Keras `.h5`/`.keras`, and dangerous TensorFlow `SavedModel` operators).

## 2. Supported Formats and Safetensors Behavior
- **Formats Scanned by ModelScan:** Pickle (`.pkl`, `.pickle`, `.joblib`, `.dill`), PyTorch (`.pt`, `.pth`, `.bin`, `.ckpt`), TensorFlow (`saved_model.pb`), Keras (`.h5`, `.hdf5`, `.keras`), NumPy (`.npy`, `.npz`).
- **Safetensors (`.safetensors`):** Because `.safetensors` consists strictly of an 8-byte length prefix, a UTF-8 JSON tensor header, and raw numerical bytes with no executable opcodes, ModelScan records `.safetensors` files under `summary.skipped` (and exits with code `3` when a directory contains only `.safetensors` and `.json` files).
- **Defense-in-Depth in `ai-model-provenance-gate`:**
  1. `ai-model-provenance-gate` always performs native static inspection of `.safetensors` headers (`internal/formats/safetensors`), checking for disguised Pickle (`\x80\x02`..`\x80\x05`) or ZIP (`PK\x03\x04`) magic bytes, header length bounds, and contiguous tensor offsets.
  2. `ai-model-provenance-gate` rejects `.pkl`, `.pt`, `.bin`, and `.ckpt` files by default (`ErrUnsupportedFormat`).
  3. When `--scanner-report <scan.json>` is provided to `gate evaluate`, `internal/scanner` validates the ModelScan JSON report (`modelscan_version`, `summary.total_issues == 0`, `summary.total_errors == 0`) and records its SHA-256 digest in the `release-qualification/v1` attestation.

## 3. Critical Security Boundary
A passing ModelScan report (`PASS`) or static Safetensors header check **never** establishes model behavioral safety, alignment, or absence of weight-level backdoors. Every report emitted by `ai-model-provenance-gate` includes an explicit `coverage_limitation` field stating this boundary.
