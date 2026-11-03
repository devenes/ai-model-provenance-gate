# Environment Baseline Report

**Generated:** 2026-10-31T00:10:00+03:00  
**Phase:** Phase 0 — Environment and Baseline Inspection  
**Workspace:** `ai-model-provenance-gate`

---

## 1. Host System and Hardware

| Property | Observed Value |
|---|---|
| Operating System | macOS 27.0.1 (Build `26A434`) |
| Kernel | `Darwin Eness-MacBook-Air-2.local 27.0.0 Darwin Kernel Version 27.0.0: RELEASE_ARM64_T8103 arm64` |
| CPU Architecture | `arm64` (Apple Silicon) |
| CPU Model | `Apple M1` (8 cores) |
| Physical Memory (RAM) | `8,589,934,592` bytes (8.0 GB) |
| Execution Mode | CPU-only local development (no GPU acceleration required or used) |

---

## 2. Core Toolchain & Build Environment

| Tool | Status | Version / Path | Notes |
|---|---|---|---|
| Go (system binary) | Installed | `go1.27.2 darwin/arm64` (`/opt/homebrew/bin/go`) | `GOTOOLCHAIN=auto` enabled |
| Go (cached toolchain) | Installed | `go1.27.3 darwin/arm64` (`~/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.27.3.darwin-arm64`) | Resolves stdlib `crypto/x509` advisory `GO-2026-6809` in `go1.27.2`; matches sibling repos |
| Git | Installed | `git version 2.54.0 (Apple Git-157)` | Clean working tree |
| `golangci-lint` | Installed | `2.14.0` (`/opt/homebrew/bin/golangci-lint`) | Built with `go1.27.1` |
| `govulncheck` | Installed | `v1.9.0` (`~/go/bin/govulncheck`) | Vuln DB updated `2026-10-27T21:16:18Z` |
| OpenSSL | Installed | `OpenSSL 4.0.3 29 Sep 2026` (`/opt/homebrew/bin/openssl`) | Available for key generation and verification tests |
| `jq` | Installed | `/usr/bin/jq` | JSON inspection utility |
| `shasum` | Installed | `/usr/bin/shasum` | Cross-check digest utility |
| Python 3 | Installed | `/usr/bin/python3` (`3.9.6`), `/opt/homebrew/bin/python3.13` (`3.13.16`), `/opt/homebrew/bin/python3.14` (`3.14.8`) | Not required at runtime by the Go CLI |
| `uv` | Installed | `0.13.0` (`/opt/homebrew/bin/uv`) | Python package/tool runner |
| `cosign` | **NOT_FOUND** | Not installed on `PATH` | Optional CLI adapter supported; native Go DSSE/Ed25519/ECDSA verification + Sigstore bundle parsing also provided |
| `model-signing` (`model_signing`) | **NOT_FOUND** | Not installed on `PATH` or Python environments | External CLI subprocess adapter + native Go in-toto/DSSE OMS v1.0 (`https://model_signing/signature/v1.0`) verifier supported |
| `modelscan` | **NOT_FOUND** | Not installed on `PATH` or Python environments | Optional scanner adapter interface and JSON report ingestion supported |
| `cyclonedx` CLI | **NOT_FOUND** | Not installed on `PATH` | Deterministic built-in CycloneDX v1.6/v1.7 schema structural validator implemented in Go |

---

## 3. Target Repository State (`ai-model-provenance-gate`)

- **Directory Path:** `ai-model-provenance-gate`
- **Git Status:** Initialized Git repository on branch `main`, tracking `origin/main` (`https://github.com/devenes/ai-model-provenance-gate.git`).
- **HEAD Commit:** `eafb5e987c8ee0ee8bd622e4a9a5787b43677bd9` (`Initial commit`, `2026-10-30 22:04:19 +0100`).
- **Existing Tracked Files:** `.gitattributes` (`* text=auto`).
- **Working Tree State:** Clean (`nothing to commit, working tree clean`).
- **Conflict Assessment:** No conflict. The directory is an empty, dedicated repository initialized specifically for `ai-model-provenance-gate`.

---

## 4. Portfolio Sibling Repositories (Strictly Read-Only)

| Repository | Local Path | Remote URL | Responsibility | Isolation Policy |
|---|---|---|---|---|
| `ai-platform-conformance-kit` | `ai-platform-conformance-kit` | `https://github.com/devenes/ai-platform-conformance-kit` | Infrastructure and platform conformance | Strictly Read-Only |
| `llm-release-gate` | `llm-release-gate` | `https://github.com/devenes/llm-release-gate` | Model behavior, quality, regression, and evaluation | Strictly Read-Only |
| `ai-model-provenance-gate` | `ai-model-provenance-gate` | `https://github.com/devenes/ai-model-provenance-gate` | Model artifact identity, integrity, provenance, evaluation evidence binding, and release qualification | Active target workspace (local only, no remote push) |
