# Release Readiness Checklist (`v0.1.0-rc.1`)

**Target Release Candidate:** `v0.1.0-rc.1`  
**Verification Date:** `2026-10-31`

---

## 1. Engineering & Security Verification Checklist (Completed Locally)

- [x] **Baseline Repository Audit (`docs/release/BASELINE.md`)**:
  - Verified local branch (`main`), remote (`https://github.com/devenes/ai-model-provenance-gate.git`), absence of premature tags, `.gitignore` rules, and sibling repository isolation (`llm-release-gate` and `ai-platform-conformance-kit` untouched).
- [x] **All 10 Security & Standards Audit Findings Closed (`AUD-01`..`AUD-10`)**:
  - CycloneDX 1.7 (`v0.12.0`) + official JSON Schema validation (`AUD-01`, `AUD-02`).
  - OpenSSF Model Signing v1.0 upstream conformance (`80/80` default, `55/55` `test_verify.py`, `87/87` offline-capable) + duplicate/traversal protection (`AUD-03`, `AUD-04`).
  - LLM Release Gate 7-boolean trust model + `OPERATOR_ENDORSEMENT` separation + evaluator context binding (`AUD-05`, `AUD-06`, `AUD-07`).
  - SLSA v1.0/v1.2 provenance support + strict RFC 3339 policy exception expiry (`AUD-08`, `AUD-09`).
  - Filesystem symlink/hardlink/FIFO/NFC/case-collision/TOCTOU guards (`AUD-10`).
- [x] **Full Quality Gate (`artifacts/release-candidate/quality-gate-results.txt`)**:
  - `gofmt -s -l .` (0 unformatted files)
  - `go vet ./...` (`PASS`)
  - `go test -count=1 ./...` (`PASS`)
  - `go test -count=1 -race ./...` (`PASS`)
  - `golangci-lint run ./...` (`0 issues`)
  - `govulncheck ./...` (`No vulnerabilities found`)
  - `go mod verify` (`all modules verified`)
  - `shellcheck scripts/*.sh` (`PASS`)
  - `make check` (`PASS`)
- [x] **CLI User Experience Polish (`internal/cli/cli.go`)**:
  - All commands, subcommands, and aliases (`inspect`/`bundle`, `bom`, `oms`, `evidence`/`eval`, `gate`/`attest`, `release`/`deploy`, `keygen`, `version`) support `--help` and exit `0`.
- [x] **Cross-Platform Release Candidate Packaging (`artifacts/release-candidate/v0.1.0-rc.1/`)**:
  - Built static `CGO_ENABLED=0` archives for `darwin/arm64`, `darwin/amd64`, `linux/amd64`, `linux/arm64`, and `windows/amd64`.
  - Generated and verified `checksums.txt`, `SHA256SUMS`, `manifest.json`, and `RELEASE_NOTES.md`.
- [x] **Clean Installation Smoke Test & Final E2E Demo (`artifacts/release-candidate/v0.1.0-rc.1/clean-install-smoke-test/`)**:
  - Extracted packaged `ai-model-provenance_0.1.0-rc.1_darwin_arm64.tar.gz` into an isolated temporary directory outside the repository and verified all 12 positive steps and all negative tampering/policy rejection scenarios.

---

## 2. Manual Owner Actions Required Before Public Release

Because all Git commits, tags, pushes, and GitHub Releases are strictly gated on explicit owner authorization, execute the following steps when ready to publish `v0.1.0-rc.1`:

1. **Confirm License Selection (`OWNER_APPROVAL_REQUIRED`):**
   - Review `ai-model-provenance-gate/LICENSE` (`MIT License`, `Copyright (c) 2026 Enes Turan`) and confirm approval for public open-source distribution.
2. **Stage and Commit Release Candidate (`main`):**
   ```bash
   git add .
   git status
   git commit -m "feat: release candidate v0.1.0-rc.1"
   ```
3. **Create Annotated Git Tag (`v0.1.0-rc.1`):**
   ```bash
   git tag -a v0.1.0-rc.1 -m "AI Model Provenance Gate v0.1.0-rc.1"
   ```
4. **Push Branch and Tag to GitHub:**
   ```bash
   git push origin main
   git push origin v0.1.0-rc.1
   ```
5. **Verify GitHub Actions CI & Optional Live OIDC Conformance:**
   - Confirm `.github/workflows/ci.yml` (`verify` job on `ubuntu-latest`) and `.github/workflows/release.yml` (`package` job) succeed.
   - Optionally trigger the `CI` workflow manually via `workflow_dispatch` with `run_live_oidc: true` to execute the 7 live Fulcio/Rekor OIDC signing conformance tests in `ossf/model-signing-spec`.
6. **Publish GitHub Pre-Release (`v0.1.0-rc.1`):**
   - Upload the 5 archives (`*.tar.gz`, `*.zip`), `checksums.txt`, `SHA256SUMS`, and `manifest.json` from `artifacts/release-candidate/v0.1.0-rc.1/` along with `RELEASE_NOTES.md`, marking the release as a **pre-release**.
