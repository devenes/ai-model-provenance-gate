# Open-Source & Governance Readiness (`v0.1.0-rc.1`)

**Document Status:** Verified for `v0.1.0-rc.1` Local Release Candidate  
**Repository:** `https://github.com/devenes/ai-model-provenance-gate`

---

## 1. Repository License Status (`APPROVED_BY_OWNER`)

- **Local Workspace File:** `/Users/enes/GitHub/ai-model-provenance-gate/LICENSE`
- **License Type:** `MIT License` (`Copyright (c) 2026 Enes Turan`), matching the sibling repository `/Users/enes/GitHub/llm-release-gate/LICENSE`.
- **Governance Status:** **`APPROVED_BY_OWNER`** for public open-source distribution (`v0.1.0`).

---

## 2. Direct & Transitive Go Dependency License Inventory

All dependencies in `go.mod` use permissive, OSI-approved open-source licenses compatible with MIT distribution:

| Dependency Module | Version | License | Purpose |
|---|---|---|---|
| `github.com/CycloneDX/cyclonedx-go` | `v0.12.0` | `Apache-2.0` | CycloneDX 1.7 / 1.6 AI/ML-BOM data structures |
| `github.com/santhosh-tekuri/jsonschema/v6` | `v6.0.3` | `Apache-2.0` | Official CycloneDX 1.7 / 1.6 JSON Schema Draft-07 validation |
| `github.com/in-toto/in-toto-golang` | `v0.9.0` | `Apache-2.0` | in-toto Statement v1 data structures |
| `github.com/secure-systems-lab/go-securesystemslib` | `v0.9.0` | `MIT` | DSSE envelope structures |
| `golang.org/x/crypto` | `v0.33.0` | `BSD-3-Clause` | Cryptographic primitives |
| `golang.org/x/text` | `v0.22.0` | `BSD-3-Clause` | Unicode NFC normalization (`internal/inventory`) |
| `gopkg.in/yaml.v3` | `v3.0.1` | `MIT` / `Apache-2.0` | YAML policy and deployment descriptor parsing |

Embedded specification schemas (`internal/bom/schemas/`):
- `bom-1.7.schema.json`, `bom-1.6.schema.json`, `spdx.schema.json`, `jsf-0.82.schema.json`: Official CycloneDX Specification schemas (`Apache-2.0`, OWASP Foundation).

---

## 3. Security Vulnerability Reporting Guidance

- **Supported Versions:** `0.1.0-rc.1` (pre-release candidate).
- **Reporting Channel:** Do **not** open public GitHub issues for suspected cryptographic bypasses, path traversal vulnerabilities, or policy engine fail-open bugs. Report security vulnerabilities privately via GitHub Security Advisories (`https://github.com/devenes/ai-model-provenance-gate/security/advisories/new`) once the repository is public.
- **Required Triage Artifacts:** Include the exact `ai-model-provenance version --json` output, policy configuration (`policy.yaml`), and a minimal synthetic bundle fixture reproducing the issue without proprietary model weights.

---

## 4. Contribution & Quality Gate Standards

Every contribution must pass the local deterministic quality gate before merge:

```bash
make check
shellcheck scripts/*.sh
```

Required invariants for contributors:
1. **Zero Custom Cryptography:** Use only Go standard library `crypto/*` and vetted specification formats (DSSE, in-toto v1, Sigstore Bundle v0.3, RFC 8785 JCS).
2. **Streaming & Bounded Memory:** Never read model weight files into memory with `os.ReadFile`; always use streaming readers (`internal/digest`) and bounded header parsers (`internal/formats/safetensors`).
3. **Fail-Closed Policy Semantics:** Missing, unsigned, expired, or untrusted evidence must never silently default to `PASS`.
4. **Honest Status Reporting:** Never convert `BLOCKED` or `NOT_RUN` states into `PASS`.
