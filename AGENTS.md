# AGENTS.md — Agent & Engineer Operational Guidance

Welcome to **ProvenanceGuard**. This document governs how autonomous AI agents, security engineers, and developers interact with, extend, and maintain the ProvenanceGuard codebase.

## 1. Core Mission & Security Imperative

ProvenanceGuard is an enterprise zero-trust software supply-chain verification and CI/CD security platform.

### Security Hierarchy
```
SECURITY > CORRECTNESS > MAINTAINABILITY > SIMPLICITY > DEVELOPMENT SPEED
```
Never sacrifice a security boundary or bypass verification logic to simplify implementation or speed up development.

---

## 2. Fundamental Architectural Rules

1. **Zero-Trust CI**: Never trust production CI (`Domain B`). Authenticated CI runners must be treated as untrusted data submitters.
2. **Never Trust Signatures Alone**: A valid signature indicates key authorization, not artifact safety. Always correlate signatures with build provenance, reference builds, SBOM inventory, and binary characteristics.
3. **Isolated Analysis Workers**: Untrusted artifacts must NEVER be executed directly on the host. Analysis workers (`Domain E`) must run in unprivileged, resource-constrained sandboxes. Never mount the host Docker socket into worker containers without explicit ADR approval.
4. **Deterministic Decision Authority**: Security decisions (`PASS`, `PASS_WITH_WARNING`, `BLOCK`) are driven strictly by deterministic policy rules. AI/LLM models may assist with finding explanation, report generation, and analyst triage, but **AI MUST NEVER silently override deterministic policy evaluation**.
5. **No Secret Leakage**: Never hardcode secrets in source code, tests, configs, or commit histories. Secrets must be passed via environment variables or secret manager adapters. Never log raw secrets, private keys, or credentials.

---

## 3. Directory Layout & Scaffolding Standard

```
provenanceguard/
├── apps/                 # Application entry points (api, worker, cli)
├── core/                 # Core domain logic (artifacts, verification, policy, risk, common)
├── analyzers/            # Pluggable artifact analyzers (elf, container, sbom, dependencies)
├── builders/             # Isolated reference builder abstraction
├── integrations/         # CI/CD adapters (github, gitlab, jenkins)
├── database/             # Relational data access, migrations, schemas
├── dashboard/            # React/TypeScript web interface (Phase 15)
├── policies/             # Default policy definitions (YAML)
├── config/               # Environment configs (development, staging, production, worker, logging)
├── docker/               # Containerfiles and isolation scripts
├── archive/prototype-v0/ # Legacy experimental code archive
├── docs/                 # Documentation (ADRs, sequence diagrams, STRIDE, threat model)
└── tests/                # Test suites (unit, integration, security, attack-scenarios, etc.)
```

---

## 4. Code Quality & Standards

- **Python**: Python 3.11+, strict type annotations (`typing`), `pytest` for testing, `ruff` for linting/formatting, `mypy` for static type verification.
- **C/Systems Code** (Future C Analyzers): Compile with `-Wall -Wextra -Wpedantic`. Use `AddressSanitizer` (ASan) and `UndefinedBehaviorSanitizer` (UBSan) during dev/testing.
- **API Contracts**: OpenAPI 3.1.2 schema compliance. All REST endpoints must be under `/api/v1/`.
- **Standards Mapping**: Follow SLSA v1.2, in-toto attestation framework, Sigstore/Cosign standards, SPDX/CycloneDX SBOM specs, and OCI image specifications.

---

## 5. Development Workflow for Agents

1. **Check Architecture & ADRs**: Before modifying code, read `ARCHITECTURE.md`, `THREAT-MODEL.md`, and relevant ADRs in `docs/adr/`.
2. **Phase Boundaries**: Do NOT jump ahead to future phases. Complete the current phase according to its Definition of Done.
3. **Traceability**: Every code addition must map to a requirement in `docs/REQUIREMENTS-TRACEABILITY.md`.
4. **Verification**: Always run pytest and ruff before concluding any task:
   ```bash
   pytest
   ruff check .
   ```
5. **Explicit Error Codes**: All errors raised across components must use stable, machine-readable codes defined in `docs/ERROR-CODES.md` (e.g., `PG-1001`, `PG-3001`).

---

## 6. Security Claims & Language Policy

Do **NOT** use misleading claim terminology in documentation, comments, or log messages:
- ❌ **Forbidden**: "ProvenanceGuard detects all malware."
- ❌ **Forbidden**: "ProvenanceGuard prevents all supply chain attacks."
- ❌ **Forbidden**: "Hash mismatch proves malicious intent."
- ✅ **Required**: "ProvenanceGuard detects policy-relevant discrepancies between expected source/build/provenance information and released artifacts and can prevent unverified artifacts from progressing through controlled CI/CD release pipelines."
