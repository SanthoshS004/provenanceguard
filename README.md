# ProvenanceGuard — Enterprise Software Supply-Chain Security Platform

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Phase](https://img.shields.io/badge/Phase-0%20Foundation-orange.svg)](#phase-status)

**ProvenanceGuard** is an enterprise-oriented, zero-trust software supply-chain verification and CI/CD security platform.

It independently verifies software artifacts before release and deployment by correlating source identity, build provenance, cryptographic signatures, independent reference builds, binary characteristics, and dependency/SBOM metadata against enterprise policies.

---

## 🎯 Primary Security Claim

> **ProvenanceGuard detects policy-relevant discrepancies between expected source/build/provenance information and released artifacts and can prevent unverified artifacts from progressing through controlled CI/CD release pipelines.**

### What ProvenanceGuard DOES NOT Claim:
- It does **NOT** claim to detect all malware.
- It does **NOT** claim to prevent all supply-chain attacks.
- It does **NOT** claim to solve all Trusting-Trust compiler compromise attacks (T9).
- It does **NOT** assume that binary byte inequality automatically proves malicious intent.
- It does **NOT** assume that a valid cryptographic signature guarantees software safety.

---

## 🏗️ High-Level Architecture

```
Developer ──► SCM (GitHub/GitLab) ──► Production CI ──► Production Artifact ──┐
                 │                                                          │
                 └──────────────────► ProvenanceGuard                       │
                                            │                               │
                                            ▼                               │
                                   Independent Builder                      │
                                            │                               │
                                            ▼                               │
                                    Reference Artifact                      │
                                            │                               │
                                            ▼                               ▼
                                   Verification Engine ◄────────────────────┘
                                            │
               ┌────────────────────────────┼────────────────────────────┐
               ▼                            ▼                            ▼
      Provenance Verification      Signature Verification        SBOM Inventory
               │                            │                            │
               └────────────────────────────┼────────────────────────────┘
                                            │
                                            ▼
                                   Artifact Analysis
                         (ELF / OCI Container / Dependencies)
                                            │
                                            ▼
                                    Comparison Engine
                                            │
                                            ▼
                                       Risk Engine
                                            │
                                            ▼
                                      Policy Engine
                                            │
                                    ┌───────┴───────┐
                                    ▼               ▼
                                  PASS            BLOCK
                                    │               │
                                    ▼               ▼
                              Deploy Pipeline   Stop CI/CD
```

---

## 🚀 CLI Exit Code Semantics

The CLI component (`provenanceguard`) returns deterministic, standard exit codes to allow tight integration with CI/CD release gates:

| Exit Code | Decision / Meaning | Description |
|---|---|---|
| `0` | **PASS** / **PASS_WITH_WARNING** | Verification succeeded. Policy constraints met. Pipeline can proceed. |
| `1` | **BLOCK** / Policy Failure | Verification failed or risk score exceeded block threshold. CI/CD must halt release. |
| `2` | Configuration Error | Invalid policy syntax, missing credentials, or invalid CLI flags. |
| `3` | Verifier System Error | Internal verifier exception, storage failure, or isolated worker timeout. |

---

## 🔒 Trust Domain Boundary Summary

- **Domain A**: Source Control Management (SCM) — Code & build definitions.
- **Domain B**: Production Build Environment — **Untrusted** for verification purposes.
- **Domain C**: ProvenanceGuard Control Plane — Trusted security enforcement domain.
- **Domain D**: Independent Reference Builder — Isolated reference build environment.
- **Domain E**: Ephemeral Analysis Workers — Ephemeral, resource-constrained sandboxes.
- **Domain F**: Artifact & Metadata Storage — Controlled object and relational storage.

---

## 📁 Repository Structure

```
provenanceguard/
├── apps/               # API server, Celery/Redis background worker, CLI
├── core/               # Domain objects (Artifacts, Verification, Provenance, Policy, Risk)
├── analyzers/          # Artifact analyzers (ELF, Container/OCI, SBOM, Dependencies)
├── builders/           # Isolated builder driver (Docker/Podman reference builder)
├── integrations/       # CI/CD adapters (GitHub Actions, GitLab CI, Jenkins)
├── database/           # Relational schema (PostgreSQL), migrations, repositories
├── config/             # YAML configurations (development, staging, production, worker, logging)
├── docker/             # Container images & compose setups
├── archive/            # Prototype archive (prototype-v0)
├── docs/               # System documentation, ADRs, sequence diagrams, threat model
└── tests/              # Scaffolding for unit, integration, security, attack scenarios
```

---

## 🛠️ Quickstart (Phase 0 Development)

### Prerequisites
- Python 3.11+
- Docker & Docker Compose
- `uv` or `pip`

### Local Setup
```bash
# Clone the repository
git clone https://github.com/provenanceguard/provenanceguard.git
cd provenanceguard

# Create python virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies in editable mode
pip install -e .[dev]

# Run tests & linter
pytest
ruff check .

# Start Docker Infrastructure (PostgreSQL, Redis, MinIO)
docker compose up -d
```

---

## 📚 Key Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md): Comprehensive architectural design and data paths.
- [THREAT-MODEL.md](THREAT-MODEL.md): Threats T1–T9 and mitigation strategies.
- [SECURITY.md](SECURITY.md): Sandboxing rules, zero-trust policies, secret handling.
- [STANDARDS.md](STANDARDS.md): SLSA v1.2, in-toto, Sigstore, SPDX/CycloneDX mapping.
- [LIMITATIONS.md](LIMITATIONS.md): Transparent bounds of binary verification.
- [ADRs](docs/adr/): Architecture Decision Records (ADR-001 through ADR-010).

---

## 📜 License

[MIT License](LICENSE)
