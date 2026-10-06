# ProvenanceGuard Requirements Traceability Matrix

This document tracks all functional and non-functional requirements to their implementation components, automated tests, verification evidence, and lifecycle status.

---

## 1. Traceability Matrix

| Requirement ID | Description | Target Component | Implementation Module | Automated Test File | Status |
|---|---|---|---|---|---|
| **REQ-001** | Artifact Ingestion (ELF, OCI, SBOM) | Ingestion Engine | `core/artifacts/ingestion.py` | `tests/unit/test_ingestion.py` | VERIFIED |
| **REQ-002** | Cryptographic Digest Calculation | Streaming Hashing | `core/common/crypto.py` | `tests/unit/test_hashing.py` | VERIFIED |
| **REQ-003** | Object Storage Abstraction | Storage Module | `infrastructure/storage/` | `tests/unit/test_storage_filesystem.py` | VERIFIED |
| **REQ-004** | Extensible `ArtifactAnalyzer` Interface | Analyzers Base | `analyzers/base.py` | `tests/unit/test_analyzers.py` | VERIFIED |
| **REQ-005** | ELF Header & Section Parsing | ELF Analyzer | `analyzers/elf/parser.py` | `tests/unit/test_elf_analyzer.py` | VERIFIED |
| **REQ-006** | Stripped ELF Graceful Handling | ELF Analyzer | `analyzers/elf/parser.py` | `tests/unit/test_elf_analyzer.py` | VERIFIED |
| **REQ-007** | Function Identity Digest & Comparison | Comparison Engine | `core/verification/comparison.py` | `tests/unit/test_comparison.py` | VERIFIED |
| **REQ-008** | SLSA v1.2 Provenance Validation | Provenance Module | `core/verification/provenance.py` | `tests/unit/test_provenance.py` | VERIFIED |
| **REQ-009** | in-toto DSSE Envelope Verification | DSSE Module | `core/verification/dsse.py` | `tests/unit/test_dsse.py` | VERIFIED |
| **REQ-010** | Provenance Tampering & Finding Detection | Exception Module | `core/verification/exceptions.py` | `tests/unit/test_provenance.py` | VERIFIED |
| **REQ-011** | Sigstore / Cosign Integration | Signature Module | `core/verification/sigstore.py` | `tests/unit/test_sigstore.py` | VERIFIED |
| **REQ-012** | OIDC Issuer & SAN Verification | Signature Module | `core/verification/sigstore.py` | `tests/unit/test_sigstore.py` | VERIFIED |
| **REQ-013** | Multi-Factor Decision (Signature != Safe) | Policy Engine | `core/policy/policy_engine.py` | `tests/security/test_policy_security.py` | VERIFIED |
| **REQ-014** | SPDX & CycloneDX SBOM Parsing | SBOM Analyzer | `analyzers/sbom/parser.py` | `tests/unit/test_sbom_parser.py` | VERIFIED |
| **REQ-015** | SBOM Delta Inventory Comparison | Comparison Engine | `core/verification/sbom_compare.py` | `tests/unit/test_sbom_compare.py` | VERIFIED |
| **REQ-016** | Isolated Reference Builder Driver | Isolated Builder | `builders/isolated/docker_builder.py` | `tests/unit/test_builder.py` | VERIFIED |
| **REQ-017** | Builder Isolation & Pinned Toolchain | Isolated Builder | `builders/isolated/docker_builder.py` | `tests/security/test_sandbox.py` | VERIFIED |
| **REQ-018** | Transparent Rule-Based Risk Engine | Risk Engine | `core/policy/risk_engine.py` | `tests/unit/test_risk_engine.py` | VERIFIED |
| **REQ-019** | YAML-Driven Policy Engine | Policy Engine | `core/policy/policy_engine.py` | `tests/unit/test_policy_engine.py` | VERIFIED |
| **REQ-020** | Explainable Decision Findings | Policy Engine | `core/policy/policy_engine.py` | `tests/unit/test_policy_engine.py` | VERIFIED |
| **REQ-021** | CLI Command Semantics | CLI Application | `apps/cli/main.py` | `tests/unit/test_cli_policy.py` | VERIFIED |
| **REQ-022** | Exit Code Semantics (0, 1, 2, 3) | CLI Application | `apps/cli/exit_codes.py` | `tests/unit/test_cli_policy.py` | VERIFIED |
| **REQ-023** | GitHub Actions / CI Adapters | Integrations | `integrations/github/action.py` | `tests/integration/test_github_action.py` | VERIFIED |
| **REQ-024** | OIDC/OAuth2 IdP Federation | API Security Subsystem | `apps/api/auth_oidc.py`, `routes_idp.py` | `tests/security/test_oidc_security.py` | VERIFIED |
| **REQ-025** | Asynchronous Webhook Event Engine | Webhook Engine | `infrastructure/webhooks/` | `tests/integration/test_webhooks.py`, `test_webhook_delivery_claims.py`, `test_webhook_crypto.py` | VERIFIED |
| **NFR-001** | Worker Container Hardening & Isolation | Worker Sandbox | `apps/worker/worker.py` | `tests/security/test_worker_security.py` | PRODUCTION-READY |
| **NFR-002** | Multi-Tenancy Data Isolation | Database Schema | `infrastructure/database/` | `tests/security/test_multitenancy.py` | PRODUCTION-READY |
| **NFR-003** | OAuth2/JWT Authentication & RBAC | API Security Subsystem | `apps/api/auth.py`, `apps/api/rbac.py` | `tests/security/test_jwt_security.py`, `test_api_key_security.py`, `test_api_rbac_security.py` | PRODUCTION-READY |
| **NFR-004** | Verification Gateway API Endpoints | REST Integration Gateway | `apps/api/routes_verifications.py` | `tests/integration/test_api_endpoints.py` | PRODUCTION-READY |
| **NFR-005** | Async Worker Queue & Redis Task Dispatch | Worker Queue | `infrastructure/queue/` | `tests/integration/test_worker_queue.py` | PRODUCTION-READY |
| **NFR-006** | Immutable Audit Log Generation | Database / Audit | `infrastructure/database/` | `tests/unit/test_audit.py` | PRODUCTION-READY |
| **NFR-007** | Audit Log Hash Chain & Tamper Evidency | Domain Audit Module | `core/domain/audit.py` | `tests/unit/test_audit_tamper_resistance.py` | PRODUCTION-READY |
| **NFR-008** | Two-Stage Rate Limiting & Security Headers | API Gateway Middleware | `apps/api/rate_limiter.py` | `tests/security/test_rate_limiter_security.py` | PRODUCTION-READY |

---

## 2. Status Definitions

- **PLANNED**: Specified in architecture but files not yet created.
- **SCAFFOLDED**: File structure, modules, interfaces, and test stubs created.
- **IMPLEMENTED**: Code logic built and integrated into system.
- **VERIFIED**: Unit, integration, security, or E2E tests pass with contract validation.
- **PRODUCTION-READY**: Formally evaluated and vetted for enterprise release against defined operational criteria.
- **DEFERRED**: Explicitly postponed capability (e.g. HSM / external immutable ledger audit anchoring).
- **NOT APPLICABLE**: Not required for target system scope.
