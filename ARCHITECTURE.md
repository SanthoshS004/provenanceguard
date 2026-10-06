# ProvenanceGuard Architecture Specification

## 1. System Overview & Philosophy

ProvenanceGuard is an independent, zero-trust software supply-chain verification platform designed to evaluate software artifacts prior to deployment in production environments.

The architecture enforces a strict separation of trust: **production build infrastructure is treated as untrusted**. The verifier independently ingests production artifacts, triggers reference builds in isolated builders, analyzes binary/structural characteristics, evaluates provenance & cryptographic signatures, computes risk metrics, and enforces policy constraints.

---

## 2. High-Level System Architecture

```
                                  [ DOMAIN A: SOURCE CONTROL ]
                                 (GitHub / GitLab / Bitbucket)
                                               │
                       ┌───────────────────────┴───────────────────────┐
                       │                                               │
                       ▼                                               ▼
         [ DOMAIN B: PRODUCTION BUILD ]               [ DOMAIN C: PROVENANCEGUARD CONTROL PLANE ]
        (Potentially Compromised CI)                                   │
                       │                                               ├────────► API Gateway / REST Service
                       │ Submission                                    ├────────► Task Queue (Redis / Celery)
                       ▼                                               └────────► Verification Engine
            Production Artifact                                                │
                       │                                                       │ Trigger Build
                       └───────────────────────┬───────────────────────────────┘
                                               │
                                               ▼
                                 [ DOMAIN D: INDEPENDENT BUILDER ]
                               (Isolated Container / Ephemeral Workspace)
                                               │
                                               ▼
                                      Reference Artifact
                                               │
                       ┌───────────────────────┴───────────────────────┐
                       ▼                                               ▼
         [ DOMAIN E: ANALYSIS WORKERS ]                  [ DOMAIN F: STORAGE & METADATA ]
     (Ephemeral Sandboxed Analyzers)                    (PostgreSQL / MinIO / S3 Storage)
    ┌──────────────────────────────────┐               ┌─────────────────────────────────┐
    │ - ELF Analyzer                   │               │ - Artifact Objects & Hashes     │
    │ - OCI Container Analyzer         │               │ - Provenance & Attestations     │
    │ - SBOM & Dependency Analyzer     │               │ - Verification Runs & Findings  │
    └──────────────────────────────────┘               └─────────────────────────────────┘
                       │                                               │
                       └───────────────────────┬───────────────────────┘
                                               │
                                               ▼
                                  [ COMPARISON & RISK ENGINE ]
                                               │
                                               ▼
                                       [ POLICY ENGINE ]
                                               │
                                ┌──────────────┴──────────────┐
                                ▼                             ▼
                             [ PASS ]                      [ BLOCK ]
                                │                             │
                                ▼                             ▼
                        Deploy Pipeline                 Pipeline Halted
```

---

## 3. Subsystem Breakdown

### 3.1 REST API & Control Plane (`apps/api`)
- **Technology**: Python 3.11+, FastAPI, Pydantic v2, Uvicorn/Gunicorn.
- **Responsibilities**:
  - Ingestion of production artifacts, SLSA provenance predicates, Sigstore signatures, and SBOM documents.
  - Multi-tenant RBAC enforcement and authentication (JWT, Service Tokens for CI).
  - Versioned API under `/api/v1/` with auto-generated OpenAPI 3.1.2 schemas.
  - Triggering verification jobs asynchronously via task queue.

### 3.2 Asynchronous Worker & Queue (`apps/worker`)
- **Technology**: Redis + Celery / ARQ background task workers.
- **Responsibilities**:
  - Ephemeral analysis worker orchestration (`Domain E`).
  - Strict resource limits (CPU quotas, memory caps, processing timeouts).
  - Isolated file parsing to prevent parser crash DoS or host compromise.

### 3.3 Independent Builder (`builders/isolated`)
- **Responsibilities**:
  - Establishing a reference build (`Domain D`) from clean SCM source commits.
  - Executing build steps inside ephemeral Docker/Podman builder images with pinned base layers and deterministic environment variables.
  - Isolated networking, read-only root mounts, non-root execution (`nobody`/`10001`).

### 3.4 Verification Engine & ELF Analyzer (`analyzers/elf/`, `core/verification/`)
- **Static ELF Parsing Pipeline**: Untrusted ELF binaries pass through pure-Python file-backed static binary parsing (`StaticELFParser`) without binary execution or CLI readelf dependencies.
- **Hostile Input Bounds Validation**: Every offset, table length, entry count, and section size is validated prior to access using overflow-safe formulas (`offset + size <= file_size`, integer multiplication overflow checks).
- **10 Configurable Resource Limits**: Enforces `max_analysis_file_size` (500 MB), `max_sections` (1,000), `max_program_headers` (256), `max_symbols` (50,000), `max_dynamic_entries` (5,000), `max_relocations` (50,000), `max_string_table_size` (10 MB), `max_functions` (50,000), `max_total_bytes_processed` (500 MB), and `max_report_size` (10 MB). Exceeding limits sets `is_truncated = True` deterministically without dropping evidence.
- **Symbol-Derived Functions Only**: Reports `STT_FUNC` symbols as `symbol_derived_functions`. Stripped binaries are handled gracefully without assuming zero functions.
- **Security Observations**: Preserves section-level `has_wx_sections` (`SHF_WRITE` + `SHF_EXECINSTR`) and segment-level `has_wx_load_segments` (`PF_W` + `PF_X`) observations as evidence. Output contains zero maliciousness verdicts (`SAFE`/`BLOCK`).

### 3.5 Risk & Policy Engine (`core/risk`, `core/policy`)
- **Risk Engine**: Applies transparent, rule-based scoring across findings (e.g., function added = 25, unexpected dependency = 20, missing provenance = 30).
- **Policy Engine**: Evaluates YAML-configured organizational thresholds (e.g., `warning_threshold: 30`, `block_threshold: 70`, `fail_on_new_functions: true`).
- **Decision Matrix**:
  - `PASS`: Zero policy failures, risk score below warning threshold.
  - `PASS_WITH_WARNING`: Minor policy warnings, risk score between warning and block thresholds.
  - `BLOCK`: Critical policy failure, unexpected binary code/import modifications, or risk score above block threshold.

### 3.6 Storage Abstraction & Ingestion Boundary (`core/storage/`, `infrastructure/storage/`)
- **Ingestion Boundary**: All uploaded artifact bytes pass through bounded streaming hash calculation (SHA-256 & SHA-512 in 64 KiB chunks) and magic-byte media type classification.
- **Client Digest Untrusted Claim**: Client-provided digests are treated as untrusted claims. Ingestion compares the calculated SHA-256 against `claimed_digest` and rejects payload mismatches (`PG-2003`).
- **Streaming Upload Limit (2 GB)**: Upload size limits (2 GB) are enforced during streaming, immediately aborting oversized payloads without buffering multi-gigabyte files in RAM.
- **Dependency Boundary**: Storage interface `ObjectStorageDriver` resides under `core/storage/ports.py` (zero third-party imports). Concrete storage drivers (`FilesystemStorageDriver`, `MinIOStorageDriver`) reside under `infrastructure/storage/`.
- **Relational DB**: PostgreSQL 16 for metadata, tenants, projects, verification runs, findings, audit trails, and policies.
- **Object Storage**: MinIO (local dev) / S3 abstraction for raw binaries, reference artifacts, and large SBOM payloads, using immutable tenant keys: `<organization_id>/<project_id>/artifacts/<sha256_hash>`.

---

## 4. Multi-Tenancy Architecture

The data model enforces organization-level and project-level isolation:
```
Organization
  ├── Users & API Keys (RBAC)
  └── Projects
       ├── Repositories & Builder Profiles
       ├── Artifacts & Digests
       ├── Verification Runs & Findings
       └── Organizational Policies
```
All database queries and storage keys include `organization_id` and `project_id` filters to prevent cross-tenant data leakage. Cross-tenant access tests are enforced in `tests/security/test_multitenancy.py`.

---

## 5. Non-Functional Requirements & Security Bounds

1. **Deterministic Execution**: Given identical inputs (artifacts, provenance, policy), the verifier returns identical findings and decisions.
2. **Resource Constraints**: Upload limit: 2GB per artifact; worker timeout: 300 seconds; worker memory limit: 2GB RAM.
3. **Fail-Closed Strategy**: If verification infrastructure or worker processes fail unexpectedly, CI/CD pipeline verification defaults to `BLOCK` (`exit code 1` or `3`) unless explicitly configured otherwise.
