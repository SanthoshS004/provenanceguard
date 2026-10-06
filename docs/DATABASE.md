# ProvenanceGuard Relational Data Model Specification

This document details the relational entity schema for PostgreSQL 16 backing ProvenanceGuard metadata, multi-tenancy, audit logs, and verification runs.

---

## 1. Entity-Relationship Conceptual Model

```
Organizations (1) ───< Projects (N)
                           │
    ┌──────────────────────┼──────────────────────┬──────────────────────┐
    ▼                      ▼                      ▼                      ▼
Repositories (N)       Builds (N)             Artifacts (N)          Policies (N)
                           │                      │                      │
                           ▼                      ▼                      ▼
                     BuildMaterials          ArtifactDigests        PolicyRules
                           │                      │
                           └──────────┬───────────┘
                                      │
                                      ▼
                             VerificationRuns (N)
                                      │
                                      ├──────────────────┐
                                      ▼                  ▼
                                Findings (N)       AuditLogs (N)
```

---

## 2. Core Relational Entities

### `organizations`
- `id`: UUID (Primary Key)
- `name`: VARCHAR(255) UNIQUE NOT NULL
- `slug`: VARCHAR(100) UNIQUE NOT NULL
- `created_at`: TIMESTAMP WITH TIME ZONE

### `projects`
- `id`: UUID (Primary Key)
- `organization_id`: UUID FK -> `organizations.id`
- `name`: VARCHAR(255) NOT NULL
- `created_at`: TIMESTAMP WITH TIME ZONE

### `artifacts`
- `id`: UUID (Primary Key)
- `project_id`: UUID FK -> `projects.id`
- `name`: VARCHAR(255) NOT NULL
- `version`: VARCHAR(100) NOT NULL
- `media_type`: VARCHAR(100) NOT NULL (`application/vnd.elf`, `application/vnd.oci.image.layer.v1.tar+gzip`)
- `digest_sha256`: CHAR(64) NOT NULL
- `size_bytes`: BIGINT NOT NULL
- `storage_path`: VARCHAR(1024) NOT NULL

### `verification_runs`
- `id`: UUID (Primary Key)
- `project_id`: UUID FK -> `projects.id`
- `production_artifact_id`: UUID FK -> `artifacts.id`
- `reference_artifact_id`: UUID FK -> `artifacts.id` (NULLABLE)
- `status`: VARCHAR(50) NOT NULL (`PENDING`, `RUNNING`, `COMPLETED`, `FAILED`)
- `decision`: VARCHAR(50) NOT NULL (`PASS`, `PASS_WITH_WARNING`, `BLOCK`)
- `risk_score`: INT NOT NULL
- `created_at`: TIMESTAMP WITH TIME ZONE

### `findings`
- `id`: UUID (Primary Key)
- `verification_run_id`: UUID FK -> `verification_runs.id`
- `severity`: VARCHAR(20) NOT NULL (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`)
- `category`: VARCHAR(100) NOT NULL (`FUNCTION_ADDED`, `UNEXPECTED_DEPENDENCY`, `PROVENANCE_INVALID`, etc.)
- `explanation`: TEXT NOT NULL

### `audit_logs`
- `id`: UUID (Primary Key)
- `organization_id`: UUID FK -> `organizations.id`
- `actor_id`: VARCHAR(255) NOT NULL
- `action`: VARCHAR(100) NOT NULL
- `resource`: VARCHAR(255) NOT NULL
- `result`: VARCHAR(50) NOT NULL
- `created_at`: TIMESTAMP WITH TIME ZONE
