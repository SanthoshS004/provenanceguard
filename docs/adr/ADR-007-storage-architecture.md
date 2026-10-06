# ADR-007: Relational Metadata & Object Storage Architecture

- **Status**: ACCEPTED
- **Date**: 2026-09-04
- **Authors**: Backend Infrastructure Team

## 1. Context
ProvenanceGuard manages relational metadata (users, projects, verification runs, audit logs) alongside large binary artifacts (ELF executables, container layer tarballs, reference binaries).

## 2. Problem
Storing multi-gigabyte binary files directly in PostgreSQL causes database bloat, backup slowness, and high memory usage.

## 3. Decision
We adopt a hybrid storage architecture:
- **PostgreSQL 16**: Relational metadata, tenant records, verification runs, findings, audit trails.
- **S3 / MinIO Object Storage**: Artifact binaries, reference artifacts, raw SBOM payloads, and build logs, accessed via a unified storage abstraction interface (`core/storage/`).

## 4. Alternatives Considered
- **Filesystem Only**: Simple for local dev, but fails cloud-native horizontal worker scalability requirements.

## 5. Security Consequences
- Storage paths are key-scoped by tenant (`org_id/project_id/artifact_id`), preventing cross-tenant file access.

## 6. Operational Consequences
- Requires MinIO for local Docker development and S3-compatible cloud storage for production.

## 7. Future Reconsideration Conditions
- Re-evaluate if specialized CAS (Content Addressable Storage) deduplication is needed for multi-terabyte artifact stores.
