# ProvenanceGuard Deployment Architecture & Guide

This document details deployment strategies for local development and enterprise production environments.

---

## 1. Local Development Deployment (Docker Compose)

The local development environment runs via `docker-compose.yml`:
- **API Container**: FastAPI REST Gateway on port `8000`.
- **Worker Container**: Ephemeral task processing worker.
- **PostgreSQL 16**: Metadata, tenant records, and audit logs on port `5432`.
- **Redis 7**: Async task queue broker on port `6379`.
- **MinIO**: S3-compatible object storage on port `9000` (API) and `9001` (Console).

---

## 2. Production Enterprise Architecture (Kubernetes Target)

```
[ Internet / Enterprise Network ]
              │
              ▼
[ Ingress Controller / Reverse Proxy (TLS 1.3 Termination) ]
              │
              ▼
    ┌───────────────────┐
    │  API Deployment   │ (HPA: 3-10 Pods)
    └─────────┬─────────┘
              │
    ┌─────────┴─────────────────────────┬─────────────────────────┐
    ▼                                   ▼                         ▼
[ PostgreSQL Cluster ]          [ Redis Sentinel ]        [ Enterprise S3 Object Storage ]
(Multi-AZ Managed DB)          (Task Queue Broker)       (AWS S3 / GCP Cloud Storage / MinIO)
    ▲                                   ▲
    │                                   │
    ├───────────────────────────────────┘
    │
    ▼
[ Worker Pool Deployment ] (HPA: 5-50 Ephemeral Pods)
    │
    ▼
[ Isolated Sandbox Containers ] (Pod Security Standards: Restricted)
```

---

## 3. Container Hardening Guidelines

- All containers MUST run with `readOnlyRootFilesystem: true` (using `tmpfs` for `/tmp`).
- Containers MUST run as non-root (`runAsNonRoot: true`, `runAsUser: 10001`).
- All Linux capabilities MUST be dropped (`capabilities: { drop: ["ALL"] }`).
- Memory and CPU requests/limits MUST be explicitly defined for every worker pod.
