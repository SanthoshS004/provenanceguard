# ProvenanceGuard STRIDE Threat Modeling Analysis

This document presents a comprehensive **STRIDE** (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) security assessment across all ProvenanceGuard components.

---

## 1. STRIDE Component Mapping Matrix

| Component | Spoofing | Tampering | Repudiation | Information Disclosure | Denial of Service | Elevation of Privilege |
|---|---|---|---|---|---|---|
| **API Gateway (`apps/api`)** | Service token forgery | Payload modification in transit | Unauthenticated API calls | Leakage of cross-tenant data | Request flooding / slowloris | JWT role escalation |
| **Worker (`apps/worker`)** | Fake worker registration | Poisoned analysis results | Un-logged job executions | Memory dumping of analyzed artifacts | Zip/Decompression bombs, parser crash | Container breakout via Docker socket |
| **Independent Builder (`builders/`)** | Impersonation of builder identity | Tampering with reference build flags | Un-audited reference build invocations | Source code repository leakage | CPU/RAM exhaustion during compilation | Host breakout via root container |
| **Storage (`Domain F`)** | Impersonation of MinIO/DB credentials | Direct tampering with artifact object files | Deletion of verification audit trails | Un-encrypted storage access | Disk space exhaustion | Database SQL injection |

---

## 2. Detailed Threat Analysis & Security Controls

### 2.1 Spoofing (Identity Impersonation)
- **Threat**: Attacker spoofs production CI identity or worker identity to submit unverified verification results.
- **Affected Component**: API Gateway, Worker Task Queue.
- **Controls**:
  - Mutual TLS (mTLS) or HMAC-signed JWT service tokens for worker-to-control-plane communication.
  - Short-lived scoped API tokens for CI integrations (`CI_SERVICE` role).
  - Validation of Cosign OIDC certificate claims against approved issuer list.

### 2.2 Tampering (Data Alteration)
- **Threat**: Attacker modifies production binary in object storage post-verification, or tampers with SLSA provenance JSON payload.
- **Affected Component**: Object Storage, Provenance Parser.
- **Controls**:
  - Immutability enforcement in object storage (MinIO WORM / S3 Object Lock).
  - Verification of cryptographic hash (SHA-256) on every read operation.
  - DSSE signature verification on in-toto provenance statements.

### 2.3 Repudiation (Denial of Actions)
- **Threat**: Rogue user changes policy thresholds to allow a malicious binary to pass and denies initiating the change.
- **Affected Component**: Policy Engine, Audit Log Store.
- **Controls**:
  - Append-only PostgreSQL audit table (`audit_logs`) capturing `timestamp`, `actor`, `organization_id`, `action`, `resource`, `ip_address`, and `prev_state_hash`.
  - Digitally signed audit event logs.

### 2.4 Information Disclosure (Data Leakage)
- **Threat**: Cross-tenant data leakage allowing Tenant A to view Tenant B's proprietary source code or SBOM vulnerability findings.
- **Affected Component**: Database ORM, API Endpoints.
- **Controls**:
  - Mandatory tenant filtering (`organization_id` & `project_id`) on all database queries.
  - Encryption at rest (AES-256) for object storage and database columns containing sensitive metadata.
  - Automatic scrubbing of secrets, bearer tokens, and private keys from structured JSON logs.

### 2.5 Denial of Service (Resource Exhaustion)
- **Threat**: Malicious actor submits an archive bomb (10MB file expanding to 500GB) or malformed ELF binary triggering infinite parsing loops.
- **Affected Component**: Analysis Workers (`Domain E`).
- **Controls**:
  - Strict upload size limit (2GB).
  - Decompression ratio limit (100:1) and total uncompressed limit (5GB).
  - Hard execution timeout (300s) and memory caps (2GB RAM) per worker container.

### 2.6 Elevation of Privilege (Unauthorized Escalation)
- **Threat**: Malicious binary exploits a parser bug in the worker container to achieve container breakout and gain host root privileges.
- **Affected Component**: Worker Container, Docker Engine.
- **Controls**:
  - Workers run strictly as unprivileged users (`nobody`/`uid: 10001`).
  - No Docker socket (`/var/run/docker.sock`) mounted inside worker containers.
  - Read-only root filesystem (`--read-only`) with tmpfs for scratch directories.
