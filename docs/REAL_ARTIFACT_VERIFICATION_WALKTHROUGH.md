# ProvenanceGuard Real Artifact Verification Walkthrough

This document provides a step-by-step guide for software supply-chain security engineers, SOC analysts, and developers to ingest, inspect, verify, and track real application build artifacts using **ProvenanceGuard v1.0.0**.

---

## Prerequisites

Before submitting artifacts, ensure that all core infrastructure services and application processes are running:

1. **PostgreSQL 15+** (`127.0.0.1:5432`) — Relational database with Row-Level Security (RLS) tenant isolation.
2. **Redis 7+** (`127.0.0.1:6379`) — In-memory broker for ARQ task queue and rate limiting.
3. **MinIO / S3 Storage** (`127.0.0.1:9000`) — Immutable object storage bucket (`provenanceguard-artifacts`).
4. **FastAPI Gateway** (`http://127.0.0.1:8000`) — REST API control plane.
5. **ARQ Worker Process** (`python -m provenanceguard.apps.worker.main`) — Background job processor.
6. **Vite Dashboard UI** (`http://127.0.0.1:5173`) — Enterprise Security Control Panel.

### Verify Environment Readiness

Execute HTTP health check calls to ensure system readiness:

```bash
# Check API Gateway Liveness
curl -X GET http://127.0.0.1:8000/api/v1/health/liveness

# Check Subsystem Readiness (Database, Redis, Storage)
curl -X GET http://127.0.0.1:8000/api/v1/health/readiness
```

---

## Step 1 — Prepare Your Artifact

ProvenanceGuard supports multi-modal artifact ingestion across:
- **ELF Binaries** (`application/vnd.elf`, `application/x-executable`): 32-bit and 64-bit Linux binaries.
- **OCI Container Images & Archives** (`application/vnd.oci.image.manifest.v1+json`, `application/x-tar`): OCI layer diffs and whiteout analysis.
- **SBOM Documents** (`application/spdx+json`, `application/cyclonedx+json`): Dependency inventory and PURL drift analysis.
- **Attestation Payloads** (`application/vnd.dsse+json`, Sigstore bundles): DSSE envelopes, Cosign certificates, Rekor proofs, and SLSA v1.2 provenance.

### Creating a Safe Test ELF Binary

To generate a minimal, safe 64-bit ELF test binary locally without compiling external source code, run this Python snippet:

```python
import struct

# Construct 64-bit ELF binary header
ident = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
header = struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, 0x400000, 64, 120, 0, 64, 56, 1, 64, 2, 1)
phdr = struct.pack("<IIQQQQQQ", 1, 5, 0, 0x400000, 0x400000, 256, 256, 4096)
shdr0 = b"\x00" * 64
shdr1 = struct.pack("<IIQQQQIIQQ", 1, 3, 0, 0, 248, 11, 0, 0, 1, 0)
shstrtab = b"\x00.shstrtab\x00"

elf_bytes = ident + header + phdr + shdr0 + shdr1 + shstrtab

with open("app-service-v1.bin", "wb") as f:
    f.write(elf_bytes)

print("[OK] Created safe test binary: app-service-v1.bin")
```

---

## Step 2 — Start ProvenanceGuard Services

Launch the complete local development server stack from the repository root:

```powershell
# 1. Start FastAPI REST Gateway
uvicorn provenanceguard.apps.api.main:app --host 127.0.0.1 --port 8000

# 2. Start ARQ Background Worker (in a second terminal)
python -m provenanceguard.apps.worker.main

# 3. Start Frontend Vite Dashboard (in a third terminal)
cd dashboard
npm run dev
```

---

## Step 3 — Authenticate

ProvenanceGuard enforces strict RS256 JWT bearer token authentication and Role-Based Access Control (RBAC).

To mint a development JWT bearer token for API/CLI operations:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/auth/token \
  -H "Content-Type: application/json" \
  -d '{
    "organization_id": "00000000-0000-0000-0000-000000000001",
    "role": "SECURITY_ANALYST",
    "user_id": "sec-analyst-01",
    "project_id": "00000000-0000-0000-0000-000000000002",
    "scopes": ["*"]
  }'
```

**Response**:
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "token_type": "bearer",
  "expires_in": 3600
}
```

Save the `access_token` string to an environment variable:
```bash
export PG_TOKEN="eyJhbGciOiJSUzI1NiIs..."
```

---

## Step 4 — Submit Your Artifact for Verification

### Option A: Local CLI Verification (In-Process)

Run immediate local static binary inspection and policy evaluation directly via CLI:

```bash
# 1. Inspect binary metadata & SHA256 digest
provenanceguard inspect --artifact app-service-v1.bin --json-output

# 2. Verify artifact against local policy
provenanceguard verify --artifact app-service-v1.bin --json-output
```

### Option B: Async REST API Submission (Queue & Worker)

Submit a verification job to the enterprise backend API:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/verifications \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $PG_TOKEN" \
  -d '{
    "organization_id": "00000000-0000-0000-0000-000000000001",
    "project_id": "00000000-0000-0000-0000-000000000002",
    "production_artifact_id": "4e298527-fb98-4b5b-90c5-f68900bd93b8",
    "reference_artifact_id": "2c9b61ca-101d-4406-98fd-05db1441f426"
  }'
```

**Response** (`HTTP 202 Accepted`):
```json
{
  "job_id": "job_01h9x...",
  "verification_run_id": "c00b3cb1-91c8-44e5-8316-3c07137233f6",
  "status": "QUEUED"
}
```

---

## Step 5 — Observe Job Execution

Track the status of the verification run asynchronously via the REST API:

```bash
curl -X GET http://127.0.0.1:8000/api/v1/verifications/c00b3cb1-91c8-44e5-8316-3c07137233f6 \
  -H "Authorization: Bearer $PG_TOKEN"
```

Job Lifecycle Transitions:
- `QUEUED`: Submitted to PostgreSQL Outbox and dispatched to Redis ARQ Queue.
- `RUNNING`: Claimed atomically by background worker (`UPDATE verification_runs SET status = 'RUNNING'`).
- `SUCCEEDED`: Background analysis completed; decision, risk score, and completion timestamp persisted.

---

## Step 6 — Worker Processing Pipeline

The ARQ background worker executes the following multi-stage verification pipeline:

1. **Atomic Claim & RLS Setup**: Sets PostgreSQL transaction-local RLS context `app.current_tenant_id` to enforce strict organization isolation.
2. **Ingestion & Streaming Hash**: Calculates SHA-256 and SHA-512 streaming digests; validates against claimed digest.
3. **Static Binary / Container Analysis**: Parses ELF sections (`W^X` permissions, dynamic symbols) or OCI image layers (whiteout files, RootFS diffs).
4. **Attestation & Provenance Check**: Verifies DSSE envelopes, Cosign certificates, Rekor transparency log inclusion proofs, and SLSA v1.2 build environment constraints.
5. **SBOM Drift Analysis**: Compares package URLs (PURLs) against reference SBOMs to detect unauthorized dependencies.
6. **Risk Engine & Policy Engine Evaluation**: Calculates aggregate risk score ($0 \le S \le 100$) and evaluates policy rules to yield an authoritative decision (`PASS`, `PASS_WITH_WARNING`, `REJECT`).

---

## Step 7 — Retrieve the Final Verification Record

Fetch the completed verification record via REST API:

```bash
curl -X GET http://127.0.0.1:8000/api/v1/verifications/c00b3cb1-91c8-44e5-8316-3c07137233f6 \
  -H "Authorization: Bearer $PG_TOKEN"
```

**Response**:
```json
{
  "id": "c00b3cb1-91c8-44e5-8316-3c07137233f6",
  "organization_id": "00000000-0000-0000-0000-000000000001",
  "project_id": "00000000-0000-0000-0000-000000000002",
  "production_artifact_id": "4e298527-fb98-4b5b-90c5-f68900bd93b8",
  "reference_artifact_id": "2c9b61ca-101d-4406-98fd-05db1441f426",
  "status": "SUCCEEDED",
  "decision": "PASS",
  "risk_score": 0,
  "attempt_count": 1
}
```

---

## Step 8 — Open the Dashboard

1. Open your web browser and navigate to: `http://127.0.0.1:5173/`
2. Authenticate using the Dev JWT token or Org Credentials.
3. Select Organization **Acme Security (Default)** and Project **Default Project**.

---

## Step 9 — Inspect Real Findings on the Dashboard

On the live dashboard UI:
- **Executive Overview**: View global metric cards (**Verification Runs**, **PASS / WARNING / BLOCK** counts) updated with real backend verification data.
- **Verification Explorer**: Click on any verification run row (e.g. `c00b3cb1-91c8-44e5-8316-3c07137233f6`) to open details showing artifact IDs, status, decision, risk score, and execution timeline.
- **Sigstore & SLSA Evidence**: Inspect verified Cosign leaf certificates, Rekor transparency log indices, and SLSA v1.2 provenance graphs.
- **OCI Container & ELF Diff**: Review ELF section permissions (`W^X` hardening), symbol deltas, and container layer whiteouts.
- **Audit Log Stream**: Review immutable hash-chained audit events recording verification creation and execution.

---

## Step 10 — Test with Your Own Project Artifact

Integrate ProvenanceGuard into your own build pipeline (CI/CD):

```
Your Project Source Code
       │
       ▼ (Build Step)
Production Artifact (.bin / .tar.gz / OCI Image)
       │
       ▼ (CLI or API Ingestion)
ProvenanceGuard Verification Pipeline
       │
       ├── Ingestion & Hash Validation
       ├── Binary / OCI / Attestation Analysis
       ├── Risk Score & Policy Evaluation
       │
       ▼
Authoritative Decision (PASS / BLOCK) -> Dashboard & Audit Stream
```

1. **Build your binary**: `gcc -O2 -o my-service main.c`
2. **Generate SBOM** (using Syft / Trivy): `syft my-service -o spdx-json > sbom.spdx.json`
3. **Run local verification**:
   ```bash
   provenanceguard verify --artifact my-service --sbom sbom.spdx.json --json-output
   ```
4. **View results**: ProvenanceGuard will output an explainable JSON decision object with risk scores and policy rationale suitable for blocking non-compliant deployment artifacts in CI/CD pipelines.
