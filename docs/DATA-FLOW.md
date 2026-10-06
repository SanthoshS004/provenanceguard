# ProvenanceGuard Data Flow Architecture

This document details the data flows within ProvenanceGuard, explicitly classifying data sensitivity, trust boundaries, persistence models, and data types across each step of the verification pipeline.

---

## 1. End-to-End Data Flow Map

```
[ Developer ]
     │ (1) Push Code / Create Release Tag
     ▼
[ Domain A: SCM (GitHub/GitLab) ]
     │ (2) Webhook Trigger & Commit SHA
     ├─────────────────────────────────────────┐
     │ (3) Source Code & Build Config          │ (4) Source Commit SHA & Repo URL
     ▼                                         ▼
[ Domain B: Production CI ]             [ Domain C: ProvenanceGuard API ]
     │ (5) Build Executed                      │ (6) Create Verification Run
     ▼                                         ▼
[ Production Artifact ]                 [ Domain D: Independent Builder ]
     │ (7) Submit Artifact + Provenance + SBOM │ (8) Execute Reference Build
     └───────────────────┬─────────────────────┘
                         │
                         ▼
             [ Domain F: Object Storage ]
                         │ (9) Fetch Artifacts
                         ▼
             [ Domain E: Analysis Workers ]
                         │ (10) Emit Structural Analysis (JSON)
                         ▼
             [ Verification & Comparison Engine ]
                         │ (11) Compare Binary, Provenance, SBOM
                         ▼
                 [ Risk Engine ]
                         │ (12) Compute Risk Score
                         ▼
                [ Policy Engine ]
                         │ (13) Evaluate Thresholds & Output Decision
                         ▼
          [ PostgreSQL Audit & Event Store ]
                         │ (14) Store Decision & Findings
                         ▼
             [ CLI Exit Code / Dashboard UI ]
```

---

## 2. Classification Matrix

| Data Flow Step | Data Description | Data Type | Trust Classification | Sensitivity Level | Persistence Model |
|---|---|---|---|---|---|
| **(1) Developer Push** | Git commits, tags, signed commits | SCM Metadata | Trusted (Domain A) | Internal | Persistent (Git SCM) |
| **(3) Build Script** | Makefiles, Dockerfiles, YAML pipelines | Build Definition | Untrusted (Domain B) | Internal | Persistent (Git SCM) |
| **(7) Prod Artifact** | ELF executable, OCI tarball | Binary Payload | **Untrusted** (Domain B) | Confidential | Persistent (Object Storage) |
| **(7) Provenance** | SLSA v1.2 JSON, in-toto attestation | Attestation Metadata | **Untrusted** until signed | Internal | Persistent (PostgreSQL / Storage) |
| **(7) SBOM Payload** | SPDX / CycloneDX JSON document | Inventory | **Untrusted** (Domain B) | Internal | Persistent (PostgreSQL) |
| **(8) Ref Artifact** | Reference binary built independently | Binary Payload | **Trusted** (Domain D) | Confidential | Ephemeral / Retained for Audit |
| **(10) Analyzer JSON** | Extracted sections, functions, imports | Structured Metadata | **Trusted** (Domain E Output) | Internal | Ephemeral |
| **(12) Findings** | Identified diffs, severity, explanations | Risk Findings | **Trusted** (Domain C Output) | Confidential | Persistent (PostgreSQL) |
| **(14) Audit Event** | Immutable verification decision record | Audit Record | **Trusted** (Domain C Output) | Confidential | Immutable Persistent (PostgreSQL) |

---

## 3. Data Boundary Protections

1. **Boundary B → C (CI to Verifier)**: Untrusted payload boundary. Handled via HTTPS TLS 1.3, strict payload size limits (2GB max), input validation, and API authentication.
2. **Boundary C → E (Verifier to Worker)**: Worker sandbox boundary. Payloads passed via read-only volume mounts or secure byte streams. Worker emits structured JSON back to control plane over authenticated IPC/gRPC.
3. **Boundary C → F (Control Plane to Storage)**: Encrypted at rest (AES-256) with tenant-isolated bucket keys (`org_id/project_id/artifact_id`).
