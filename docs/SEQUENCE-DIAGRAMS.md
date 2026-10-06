# ProvenanceGuard Sequence Diagrams Specification

This document contains Mermaid sequence diagrams illustrating core interaction flows across ProvenanceGuard trust domains.

---

## 1. Artifact Verification Sequence

```mermaid
sequenceDiagram
    autonumber
    participant CI as Production CI (Domain B)
    participant API as API Gateway (Domain C)
    participant Q as Redis / Task Queue
    participant Builder as Independent Builder (Domain D)
    participant Worker as Analysis Worker (Domain E)
    participant DB as PostgreSQL (Domain F)
    participant Store as Object Storage (Domain F)

    CI->>API: POST /api/v1/verification-runs (Upload Artifact, Provenance, SBOM)
    API->>Store: Store Production Artifact & Payloads
    API->>DB: Record VerificationRun (Status: PENDING)
    API->>Q: Enqueue BuildReferenceJob & AnalyzeArtifactJob
    API-->>CI: 202 Accepted (VerificationRun ID: `vr_123`)

    par Reference Build
        Q->>Builder: Execute Reference Build from SCM Commit SHA
        Builder->>Store: Store Reference Artifact
    and Artifact Analysis
        Q->>Worker: Analyze Production & Reference Artifacts
        Worker->>Worker: Extract ELF Sections, Functions, Imports
        Worker-->>Q: Return Analysis JSON
    end

    Q->>API: Execute Verification & Comparison
    API->>API: Calculate Binary Diffs, Verify Provenance & Signature
    API->>API: Evaluate Risk Rules & Policy Thresholds
    API->>DB: Store Verification Decision & Audit Log
    
    CI->>API: GET /api/v1/verification-runs/vr_123
    API-->>CI: 200 OK (Status: COMPLETED, Decision: BLOCK/PASS)
```

---

## 2. Independent Reference Build Sequence

```mermaid
sequenceDiagram
    autonumber
    participant Engine as Verification Engine (Domain C)
    participant Builder as Isolated Builder Service (Domain D)
    participant SCM as Git SCM (Domain A)
    participant Docker as Ephemeral Builder Container

    Engine->>Builder: TriggerReferenceBuild(project_id, commit_sha, build_profile)
    Builder->>SCM: Fetch Clean Git Repository at `commit_sha`
    Builder->>Docker: Spawn Ephemeral Container (Pinned Toolchain, No Root)
    Docker->>Docker: Execute Build Commands (`make`, `cargo build`, etc.)
    Docker-->>Builder: Emit Reference Binary Artifact
    Builder->>Engine: Return Reference Artifact Digest & Storage Location
```

---

## 3. Policy Evaluation Sequence

```mermaid
sequenceDiagram
    autonumber
    participant Comp as Comparison Engine
    participant Risk as Risk Engine
    participant Policy as Policy Engine
    participant Audit as Audit Store (PostgreSQL)

    Comp->>Risk: Pass Discrepancies (Function changes, Unexpected imports, Provenance mismatch)
    Risk->>Risk: Sum Weighted Rule Scores (e.g. Function change = 25, Provenance invalid = 30)
    Risk-->>Policy: Total Risk Score (e.g. Score: 85) + Discrepancy Findings
    Policy->>Policy: Evaluate Policy Rules (`block_threshold: 70`, `fail_on_new_functions: true`)
    Policy->>Policy: Decision = BLOCK (Rule: risk_score > block_threshold)
    Policy->>Audit: Write Immutable Audit Record (`VERIFICATION_BLOCKED`)
```

---

## 4. Verification Failure & CI Release Block Sequence

```mermaid
sequenceDiagram
    autonumber
    participant Runner as GitHub Actions Runner
    participant CLI as ProvenanceGuard CLI
    participant API as Verifier REST API

    Runner->>CLI: `provenanceguard verify --artifact ./app --policy release.yaml`
    CLI->>API: Submit Artifact & Await Poll Decision
    API-->>CLI: Decision: BLOCK (Exit Code: 1, Reasons: ["NEW_FUNCTION detected: send_data"])
    CLI-->>Runner: Exit Code 1
    Runner->>Runner: Pipeline Step Failed -> Release Blocked!
```

---

## 5. Artifact Upload Sequence

```mermaid
sequenceDiagram
    autonumber
    participant Client as CI / Developer CLI
    participant API as FastAPI Gateway
    participant MinIO as S3 / MinIO Object Storage
    participant DB as Relational Database

    Client->>API: POST /api/v1/artifacts (Multipart Upload)
    API->>API: Compute SHA-256 Digest & Validate Magic Bytes
    API->>MinIO: PutObject(`org_id/proj_id/sha256_hash.bin`)
    API->>DB: INSERT INTO artifacts (id, name, digest, size, media_type)
    API-->>Client: 201 Created (Artifact Metadata JSON)
```

---

## 6. Signature & Provenance Verification Sequence (Cosign & SLSA)

```mermaid
sequenceDiagram
    autonumber
    participant Verifier as Provenance Verifier
    participant Sigstore as Sigstore Rekor / Fulcio
    participant SLSA as SLSA Predicate Parser

    Verifier->>Sigstore: Verify Cosign Signature & Certificate SAN
    Sigstore-->>Verifier: Certificate Valid (Issuer: GitHub Actions, Subject: repo:org/app)
    Verifier->>SLSA: Parse SLSA v1.2 In-Toto Attestation DSSE
    SLSA-->>Verifier: Predicate Valid (Builder: https://github.com/actions/runner)
    Verifier->>Verifier: Match Commit SHA in Provenance against Git SCM Commit
```
