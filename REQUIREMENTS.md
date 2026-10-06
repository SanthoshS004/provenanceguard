# ProvenanceGuard Functional & Non-Functional Requirements Specification

This document details the functional and non-functional requirements for the ProvenanceGuard enterprise platform.

---

## 1. Functional Requirements Matrix

### 1.1 Core Domain & Ingestion
- **REQ-001**: The system MUST ingest production software artifacts (Linux ELF binaries, OCI container image tarballs) along with associated SLSA provenance, Sigstore signatures, and SBOM inventories.
- **REQ-002**: The system MUST calculate deterministic SHA-256 and SHA-512 cryptographic digests for every ingested artifact.
- **REQ-003**: The system MUST store metadata and artifact binaries in an enterprise object storage abstraction with organization/project scoping.

### 1.2 Analyzers & Binary Verification
- **REQ-004**: The system MUST provide an extensible `ArtifactAnalyzer` interface supporting ELF binaries, OCI containers, and SBOM documents.
- **REQ-005**: The ELF analyzer MUST extract ELF headers, section tables, section flags, symbol tables, imported libraries, and function boundaries without executing the binary.
- **REQ-006**: The ELF analyzer MUST gracefully handle stripped binaries, 32-bit/64-bit architectures, and missing symbol tables.
- **REQ-007**: The comparison engine MUST compute function-level identity digests (normalized symbol name, section, size, code digest) to detect changed, added, or removed functions between production and reference builds.

### 1.3 Provenance & Attestations
- **REQ-008**: The system MUST validate SLSA v1.2 provenance predicates (`https://slsa.dev/provenance/v1`).
- **REQ-009**: The system MUST verify in-toto attestation DSSE envelopes and validate that builder identities match approved project policies.
- **REQ-010**: The system MUST detect provenance tampering, missing provenance fields, or commit SHA mismatches between SCM and build predicates.

### 1.4 Signatures & Cryptography
- **REQ-011**: The system MUST integrate Sigstore / Cosign for signature verification on supported container and binary artifacts.
- **REQ-012**: The system MUST extract signer identity, OIDC issuer, and certificate SANs, verifying them against organizational policy.
- **REQ-013**: The system MUST NOT treat signature validity alone as sufficient to issue a `PASS` decision.

### 1.5 SBOM & Dependencies
- **REQ-014**: The system MUST parse SPDX (v2.3/v3.0) and CycloneDX (v1.4/v1.5) JSON/XML SBOM formats.
- **REQ-015**: The system MUST compare production SBOM inventory against reference build SBOM inventory, flagging unexpected dependencies, missing dependencies, or version/digest shifts.

### 1.6 Independent Reference Builder
- **REQ-016**: The system MUST provide an isolated builder service capable of executing clean reference builds from SCM source commits inside unprivileged containers.
- **REQ-017**: The builder MUST enforce pinned toolchains, non-root execution, restricted networking, and resource limits.

### 1.7 Risk Engine & Policy Engine
- **REQ-018**: The system MUST compute a transparent, rule-based numerical risk score based on configurable evidence weights (e.g. function change, unexpected dependency, invalid provenance).
- **REQ-019**: The policy engine MUST evaluate YAML-driven organizational policies and output a deterministic decision: `PASS`, `PASS_WITH_WARNING`, or `BLOCK`.
- **REQ-020**: Every decision MUST include detailed machine-readable findings with severity, category, evidence, and explanation.

### 1.8 CLI & CI/CD Integration
- **REQ-021**: The CLI (`provenanceguard`) MUST support commands: `verify`, `inspect`, `policy validate`, and `provenance verify`.
- **REQ-022**: The CLI MUST return strict exit codes for CI/CD pipelines: `0` (PASS/PASS_WITH_WARNING), `1` (BLOCK), `2` (Configuration Error), `3` (System Error).
- **REQ-023**: GitHub Actions, GitLab CI, and Jenkins integration adapters MUST support fail-closed release blocking.

---

## 2. Non-Functional Requirements

### 2.1 Security & Sandboxing
- **NFR-001**: Analysis workers MUST execute in unprivileged environments without Docker socket access or host binary execution.
- **NFR-002**: The platform MUST enforce tenant isolation across PostgreSQL databases and MinIO object storage keys.
- **NFR-003**: The API MUST enforce strict OAuth2/JWT authentication and RBAC roles (`ADMIN`, `SECURITY_ANALYST`, `DEVELOPER`, `AUDITOR`, `VIEWER`, `CI_SERVICE`).

### 2.2 Performance & Scalability
- **NFR-004**: Artifact verification API latency (excluding independent reference build time) MUST NOT exceed 15 seconds for binaries up to 100MB.
- **NFR-005**: The worker task queue MUST scale horizontally to support concurrent verification jobs across isolated worker containers.

### 2.3 Reliability & Auditability
- **NFR-006**: Every security decision and policy evaluation MUST generate an immutable, structured audit log event in PostgreSQL.
- **NFR-007**: The system MUST fail safely (`fail-closed` policy default) if worker or verifier infrastructure experiences unexpected outages.
