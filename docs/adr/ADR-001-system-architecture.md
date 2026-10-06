# ADR-001: System Architecture & Subsystem Boundaries

- **Status**: ACCEPTED
- **Date**: 2026-09-04
- **Authors**: Principal Architecture Team

## 1. Context
ProvenanceGuard requires a modular, scalable architecture capable of ingesting, analyzing, verifying, and storing software artifacts and verification metadata without exposing the verification control plane to untrusted production CI build runners.

## 2. Problem
Monolithic designs risk mixing untrusted artifact execution with verifier decision logic. Overly complex distributed microservice meshes introduce operational overhead and expand network attack surfaces.

## 3. Decision
We adopt a hybrid modular control plane architecture consisting of:
1. **REST API Gateway** (`apps/api`): FastAPI service handling ingestion, auth, and policy endpoints.
2. **Asynchronous Task Workers** (`apps/worker`): Redis/Celery queue driving isolated analyzer processes.
3. **Independent Builder Service** (`builders/isolated`): Containerized builder establishing reference builds.
4. **Core Verification Library** (`core/`): Embedded Python modules for provenance, signatures, SBOM, binary comparison, risk, and policy.

## 4. Alternatives Considered
- **Pure Monolith**: Simpler deployment, but fails to isolate untrusted artifact parsing from control plane API processes.
- **Microservices Mesh (10+ services)**: High network latency, complex gRPC setup, unnecessary for Phase 0–1.

## 5. Security Consequences
- Isolates untrusted parsing logic to background worker containers.
- Control plane API remains unresponsive to worker memory corruptions or parser crashes.

## 6. Operational Consequences
- Clean separation between synchronous REST API requests and asynchronous long-running verification jobs.

## 7. Future Reconsideration Conditions
- Re-evaluate if worker horizontal scaling requirements exceed Redis queue throughput.
