# ADR-004: Independent Builder Isolation & Reference Build Execution

- **Status**: ACCEPTED
- **Date**: 2026-09-04
- **Authors**: DevSecOps Engineering Team

## 1. Context
To verify whether a production binary reflects clean SCM source code, ProvenanceGuard requires an independent reference build (`Domain D`).

## 2. Problem
Running reference builds on host machines or shared CI runners risks host infection, resource contention, and non-deterministic environment variations.

## 3. Decision
We implement a containerized isolated builder abstraction (`builders/isolated/docker_builder.py`):
- Executes reference builds inside ephemeral Docker/Podman containers.
- Uses pinned base images, non-root execution (`nobody`), and restricted network access.
- Captures environment parameters, compiler flags, and stdout/stderr build logs for auditability.

## 4. Alternatives Considered
- **Bare-metal VM Builder**: High isolation, but slow startup times (minutes vs seconds).

## 5. Security Consequences
- Completely segregates reference build execution from production CI runners and control plane API hosts.

## 6. Operational Consequences
- Requires Docker/Podman engine availability on worker nodes.

## 7. Future Reconsideration Conditions
- Re-evaluate if gVisor or Firecracker microVMs are required for higher isolation guarantees.
