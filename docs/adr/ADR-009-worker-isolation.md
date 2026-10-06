# ADR-009: Ephemeral Worker Isolation & Hostile Input Sandboxing

- **Status**: ACCEPTED
- **Date**: 2026-09-04
- **Authors**: Security Architecture Team

## 1. Context
Analysis workers (`Domain E`) parse untrusted, potentially malicious ELF binaries, container layers, and archives submitted by production CI. Parsers may contain unknown memory corruption vulnerabilities or buffer overflows.

## 2. Problem
If an analyzer runs directly on the host or inside a privileged container with Docker socket access, a malformed binary could exploit the parser to compromise the verifier host.

## 3. Decision
Enforce strict ephemeral sandboxing for all analysis worker processes:
- Unprivileged user execution (`uid: 10001`).
- No host Docker socket mounting (`/var/run/docker.sock` prohibited).
- Read-only root filesystem with `tmpfs` scratch directories.
- Resource limits: 2GB RAM max, 1.0 vCPU max, 300s execution timeout per job.
- Host binary execution is strictly prohibited; all analysis is purely static/structural.

## 4. Alternatives Considered
- **In-process REST API Parsing**: Extremely unsafe; parser crash takes down API server.

## 5. Security Consequences
- Parser crashes or memory corruptions are contained entirely within the ephemeral worker sandbox.

## 6. Operational Consequences
- Workers must be spawned with strict Docker/container resource flags.

## 7. Future Reconsideration Conditions
- Re-evaluate if WebAssembly (Wasmtime) sandboxing is introduced for binary analyzers.
