# ProvenanceGuard Security Policy & Architecture Constraints

> [!WARNING]
> **Phase 0 Notice**: This codebase is currently under architectural foundation setup (Phase 0). It is **NOT PRODUCTION READY** and must not be used in live security-critical production pipelines without complete Phase 1-20 implementation and formal security evaluation.

---

## 1. Zero-Trust Security Imperatives

ProvenanceGuard is built on strict zero-trust assumptions:
1. **Production CI (`Domain B`) is untrusted**: Authenticated production CI runners cannot issue authoritative release approvals. They only submit artifacts for independent verification.
2. **Signatures are insufficient**: A valid cryptographic signature (`Cosign`/`Sigstore`) confirms signer key authorization, not artifact integrity or security.
3. **Artifacts are hostile input**: Uploaded binaries, container images, SBOMs, and provenance JSON files are untrusted data payloads.

---

## 2. Sandboxing & Worker Isolation (`Domain E`)

All artifact analysis (ELF inspection, container layer unpacking, SBOM parsing) must execute in ephemeral, sandboxed worker environments:
- **No Host Execution**: Untrusted binaries must **NEVER** be executed directly on the host operating system under any circumstances. Analysis must be strictly static/structural.
- **Unprivileged Execution**: Analysis containers run as non-root users (`uid: 10001`, `gid: 10001`).
- **No Docker Socket Mounting**: The host Docker socket (`/var/run/docker.sock`) MUST NOT be mounted into analysis containers.
- **Resource Constraints**:
  - Max Memory: 2GB per worker process.
  - Max CPU: 1.0 vCPU quota.
  - Hard Timeout: 300 seconds per analysis job.
  - Max Upload Size: 2GB per artifact file.

---

## 3. Hostile Input Protection

Analyzers must be resilient against common binary/archive exploitation techniques:
- **Decompression / Zip Bombs**: Archives are decompressed using streaming readers enforcing maximum uncompressed byte limits (ratio cap 100:1, absolute limit 5GB).
- **Path Traversal**: Absolute paths (`/etc/passwd`) and relative traversals (`../../`) inside archives or tarballs are stripped and validated prior to extraction.
- **Malformed Parser Inputs**: ELF and container manifest parsers must enforce strict bounds checking on header offsets, section lengths, and string table pointers to prevent memory corruption or infinite loops.
- **Temporary Files**: Ephemeral analysis scratch directories are created under secure random paths (`/tmp/pg-worker-XXXXXX`) and destroyed immediately upon job completion via `finally` blocks.

---

## 4. Secrets Management & Logging Protection

- **Zero Secrets in Code**: Password strings, API keys, private keys, or CI tokens MUST NOT be stored in source files, default configurations, or test fixtures.
- **Environment Ingestion**: Secrets are loaded strictly via environment variables or external secret manager abstractions (HashiCorp Vault, AWS Secrets Manager).
- **Logging Sanitization**: Structured logs MUST NOT contain secrets, authorization headers, bearer tokens, or raw sensitive binary payloads. Automatic log scrubbers redact fields matching `password`, `token`, `secret`, `private_key`, `authorization`.

---

## 5. Security Vulnerability Reporting

If you discover a potential security vulnerability in ProvenanceGuard, please report it via our security team contact rather than opening a public issue:
- **Email**: `security@provenanceguard.internal` (or project security lead)
- **Response SLA**: Initial triage within 24 hours; status updates every 48 hours.
