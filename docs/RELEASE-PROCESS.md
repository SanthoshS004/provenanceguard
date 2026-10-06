# ProvenanceGuard Self-Verification & Release Process (Dogfooding)

This document specifies the software release lifecycle for ProvenanceGuard itself. ProvenanceGuard applies its own security principles to its own release pipeline ("Dogfooding").

---

## 1. ProvenanceGuard Release Pipeline Architecture

```
[ Developer Commit ]
        │
        ▼
[ SCM: Main Branch / Release Tag ]
        │
        ├──────────────────────────────────────┐
        ▼                                      ▼
[ Production Build (GitHub Actions) ]   [ Independent Reference Builder ]
  - Compile Python Wheel / Docker Image    - Isolated Docker Build Environment
  - Generate SPDX SBOM                    - Generate Reference Binary/Image
  - Generate SLSA v1.2 Provenance          - Extract Reference Digests
  - Sign with Cosign (Sigstore)                │
        │                                      │
        └──────────────────┬───────────────────┘
                           │
                           ▼
              [ Self-Verification Step ]
     `provenanceguard verify --artifact pg-api`
                           │
                 ┌─────────┴─────────┐
                 ▼                   ▼
              [ PASS ]            [ BLOCK ]
                 │                   │
                 ▼                   ▼
       Publish to Registry      Release Pipeline Terminated
```

---

## 2. Release Sequence Steps

1. **Source Control Gate**:
   - All commits require multi-party code review, passing CI unit/integration/security test suites, and clean `ruff` linter checks.
   - Release versions follow Semantic Versioning (`vX.Y.Z`).

2. **Artifact Compilation & SBOM Generation**:
   - Production Docker images (`provenanceguard-api`, `provenanceguard-worker`, `provenanceguard-cli`) are compiled in production CI.
   - An SPDX v2.3 SBOM inventory is generated automatically via Syft / SPDX generators.

3. **Provenance Attestation & Signing**:
   - Production CI issues a SLSA v1.2 provenance predicate using the official GitHub Actions SLSA generator.
   - Binary and container images are keylessly signed using Sigstore Cosign with OIDC identity verification.

4. **Self-Verification (Dogfooding Execution)**:
   - A pre-release instance of ProvenanceGuard executes an independent reference build of ProvenanceGuard from the release Git tag.
   - ProvenanceGuard verifies its own binary characteristics, SLSA provenance, Cosign signature, and SBOM inventory against enterprise policy.
   - Release proceeds **ONLY** if the self-verification decision is `PASS` or `PASS_WITH_WARNING`.
