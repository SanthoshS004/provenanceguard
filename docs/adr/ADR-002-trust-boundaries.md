# ADR-002: Trust Domain Boundaries & Zero-Trust Architecture

- **Status**: ACCEPTED
- **Date**: 2026-09-04
- **Authors**: Security Architecture Team

## 1. Context
Production CI environments (`Domain B`) are high-risk targets frequently subjected to runner compromise, stolen credentials, and malicious PR injection. ProvenanceGuard must verify software without trusting production CI infrastructure.

## 2. Problem
If the verification platform trusts production CI authentication alone, a compromised runner can self-approve malicious release artifacts.

## 3. Decision
We establish six explicit, segregated trust domains:
- **Domain A**: Source Control Management (SCM - GitHub/GitLab).
- **Domain B**: Production Build Environment (**Untrusted**).
- **Domain C**: ProvenanceGuard Control Plane (**Trusted**).
- **Domain D**: Independent Reference Builder (**Trusted Isolation**).
- **Domain E**: Ephemeral Analysis Workers (**Isolated Sandbox**).
- **Domain F**: Artifact & Metadata Storage (**Controlled Infrastructure**).

Domain B can submit artifacts for verification, but has zero administrative access to Domain C policies or database records.

## 4. Alternatives Considered
- **Trusting Authenticated CI**: Simple API integration, but vulnerable to T1 (CI runner compromise).

## 5. Security Consequences
- Production CI compromise does not compromise the verification control plane or decision engine.

## 6. Operational Consequences
- Production CI pipelines must submit artifacts over authenticated REST endpoints and await decision status asynchronously.

## 7. Future Reconsideration Conditions
- Re-evaluate if hardware-backed enclave attestation (Intel SGX / AWS Nitro Enclaves) becomes available for Domain C/D.
