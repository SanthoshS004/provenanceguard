# ADR-005: SLSA v1.2 & in-toto Provenance Attestation Strategy

- **Status**: ACCEPTED
- **Date**: 2026-09-04
- **Authors**: Standards & Security Team

## 1. Context
ProvenanceGuard requires a standardized format for evaluating build provenance and supply chain attestations.

## 2. Problem
Inventing a proprietary provenance schema limits interoperability with existing ecosystem tooling (GitHub Actions, Tekton, Cosign).

## 3. Decision
Adopt **SLSA v1.2** provenance predicates (`https://slsa.dev/provenance/v1`) wrapped inside **in-toto DSSE** (Dead Simple Signing Envelope) statements as our primary provenance attestation standard.

## 4. Alternatives Considered
- **Custom JSON Format**: Easy to write initially, but fails enterprise ecosystem integration requirements.

## 5. Security Consequences
- Standardized verification of builder identity, build definitions, resolved dependencies, and invocation parameters.

## 6. Operational Consequences
- Production build pipelines must emit SLSA v1.2 JSON attestations during release steps.

## 7. Future Reconsideration Conditions
- Re-evaluate when SLSA v2.0 or new W3C attestation standards reach formal specification status.
