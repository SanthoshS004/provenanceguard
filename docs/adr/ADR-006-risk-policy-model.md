# ADR-006: Transparent Risk Scoring & Configurable Policy Model

- **Status**: ACCEPTED
- **Date**: 2026-09-04
- **Authors**: Policy & Security Engineering Team

## 1. Context
Security teams require transparent, explainable decisions (`PASS`, `PASS_WITH_WARNING`, `BLOCK`) with configurable risk thresholds tailored to project criticality.

## 2. Problem
Hardcoded pass/fail checks or opaque black-box scoring algorithms prevent custom policy tailoring and confuse developers during release blocks.

## 3. Decision
We separate risk scoring from policy evaluation:
1. **Risk Engine** (`core/risk`): Computes numerical risk scores from weighted discrepancy rules (e.g. function added = 25, invalid provenance = 30).
2. **Policy Engine** (`core/policy`): Evaluates project YAML configurations (`warning_threshold`, `block_threshold`, mandatory flags) and outputs explainable decision records with granular findings.

AI/LLMs MUST NOT silently override deterministic policy rules.

## 4. Alternatives Considered
- **ML Anomaly Detection Decision Engine**: Opaque, nondeterministic, prone to false positive release blocks.

## 5. Security Consequences
- Deterministic, auditable, and reproducible policy evaluation across all builds.

## 6. Operational Consequences
- Enterprise policy administrators can update YAML rule parameters per project repository.

## 7. Future Reconsideration Conditions
- Re-evaluate if complex Open Policy Agent (OPA / Rego) integration is required.
