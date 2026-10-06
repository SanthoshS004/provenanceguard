# ADR-013: Risk Engine, Policy Engine & Deterministic PASS/BLOCK Gate Enforcement

## Context

Phase 4 (Structural Artifact Comparison) and Phase 5 (Attestation Verification & Provenance Evidence Engine) established strict, evidence-only verification semantics. Evidence objects (`ComparisonResult` and `CombinedAttestationVerificationReport`) contain zero policy verdicts, zero risk scores, and zero decision outcomes.

Phase 6 introduces the decision layer: the **Risk Engine**, the **Policy Engine**, and **Deterministic Release Gate Enforcement**.

## Decision & Principles

### 1. Evidence-Only Input Boundary for Risk Engine
`RiskEngine` MUST consume exclusively existing, objective, read-only evidence reports from Phase 4 and Phase 5.
It MUST NOT:
- Inspect raw binary streams or parse ELF headers directly.
- Verify cryptographic signatures or certificates.
- Perform external network lookups or DNS/HTTP queries.
- Infer maliciousness or mutate evidence objects.

### 2. Deterministic Risk Scoring Model & Clamping
Risk score computation follows the exact formula:
$$\text{raw\_score} = \sum (\text{triggered risk factor weights})$$
$$\text{final\_score} = \min(\text{raw\_score}, 100)$$

- **Linear Accumulation**: Modified function code bytes contribute +25 per independently identified modified function. The raw score accumulates linearly and may exceed 100; `final_score` is strictly clamped to 100.
- **No Double-Counting**: Each configured risk factor contributes at most once per applicable evidence item.

### 3. Policy Decision Precedence & Threshold Rules
`PolicyEngine` evaluates evidence states and `RiskAssessment` against validated policy specifications (`PolicyConfig`).

**Precedence Order**:
1. Validate policy configuration schema (`PolicyConfig`).
2. Evaluate mandatory explicit boolean policy rules.
3. Any mandatory explicit rule violation $\rightarrow$ `BLOCK`. (Mandatory policy violations ALWAYS override numerical risk thresholds).
4. Otherwise evaluate numerical `final_score`:
   - $\text{final\_score} \ge \text{block\_threshold}$ (default 70) $\rightarrow$ `BLOCK`
   - $\text{final\_score} \ge \text{warning\_threshold}$ (default 30) $\rightarrow$ `PASS_WITH_WARNING`
   - $\text{final\_score} < \text{warning\_threshold}$ $\rightarrow$ `PASS`

### 4. Explicit Evidence State Representation
The policy engine consumes explicit, strongly typed evidence states:
- `signature_state`: `VERIFIED` | `FAILED` | `NOT_PRESENT`
- `provenance_state`: `VALID` | `INVALID` | `NOT_PRESENT`
- `subject_correlation_state`: `EXACT_ONE_MATCH` | `ZERO_SUBJECT_MATCH` | `MULTIPLE_SUBJECTS_MATCH` | `UNAVAILABLE`
- `rekor_state`: `VERIFIED` | `FAILED` | `NOT_PRESENT`
- `function_analysis_state`: `COMPLETE` | `PARTIAL` | `UNAVAILABLE`
- `function_deltas_observed`: `ADDED` | `REMOVED` | `MODIFIED`

### 5. Fail-Closed Policy Rules
- **`require_subject_match`**: Allowed ONLY for `EXACT_ONE_MATCH`. Fails closed (`BLOCK`) for `ZERO_SUBJECT_MATCH`, `MULTIPLE_SUBJECTS_MATCH`, and `UNAVAILABLE`.
- **`require_provenance`**: Allowed ONLY for `VALID`. Fails closed (`BLOCK`) for `INVALID` and `NOT_PRESENT`.
- **`require_rekor_tlog`**: Allowed ONLY for `VERIFIED`. Fails closed (`BLOCK`) for `FAILED` and `NOT_PRESENT`.

### 6. "Signature != Safe" Multi-Factor Security Invariant
A valid cryptographic signature alone MUST NOT yield a `PASS` decision if high-risk anomalies (e.g., introduced `W+X` sections/segments or function byte modifications) are present or if mandatory policy rules are violated.

### 7. W+X Section vs. W+X Segment Distinction
`disallow_wx_sections` evaluates ONLY introduced writable+executable section evidence.
`disallow_wx_segments` evaluates ONLY introduced writable+executable load segment evidence.

### 8. YAML Security Constraints
- Safe YAML parsing only (`yaml.safe_load`). Rejects arbitrary Python object instantiations.
- Validates against explicit Pydantic `PolicyConfig` schema with `model_config = ConfigDict(extra="forbid")` (rejects unknown YAML fields).
- Enforces bounded document size (max 100 KB).
- Malformed or invalid policy configuration MUST NEVER produce `PASS` or fail open; raises `PolicyConfigError`.

### 9. Deterministic CLI Exit Code Contract
CLI `provenanceguard verify` maps decisions directly to exit codes:
- `0`: `PASS` or `PASS_WITH_WARNING`
- `1`: `BLOCK` (Policy failure or risk score exceeded block threshold)
- `2`: `CLI_USAGE_ERROR` / `POLICY_CONFIG_ERROR`
- `3`: `SYSTEM_ERROR` / `STORAGE_ERROR` (Policy BLOCK and system failure are NEVER conflated)

## Status
APPROVED & IMPLEMENTED (Phase 6)
