"""
YAML-Driven Security Policy Engine for ProvenanceGuard.

Evaluates structured evidence states and RiskAssessment against validated
policy specifications to produce deterministic PASS, PASS_WITH_WARNING, or BLOCK outcomes.

PRECEDENCE ORDER:
1. Validate policy configuration schema (invalid policy configuration MUST NEVER produce PASS).
2. Evaluate mandatory explicit boolean policy rules.
3. Any mandatory explicit rule violation => BLOCK (overrides numerical risk thresholds).
4. Otherwise evaluate numerical RiskAssessment.final_score:
   - score >= block_threshold => BLOCK
   - score >= warning_threshold => PASS_WITH_WARNING
   - score < warning_threshold => PASS
"""

from enum import Enum
from typing import List, Optional, Union

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from provenanceguard.core.domain.enums import FindingCategory, Severity
from provenanceguard.core.domain.value_objects import Finding
from provenanceguard.core.policy.risk_engine import RiskAssessment
from provenanceguard.core.verification.comparison import ComparisonResult
from provenanceguard.core.verification.provenance_models import (
    CombinedAttestationVerificationReport,
)
from provenanceguard.core.verification.sbom_models import SBOMComparisonResult


class PolicyDecision(str, Enum):
    PASS = "PASS"
    PASS_WITH_WARNING = "PASS_WITH_WARNING"
    BLOCK = "BLOCK"


class PolicyConfigError(Exception):
    """Raised when policy YAML configuration is malformed, invalid, or fails validation."""

    pass


class PolicyEvaluationError(Exception):
    """Raised when an internal error occurs during policy evaluation."""

    pass


MAX_POLICY_DOC_SIZE = 100 * 1024  # 100 KB limit


class PolicyConfig(BaseModel):
    """
    Strictly validated, immutable policy specification.
    Rejects unknown fields via extra="forbid".
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(default="default-security-policy", max_length=256)
    version: str = Field(default="1.0.0", max_length=50)

    # Numerical Risk Score Thresholds
    warning_threshold: int = Field(default=30, ge=0, le=100)
    block_threshold: int = Field(default=70, ge=0, le=100)

    # Explicit Boolean Mandatory Policy Rules
    require_valid_signature: bool = Field(default=False)
    require_provenance: bool = Field(default=False)
    require_subject_match: bool = Field(default=False)
    require_rekor_tlog: bool = Field(default=False)
    disallow_wx_sections: bool = Field(default=False)
    disallow_wx_segments: bool = Field(default=False)
    disallow_function_deltas: bool = Field(default=False)
    require_complete_function_analysis: bool = Field(default=False)
    disallow_dependency_changes: bool = Field(default=False)
    disallow_unexpected_dependencies: bool = Field(default=False)


class PolicyEvaluationResult(BaseModel):
    """
    Deterministic policy evaluation outcome.
    """

    model_config = ConfigDict(frozen=True)

    decision: PolicyDecision
    policy_name: str
    risk_score: int
    raw_risk_score: int
    mandatory_violations: List[str] = Field(default_factory=list)
    triggered_risk_rules: List[str] = Field(default_factory=list)
    findings: List[Finding] = Field(default_factory=list)
    rationale: str = Field(..., max_length=4096)


class PolicyEngine:
    """
    Pure-function, deterministic Security Policy Evaluator.
    Does NOT use system clock, randomness, network state, or mutable global state.
    """

    @staticmethod
    def load_policy_from_yaml(yaml_content: Union[str, bytes]) -> PolicyConfig:
        """
        Safely parse and validate YAML policy document.
        Uses yaml.safe_load, enforces max document size, and validates against PolicyConfig.
        """
        raw_bytes = yaml_content.encode("utf-8") if isinstance(yaml_content, str) else yaml_content
        if len(raw_bytes) > MAX_POLICY_DOC_SIZE:
            raise PolicyConfigError(
                f"Policy YAML document size ({len(raw_bytes)} bytes) "
                f"exceeds limit ({MAX_POLICY_DOC_SIZE} bytes)"
            )

        try:
            parsed = yaml.safe_load(raw_bytes)
        except Exception as e:
            raise PolicyConfigError(f"Failed to parse policy YAML document: {str(e)}") from e

        if parsed is None:
            parsed = {}
        elif not isinstance(parsed, dict):
            raise PolicyConfigError("Policy YAML document root must be a dictionary")

        try:
            return PolicyConfig(**parsed)
        except ValidationError as ve:
            raise PolicyConfigError(f"Policy configuration validation failed: {str(ve)}") from ve

    def evaluate_policy(
        self,
        policy: PolicyConfig,
        risk_assessment: RiskAssessment,
        attestation_report: Optional[CombinedAttestationVerificationReport] = None,
        comparison_result: Optional[ComparisonResult] = None,
        sbom_comparison_result: Optional[SBOMComparisonResult] = None,
    ) -> PolicyEvaluationResult:
        """
        Evaluate evidence states and RiskAssessment against policy specification.
        Deterministic precedence:
        1. Validate policy threshold sanity (block_threshold >= warning_threshold).
        2. Evaluate mandatory explicit boolean policy rules.
        3. Any mandatory rule violation => BLOCK.
        4. Otherwise evaluate numerical risk_assessment.final_score.
        """

        if policy.block_threshold < policy.warning_threshold:
            raise PolicyConfigError(
                f"Invalid policy threshold config: block_threshold ({policy.block_threshold}) "
                f"cannot be less than warning_threshold ({policy.warning_threshold})"
            )

        mandatory_violations: List[str] = []

        # Extract Explicit Evidence States
        # Signature state
        signature_state = "NOT_PRESENT"
        if attestation_report is not None:
            if attestation_report.dsse_report is not None:
                if attestation_report.dsse_report.signature_verified:
                    signature_state = "VERIFIED"
                else:
                    signature_state = "FAILED"
            elif attestation_report.sigstore_report is not None:
                if attestation_report.sigstore_report.signature_verified:
                    signature_state = "VERIFIED"
                else:
                    signature_state = "FAILED"

        # Provenance state
        provenance_state = "NOT_PRESENT"
        if attestation_report is not None and attestation_report.slsa_report is not None:
            provenance_state = "VALID"

        # Subject correlation state
        subject_correlation_state = "UNAVAILABLE"
        if attestation_report is not None and attestation_report.slsa_report is not None:
            subject_correlation_state = (
                attestation_report.slsa_report.subject_correlation.matching_mode
            )

        # Rekor state
        rekor_state = "NOT_PRESENT"
        if attestation_report is not None and attestation_report.sigstore_report is not None:
            sigstore = attestation_report.sigstore_report
            if sigstore.rekor_entry_observed:
                if sigstore.rekor_set_verified:
                    rekor_state = "VERIFIED"
                else:
                    rekor_state = "FAILED"

        # Function analysis completeness state
        function_analysis_state = "UNAVAILABLE"
        if comparison_result is not None:
            function_analysis_state = comparison_result.target_completeness

        # Function deltas
        has_function_deltas = False
        if comparison_result is not None and len(comparison_result.function_deltas) > 0:
            has_function_deltas = True

        # W+X section / segment introduced
        has_wx_section = False
        has_wx_segment = False
        if comparison_result is not None:
            for sec_delta in comparison_result.security_observation_deltas:
                if sec_delta.observation_type == "WX_SECTION_INTRODUCED":
                    has_wx_section = True
                elif sec_delta.observation_type == "WX_LOAD_SEGMENT_INTRODUCED":
                    has_wx_segment = True

        # SBOM deltas
        has_dependency_changes = False
        has_unexpected_dependencies = False
        if sbom_comparison_result is not None:
            deltas_list = getattr(sbom_comparison_result, "package_deltas", None) or getattr(
                sbom_comparison_result, "deltas", []
            )
            if len(deltas_list) > 0:
                has_dependency_changes = True
                for delta in deltas_list:
                    d_type = str(
                        delta.delta_type.value
                        if hasattr(delta.delta_type, "value")
                        else delta.delta_type
                    )
                    if d_type in ("ADDED_DEPENDENCY", "ADDED_PACKAGE"):
                        has_unexpected_dependencies = True

        # Evaluate Mandatory Rules
        if policy.require_valid_signature and signature_state != "VERIFIED":
            mandatory_violations.append(
                f"Rule 'require_valid_signature' violated: signature state is '{signature_state}'"
            )

        if policy.require_provenance and provenance_state != "VALID":
            mandatory_violations.append(
                f"Rule 'require_provenance' violated: provenance state is '{provenance_state}'"
            )

        if policy.require_subject_match and subject_correlation_state != "EXACT_ONE_MATCH":
            mandatory_violations.append(
                "Rule 'require_subject_match' violated (fail-closed): "
                f"subject correlation state is '{subject_correlation_state}'"
            )

        if policy.require_rekor_tlog and rekor_state != "VERIFIED":
            mandatory_violations.append(
                f"Rule 'require_rekor_tlog' violated: Rekor transparency state is '{rekor_state}'"
            )

        if policy.disallow_wx_sections and has_wx_section:
            mandatory_violations.append(
                "Rule 'disallow_wx_sections' violated: "
                "introduced writable+executable (W+X) section detected"
            )

        if policy.disallow_wx_segments and has_wx_segment:
            mandatory_violations.append(
                "Rule 'disallow_wx_segments' violated: "
                "introduced writable+executable (W+X) segment detected"
            )

        if policy.disallow_function_deltas and has_function_deltas:
            mandatory_violations.append(
                "Rule 'disallow_function_deltas' violated: "
                "function code mutations or additions/removals observed"
            )

        if policy.require_complete_function_analysis and function_analysis_state != "COMPLETE":
            mandatory_violations.append(
                "Rule 'require_complete_function_analysis' violated: "
                f"function analysis completeness is '{function_analysis_state}'"
            )

        if policy.disallow_dependency_changes and has_dependency_changes:
            mandatory_violations.append(
                "Rule 'disallow_dependency_changes' violated: "
                "dependency inventory mutations, additions, or removals detected"
            )

        if policy.disallow_unexpected_dependencies and has_unexpected_dependencies:
            mandatory_violations.append(
                "Rule 'disallow_unexpected_dependencies' violated: "
                "unexpected dependency added to target SBOM"
            )

        # Triggered risk rules list
        triggered_rule_ids = [rf.rule_id for rf in risk_assessment.triggered_factors]

        # Construct Deterministic Domain Finding Objects (reusing Phase 1 Finding model)
        findings: List[Finding] = []

        # 1. Mandatory Policy Violation Findings
        for idx, viol in enumerate(mandatory_violations):
            finding = Finding(
                id=f"FINDING-MANDATORY-{idx + 1:03d}",
                severity=Severity.CRITICAL,
                category=FindingCategory.MANDATORY_RULE_VIOLATION,
                subject=policy.name,
                explanation=viol,
                evidence={"rule_violated": viol},
                confidence=1.0,
                remediation=(
                    "Ensure artifact and build metadata satisfy mandatory "
                    "organizational policy rules."
                ),
            )
            findings.append(finding)

        # 2. Risk Factor Findings
        for rf in sorted(risk_assessment.triggered_factors, key=lambda x: x.rule_id):
            # Derive severity from weight
            if rf.weight >= 40:
                sev = Severity.HIGH
            elif rf.weight >= 20:
                sev = Severity.MEDIUM
            else:
                sev = Severity.LOW

            # Map category
            cat_map = {
                "ATTESTATION": FindingCategory.SIGNATURE_INVALID,
                "PROVENANCE": FindingCategory.PROVENANCE_INVALID,
                "BINARY_SECURITY": FindingCategory.SUSPICIOUS_STRUCTURE,
                "DEPENDENCY": FindingCategory.UNEXPECTED_DEPENDENCY,
            }
            cat = cat_map.get(rf.category, FindingCategory.RISK_THRESHOLD_EXCEEDED)

            finding = Finding(
                id=f"FINDING-{rf.rule_id}",
                severity=sev,
                category=cat,
                subject=rf.evidence_key,
                explanation=rf.description,
                evidence={
                    "rule_id": rf.rule_id,
                    "weight": rf.weight,
                    "evidence_key": rf.evidence_key,
                },
                confidence=1.0,
                remediation="Review verification evidence and address triggered risk factor.",
            )
            findings.append(finding)

        # Determine Decision
        if len(mandatory_violations) > 0:
            decision = PolicyDecision.BLOCK
            rationale = (
                f"Policy evaluation BLOCKED by {len(mandatory_violations)} mandatory "
                f"policy rule violation(s): {'; '.join(mandatory_violations)}"
            )
        elif risk_assessment.final_score >= policy.block_threshold:
            decision = PolicyDecision.BLOCK
            rationale = (
                f"Policy evaluation BLOCKED: risk score ({risk_assessment.final_score}) "
                f"reached or exceeded block threshold ({policy.block_threshold})"
            )
        elif risk_assessment.final_score >= policy.warning_threshold:
            decision = PolicyDecision.PASS_WITH_WARNING
            rationale = (
                f"Policy evaluation PASSED WITH WARNING: risk score "
                f"({risk_assessment.final_score}) reached warning threshold "
                f"({policy.warning_threshold}) below block threshold "
                f"({policy.block_threshold})"
            )
        else:
            decision = PolicyDecision.PASS
            rationale = (
                f"Policy evaluation PASSED: risk score ({risk_assessment.final_score}) "
                f"is below warning threshold ({policy.warning_threshold})"
            )

        return PolicyEvaluationResult(
            decision=decision,
            policy_name=policy.name,
            risk_score=risk_assessment.final_score,
            raw_risk_score=risk_assessment.raw_score,
            mandatory_violations=mandatory_violations,
            triggered_risk_rules=triggered_rule_ids,
            findings=findings,
            rationale=rationale,
        )
