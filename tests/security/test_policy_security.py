"""
Adversarial Security Boundary Tests for Policy Engine & Fail-Closed Gate.
"""

import pytest

from provenanceguard.core.policy.policy_engine import (
    PolicyConfig,
    PolicyDecision,
    PolicyEngine,
)
from provenanceguard.core.policy.risk_engine import RiskEngine
from provenanceguard.core.verification.models import (
    ComparisonResult,
    FunctionInventoryCompleteness,
    SecurityObservationDelta,
)
from provenanceguard.core.verification.provenance_models import (
    BuildDefinitionEvidence,
    CombinedAttestationVerificationReport,
    DSSEVerificationReport,
    RunDetailsEvidence,
    SLSAProvenanceReport,
    SubjectCorrelationDetails,
)


def test_signature_valid_does_not_guarantee_pass_when_wx_section_introduced():
    """
    INVARIANT TEST ("Signature != Safe"):
    Valid DSSE signature MUST NOT yield PASS if high-risk W+X section is introduced.
    """
    risk_engine = RiskEngine()
    policy_engine = PolicyEngine()

    policy = PolicyConfig(
        require_valid_signature=True,
        disallow_wx_sections=True,
    )

    # Valid signature report
    att = CombinedAttestationVerificationReport(
        dsse_report=DSSEVerificationReport(
            payload_type="text/plain",
            payload_sha256="abc",
            decoded_payload_size=10,
            signatures_observed=1,
            signatures_verified=1,
            key_ids_verified=["k1"],
            signature_verified=True,
        )
    )

    # Comparison result with introduced W+X section
    comp = ComparisonResult(
        reference_artifact_digest="a" * 64,
        target_artifact_digest="b" * 64,
        digest_matches=False,
        reference_completeness=FunctionInventoryCompleteness.COMPLETE,
        target_completeness=FunctionInventoryCompleteness.COMPLETE,
        is_partial_comparison=False,
        security_observation_deltas=[
            SecurityObservationDelta(
                observation_type="WX_SECTION_INTRODUCED",
                target_name=".wx_code",
                details="Hostile W+X section",
            )
        ],
    )

    risk_assessment = risk_engine.evaluate_risk(attestation_report=att, comparison_result=comp)
    policy_result = policy_engine.evaluate_policy(
        policy=policy,
        risk_assessment=risk_assessment,
        attestation_report=att,
        comparison_result=comp,
    )

    # Must BLOCK despite valid signature!
    assert policy_result.decision == PolicyDecision.BLOCK
    assert any("disallow_wx_sections" in v for v in policy_result.mandatory_violations)


def test_subject_mismatch_blocks_when_required():
    risk_engine = RiskEngine()
    policy_engine = PolicyEngine()
    policy = PolicyConfig(require_subject_match=True)

    att_mismatch = CombinedAttestationVerificationReport(
        slsa_report=SLSAProvenanceReport(
            build_definition=BuildDefinitionEvidence(build_type="https://slsa.dev/provenance/v1"),
            run_details=RunDetailsEvidence(builder_id="https://github.com/actions/runner"),
            subject_correlation=SubjectCorrelationDetails(
                target_artifact_sha256="abc",
                matching_mode="ZERO_SUBJECT_MATCH",
                matching_subject_count=0,
                matching_subject_indices=[],
                matched_subjects=[],
                subject_digest_match=False,
                all_subjects_observed=[],
            ),
        )
    )

    risk = risk_engine.evaluate_risk(attestation_report=att_mismatch)
    res = policy_engine.evaluate_policy(policy, risk, attestation_report=att_mismatch)

    assert res.decision == PolicyDecision.BLOCK
    assert any("require_subject_match" in v for v in res.mandatory_violations)


def test_missing_provenance_blocks_when_required():
    risk_engine = RiskEngine()
    policy_engine = PolicyEngine()
    policy = PolicyConfig(require_provenance=True)

    att_no_prov = CombinedAttestationVerificationReport()
    risk = risk_engine.evaluate_risk(attestation_report=att_no_prov)
    res = policy_engine.evaluate_policy(policy, risk, attestation_report=att_no_prov)

    assert res.decision == PolicyDecision.BLOCK
    assert any("require_provenance" in v for v in res.mandatory_violations)


def test_invalid_policy_cannot_fail_open():
    """
    INVARIANT TEST:
    Invalid policy YAML or malformed config schema MUST raise PolicyConfigError.
    """
    invalid_yaml = "invalid_key_name_xxxx: true\n"
    try:
        PolicyEngine.load_policy_from_yaml(invalid_yaml)
        pytest.fail("Should have raised PolicyConfigError")
    except Exception as e:
        assert "Policy" in type(e).__name__ or "validation" in str(e).lower()
