"""
Unit Tests for PolicyEngine & YAML Policy Loading.
"""

import pytest

from provenanceguard.core.policy.policy_engine import (
    MAX_POLICY_DOC_SIZE,
    PolicyConfig,
    PolicyConfigError,
    PolicyDecision,
    PolicyEngine,
)
from provenanceguard.core.policy.risk_engine import RiskAssessment
from provenanceguard.core.verification.models import (
    ComparisonResult,
    FunctionDelta,
    FunctionInventoryCompleteness,
    SecurityObservationDelta,
)
from provenanceguard.core.verification.provenance_models import (
    BuildDefinitionEvidence,
    CombinedAttestationVerificationReport,
    DSSEVerificationReport,
    RunDetailsEvidence,
    SigstoreIdentityReport,
    SLSAProvenanceReport,
    SubjectCorrelationDetails,
)


def test_yaml_policy_loading_valid():
    yaml_str = """
name: prod-policy
warning_threshold: 25
block_threshold: 60
require_valid_signature: true
require_provenance: true
require_subject_match: true
disallow_wx_sections: true
"""
    config = PolicyEngine.load_policy_from_yaml(yaml_str)
    assert config.name == "prod-policy"
    assert config.warning_threshold == 25
    assert config.block_threshold == 60
    assert config.require_valid_signature is True
    assert config.require_provenance is True
    assert config.require_subject_match is True
    assert config.disallow_wx_sections is True


def test_yaml_policy_loading_unknown_field_rejected():
    yaml_str = """
name: invalid-policy
unknown_field: 123
"""
    with pytest.raises(PolicyConfigError) as exc:
        PolicyEngine.load_policy_from_yaml(yaml_str)
    assert "validation failed" in str(exc.value) or "extra_forbidden" in str(exc.value)


def test_yaml_policy_loading_malformed_yaml():
    yaml_str = "name: [malformed yaml"
    with pytest.raises(PolicyConfigError):
        PolicyEngine.load_policy_from_yaml(yaml_str)


def test_yaml_policy_loading_unsafe_tag_rejected():
    unsafe_yaml = "!!python/object/apply:os.system ['id']\n"
    with pytest.raises(PolicyConfigError) as exc:
        PolicyEngine.load_policy_from_yaml(unsafe_yaml)
    assert "Failed to parse policy YAML document" in str(exc.value)


def test_yaml_policy_loading_oversized_document_rejected():
    oversized_yaml = "name: test\n" + "#" * (MAX_POLICY_DOC_SIZE + 10)
    with pytest.raises(PolicyConfigError) as exc:
        PolicyEngine.load_policy_from_yaml(oversized_yaml)
    assert "exceeds limit" in str(exc.value)


def test_policy_threshold_evaluation_pass_warning_block():
    engine = PolicyEngine()
    policy = PolicyConfig(warning_threshold=30, block_threshold=70)

    # 1. Score < 30 -> PASS
    risk_low = RiskAssessment(raw_score=10, final_score=10)
    res_low = engine.evaluate_policy(policy, risk_low)
    assert res_low.decision == PolicyDecision.PASS

    # 2. Score 30 <= s < 70 -> PASS_WITH_WARNING
    risk_mid = RiskAssessment(raw_score=40, final_score=40)
    res_mid = engine.evaluate_policy(policy, risk_mid)
    assert res_mid.decision == PolicyDecision.PASS_WITH_WARNING

    # 3. Score >= 70 -> BLOCK
    risk_high = RiskAssessment(raw_score=80, final_score=80)
    res_high = engine.evaluate_policy(policy, risk_high)
    assert res_high.decision == PolicyDecision.BLOCK


def test_mandatory_rule_overrides_low_score():
    engine = PolicyEngine()
    policy = PolicyConfig(
        warning_threshold=30,
        block_threshold=70,
        require_valid_signature=True,
    )

    # Score is 0 (low risk), but signature is missing/invalid -> MUST BLOCK
    risk_zero = RiskAssessment(raw_score=0, final_score=0)
    att_no_sig = CombinedAttestationVerificationReport()

    res = engine.evaluate_policy(policy, risk_zero, attestation_report=att_no_sig)
    assert res.decision == PolicyDecision.BLOCK
    assert len(res.mandatory_violations) == 1
    assert "require_valid_signature" in res.mandatory_violations[0]


def test_subject_correlation_policy_states():
    engine = PolicyEngine()
    policy = PolicyConfig(require_subject_match=True)
    risk_zero = RiskAssessment(raw_score=0, final_score=0)

    # Mode 1: ZERO_SUBJECT_MATCH -> BLOCK
    att_zero = CombinedAttestationVerificationReport(
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
    assert (
        engine.evaluate_policy(policy, risk_zero, attestation_report=att_zero).decision
        == PolicyDecision.BLOCK
    )

    # Mode 2: MULTIPLE_SUBJECTS_MATCH -> BLOCK
    att_multi = CombinedAttestationVerificationReport(
        slsa_report=SLSAProvenanceReport(
            build_definition=BuildDefinitionEvidence(build_type="https://slsa.dev/provenance/v1"),
            run_details=RunDetailsEvidence(builder_id="https://github.com/actions/runner"),
            subject_correlation=SubjectCorrelationDetails(
                target_artifact_sha256="abc",
                matching_mode="MULTIPLE_SUBJECTS_MATCH",
                matching_subject_count=2,
                matching_subject_indices=[0, 1],
                matched_subjects=[],
                subject_digest_match=False,
                all_subjects_observed=[],
            ),
        )
    )
    assert (
        engine.evaluate_policy(policy, risk_zero, attestation_report=att_multi).decision
        == PolicyDecision.BLOCK
    )

    # Mode 3: UNAVAILABLE -> BLOCK
    att_unavail = CombinedAttestationVerificationReport(
        slsa_report=SLSAProvenanceReport(
            build_definition=BuildDefinitionEvidence(build_type="https://slsa.dev/provenance/v1"),
            run_details=RunDetailsEvidence(builder_id="https://github.com/actions/runner"),
            subject_correlation=SubjectCorrelationDetails(
                target_artifact_sha256="abc",
                matching_mode="UNAVAILABLE",
                matching_subject_count=0,
                matching_subject_indices=[],
                matched_subjects=[],
                subject_digest_match=False,
                all_subjects_observed=[],
            ),
        )
    )
    assert (
        engine.evaluate_policy(policy, risk_zero, attestation_report=att_unavail).decision
        == PolicyDecision.BLOCK
    )

    # Mode 4: EXACT_ONE_MATCH -> PASS
    att_exact = CombinedAttestationVerificationReport(
        slsa_report=SLSAProvenanceReport(
            build_definition=BuildDefinitionEvidence(build_type="https://slsa.dev/provenance/v1"),
            run_details=RunDetailsEvidence(builder_id="https://github.com/actions/runner"),
            subject_correlation=SubjectCorrelationDetails(
                target_artifact_sha256="abc",
                matching_mode="EXACT_ONE_MATCH",
                matching_subject_count=1,
                matching_subject_indices=[0],
                matched_subjects=[],
                subject_digest_match=True,
                all_subjects_observed=[],
            ),
        )
    )
    assert (
        engine.evaluate_policy(policy, risk_zero, attestation_report=att_exact).decision
        == PolicyDecision.PASS
    )


def test_rekor_tlog_policy_states():
    engine = PolicyEngine()
    policy = PolicyConfig(require_rekor_tlog=True)
    risk_zero = RiskAssessment(raw_score=0, final_score=0)

    # 1. Rekor VERIFIED -> PASS
    att_verified = CombinedAttestationVerificationReport(
        sigstore_report=SigstoreIdentityReport(
            bundle_version="v0.3",
            certificate_chain_valid=True,
            certificate_time_valid=True,
            time_validity_state="EVALUATION_TIME_VALID",
            rekor_entry_observed=True,
            rekor_set_verified=True,
            rekor_checkpoint_verified=True,
            rekor_inclusion_proof_verified=True,
            rekor_integrated_time=1770000000,
            rekor_integrated_time_cryptographically_verified=True,
            signature_verified=True,
        )
    )
    assert (
        engine.evaluate_policy(policy, risk_zero, attestation_report=att_verified).decision
        == PolicyDecision.PASS
    )

    # 2. Rekor FAILED (entry observed but set unverified) -> BLOCK
    att_failed = CombinedAttestationVerificationReport(
        sigstore_report=SigstoreIdentityReport(
            bundle_version="v0.3",
            certificate_chain_valid=True,
            certificate_time_valid=True,
            time_validity_state="EVALUATION_TIME_VALID",
            rekor_entry_observed=True,
            rekor_set_verified=False,
            rekor_checkpoint_verified=False,
            rekor_inclusion_proof_verified=False,
            rekor_integrated_time=None,
            rekor_integrated_time_cryptographically_verified=False,
            signature_verified=True,
        )
    )
    assert (
        engine.evaluate_policy(policy, risk_zero, attestation_report=att_failed).decision
        == PolicyDecision.BLOCK
    )

    # 3. Rekor NOT_PRESENT -> BLOCK
    att_absent = CombinedAttestationVerificationReport()
    assert (
        engine.evaluate_policy(policy, risk_zero, attestation_report=att_absent).decision
        == PolicyDecision.BLOCK
    )


def test_provenance_states_evaluation():
    engine = PolicyEngine()
    policy = PolicyConfig(require_provenance=True)
    risk_zero = RiskAssessment(raw_score=0, final_score=0)

    # Provenance VALID -> PASS
    att_valid = CombinedAttestationVerificationReport(
        slsa_report=SLSAProvenanceReport(
            build_definition=BuildDefinitionEvidence(build_type="https://slsa.dev/provenance/v1"),
            run_details=RunDetailsEvidence(builder_id="https://github.com/actions/runner"),
            subject_correlation=SubjectCorrelationDetails(
                target_artifact_sha256="abc",
                matching_mode="EXACT_ONE_MATCH",
                matching_subject_count=1,
                matching_subject_indices=[0],
                matched_subjects=[],
                subject_digest_match=True,
                all_subjects_observed=[],
            ),
        )
    )
    assert (
        engine.evaluate_policy(policy, risk_zero, attestation_report=att_valid).decision
        == PolicyDecision.PASS
    )

    # Provenance NOT_PRESENT -> BLOCK
    att_none = CombinedAttestationVerificationReport()
    assert (
        engine.evaluate_policy(policy, risk_zero, attestation_report=att_none).decision
        == PolicyDecision.BLOCK
    )


def test_signature_states_evaluation():
    engine = PolicyEngine()
    policy = PolicyConfig(require_valid_signature=True)
    risk_zero = RiskAssessment(raw_score=0, final_score=0)

    # Signature VERIFIED -> PASS
    att_valid = CombinedAttestationVerificationReport(
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
    assert (
        engine.evaluate_policy(policy, risk_zero, attestation_report=att_valid).decision
        == PolicyDecision.PASS
    )

    # Signature FAILED -> BLOCK
    att_failed = CombinedAttestationVerificationReport(
        dsse_report=DSSEVerificationReport(
            payload_type="text/plain",
            payload_sha256="abc",
            decoded_payload_size=10,
            signatures_observed=1,
            signatures_verified=0,
            key_ids_verified=[],
            signature_verified=False,
        )
    )
    assert (
        engine.evaluate_policy(policy, risk_zero, attestation_report=att_failed).decision
        == PolicyDecision.BLOCK
    )


def test_function_deltas_and_completeness_policy():
    engine = PolicyEngine()
    policy_no_deltas = PolicyConfig(disallow_function_deltas=True)
    policy_complete = PolicyConfig(require_complete_function_analysis=True)
    risk_zero = RiskAssessment(raw_score=0, final_score=0)

    # Disallow Function Deltas -> BLOCK when deltas present
    comp_deltas = ComparisonResult(
        reference_artifact_digest="a" * 64,
        target_artifact_digest="b" * 64,
        digest_matches=False,
        reference_completeness=FunctionInventoryCompleteness.COMPLETE,
        target_completeness=FunctionInventoryCompleteness.COMPLETE,
        is_partial_comparison=False,
        function_deltas=[
            FunctionDelta(
                function_name="main",
                delta_type="MODIFIED_FUNCTION_CODE",
                details="modified",
                old_digest="1",
                new_digest="2",
            )
        ],
    )
    assert (
        engine.evaluate_policy(policy_no_deltas, risk_zero, comparison_result=comp_deltas).decision
        == PolicyDecision.BLOCK
    )

    # Require Complete Function Analysis -> BLOCK when target_completeness is PARTIAL or UNAVAILABLE
    comp_partial = ComparisonResult(
        reference_artifact_digest="a" * 64,
        target_artifact_digest="b" * 64,
        digest_matches=False,
        reference_completeness=FunctionInventoryCompleteness.COMPLETE,
        target_completeness=FunctionInventoryCompleteness.PARTIAL,
        is_partial_comparison=True,
    )
    assert (
        engine.evaluate_policy(policy_complete, risk_zero, comparison_result=comp_partial).decision
        == PolicyDecision.BLOCK
    )

    comp_unavail = ComparisonResult(
        reference_artifact_digest="a" * 64,
        target_artifact_digest="b" * 64,
        digest_matches=False,
        reference_completeness=FunctionInventoryCompleteness.UNAVAILABLE,
        target_completeness=FunctionInventoryCompleteness.UNAVAILABLE,
        is_partial_comparison=True,
    )
    assert (
        engine.evaluate_policy(policy_complete, risk_zero, comparison_result=comp_unavail).decision
        == PolicyDecision.BLOCK
    )


def test_wx_sections_vs_segments_policy_separation():
    engine = PolicyEngine()
    policy_sec = PolicyConfig(disallow_wx_sections=True, disallow_wx_segments=False)
    policy_seg = PolicyConfig(disallow_wx_sections=False, disallow_wx_segments=True)
    risk_zero = RiskAssessment(raw_score=0, final_score=0)

    comp_sec_only = ComparisonResult(
        reference_artifact_digest="a" * 64,
        target_artifact_digest="b" * 64,
        digest_matches=False,
        reference_completeness=FunctionInventoryCompleteness.COMPLETE,
        target_completeness=FunctionInventoryCompleteness.COMPLETE,
        is_partial_comparison=False,
        security_observation_deltas=[
            SecurityObservationDelta(
                observation_type="WX_SECTION_INTRODUCED",
                target_name=".wx_section",
                details="W+X section",
            )
        ],
    )

    # Disallow W+X section policy blocks W+X section
    res1 = engine.evaluate_policy(policy_sec, risk_zero, comparison_result=comp_sec_only)
    assert res1.decision == PolicyDecision.BLOCK

    # Disallow W+X segment policy allows W+X section when no W+X segment introduced
    res2 = engine.evaluate_policy(policy_seg, risk_zero, comparison_result=comp_sec_only)
    assert res2.decision == PolicyDecision.PASS


def test_policy_engine_deterministic_repeated_evaluation():
    engine = PolicyEngine()
    policy = PolicyConfig(warning_threshold=30, block_threshold=70)
    risk = RiskAssessment(raw_score=20, final_score=20)

    res1 = engine.evaluate_policy(policy, risk)
    res2 = engine.evaluate_policy(policy, risk)

    assert res1.decision == res2.decision
    assert res1.rationale == res2.rationale


def test_policy_engine_findings_generation_and_domain_model_reuse():
    """
    Tests Phase 9 domain Finding object generation and reuse of Phase 1 value objects.
    """
    from provenanceguard.core.domain.enums import FindingCategory, Severity
    from provenanceguard.core.domain.value_objects import Finding
    from provenanceguard.core.policy.risk_engine import RiskFactor

    engine = PolicyEngine()
    policy = PolicyConfig(require_valid_signature=True, warning_threshold=30, block_threshold=70)

    triggered = [
        RiskFactor(
            rule_id="RISK-WX-SEC-001",
            category="BINARY_SECURITY",
            weight=40,
            description="Introduced W+X section",
            evidence_key="wx_section_introduced:.text",
        )
    ]
    risk = RiskAssessment(raw_score=40, final_score=40, triggered_factors=triggered)

    result = engine.evaluate_policy(policy=policy, risk_assessment=risk)

    assert result.decision == PolicyDecision.BLOCK
    assert len(result.findings) >= 2
    # Mandatory finding
    mand_f = result.findings[0]
    assert isinstance(mand_f, Finding)
    assert mand_f.severity == Severity.CRITICAL
    assert mand_f.category == FindingCategory.MANDATORY_RULE_VIOLATION
    assert "require_valid_signature" in mand_f.explanation

    # Risk factor finding
    risk_f = [f for f in result.findings if f.id == "FINDING-RISK-WX-SEC-001"][0]
    assert isinstance(risk_f, Finding)
    assert risk_f.severity == Severity.HIGH
    assert risk_f.category == FindingCategory.SUSPICIOUS_STRUCTURE


def test_policy_engine_clean_pass_findings_empty():
    """
    Tests that a clean PASS (score 0, 0 violations) returns an empty findings list [].
    """
    engine = PolicyEngine()
    policy = PolicyConfig(warning_threshold=30, block_threshold=70)
    att_clean = CombinedAttestationVerificationReport(
        dsse_report=DSSEVerificationReport(
            payload_type="text/plain",
            payload_sha256="b" * 64,
            decoded_payload_size=10,
            signatures_observed=1,
            signatures_verified=1,
            key_ids_verified=["k1"],
            signature_verified=True,
        ),
        slsa_report=SLSAProvenanceReport(
            build_definition=BuildDefinitionEvidence(build_type="https://slsa.dev/provenance/v1"),
            run_details=RunDetailsEvidence(builder_id="https://github.com/actions/runner"),
            subject_correlation=SubjectCorrelationDetails(
                target_artifact_sha256="b" * 64,
                matching_mode="EXACT_ONE_MATCH",
                matching_subject_count=1,
                matching_subject_indices=[0],
                matched_subjects=[],
                subject_digest_match=True,
                all_subjects_observed=[],
            ),
        ),
    )
    risk_zero = RiskAssessment(raw_score=0, final_score=0)

    result = engine.evaluate_policy(policy, risk_zero, attestation_report=att_clean)
    assert result.decision == PolicyDecision.PASS
    assert result.findings == []
