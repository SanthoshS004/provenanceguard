"""
Unit Tests for RiskEngine.
"""

from provenanceguard.core.policy.risk_engine import RiskEngine
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


def test_risk_engine_zero_findings():
    engine = RiskEngine()
    att = CombinedAttestationVerificationReport(
        dsse_report=DSSEVerificationReport(
            payload_type="text/plain",
            payload_sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
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
                target_artifact_sha256="abc",
                matching_mode="EXACT_ONE_MATCH",
                matching_subject_count=1,
                matching_subject_indices=[0],
                matched_subjects=[],
                subject_digest_match=True,
                all_subjects_observed=[],
            ),
        ),
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
        ),
    )

    assessment = engine.evaluate_risk(attestation_report=att)
    assert assessment.raw_score == 0
    assert assessment.final_score == 0
    assert len(assessment.triggered_factors) == 0


def test_risk_engine_individual_factor_weights():
    engine = RiskEngine()

    # Invalid DSSE signature (+50)
    att_bad_dsse = CombinedAttestationVerificationReport(
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

    res_dsse = engine.evaluate_risk(attestation_report=att_bad_dsse)
    assert res_dsse.raw_score == 50
    assert res_dsse.final_score == 50
    assert any(f.rule_id == "RISK-DSSE-001" for f in res_dsse.triggered_factors)


def test_risk_engine_modified_function_accumulation_and_clamping():
    engine = RiskEngine()

    # 5 modified functions = 5 * 25 = 125 raw score, clamped to 100 final score
    fn_deltas = [
        FunctionDelta(
            function_name=f"func_{i}",
            delta_type="MODIFIED_FUNCTION_CODE",
            details=f"Function func_{i} modified",
            old_digest="1111",
            new_digest="2222",
        )
        for i in range(5)
    ]

    comp_result = ComparisonResult(
        reference_artifact_digest="a" * 64,
        target_artifact_digest="b" * 64,
        digest_matches=False,
        reference_completeness=FunctionInventoryCompleteness.COMPLETE,
        target_completeness=FunctionInventoryCompleteness.COMPLETE,
        is_partial_comparison=False,
        function_deltas=fn_deltas,
    )

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

    assessment = engine.evaluate_risk(
        attestation_report=att_clean,
        comparison_result=comp_result,
    )

    assert assessment.raw_score == 125
    assert assessment.final_score == 100  # Clamped to 100
    assert len(assessment.triggered_factors) == 5


def test_risk_engine_wx_section_and_segment():
    engine = RiskEngine()

    sec_deltas = [
        SecurityObservationDelta(
            observation_type="WX_SECTION_INTRODUCED",
            target_name=".wx_text",
            details="W+X section",
        ),
        SecurityObservationDelta(
            observation_type="WX_LOAD_SEGMENT_INTRODUCED",
            target_name="LOAD_SEGMENT_1",
            details="W+X segment",
        ),
    ]

    comp_result = ComparisonResult(
        reference_artifact_digest="a" * 64,
        target_artifact_digest="b" * 64,
        digest_matches=False,
        reference_completeness=FunctionInventoryCompleteness.COMPLETE,
        target_completeness=FunctionInventoryCompleteness.COMPLETE,
        is_partial_comparison=False,
        security_observation_deltas=sec_deltas,
    )

    assessment = engine.evaluate_risk(comparison_result=comp_result)
    # W+X section (+40) + W+X segment (+40) + Missing attestation (+30) = 110 raw -> 100 final
    assert assessment.raw_score == 110
    assert assessment.final_score == 100


def test_risk_engine_deterministic_repeated_evaluation():
    engine = RiskEngine()
    att = CombinedAttestationVerificationReport()

    res1 = engine.evaluate_risk(attestation_report=att)
    res2 = engine.evaluate_risk(attestation_report=att)

    assert res1.raw_score == res2.raw_score
    assert res1.final_score == res2.final_score
    assert res1.triggered_factors == res2.triggered_factors


def test_risk_engine_sbom_dependency_deltas():
    """
    Tests Phase 9 extension: SBOM dependency delta risk scoring.
    MUTATED (+30), ADDED (+20), REMOVED (+10).
    """
    from provenanceguard.core.verification.sbom_models import (
        PackageDelta,
        PackageDeltaType,
        SBOMComparisonResult,
        SBOMInventoryCompleteness,
    )

    engine = RiskEngine()

    sbom_deltas = [
        PackageDelta(
            package_name="openssl",
            delta_type=PackageDeltaType.VERSION_CHANGED,
            details="Version shifted from 1.1.1 to 3.0.0",
        ),
        PackageDelta(
            package_name="libcurl",
            delta_type=PackageDeltaType.ADDED_PACKAGE,
            details="Unexpected package introduced",
        ),
        PackageDelta(
            package_name="zlib",
            delta_type=PackageDeltaType.REMOVED_PACKAGE,
            details="Package removed in target",
        ),
    ]

    sbom_result = SBOMComparisonResult(
        reference_sbom_digest="ref123",
        target_sbom_digest="tar456",
        reference_completeness=SBOMInventoryCompleteness.COMPLETE,
        target_completeness=SBOMInventoryCompleteness.COMPLETE,
        package_deltas=sbom_deltas,
    )

    # Supply clean attestation to isolate SBOM risk scoring
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

    assessment = engine.evaluate_risk(
        attestation_report=att_clean,
        sbom_comparison_result=sbom_result,
    )

    # Raw score: Mutated (+30) + Added (+20) + Removed (+10) = 60
    assert assessment.raw_score == 60
    assert assessment.final_score == 60
    assert assessment.category_scores["DEPENDENCY"] == 60
    rule_ids = [f.rule_id for f in assessment.triggered_factors]
    assert "RISK-SBOM-MUT-001" in rule_ids
    assert "RISK-SBOM-ADD-001" in rule_ids
    assert "RISK-SBOM-REM-001" in rule_ids
