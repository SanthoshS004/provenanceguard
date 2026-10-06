"""
Master End-to-End Attack Scenarios & Negative Control Runner for Phase 17.

Executes controlled, reproducible security attack scenarios and negative control tests,
asserting deterministic two-run repeatability and strict alignment with Phase 0-16 capabilities.
"""

from typing import Any, Dict, Optional

from provenanceguard.core.domain.enums import FindingCategory
from provenanceguard.core.policy.policy_engine import (
    PolicyConfig,
    PolicyDecision,
    PolicyEngine,
    PolicyEvaluationResult,
)
from provenanceguard.core.policy.risk_engine import RiskAssessment, RiskEngine
from provenanceguard.core.verification.comparison import ComparisonResult
from provenanceguard.core.verification.models import (
    FunctionDelta,
    FunctionInventoryCompleteness,
    SecurityObservationDelta,
)
from provenanceguard.core.verification.oci_compare import (
    OCIComparisonResult,
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
from provenanceguard.core.verification.sbom_models import (
    PackageDelta,
    PackageDeltaType,
    SBOMComparisonResult,
    SBOMInventoryCompleteness,
)


class SecurityScenarioRunner:
    """
    Harness for executing and verifying security scenarios deterministically.
    """

    def __init__(self):
        self.risk_engine = RiskEngine()
        self.policy_engine = PolicyEngine()

    def run_scenario(
        self,
        attestation_report: Optional[CombinedAttestationVerificationReport] = None,
        comparison_result: Optional[ComparisonResult] = None,
        sbom_comparison_result: Optional[SBOMComparisonResult] = None,
        oci_comparison_result: Optional[OCIComparisonResult] = None,
        policy_config: Optional[PolicyConfig] = None,
    ) -> Dict[str, Any]:
        """
        Executes a single scenario pass through RiskEngine and PolicyEngine.
        Returns serialized evaluation outcome for deterministic assertion.
        """
        if policy_config is None:
            policy_config = PolicyConfig()

        # 1. Evaluate Risk Score
        risk_assessment: RiskAssessment = self.risk_engine.evaluate_risk(
            attestation_report=attestation_report,
            comparison_result=comparison_result,
            sbom_comparison_result=sbom_comparison_result,
        )

        # 2. Evaluate Policy Decision
        policy_result: PolicyEvaluationResult = self.policy_engine.evaluate_policy(
            policy=policy_config,
            risk_assessment=risk_assessment,
            attestation_report=attestation_report,
            comparison_result=comparison_result,
            sbom_comparison_result=sbom_comparison_result,
        )

        # Determine CI exit code (0 for PASS/PASS_WITH_WARNING, 1 for BLOCK)
        exit_code = 1 if policy_result.decision == PolicyDecision.BLOCK else 0

        # Extract finding categories
        all_categories = [f.category for f in policy_result.findings]
        risk_categories = [
            f.category
            for f in policy_result.findings
            if f.category != FindingCategory.MANDATORY_RULE_VIOLATION
        ]
        primary_category = (
            risk_categories[0]
            if risk_categories
            else (all_categories[0] if all_categories else None)
        )

        return {
            "decision": policy_result.decision,
            "raw_score": risk_assessment.raw_score,
            "final_score": risk_assessment.final_score,
            "triggered_rules": policy_result.triggered_risk_rules,
            "unique_triggered_rules": sorted(list(set(policy_result.triggered_risk_rules))),
            "mandatory_violations": policy_result.mandatory_violations,
            "primary_finding_category": primary_category,
            "all_finding_categories": all_categories,
            "exit_code": exit_code,
        }


# --- FIXTURE BUILDERS ---


def build_nc01_trusted_attestation() -> CombinedAttestationVerificationReport:
    """NC-01: Valid SLSA subject match + valid DSSE signature."""
    subj_corr = SubjectCorrelationDetails(
        target_artifact_sha256="abc123def456",
        matching_mode="EXACT_ONE_MATCH",
        matching_subject_count=1,
        subject_digest_match=True,
    )
    slsa = SLSAProvenanceReport(
        build_definition=BuildDefinitionEvidence(
            build_type="https://actions.github.io/buildtypes/v1"
        ),
        run_details=RunDetailsEvidence(builder_id="builder-001"),
        subject_correlation=subj_corr,
    )
    dsse = DSSEVerificationReport(
        payload_type="https://in-toto.io/Statement/v1",
        payload_sha256="abc123def456",
        decoded_payload_size=1024,
        signatures_observed=1,
        signatures_verified=1,
        signature_verified=True,
    )
    return CombinedAttestationVerificationReport(
        dsse_report=dsse,
        slsa_report=slsa,
    )


def build_nc02_identical_sbom() -> SBOMComparisonResult:
    """NC-02: Identical SBOM inventory (zero deltas)."""
    return SBOMComparisonResult(
        reference_sbom_digest="sha256:ref",
        target_sbom_digest="sha256:ref",
        reference_completeness=SBOMInventoryCompleteness.COMPLETE,
        target_completeness=SBOMInventoryCompleteness.COMPLETE,
        package_deltas=[],
    )


def build_nc03_untampered_oci() -> OCIComparisonResult:
    """NC-03: Untampered OCI image (manifest digests match)."""
    ref_digest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
    base_comp = ComparisonResult(
        reference_artifact_digest=ref_digest,
        target_artifact_digest=ref_digest,
        digest_matches=True,
        reference_completeness=FunctionInventoryCompleteness.COMPLETE,
        target_completeness=FunctionInventoryCompleteness.COMPLETE,
        is_partial_comparison=False,
    )
    return OCIComparisonResult(
        reference_manifest_digest=ref_digest,
        production_manifest_digest=ref_digest,
        manifest_digest_matches=True,
        comparison_result=base_comp,
    )


def build_nc04_added_dependency_sbom() -> SBOMComparisonResult:
    """NC-04: Legitimate dependency addition (1 added package)."""
    delta = PackageDelta(
        delta_type=PackageDeltaType.ADDED_PACKAGE,
        package_name="pkg:npm/lodash@4.17.21",
        purl="pkg:npm/lodash@4.17.21",
        details="Added package lodash",
        new_value="4.17.21",
    )
    return SBOMComparisonResult(
        reference_sbom_digest="sha256:ref",
        target_sbom_digest="sha256:target",
        reference_completeness=SBOMInventoryCompleteness.COMPLETE,
        target_completeness=SBOMInventoryCompleteness.COMPLETE,
        package_deltas=[delta],
    )


# --- TEST SUITE: NEGATIVE CONTROLS ---


def test_nc01_trusted_baseline_artifact():
    """NC-01: Trusted artifact & provenance yields PASS with 0 risk score."""
    runner = SecurityScenarioRunner()
    report = build_nc01_trusted_attestation()

    res1 = runner.run_scenario(attestation_report=report)
    res2 = runner.run_scenario(attestation_report=report)

    assert res1 == res2, "Two-run repeatability failed for NC-01"
    assert res1["decision"] == PolicyDecision.PASS
    assert res1["final_score"] == 0
    assert res1["exit_code"] == 0


def test_nc02_identical_sbom_comparison():
    """NC-02: Identical SBOM baseline comparison yields PASS."""
    runner = SecurityScenarioRunner()
    trusted_attestation = build_nc01_trusted_attestation()
    sbom_res = build_nc02_identical_sbom()

    res1 = runner.run_scenario(
        attestation_report=trusted_attestation, sbom_comparison_result=sbom_res
    )
    res2 = runner.run_scenario(
        attestation_report=trusted_attestation, sbom_comparison_result=sbom_res
    )

    assert res1 == res2, "Two-run repeatability failed for NC-02"
    assert res1["decision"] == PolicyDecision.PASS
    assert res1["final_score"] == 0
    assert res1["exit_code"] == 0


def test_nc03_untampered_offline_oci_layout():
    """NC-03: Untampered offline OCI image layout yields PASS."""
    runner = SecurityScenarioRunner()
    trusted_attestation = build_nc01_trusted_attestation()
    oci_res = build_nc03_untampered_oci()

    res1 = runner.run_scenario(
        attestation_report=trusted_attestation, comparison_result=oci_res.comparison_result
    )
    res2 = runner.run_scenario(
        attestation_report=trusted_attestation, comparison_result=oci_res.comparison_result
    )

    assert res1 == res2, "Two-run repeatability failed for NC-03"
    assert res1["decision"] == PolicyDecision.PASS
    assert res1["final_score"] == 0
    assert res1["exit_code"] == 0


def test_nc04_legitimate_dependency_addition_permissive():
    """NC-04: Legitimate dependency addition under permissive policy yields PASS_WITH_WARNING."""
    runner = SecurityScenarioRunner()
    trusted_attestation = build_nc01_trusted_attestation()
    sbom_res = build_nc04_added_dependency_sbom()
    policy = PolicyConfig(
        warning_threshold=20,
        block_threshold=70,
        disallow_unexpected_dependencies=False,
    )

    res1 = runner.run_scenario(
        attestation_report=trusted_attestation,
        sbom_comparison_result=sbom_res,
        policy_config=policy,
    )
    res2 = runner.run_scenario(
        attestation_report=trusted_attestation,
        sbom_comparison_result=sbom_res,
        policy_config=policy,
    )

    assert res1 == res2, "Two-run repeatability failed for NC-04"
    assert res1["decision"] == PolicyDecision.PASS_WITH_WARNING
    assert res1["final_score"] == 20
    assert res1["unique_triggered_rules"] == ["RISK-SBOM-ADD-001"]
    assert res1["primary_finding_category"] == FindingCategory.UNEXPECTED_DEPENDENCY
    assert res1["exit_code"] == 0


# --- TEST SUITE: ATTACK SCENARIOS ---


def test_scenario_01_artifact_replacement_sha256_mismatch():
    """Scenario 1: Binary replaced post-provenance (ZERO_SUBJECT_MATCH)."""
    runner = SecurityScenarioRunner()
    subj_corr = SubjectCorrelationDetails(
        target_artifact_sha256="mismatched123",
        matching_mode="ZERO_SUBJECT_MATCH",
        matching_subject_count=0,
        subject_digest_match=False,
    )
    slsa = SLSAProvenanceReport(
        build_definition=BuildDefinitionEvidence(
            build_type="https://actions.github.io/buildtypes/v1"
        ),
        run_details=RunDetailsEvidence(builder_id="builder-001"),
        subject_correlation=subj_corr,
    )
    dsse = DSSEVerificationReport(
        payload_type="https://in-toto.io/Statement/v1",
        payload_sha256="abc123def456",
        decoded_payload_size=1024,
        signatures_observed=1,
        signatures_verified=1,
        signature_verified=True,
    )
    report = CombinedAttestationVerificationReport(dsse_report=dsse, slsa_report=slsa)
    policy = PolicyConfig(require_subject_match=True, block_threshold=70)

    res1 = runner.run_scenario(attestation_report=report, policy_config=policy)
    res2 = runner.run_scenario(attestation_report=report, policy_config=policy)

    assert res1 == res2, "Two-run repeatability failed for Scenario 1"
    assert res1["decision"] == PolicyDecision.BLOCK
    assert res1["final_score"] == 60
    assert res1["unique_triggered_rules"] == ["RISK-SUBJ-001"]
    assert res1["primary_finding_category"] == FindingCategory.PROVENANCE_INVALID
    assert res1["exit_code"] == 1


def test_scenario_02_modified_build_output_function_mutation():
    """Scenario 2: Compiler wrapper modifies 3 function code bytes."""
    runner = SecurityScenarioRunner()
    trusted_attestation = build_nc01_trusted_attestation()
    fn_deltas = [
        FunctionDelta(
            delta_type="MODIFIED_FUNCTION_CODE",
            function_name="foo",
            details="Bytecode modified",
        ),
        FunctionDelta(
            delta_type="MODIFIED_FUNCTION_CODE",
            function_name="bar",
            details="Bytecode modified",
        ),
        FunctionDelta(
            delta_type="MODIFIED_FUNCTION_CODE",
            function_name="baz",
            details="Bytecode modified",
        ),
    ]
    comp_res = ComparisonResult(
        reference_artifact_digest="sha256:ref",
        target_artifact_digest="sha256:target",
        digest_matches=False,
        reference_completeness=FunctionInventoryCompleteness.COMPLETE,
        target_completeness=FunctionInventoryCompleteness.COMPLETE,
        is_partial_comparison=False,
        function_deltas=fn_deltas,
    )
    policy = PolicyConfig(block_threshold=70)

    res1 = runner.run_scenario(
        attestation_report=trusted_attestation,
        comparison_result=comp_res,
        policy_config=policy,
    )
    res2 = runner.run_scenario(
        attestation_report=trusted_attestation,
        comparison_result=comp_res,
        policy_config=policy,
    )

    assert res1 == res2, "Two-run repeatability failed for Scenario 2"
    assert res1["decision"] == PolicyDecision.BLOCK
    assert res1["final_score"] == 75  # 3 * 25
    assert res1["unique_triggered_rules"] == ["RISK-FN-MOD-001"]
    assert res1["primary_finding_category"] == FindingCategory.SUSPICIOUS_STRUCTURE
    assert res1["exit_code"] == 1


def test_scenario_03_dependency_substitution():
    """Scenario 3: Dependency version/digest mutated (VERSION_CHANGED)."""
    runner = SecurityScenarioRunner()
    trusted_attestation = build_nc01_trusted_attestation()
    delta = PackageDelta(
        delta_type=PackageDeltaType.VERSION_CHANGED,
        package_name="pkg:npm/express@4.17.1",
        purl="pkg:npm/express@4.17.1",
        details="Version changed",
        old_value="4.17.1",
        new_value="4.17.2-malicious",
    )
    sbom_res = SBOMComparisonResult(
        reference_sbom_digest="sha256:ref",
        target_sbom_digest="sha256:target",
        reference_completeness=SBOMInventoryCompleteness.COMPLETE,
        target_completeness=SBOMInventoryCompleteness.COMPLETE,
        package_deltas=[delta],
    )
    policy = PolicyConfig(disallow_dependency_changes=True)

    res1 = runner.run_scenario(
        attestation_report=trusted_attestation,
        sbom_comparison_result=sbom_res,
        policy_config=policy,
    )
    res2 = runner.run_scenario(
        attestation_report=trusted_attestation,
        sbom_comparison_result=sbom_res,
        policy_config=policy,
    )

    assert res1 == res2, "Two-run repeatability failed for Scenario 3"
    assert res1["decision"] == PolicyDecision.BLOCK
    assert res1["final_score"] == 30
    assert res1["unique_triggered_rules"] == ["RISK-SBOM-MUT-001"]
    assert res1["primary_finding_category"] == FindingCategory.UNEXPECTED_DEPENDENCY
    assert res1["exit_code"] == 1


def test_scenario_04_dependency_addition():
    """Scenario 4: Supply-chain attack introducing unapproved package."""
    runner = SecurityScenarioRunner()
    trusted_attestation = build_nc01_trusted_attestation()
    delta = PackageDelta(
        delta_type=PackageDeltaType.ADDED_PACKAGE,
        package_name="pkg:npm/malicious-telemetry@1.0.0",
        purl="pkg:npm/malicious-telemetry@1.0.0",
        details="Added package",
        new_value="1.0.0",
    )
    sbom_res = SBOMComparisonResult(
        reference_sbom_digest="sha256:ref",
        target_sbom_digest="sha256:target",
        reference_completeness=SBOMInventoryCompleteness.COMPLETE,
        target_completeness=SBOMInventoryCompleteness.COMPLETE,
        package_deltas=[delta],
    )
    policy = PolicyConfig(disallow_unexpected_dependencies=True)

    res1 = runner.run_scenario(
        attestation_report=trusted_attestation,
        sbom_comparison_result=sbom_res,
        policy_config=policy,
    )
    res2 = runner.run_scenario(
        attestation_report=trusted_attestation,
        sbom_comparison_result=sbom_res,
        policy_config=policy,
    )

    assert res1 == res2, "Two-run repeatability failed for Scenario 4"
    assert res1["decision"] == PolicyDecision.BLOCK
    assert res1["final_score"] == 20
    assert res1["unique_triggered_rules"] == ["RISK-SBOM-ADD-001"]
    assert res1["primary_finding_category"] == FindingCategory.UNEXPECTED_DEPENDENCY
    assert res1["exit_code"] == 1


def test_scenario_05_dependency_removal():
    """Scenario 5: Attacker strips 3 dependencies from reported SBOM."""
    runner = SecurityScenarioRunner()
    trusted_attestation = build_nc01_trusted_attestation()
    deltas = [
        PackageDelta(
            delta_type=PackageDeltaType.REMOVED_PACKAGE,
            package_name=f"pkg:npm/pkg-{i}",
            purl=f"pkg:npm/pkg-{i}",
            details="Removed package",
            old_value="1.0.0",
        )
        for i in range(3)
    ]
    sbom_res = SBOMComparisonResult(
        reference_sbom_digest="sha256:ref",
        target_sbom_digest="sha256:target",
        reference_completeness=SBOMInventoryCompleteness.COMPLETE,
        target_completeness=SBOMInventoryCompleteness.COMPLETE,
        package_deltas=deltas,
    )
    policy = PolicyConfig(disallow_dependency_changes=True)

    res1 = runner.run_scenario(
        attestation_report=trusted_attestation,
        sbom_comparison_result=sbom_res,
        policy_config=policy,
    )
    res2 = runner.run_scenario(
        attestation_report=trusted_attestation,
        sbom_comparison_result=sbom_res,
        policy_config=policy,
    )

    assert res1 == res2, "Two-run repeatability failed for Scenario 5"
    assert res1["decision"] == PolicyDecision.BLOCK
    assert res1["final_score"] == 30  # 3 * 10
    assert res1["unique_triggered_rules"] == ["RISK-SBOM-REM-001"]
    assert res1["primary_finding_category"] == FindingCategory.UNEXPECTED_DEPENDENCY
    assert res1["exit_code"] == 1


def test_scenario_06_forged_dsse_signature():
    """Scenario 6: Corrupted/forged in-toto DSSE signature."""
    runner = SecurityScenarioRunner()
    dsse = DSSEVerificationReport(
        payload_type="https://in-toto.io/Statement/v1",
        payload_sha256="abc123def456",
        decoded_payload_size=1024,
        signatures_observed=1,
        signatures_verified=0,
        signature_verified=False,
    )
    report = CombinedAttestationVerificationReport(dsse_report=dsse)
    policy = PolicyConfig(require_valid_signature=True)

    res1 = runner.run_scenario(attestation_report=report, policy_config=policy)
    res2 = runner.run_scenario(attestation_report=report, policy_config=policy)

    assert res1 == res2, "Two-run repeatability failed for Scenario 6"
    assert res1["decision"] == PolicyDecision.BLOCK
    assert res1["final_score"] == 50
    assert res1["unique_triggered_rules"] == ["RISK-DSSE-001"]
    assert res1["primary_finding_category"] == FindingCategory.SIGNATURE_INVALID
    assert res1["exit_code"] == 1


def test_scenario_07_invalid_fulcio_certificate_chain():
    """Scenario 7: Invalid Fulcio cert chain while DSSE signature is valid (no double counting)."""
    runner = SecurityScenarioRunner()
    dsse = DSSEVerificationReport(
        payload_type="https://in-toto.io/Statement/v1",
        payload_sha256="abc123def456",
        decoded_payload_size=1024,
        signatures_observed=1,
        signatures_verified=1,
        signature_verified=True,
    )
    sigstore = SigstoreIdentityReport(
        bundle_version="0.1",
        certificate_chain_valid=False,
        certificate_time_valid=True,
        time_validity_state="EVALUATION_TIME_VALID",
        signature_verified=True,
    )
    report = CombinedAttestationVerificationReport(dsse_report=dsse, sigstore_report=sigstore)
    policy = PolicyConfig(warning_threshold=30, block_threshold=50)

    res1 = runner.run_scenario(attestation_report=report, policy_config=policy)
    res2 = runner.run_scenario(attestation_report=report, policy_config=policy)

    assert res1 == res2, "Two-run repeatability failed for Scenario 7"
    assert res1["decision"] == PolicyDecision.BLOCK
    assert res1["final_score"] == 50  # WEIGHT_FULCIO_INVALID only
    assert res1["unique_triggered_rules"] == ["RISK-SIGSTORE-001"]
    assert res1["primary_finding_category"] == FindingCategory.SIGNATURE_INVALID
    assert res1["exit_code"] == 1


def test_scenario_08_oci_layer_descriptor_digest_mismatch():
    """Scenario 8: OCI layer digest mismatch validates evidence detection; deferred RiskEngine/policy enforcement."""
    runner = SecurityScenarioRunner()
    trusted_attestation = build_nc01_trusted_attestation()
    ref_digest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
    prod_digest = "sha256:2222222222222222222222222222222222222222222222222222222222222222"

    base_comp = ComparisonResult(
        reference_artifact_digest=ref_digest,
        target_artifact_digest=prod_digest,
        digest_matches=False,
        reference_completeness=FunctionInventoryCompleteness.COMPLETE,
        target_completeness=FunctionInventoryCompleteness.COMPLETE,
        is_partial_comparison=False,
    )
    oci_res = OCIComparisonResult(
        reference_manifest_digest=ref_digest,
        production_manifest_digest=prod_digest,
        manifest_digest_matches=False,
        comparison_result=base_comp,
    )

    # Validates detection evidence structure
    assert oci_res.manifest_digest_matches is False
    assert oci_res.comparison_result.digest_matches is False

    # Risk score is 0 because direct OCI-layer risk mapping is a Deferred Capability
    res1 = runner.run_scenario(
        attestation_report=trusted_attestation, comparison_result=oci_res.comparison_result
    )
    res2 = runner.run_scenario(
        attestation_report=trusted_attestation, comparison_result=oci_res.comparison_result
    )

    assert res1 == res2, "Two-run repeatability failed for Scenario 8"
    assert res1["decision"] == PolicyDecision.PASS
    assert res1["final_score"] == 0
    assert res1["exit_code"] == 0


def test_scenario_09_elf_wx_security_discrepancy():
    """Scenario 9: Binary contains introduced W+X sections/segments."""
    runner = SecurityScenarioRunner()
    trusted_attestation = build_nc01_trusted_attestation()
    sec_deltas = [
        SecurityObservationDelta(
            observation_type="WX_SECTION_INTRODUCED",
            target_name=".writable_text",
            details="Writable and executable section introduced",
        ),
        SecurityObservationDelta(
            observation_type="WX_LOAD_SEGMENT_INTRODUCED",
            target_name="LOAD_SEG_1",
            details="Writable and executable segment introduced",
        ),
    ]
    comp_res = ComparisonResult(
        reference_artifact_digest="sha256:ref",
        target_artifact_digest="sha256:target",
        digest_matches=False,
        reference_completeness=FunctionInventoryCompleteness.COMPLETE,
        target_completeness=FunctionInventoryCompleteness.COMPLETE,
        is_partial_comparison=False,
        security_observation_deltas=sec_deltas,
    )
    policy = PolicyConfig(disallow_wx_sections=True, block_threshold=70)

    res1 = runner.run_scenario(
        attestation_report=trusted_attestation,
        comparison_result=comp_res,
        policy_config=policy,
    )
    res2 = runner.run_scenario(
        attestation_report=trusted_attestation,
        comparison_result=comp_res,
        policy_config=policy,
    )

    assert res1 == res2, "Two-run repeatability failed for Scenario 9"
    assert res1["decision"] == PolicyDecision.BLOCK
    assert res1["final_score"] == 80  # 40 + 40
    assert res1["unique_triggered_rules"] == ["RISK-WX-SEC-001", "RISK-WX-SEG-001"]
    assert res1["primary_finding_category"] == FindingCategory.SUSPICIOUS_STRUCTURE
    assert res1["exit_code"] == 1


def test_scenario_10_storage_retrieval_content_tampering():
    """Scenario 10: In-place file modification on storage yields ZERO_SUBJECT_MATCH when submitted to verification."""
    runner = SecurityScenarioRunner()
    subj_corr = SubjectCorrelationDetails(
        target_artifact_sha256="tampered_hash_123",
        matching_mode="ZERO_SUBJECT_MATCH",
        matching_subject_count=0,
        subject_digest_match=False,
    )
    slsa = SLSAProvenanceReport(
        build_definition=BuildDefinitionEvidence(
            build_type="https://actions.github.io/buildtypes/v1"
        ),
        run_details=RunDetailsEvidence(builder_id="builder-001"),
        subject_correlation=subj_corr,
    )
    report = CombinedAttestationVerificationReport(slsa_report=slsa)
    policy = PolicyConfig(require_subject_match=True)

    res1 = runner.run_scenario(attestation_report=report, policy_config=policy)
    res2 = runner.run_scenario(attestation_report=report, policy_config=policy)

    assert res1 == res2, "Two-run repeatability failed for Scenario 10"
    assert res1["decision"] == PolicyDecision.BLOCK
    assert res1["final_score"] == 60
    assert res1["unique_triggered_rules"] == ["RISK-SUBJ-001"]
    assert res1["primary_finding_category"] == FindingCategory.PROVENANCE_INVALID
    assert res1["exit_code"] == 1


def test_load_and_validate_all_scenario_yaml_specs():
    """Validates that all YAML scenario specification files parse cleanly into ScenarioSpec Pydantic models."""
    from pathlib import Path

    import yaml

    from .schema import ScenarioSpec

    fixtures_dir = Path(__file__).parent / "fixtures" / "scenarios"
    yaml_files = list(fixtures_dir.glob("*.yaml"))
    assert len(yaml_files) >= 15, (
        f"Expected at least 15 scenario YAML specs, found {len(yaml_files)}"
    )

    for yf in yaml_files:
        with open(yf, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        spec = ScenarioSpec(**data)
        assert spec.metadata.scenario_id is not None
        assert spec.expected_results is not None
