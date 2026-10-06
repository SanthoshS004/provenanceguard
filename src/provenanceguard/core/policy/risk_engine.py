"""
Risk Engine for ProvenanceGuard.

Calculates deterministic numerical risk scores (0 to 100) based on objective
evidence inputs from Phase 4 (ComparisonResult) and Phase 5 (CombinedAttestationVerificationReport).

CRITICAL BOUNDARY INVARIANT:
RiskEngine MUST NOT inspect raw binaries, parse ELF headers, verify signatures,
access external network, or mutate evidence objects. It consumes strictly
read-only evidence reports.
"""

from typing import Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from provenanceguard.core.verification.comparison import ComparisonResult
from provenanceguard.core.verification.provenance_models import (
    CombinedAttestationVerificationReport,
)
from provenanceguard.core.verification.sbom_models import SBOMComparisonResult


class RiskFactor(BaseModel):
    """Individual triggered risk factor evidence item."""

    model_config = ConfigDict(frozen=True)

    rule_id: str = Field(..., max_length=256)
    category: str = Field(
        ..., max_length=100
    )  # ATTESTATION, PROVENANCE, BINARY_SECURITY, DEPENDENCY
    weight: int = Field(..., ge=0)
    description: str = Field(..., max_length=1024)
    evidence_key: str = Field(..., max_length=256)


class RiskAssessment(BaseModel):
    """
    Aggregated numerical risk score & triggered factors report.
    """

    model_config = ConfigDict(frozen=True)

    raw_score: int = Field(..., ge=0)
    final_score: int = Field(..., ge=0, le=100)  # Clamped to min(raw_score, 100)
    category_scores: Dict[str, int] = Field(default_factory=dict)
    triggered_factors: List[RiskFactor] = Field(default_factory=list)


class RiskEngine:
    """
    Deterministic Risk Calculator consuming Phase 4, Phase 5 & Phase 7 evidence reports.
    """

    # Configured risk weights
    WEIGHT_DSSE_INVALID: int = 50
    WEIGHT_FULCIO_INVALID: int = 50
    WEIGHT_REKOR_INVALID: int = 20
    WEIGHT_CERT_EXPIRED: int = 15

    WEIGHT_SUBJECT_NO_MATCH: int = 60
    WEIGHT_SUBJECT_UNAVAILABLE: int = 40
    WEIGHT_SUBJECT_MULTIPLE_MATCHES: int = 20
    WEIGHT_PROVENANCE_MISSING_OR_INVALID: int = 30

    WEIGHT_WX_SECTION_INTRODUCED: int = 40
    WEIGHT_WX_SEGMENT_INTRODUCED: int = 40
    WEIGHT_MODIFIED_FUNCTION_PER_ITEM: int = 25
    WEIGHT_FUNCTION_ADDED_OR_REMOVED_PER_ITEM: int = 10

    # Phase 9 Extension: SBOM Dependency Weights
    WEIGHT_DEPENDENCY_MUTATED: int = 30
    WEIGHT_DEPENDENCY_ADDED: int = 20
    WEIGHT_DEPENDENCY_REMOVED: int = 10

    def evaluate_risk(
        self,
        attestation_report: Optional[CombinedAttestationVerificationReport] = None,
        comparison_result: Optional[ComparisonResult] = None,
        sbom_comparison_result: Optional[SBOMComparisonResult] = None,
    ) -> RiskAssessment:
        """
        Calculate deterministic risk score from objective evidence reports.

        raw_score = sum(triggered risk factor weights)
        final_score = min(raw_score, 100)
        """
        triggered_factors: List[RiskFactor] = []
        cat_scores: Dict[str, int] = {
            "ATTESTATION": 0,
            "PROVENANCE": 0,
            "BINARY_SECURITY": 0,
            "DEPENDENCY": 0,
        }

        # 1. Attestation Evidence Evaluation (Phase 5)
        if attestation_report is not None:
            # DSSE Evidence
            if attestation_report.dsse_report is not None:
                if not attestation_report.dsse_report.signature_verified:
                    rf = RiskFactor(
                        rule_id="RISK-DSSE-001",
                        category="ATTESTATION",
                        weight=self.WEIGHT_DSSE_INVALID,
                        description="DSSE envelope signature is unverified or invalid",
                        evidence_key="dsse_report.signature_verified=False",
                    )
                    triggered_factors.append(rf)
                    cat_scores["ATTESTATION"] += rf.weight

            # Sigstore / Certificate / Rekor Evidence
            if attestation_report.sigstore_report is not None:
                sigstore = attestation_report.sigstore_report
                if not sigstore.certificate_chain_valid:
                    rf = RiskFactor(
                        rule_id="RISK-SIGSTORE-001",
                        category="ATTESTATION",
                        weight=self.WEIGHT_FULCIO_INVALID,
                        description="Fulcio X.509 certificate path validation failed",
                        evidence_key="sigstore_report.certificate_chain_valid=False",
                    )
                    triggered_factors.append(rf)
                    cat_scores["ATTESTATION"] += rf.weight

                if sigstore.rekor_entry_observed and not sigstore.rekor_set_verified:
                    rf = RiskFactor(
                        rule_id="RISK-REKOR-001",
                        category="ATTESTATION",
                        weight=self.WEIGHT_REKOR_INVALID,
                        description="Rekor transparency log entry SET verification failed",
                        evidence_key="sigstore_report.rekor_set_verified=False",
                    )
                    triggered_factors.append(rf)
                    cat_scores["ATTESTATION"] += rf.weight

                if not sigstore.certificate_time_valid:
                    rf = RiskFactor(
                        rule_id="RISK-CERT-TIME-001",
                        category="ATTESTATION",
                        weight=self.WEIGHT_CERT_EXPIRED,
                        description="Certificate is expired at evaluation time without valid SET",
                        evidence_key="sigstore_report.certificate_time_valid=False",
                    )
                    triggered_factors.append(rf)
                    cat_scores["ATTESTATION"] += rf.weight

            # SLSA Provenance & Subject Evidence
            if attestation_report.slsa_report is not None:
                slsa = attestation_report.slsa_report

                # Subject Correlation Evidence
                subj_corr = slsa.subject_correlation
                if subj_corr.matching_mode == "ZERO_SUBJECT_MATCH":
                    rf = RiskFactor(
                        rule_id="RISK-SUBJ-001",
                        category="PROVENANCE",
                        weight=self.WEIGHT_SUBJECT_NO_MATCH,
                        description="Target artifact digest matches zero subjects in provenance",
                        evidence_key="subject_correlation.matching_mode=ZERO_SUBJECT_MATCH",
                    )
                    triggered_factors.append(rf)
                    cat_scores["PROVENANCE"] += rf.weight
                elif subj_corr.matching_mode == "UNAVAILABLE":
                    rf = RiskFactor(
                        rule_id="RISK-SUBJ-002",
                        category="PROVENANCE",
                        weight=self.WEIGHT_SUBJECT_UNAVAILABLE,
                        description="Target artifact SHA-256 unavailable for subject correlation",
                        evidence_key="subject_correlation.matching_mode=UNAVAILABLE",
                    )
                    triggered_factors.append(rf)
                    cat_scores["PROVENANCE"] += rf.weight
                elif subj_corr.matching_mode == "MULTIPLE_SUBJECTS_MATCH":
                    rf = RiskFactor(
                        rule_id="RISK-SUBJ-003",
                        category="PROVENANCE",
                        weight=self.WEIGHT_SUBJECT_MULTIPLE_MATCHES,
                        description="Multiple provenance subjects match target artifact digest",
                        evidence_key="subject_correlation.matching_mode=MULTIPLE_SUBJECTS_MATCH",
                    )
                    triggered_factors.append(rf)
                    cat_scores["PROVENANCE"] += rf.weight
        else:
            # Missing Attestation Evidence completely
            rf = RiskFactor(
                rule_id="RISK-PROV-MISSING",
                category="PROVENANCE",
                weight=self.WEIGHT_PROVENANCE_MISSING_OR_INVALID,
                description="No attestation or SLSA provenance evidence payload supplied",
                evidence_key="attestation_report=None",
            )
            triggered_factors.append(rf)
            cat_scores["PROVENANCE"] += rf.weight

        # 2. Structural & Binary Delta Evidence Evaluation (Phase 4)
        if comparison_result is not None:
            # Check W+X Security Observation Deltas
            for sec_delta in comparison_result.security_observation_deltas:
                if sec_delta.observation_type == "WX_SECTION_INTRODUCED":
                    rf = RiskFactor(
                        rule_id="RISK-WX-SEC-001",
                        category="BINARY_SECURITY",
                        weight=self.WEIGHT_WX_SECTION_INTRODUCED,
                        description=(
                            "Introduced writable and executable (W+X) section "
                            f"'{sec_delta.target_name}'"
                        ),
                        evidence_key=f"wx_section_introduced:{sec_delta.target_name}",
                    )
                    triggered_factors.append(rf)
                    cat_scores["BINARY_SECURITY"] += rf.weight

                if sec_delta.observation_type == "WX_LOAD_SEGMENT_INTRODUCED":
                    rf = RiskFactor(
                        rule_id="RISK-WX-SEG-001",
                        category="BINARY_SECURITY",
                        weight=self.WEIGHT_WX_SEGMENT_INTRODUCED,
                        description=(
                            "Introduced writable and executable (W+X) segment "
                            f"'{sec_delta.target_name}'"
                        ),
                        evidence_key=f"wx_segment_introduced:{sec_delta.target_name}",
                    )
                    triggered_factors.append(rf)
                    cat_scores["BINARY_SECURITY"] += rf.weight

            # Check Function Code Byte Mutations
            for fn_delta in comparison_result.function_deltas:
                if fn_delta.delta_type == "MODIFIED_FUNCTION_CODE":
                    rf = RiskFactor(
                        rule_id="RISK-FN-MOD-001",
                        category="BINARY_SECURITY",
                        weight=self.WEIGHT_MODIFIED_FUNCTION_PER_ITEM,
                        description=f"Function code bytes modified in '{fn_delta.function_name}'",
                        evidence_key=f"function_modified:{fn_delta.function_name}",
                    )
                    triggered_factors.append(rf)
                    cat_scores["BINARY_SECURITY"] += rf.weight
                elif fn_delta.delta_type in ("ADDED_FUNCTION", "REMOVED_FUNCTION"):
                    rf = RiskFactor(
                        rule_id="RISK-FN-DELTA-001",
                        category="BINARY_SECURITY",
                        weight=self.WEIGHT_FUNCTION_ADDED_OR_REMOVED_PER_ITEM,
                        description=(
                            f"Function {fn_delta.delta_type.lower()} symbol: "
                            f"'{fn_delta.function_name}'"
                        ),
                        evidence_key=f"function_{fn_delta.delta_type.lower()}:{fn_delta.function_name}",
                    )
                    triggered_factors.append(rf)
                    cat_scores["BINARY_SECURITY"] += rf.weight

        # 3. SBOM Dependency Delta Evidence Evaluation (Phase 7 / Phase 9)
        if sbom_comparison_result is not None:
            deltas_list = getattr(sbom_comparison_result, "package_deltas", None) or getattr(
                sbom_comparison_result, "deltas", []
            )
            for pkg_delta in deltas_list:
                d_type = str(
                    pkg_delta.delta_type.value
                    if hasattr(pkg_delta.delta_type, "value")
                    else pkg_delta.delta_type
                )
                comp_name = getattr(pkg_delta, "package_name", None) or getattr(
                    pkg_delta, "component_name", "unknown_package"
                )

                if d_type in (
                    "MUTATED_DEPENDENCY",
                    "VERSION_CHANGED",
                    "CHECKSUM_MISMATCH",
                    "LICENSE_CHANGED",
                ):
                    rf = RiskFactor(
                        rule_id="RISK-SBOM-MUT-001",
                        category="DEPENDENCY",
                        weight=self.WEIGHT_DEPENDENCY_MUTATED,
                        description=f"Dependency version/digest mutated for '{comp_name}'",
                        evidence_key=f"dependency_mutated:{comp_name}",
                    )
                    triggered_factors.append(rf)
                    cat_scores["DEPENDENCY"] += rf.weight
                elif d_type in ("ADDED_DEPENDENCY", "ADDED_PACKAGE"):
                    rf = RiskFactor(
                        rule_id="RISK-SBOM-ADD-001",
                        category="DEPENDENCY",
                        weight=self.WEIGHT_DEPENDENCY_ADDED,
                        description=f"Unexpected dependency introduced: '{comp_name}'",
                        evidence_key=f"dependency_added:{comp_name}",
                    )
                    triggered_factors.append(rf)
                    cat_scores["DEPENDENCY"] += rf.weight
                elif d_type in ("REMOVED_DEPENDENCY", "REMOVED_PACKAGE"):
                    rf = RiskFactor(
                        rule_id="RISK-SBOM-REM-001",
                        category="DEPENDENCY",
                        weight=self.WEIGHT_DEPENDENCY_REMOVED,
                        description=f"Dependency removed: '{comp_name}'",
                        evidence_key=f"dependency_removed:{comp_name}",
                    )
                    triggered_factors.append(rf)
                    cat_scores["DEPENDENCY"] += rf.weight

        # Calculate total raw score and clamp final score to 100
        raw_score = sum(f.weight for f in triggered_factors)
        final_score = min(raw_score, 100)

        return RiskAssessment(
            raw_score=raw_score,
            final_score=final_score,
            category_scores=cat_scores,
            triggered_factors=triggered_factors,
        )
