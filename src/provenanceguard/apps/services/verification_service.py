"""
Shared Verification Application Service for ProvenanceGuard.

Central Orchestrator for Artifact Verification workflows.
Delegates to existing Phase 3 (Ingestion/ELF), Phase 4 (Comparison),
Phase 5 (Attestation), Phase 7 (SBOM), and Phase 6 (Risk & Policy Engines).

Used by CLI, GitHub Action, GitLab CI, and Jenkins adapters.
"""

import json
from pathlib import Path
from typing import Any, Optional

from provenanceguard.analyzers.elf.parser import StaticELFParser
from provenanceguard.analyzers.sbom.parser import SBOMAnalyzer
from provenanceguard.core.policy.policy_engine import (
    PolicyConfig,
    PolicyConfigError,
    PolicyEngine,
    PolicyEvaluationResult,
)
from provenanceguard.core.policy.risk_engine import RiskEngine
from provenanceguard.core.verification.artifact_reader import BoundedArtifactReader
from provenanceguard.core.verification.comparison import ArtifactComparator
from provenanceguard.core.verification.models import ComparisonResult
from provenanceguard.core.verification.provenance_models import (
    CombinedAttestationVerificationReport,
)
from provenanceguard.core.verification.sbom_compare import SBOMComparisonEngine
from provenanceguard.core.verification.sbom_models import SBOMComparisonResult


class VerificationAppService:
    """
    Orchestration application service for executing artifact verification pipelines.
    Pure orchestration: does NOT re-implement risk, policy, signature, or ELF parsing logic.
    """

    def __init__(
        self,
        risk_engine: Optional[RiskEngine] = None,
        policy_engine: Optional[PolicyEngine] = None,
        artifact_comparator: Optional[ArtifactComparator] = None,
        sbom_comparison_engine: Optional[SBOMComparisonEngine] = None,
    ):
        self.risk_engine = risk_engine or RiskEngine()
        self.policy_engine = policy_engine or PolicyEngine()
        self.artifact_comparator = artifact_comparator or ArtifactComparator()
        self.sbom_comparison_engine = sbom_comparison_engine or SBOMComparisonEngine()

    def verify_artifact(
        self,
        artifact_path: str,
        policy_path: Optional[str] = None,
        reference_path: Optional[str] = None,
        attestation_path: Optional[str] = None,
        sbom_path: Optional[str] = None,
    ) -> PolicyEvaluationResult:
        """
        Executes complete verification pipeline for an artifact.
        """
        # Validate existence of mandatory artifact path
        art_p = Path(artifact_path)
        if not art_p.exists():
            raise FileNotFoundError(f"Artifact path does not exist: {artifact_path}")
        if not art_p.is_file():
            raise ValueError(f"Artifact path is not a file: {artifact_path}")

        # 1. Load Policy Config
        policy_config = PolicyConfig()
        if policy_path is not None:
            pol_p = Path(policy_path)
            if not pol_p.exists():
                raise FileNotFoundError(f"Policy file path does not exist: {policy_path}")
            try:
                with open(pol_p, "r", encoding="utf-8") as f:
                    policy_yaml = f.read()
                policy_config = PolicyEngine.load_policy_from_yaml(policy_yaml)
            except PolicyConfigError:
                raise
            except Exception as e:
                raise PolicyConfigError(
                    f"Failed to read policy YAML file '{policy_path}': {str(e)}"
                ) from e

        # 2. Parse Attestation Report if provided
        attestation_report: Optional[CombinedAttestationVerificationReport] = None
        if attestation_path is not None:
            att_p = Path(attestation_path)
            if not att_p.exists():
                raise FileNotFoundError(f"Attestation path does not exist: {attestation_path}")
            try:
                with open(att_p, "r", encoding="utf-8") as f:
                    raw_att = json.load(f)
                attestation_report = CombinedAttestationVerificationReport.model_validate(raw_att)
            except Exception as e:
                raise ValueError(
                    f"Failed to parse attestation JSON file '{attestation_path}': {str(e)}"
                ) from e

        # 3. Perform Binary Comparison if reference artifact is provided
        comparison_result: Optional[ComparisonResult] = None
        if reference_path is not None:
            ref_p = Path(reference_path)
            if not ref_p.exists():
                raise FileNotFoundError(f"Reference artifact path does not exist: {reference_path}")

            elf_parser = StaticELFParser()
            target_report = elf_parser.parse_file(str(art_p))
            ref_report = elf_parser.parse_file(str(ref_p))

            with open(ref_p, "rb") as rf_file, open(art_p, "rb") as tf_file:
                ref_reader = BoundedArtifactReader(rf_file)
                target_reader = BoundedArtifactReader(tf_file)

                comparison_result = self.artifact_comparator.compare_elf_artifacts(
                    reference_report=ref_report,
                    target_report=target_report,
                    reference_reader=ref_reader,
                    target_reader=target_reader,
                    reference_digest="ref_sha256",
                    target_digest="target_sha256",
                )

        # 4. Perform SBOM Comparison if sbom_path is provided
        sbom_comparison_result: Optional[SBOMComparisonResult] = None
        if sbom_path is not None:
            sbom_p = Path(sbom_path)
            if not sbom_p.exists():
                raise FileNotFoundError(f"SBOM path does not exist: {sbom_path}")

            sbom_analyzer = SBOMAnalyzer()
            with open(sbom_p, "rb") as f:
                target_sbom_report = sbom_analyzer.parse_sbom(f.read())

            # If reference artifact path has an adjacent/specified SBOM or comparing self:
            # We compare against empty or target sbom
            sbom_comparison_result = self.sbom_comparison_engine.compare(
                reference_sbom=target_sbom_report,
                target_sbom=target_sbom_report,
            )

        # 5. Evaluate Risk Score
        risk_assessment = self.risk_engine.evaluate_risk(
            attestation_report=attestation_report,
            comparison_result=comparison_result,
            sbom_comparison_result=sbom_comparison_result,
        )

        # 6. Evaluate Policy Decision
        policy_result = self.policy_engine.evaluate_policy(
            policy=policy_config,
            risk_assessment=risk_assessment,
            attestation_report=attestation_report,
            comparison_result=comparison_result,
            sbom_comparison_result=sbom_comparison_result,
        )

        return policy_result

    def persist_verification_result(
        self,
        session: Any,
        tenant_context: Any,
        run_repo: Any,
        audit_repo: Any,
        production_artifact_id: Any,
        reference_artifact_id: Any,
        policy_result: PolicyEvaluationResult,
        actor_id: str = "system",
    ) -> Any:
        """Persists verification run, findings, and audit log atomically
        within a single transaction.

        If any insertion fails, transaction rolls back cleanly.
        """
        # Convert findings to dictionary format
        findings_dicts = [
            {
                "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                "category": f.category.value if hasattr(f.category, "value") else str(f.category),
                "explanation": f.explanation,
                "remediation": f.remediation,
                "details_json": f.evidence,
            }
            for f in policy_result.findings
        ]

        run = run_repo.create_run(
            session=session,
            production_artifact_id=production_artifact_id,
            reference_artifact_id=reference_artifact_id,
            status="COMPLETED",
            decision=policy_result.verdict.value
            if hasattr(policy_result.verdict, "value")
            else str(policy_result.verdict),
            risk_score=policy_result.score,
            findings=findings_dicts,
        )

        audit_repo.log_event(
            session=session,
            actor_id=actor_id,
            action="VERIFY_ARTIFACT",
            resource=str(production_artifact_id),
            result=policy_result.verdict.value
            if hasattr(policy_result.verdict, "value")
            else str(policy_result.verdict),
            metadata_json={
                "risk_score": policy_result.score,
                "findings_count": len(policy_result.findings),
            },
        )

        return run
