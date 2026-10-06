"""REST API Policy Management & Live Simulator Route Module for ProvenanceGuard.

Exposes server-side YAML policy validation and non-mutating live simulation endpoints.
Enforces POLICY_MANAGE permission, strictly bounded 64 KB payload size limits, and safe PyYAML parsing.
Simulation evaluates via authoritative PolicyEngine without mutating database or verification state.
"""

from __future__ import annotations

from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from provenanceguard.apps.api.auth import AuthUser, require_permission
from provenanceguard.apps.api.rbac import Permission
from provenanceguard.core.policy.policy_engine import (
    PolicyConfigError,
    PolicyEngine,
)
from provenanceguard.core.policy.risk_engine import RiskAssessment
from provenanceguard.infrastructure.database.models import VerificationRunModel
from provenanceguard.infrastructure.database.session import DatabaseManager
from provenanceguard.infrastructure.database.tenant_context import TenantContext

router = APIRouter(prefix="/api/v1/policy", tags=["policy"])

MAX_POLICY_YAML_BYTES = 64 * 1024  # 64 KB limit


class ValidatePolicyRequest(BaseModel):
    yaml_content: str = Field(..., min_length=1, max_length=65536)


class ValidatePolicyResponse(BaseModel):
    valid: bool
    errors: list[str] = Field(default_factory=list)
    policy_name: Optional[str] = None
    warning_threshold: Optional[int] = None
    block_threshold: Optional[int] = None


class SimulatePolicyRequest(BaseModel):
    yaml_content: str = Field(..., min_length=1, max_length=65536)
    verification_id: Optional[UUID] = None
    mock_risk_score: Optional[int] = Field(default=0, ge=0, le=100)


class SimulatePolicyResponse(BaseModel):
    simulated_decision: str
    simulated_risk_score: int
    mandatory_violations: list[str] = Field(default_factory=list)
    triggered_rules: list[str] = Field(default_factory=list)
    rationale: str
    watermark: str = "SIMULATION ONLY — PREVIEW ONLY"


@router.post("/validate", response_model=ValidatePolicyResponse)
async def validate_policy_schema(
    req: ValidatePolicyRequest,
    current_user: AuthUser = Depends(require_permission(Permission.POLICY_MANAGE)),
):
    """Validates policy YAML syntax and schema using server-side PyYAML safe_load and PolicyConfig."""
    if len(req.yaml_content.encode("utf-8")) > MAX_POLICY_YAML_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Policy payload size exceeds {MAX_POLICY_YAML_BYTES} bytes.",
        )

    try:
        policy_config = PolicyEngine.load_policy_from_yaml(req.yaml_content)
        return ValidatePolicyResponse(
            valid=True,
            errors=[],
            policy_name=policy_config.name,
            warning_threshold=policy_config.warning_threshold,
            block_threshold=policy_config.block_threshold,
        )
    except PolicyConfigError as err:
        return ValidatePolicyResponse(
            valid=False,
            errors=[str(err)],
        )


@router.post("/simulate", response_model=SimulatePolicyResponse)
async def simulate_policy_rules(
    req: SimulatePolicyRequest,
    current_user: AuthUser = Depends(require_permission(Permission.POLICY_MANAGE)),
):
    """Simulates policy evaluation in-memory against a target verification run or mock score."""
    if len(req.yaml_content.encode("utf-8")) > MAX_POLICY_YAML_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Policy payload size exceeds {MAX_POLICY_YAML_BYTES} bytes.",
        )

    try:
        policy_config = PolicyEngine.load_policy_from_yaml(req.yaml_content)
    except PolicyConfigError as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid policy specification: {err}",
        ) from err

    risk_score = req.mock_risk_score or 0

    if req.verification_id is not None:
        tenant_ctx = TenantContext(
            organization_id=current_user.organization_id,
            project_id=getattr(current_user, "project_id", None),
        )
        db_mgr = DatabaseManager()
        with db_mgr.get_session() as session:
            db_mgr.set_tenant_context(session, current_user.organization_id)
            run = session.get(VerificationRunModel, req.verification_id)
            if run is not None and run.organization_id == tenant_ctx.organization_id:
                risk_score = run.risk_score

    risk_assessment = RiskAssessment(
        final_score=risk_score,
        raw_score=risk_score,
        risk_factors=[],
    )

    engine = PolicyEngine()
    result = engine.evaluate_policy(
        policy=policy_config,
        risk_assessment=risk_assessment,
    )

    return SimulatePolicyResponse(
        simulated_decision=result.decision.value,
        simulated_risk_score=result.risk_score,
        mandatory_violations=result.mandatory_violations,
        triggered_rules=result.triggered_risk_rules,
        rationale=result.rationale,
        watermark="SIMULATION ONLY — PREVIEW ONLY",
    )
