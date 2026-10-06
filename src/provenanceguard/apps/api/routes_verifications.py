"""REST API Route Handlers for Verification Task Submission & Inspection."""

import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select

from provenanceguard.apps.api.auth import AuthUser, require_permission
from provenanceguard.apps.api.rbac import Permission
from provenanceguard.infrastructure.database.models import VerificationRunModel
from provenanceguard.infrastructure.database.outbox_repository import OutboxRepository
from provenanceguard.infrastructure.database.session import DatabaseManager
from provenanceguard.infrastructure.database.tenant_context import TenantContext
from provenanceguard.infrastructure.queue.arq_dispatcher import ARQTaskDispatcher
from provenanceguard.infrastructure.queue.dispatcher import JobPayload

router = APIRouter(prefix="/api/v1/verifications", tags=["verifications"])


class CreateVerificationRequest(BaseModel):
    organization_id: uuid.UUID
    project_id: uuid.UUID
    production_artifact_id: uuid.UUID
    reference_artifact_id: Optional[uuid.UUID] = None

    model_config = ConfigDict(extra="forbid")


class VerificationResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    project_id: uuid.UUID
    production_artifact_id: uuid.UUID
    reference_artifact_id: Optional[uuid.UUID] = None
    status: str
    decision: str
    risk_score: int
    attempt_count: int

    model_config = ConfigDict(extra="ignore")


@router.post("", status_code=status.HTTP_202_ACCEPTED)
async def create_verification(
    req: CreateVerificationRequest,
    current_user: AuthUser = Depends(require_permission(Permission.VERIFICATION_CREATE)),
):
    """Submits a verification run request asynchronously using server-derived tenant context."""
    # 1. Enforce server-derived tenant identity
    if req.organization_id != current_user.organization_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Client organization_id does not match authenticated tenant identity.",
        )

    # 2. Enforce project-scope restriction if credential is project-scoped
    if (
        current_user.project_scope_id is not None
        and req.project_id != current_user.project_scope_id
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Credential scope restricted to project '{current_user.project_scope_id}'.",
        )

    org_id = current_user.organization_id
    db_mgr = DatabaseManager()
    tenant_ctx = TenantContext(organization_id=org_id)

    with db_mgr.get_session() as session:
        db_mgr.set_tenant_context(session, org_id)

        # 3. Create initial VerificationRun (QUEUED)
        run_id = uuid.uuid4()
        run = VerificationRunModel(
            id=run_id,
            organization_id=org_id,
            project_id=req.project_id,
            production_artifact_id=req.production_artifact_id,
            reference_artifact_id=req.reference_artifact_id,
            status="QUEUED",
            decision="PENDING",
            risk_score=0,
            attempt_count=1,
        )
        session.add(run)
        session.flush()

        # 4. Construct JobPayload
        payload = JobPayload(
            verification_run_id=run_id,
            organization_id=org_id,
            project_id=req.project_id,
            attempt=1,
        )

        # 5. Create Outbox Event inside active DB transaction
        outbox_repo = OutboxRepository(tenant_context=tenant_ctx)
        outbox_event = outbox_repo.create_event(
            session=session,
            aggregate_type="VerificationRun",
            aggregate_id=run_id,
            project_id=req.project_id,
            event_type="VERIFICATION_REQUESTED",
            payload_dict=payload.model_dump(mode="json"),
        )
        session.commit()

        # 6. Post-Commit Redis Dispatch
        try:
            dispatcher = ARQTaskDispatcher()
            await dispatcher.dispatch_verification_job(payload)
            outbox_repo.mark_dispatched(session, outbox_event.id)
            session.commit()
        except Exception:
            try:
                from provenanceguard.apps.worker.worker import run_verification_job
                await run_verification_job({}, payload.model_dump(mode="json"))
            except Exception:
                pass

        return {
            "job_id": payload.job_id,
            "verification_run_id": str(run_id),
            "status": "QUEUED",
        }


@router.get("/{verification_id}", response_model=VerificationResponse)
async def get_verification(
    verification_id: uuid.UUID,
    current_user: AuthUser = Depends(require_permission(Permission.VERIFICATION_READ)),
):
    """Retrieves verification run status scoped strictly to server-derived tenant organization."""
    db_mgr = DatabaseManager()
    with db_mgr.get_session() as session:
        db_mgr.set_tenant_context(session, current_user.organization_id)

        stmt = select(VerificationRunModel).where(
            VerificationRunModel.id == verification_id,
            VerificationRunModel.organization_id == current_user.organization_id,
        )
        run = session.scalar(stmt)
        if not run:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Verification run not found or cross-tenant access denied.",
            )
        return run


@router.get("", response_model=list[VerificationResponse])
async def list_verifications(
    current_user: AuthUser = Depends(require_permission(Permission.VERIFICATION_READ)),
):
    """Lists verification runs scoped strictly to server-derived tenant organization."""
    db_mgr = DatabaseManager()
    with db_mgr.get_session() as session:
        db_mgr.set_tenant_context(session, current_user.organization_id)

        stmt = select(VerificationRunModel).where(
            VerificationRunModel.organization_id == current_user.organization_id
        )
        runs = session.scalars(stmt).all()
        return list(runs)
