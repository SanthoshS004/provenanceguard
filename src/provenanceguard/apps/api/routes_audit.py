"""REST API Audit Log Stream Route Module for ProvenanceGuard.

Exposes bounded, filterable audit log streams for security auditors.
Enforces AUDIT_READ permission, server-side pagination limits, and append-only immutability.
"""

from __future__ import annotations

import datetime
from typing import Any, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, ConfigDict

from provenanceguard.apps.api.auth import AuthUser, require_permission
from provenanceguard.apps.api.rbac import Permission
from provenanceguard.infrastructure.database.repositories import AuditLogRepository
from provenanceguard.infrastructure.database.session import DatabaseManager
from provenanceguard.infrastructure.database.tenant_context import TenantContext

router = APIRouter(prefix="/api/v1/audit-log", tags=["audit-log"])


class AuditLogResponse(BaseModel):
    id: UUID
    organization_id: UUID
    actor_id: str
    action: str
    resource: str
    result: str
    created_at: datetime.datetime
    sequence_number: int = 1
    previous_hash: str = "0000000000000000000000000000000000000000000000000000000000000000"
    current_hash: str = "0000000000000000000000000000000000000000000000000000000000000000"
    metadata_json: Optional[dict[str, Any]] = None

    model_config = ConfigDict(extra="ignore", from_attributes=True)


class AuditLogPageResponse(BaseModel):
    items: list[AuditLogResponse]
    total: int
    limit: int
    offset: int


@router.get("", response_model=AuditLogPageResponse)
async def query_audit_logs(
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    action: Optional[str] = Query(default=None, max_length=100),
    resource: Optional[str] = Query(default=None, max_length=255),
    actor_id: Optional[str] = Query(default=None, max_length=255),
    current_user: AuthUser = Depends(require_permission(Permission.AUDIT_READ)),
):
    """Query bounded, filterable audit log stream for caller's active organization."""
    tenant_ctx = TenantContext(
        organization_id=current_user.organization_id,
        project_id=getattr(current_user, "project_id", None),
    )
    db_mgr = DatabaseManager()
    with db_mgr.get_session() as session:
        db_mgr.set_tenant_context(session, current_user.organization_id)
        repo = AuditLogRepository(tenant_ctx)
        items, total = repo.query_events(
            session=session,
            limit=limit,
            offset=offset,
            action=action,
            resource=resource,
            actor_id=actor_id,
        )
        return AuditLogPageResponse(
            items=[AuditLogResponse.model_validate(it) for it in items],
            total=total,
            limit=min(limit, 100),
            offset=offset,
        )
