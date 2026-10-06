"""REST API Projects Route Module for ProvenanceGuard.

Exposes project discovery endpoints for the authenticated tenant organization.
Enforces VERIFICATION_READ permission and server-derived TenantContext isolation.
"""

from __future__ import annotations

import datetime
from uuid import UUID

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict

from provenanceguard.apps.api.auth import AuthUser, require_permission
from provenanceguard.apps.api.rbac import Permission
from provenanceguard.infrastructure.database.repositories import ProjectRepository
from provenanceguard.infrastructure.database.session import DatabaseManager
from provenanceguard.infrastructure.database.tenant_context import TenantContext

router = APIRouter(prefix="/api/v1/projects", tags=["projects"])


class ProjectResponse(BaseModel):
    id: UUID
    organization_id: UUID
    name: str
    created_at: datetime.datetime

    model_config = ConfigDict(extra="ignore", from_attributes=True)


@router.get("", response_model=list[ProjectResponse])
async def list_projects(
    current_user: AuthUser = Depends(require_permission(Permission.VERIFICATION_READ)),
):
    """Lists all projects belonging to the authenticated user's organization."""
    tenant_ctx = TenantContext(
        organization_id=current_user.organization_id,
        project_id=getattr(current_user, "project_id", None),
    )
    db_mgr = DatabaseManager()
    with db_mgr.get_session() as session:
        db_mgr.set_tenant_context(session, current_user.organization_id)
        repo = ProjectRepository(tenant_ctx)
        projects = repo.list_by_organization(session)
        return [ProjectResponse.model_validate(p) for p in projects]
