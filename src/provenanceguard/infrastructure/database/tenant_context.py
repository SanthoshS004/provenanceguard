"""Tenant Context Value Object & Lifecycle Module for ProvenanceGuard.

Defines `TenantContext` containing validated `organization_id` and optional `project_id`.
Provides 2-stage context initialization and project-tenant correlation validation.
"""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from provenanceguard.infrastructure.database.models import ProjectModel


class TenantSecurityError(Exception):
    """Raised when tenant security boundary or context validation fails."""

    pass


@dataclass(frozen=True)
class TenantContext:
    """Immutable value object representing active tenant context."""

    organization_id: UUID
    project_id: UUID | None = None

    def validate_project_ownership(self, session: Session) -> None:
        """Validates that project_id belongs to organization_id.

        Prevents `Organization A + Project B` context inconsistencies.
        """
        if self.project_id is None:
            return

        stmt = select(ProjectModel.organization_id).where(ProjectModel.id == self.project_id)
        result = session.scalar(stmt)
        if result is None:
            raise TenantSecurityError(f"Project '{self.project_id}' not found.")
        if result != self.organization_id:
            msg = f"Project '{self.project_id}' not in org '{self.organization_id}'."
            raise TenantSecurityError(msg)
