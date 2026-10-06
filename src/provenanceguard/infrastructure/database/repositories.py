"""Repository & Data Access Layer Module for ProvenanceGuard.

Implements repositories scoped strictly by `TenantContext` for Organizations,
Projects, Artifacts, VerificationRuns, Findings, and AuditLogs.
Enforces audit immutability, metadata sanitization, and ownership integrity.
"""

from __future__ import annotations

import logging
from typing import Any, Sequence
from uuid import UUID

from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from provenanceguard.core.domain.audit import (
    GENESIS_PREVIOUS_HASH,
    canonicalize_audit_entry,
    compute_audit_hash,
)
from provenanceguard.infrastructure.database.models import (
    ArtifactModel,
    AuditLogModel,
    FindingModel,
    OrganizationModel,
    ProjectModel,
    VerificationRunModel,
    utc_now,
)
from provenanceguard.infrastructure.database.tenant_context import (
    TenantContext,
    TenantSecurityError,
)

logger = logging.getLogger(__name__)


class AuditImmutabilityError(Exception):
    """Raised when an attempt is made to update or delete audit log entries."""

    pass


class BaseRepository:
    """Base repository enforcing TenantContext validation."""

    def __init__(self, tenant_context: TenantContext) -> None:
        self.tenant_ctx = tenant_context


class OrganizationRepository:
    """Repository for Organization operations."""

    def create_organization(self, session: Session, name: str, slug: str) -> OrganizationModel:
        org = OrganizationModel(name=name, slug=slug)
        session.add(org)
        session.flush()
        return org

    def get_by_id(
        self, session: Session, tenant_ctx: TenantContext, org_id: UUID
    ) -> OrganizationModel | None:
        if tenant_ctx.organization_id != org_id:
            return None
        return session.scalar(select(OrganizationModel).where(OrganizationModel.id == org_id))


class ProjectRepository(BaseRepository):
    """Repository for Project operations scoped by TenantContext."""

    def create_project(self, session: Session, name: str) -> ProjectModel:
        project = ProjectModel(organization_id=self.tenant_ctx.organization_id, name=name)
        session.add(project)
        session.flush()
        return project

    def get_by_id(self, session: Session, project_id: UUID) -> ProjectModel | None:
        stmt = select(ProjectModel).where(
            ProjectModel.id == project_id,
            ProjectModel.organization_id == self.tenant_ctx.organization_id,
        )
        return session.scalar(stmt)

    def list_by_organization(self, session: Session) -> Sequence[ProjectModel]:
        """List all projects belonging to caller's active organization ID."""
        stmt = (
            select(ProjectModel)
            .where(ProjectModel.organization_id == self.tenant_ctx.organization_id)
            .order_by(ProjectModel.created_at.desc())
        )
        return session.scalars(stmt).all()


class ArtifactRepository(BaseRepository):
    """Repository for Artifact operations scoped by TenantContext."""

    def create_artifact(
        self,
        session: Session,
        name: str,
        version: str,
        media_type: str,
        digest_sha256: str,
        size_bytes: int,
        storage_path: str,
        git_repository: str | None = None,
        git_branch: str | None = None,
        git_commit_sha: str | None = None,
        git_workflow_run_id: str | None = None,
        git_workflow_name: str | None = None,
        git_build_number: str | None = None,
        artifact_type: str = "BUILD_ARTIFACT",
    ) -> ArtifactModel:
        if self.tenant_ctx.project_id is None:
            raise TenantSecurityError(
                "project_id is required in TenantContext to create an artifact."
            )

        artifact = ArtifactModel(
            organization_id=self.tenant_ctx.organization_id,
            project_id=self.tenant_ctx.project_id,
            name=name,
            version=version,
            media_type=media_type,
            digest_sha256=digest_sha256,
            size_bytes=size_bytes,
            storage_path=storage_path,
            git_repository=git_repository,
            git_branch=git_branch,
            git_commit_sha=git_commit_sha,
            git_workflow_run_id=git_workflow_run_id,
            git_workflow_name=git_workflow_name,
            git_build_number=git_build_number,
            artifact_type=artifact_type,
        )
        session.add(artifact)
        session.flush()
        return artifact

    def get_by_digest(self, session: Session, digest_sha256: str) -> ArtifactModel | None:
        if self.tenant_ctx.project_id is None:
            stmt = select(ArtifactModel).where(
                ArtifactModel.digest_sha256 == digest_sha256,
                ArtifactModel.organization_id == self.tenant_ctx.organization_id,
            )
        else:
            stmt = select(ArtifactModel).where(
                ArtifactModel.digest_sha256 == digest_sha256,
                ArtifactModel.project_id == self.tenant_ctx.project_id,
                ArtifactModel.organization_id == self.tenant_ctx.organization_id,
            )
        return session.scalar(stmt)


class VerificationRunRepository(BaseRepository):
    """Repository for VerificationRun operations with project cross-reference validation."""

    def create_run(
        self,
        session: Session,
        production_artifact_id: UUID,
        reference_artifact_id: UUID | None,
        status: str,
        decision: str,
        risk_score: int,
        findings: Sequence[dict[str, Any]] | None = None,
    ) -> VerificationRunModel:
        if self.tenant_ctx.project_id is None:
            raise TenantSecurityError(
                "project_id is required in TenantContext to create a verification run."
            )

        # Verify production artifact belongs to active project and organization
        prod_art = session.scalar(
            select(ArtifactModel).where(
                ArtifactModel.id == production_artifact_id,
                ArtifactModel.project_id == self.tenant_ctx.project_id,
                ArtifactModel.organization_id == self.tenant_ctx.organization_id,
            )
        )
        if prod_art is None:
            msg = f"Prod artifact '{production_artifact_id}' invalid."
            raise TenantSecurityError(msg)

        # Verify reference artifact belongs to active project and organization if present
        if reference_artifact_id is not None:
            ref_art = session.scalar(
                select(ArtifactModel).where(
                    ArtifactModel.id == reference_artifact_id,
                    ArtifactModel.project_id == self.tenant_ctx.project_id,
                    ArtifactModel.organization_id == self.tenant_ctx.organization_id,
                )
            )
            if ref_art is None:
                msg = f"Ref artifact '{reference_artifact_id}' invalid."
                raise TenantSecurityError(msg)

        run = VerificationRunModel(
            organization_id=self.tenant_ctx.organization_id,
            project_id=self.tenant_ctx.project_id,
            production_artifact_id=production_artifact_id,
            reference_artifact_id=reference_artifact_id,
            status=status,
            decision=decision,
            risk_score=risk_score,
        )
        session.add(run)
        session.flush()

        if findings:
            for item in findings:
                finding = FindingModel(
                    verification_run_id=run.id,
                    organization_id=self.tenant_ctx.organization_id,
                    severity=item.get("severity", "MEDIUM"),
                    category=item.get("category", "UNKNOWN"),
                    explanation=item.get("explanation", ""),
                    remediation=item.get("remediation"),
                    details_json=item.get("details_json"),
                )
                session.add(finding)
            session.flush()

        return run


class AuditLogRepository(BaseRepository):
    """Repository for AuditLog operations. Append/INSERT only."""

    _SENSITIVE_KEYS = {"password", "secret", "token", "key", "api_key", "credential"}

    def _sanitize_metadata(self, metadata: dict[str, Any] | None) -> dict[str, Any] | None:
        if not metadata:
            return metadata

        clean_meta = {}
        for k, v in metadata.items():
            if any(s in k.lower() for s in self._SENSITIVE_KEYS):
                clean_meta[k] = "[REDACTED]"
            elif isinstance(v, dict):
                clean_meta[k] = self._sanitize_metadata(v)
            else:
                clean_meta[k] = v
        return clean_meta

    def log_event(
        self,
        session: Session,
        actor_id: str,
        action: str,
        resource: str,
        result: str,
        metadata_json: dict[str, Any] | None = None,
    ) -> AuditLogModel:
        sanitized_meta = self._sanitize_metadata(metadata_json)
        org_id = self.tenant_ctx.organization_id

        # Organization advisory lock for Postgres to serialize concurrent audit appends
        try:
            if session.bind and session.bind.dialect.name == "postgresql":
                lock_key = int(org_id.int & 0x7FFFFFFFFFFFFFFF)
                session.execute(func.pg_advisory_xact_lock(lock_key))
        except Exception:
            pass

        # Query last audit entry for organization to find last sequence_number and current_hash
        stmt = (
            select(AuditLogModel)
            .where(AuditLogModel.organization_id == org_id)
            .order_by(desc(AuditLogModel.sequence_number))
            .limit(1)
        )
        last_event = session.scalar(stmt)

        if last_event:
            new_seq = last_event.sequence_number + 1
            prev_hash = last_event.current_hash
        else:
            new_seq = 1
            prev_hash = GENESIS_PREVIOUS_HASH

        now_utc = utc_now()
        clean_actor = actor_id[:255]
        clean_action = action[:100]
        clean_resource = resource[:255]
        clean_result = result[:50]

        canonical_bytes = canonicalize_audit_entry(
            version="1",
            sequence_number=new_seq,
            previous_hash=prev_hash,
            organization_id=org_id,
            actor_id=clean_actor,
            action=clean_action,
            resource=clean_resource,
            result=clean_result,
            timestamp_utc=now_utc,
            metadata_json=sanitized_meta,
        )
        curr_hash = compute_audit_hash(canonical_bytes)

        audit_entry = AuditLogModel(
            organization_id=org_id,
            sequence_number=new_seq,
            actor_id=clean_actor,
            action=clean_action,
            resource=clean_resource,
            result=clean_result,
            previous_hash=prev_hash,
            current_hash=curr_hash,
            metadata_json=sanitized_meta,
            created_at=now_utc,
        )
        session.add(audit_entry)
        session.flush()
        return audit_entry

    def query_events(
        self,
        session: Session,
        limit: int = 20,
        offset: int = 0,
        action: str | None = None,
        resource: str | None = None,
        actor_id: str | None = None,
    ) -> tuple[Sequence[AuditLogModel], int]:
        """Queries audit log events with bounded pagination and optional filtering."""
        bounded_limit = min(max(1, limit), 100)
        bounded_offset = max(0, offset)

        base_stmt = select(AuditLogModel).where(
            AuditLogModel.organization_id == self.tenant_ctx.organization_id
        )
        count_stmt = (
            select(func.count())
            .select_from(AuditLogModel)
            .where(AuditLogModel.organization_id == self.tenant_ctx.organization_id)
        )

        if action:
            base_stmt = base_stmt.where(AuditLogModel.action == action)
            count_stmt = count_stmt.where(AuditLogModel.action == action)
        if resource:
            base_stmt = base_stmt.where(AuditLogModel.resource.contains(resource))
            count_stmt = count_stmt.where(AuditLogModel.resource.contains(resource))
        if actor_id:
            base_stmt = base_stmt.where(AuditLogModel.actor_id == actor_id)
            count_stmt = count_stmt.where(AuditLogModel.actor_id == actor_id)

        total = session.scalar(count_stmt) or 0
        items_stmt = (
            base_stmt.order_by(desc(AuditLogModel.created_at))
            .limit(bounded_limit)
            .offset(bounded_offset)
        )
        items = session.scalars(items_stmt).all()

        return items, total

    def update(self, *args: Any, **kwargs: Any) -> None:
        """UPDATE on audit logs is strictly prohibited."""
        raise AuditImmutabilityError("UPDATE operations on audit_logs are prohibited by NFR-006.")

    def delete(self, *args: Any, **kwargs: Any) -> None:
        """DELETE on audit logs is strictly prohibited."""
        raise AuditImmutabilityError("DELETE operations on audit_logs are prohibited by NFR-006.")
