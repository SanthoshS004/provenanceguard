"""REST API Route Handlers for Artifact Ingestion & Inspection."""

import datetime
import os
import uuid
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select

from provenanceguard.apps.api.auth import AuthUser, require_permission
from provenanceguard.apps.api.rbac import Permission
from provenanceguard.core.artifacts.ingestion import ingest_artifact
from provenanceguard.core.domain.exceptions import IngestionRejectedError
from provenanceguard.infrastructure.database.models import ArtifactModel, OrganizationModel, ProjectModel
from provenanceguard.infrastructure.database.repositories import (
    ArtifactRepository,
    AuditLogRepository,
    ProjectRepository,
)
from provenanceguard.infrastructure.database.session import DatabaseManager
from provenanceguard.infrastructure.database.tenant_context import TenantContext
from provenanceguard.infrastructure.storage.filesystem import FilesystemStorageDriver
from provenanceguard.infrastructure.storage.s3 import MinIOStorageDriver

router = APIRouter(prefix="/api/v1/artifacts", tags=["artifacts"])


class ArtifactResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    project_id: uuid.UUID
    name: str
    version: str
    media_type: str
    digest_sha256: str
    size_bytes: int
    storage_path: str
    created_at: datetime.datetime

    model_config = ConfigDict(extra="ignore", from_attributes=True)


def get_storage_driver():
    """Factory creating MinIOStorageDriver with safe local Filesystem fallback."""
    endpoint = os.getenv("PG_MINIO_ENDPOINT", "localhost:9000")
    access_key = os.getenv("PG_MINIO_ACCESS_KEY", "minioadmin")
    secret_key = os.getenv("PG_MINIO_SECRET_KEY", "minioadminpassword")
    bucket_name = os.getenv("PG_MINIO_BUCKET", "provenanceguard-artifacts")
    try:
        import socket
        host, port_str = endpoint.split(":") if ":" in endpoint else (endpoint, "9000")
        s = socket.create_connection((host, int(port_str)), timeout=1.0)
        s.close()

        driver = MinIOStorageDriver(
            endpoint=endpoint,
            access_key=access_key,
            secret_key=secret_key,
            bucket_name=bucket_name,
        )
        return driver
    except Exception:
        storage_dir = Path("scratch/storage")
        storage_dir.mkdir(parents=True, exist_ok=True)
        return FilesystemStorageDriver(storage_dir)


@router.post("/upload", response_model=ArtifactResponse, status_code=status.HTTP_201_CREATED)
async def upload_artifact(
    file: UploadFile = File(...),
    project_id: Optional[uuid.UUID] = Form(None),
    name: Optional[str] = Form(None),
    version: str = Form("1.0.0"),
    claimed_digest: Optional[str] = Form(None),
    current_user: AuthUser = Depends(require_permission(Permission.VERIFICATION_CREATE)),
):
    """Securely streams and ingests an untrusted software artifact payload."""
    org_id = current_user.organization_id
    db_mgr = DatabaseManager()

    # Enforce strict tenant & project validation
    with db_mgr.get_session() as db_session:
        db_mgr.set_tenant_context(db_session, org_id)

        if current_user.project_scope_id is not None:
            if project_id is not None and project_id != current_user.project_scope_id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Credential scope restricted to project '{current_user.project_scope_id}'.",
                )
            target_project_id = current_user.project_scope_id
        elif project_id is not None:
            proj_stmt = select(ProjectModel).where(
                ProjectModel.id == project_id,
                ProjectModel.organization_id == org_id,
            )
            proj = db_session.scalar(proj_stmt)
            if not proj:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Project '{project_id}' not found for tenant organization.",
                )
            target_project_id = project_id
        else:
            repo = ProjectRepository(TenantContext(organization_id=org_id))
            projects = repo.list_by_organization(db_session)
            if projects:
                target_project_id = projects[0].id
            else:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"No active project found for organization '{org_id}'. Please select or create a project first.",
                )

    artifact_name = name or file.filename or "artifact.bin"
    storage_driver = get_storage_driver()

    try:
        # Stream file payload into core ingestion pipeline
        domain_artifact = ingest_artifact(
            stream_or_path=file.file,
            organization_id=str(org_id),
            project_id=str(target_project_id),
            name=artifact_name,
            version=version,
            storage_driver=storage_driver,
            claimed_digest=claimed_digest,
        )
    except IngestionRejectedError as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Artifact ingestion rejected: {err.message}",
        ) from err
    except Exception as err:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to ingest artifact: {str(err)}",
        ) from err

    # Extract authoritative SHA-256 digest from domain artifact entity
    sha256_digest = next(
        (d.value for d in domain_artifact.digests if "SHA256" in str(d.algorithm).upper()),
        domain_artifact.digests[0].value if domain_artifact.digests else "",
    )

    db_mgr = DatabaseManager()
    tenant_ctx = TenantContext(organization_id=org_id, project_id=target_project_id)

    with db_mgr.get_session() as session:
        db_mgr.set_tenant_context(session, org_id)
        artifact_repo = ArtifactRepository(tenant_ctx)

        # Check if artifact already registered under (project_id, digest_sha256)
        existing = artifact_repo.get_by_digest(session, sha256_digest)
        if existing:
            artifact_model = existing
        else:
            artifact_model = artifact_repo.create_artifact(
                session=session,
                name=domain_artifact.name,
                version=domain_artifact.version,
                media_type=domain_artifact.media_type.value
                if hasattr(domain_artifact.media_type, "value")
                else str(domain_artifact.media_type),
                digest_sha256=sha256_digest,
                size_bytes=domain_artifact.size_bytes,
                storage_path=domain_artifact.storage_reference,
            )
            session.commit()

        # Audit Event Logging
        try:
            audit_repo = AuditLogRepository(tenant_ctx)
            audit_repo.log_event(
                session=session,
                actor_id=str(current_user.user_id),
                action="ARTIFACT_INGESTED",
                resource=f"artifact:{artifact_model.id}",
                result="SUCCESS",
                metadata_json={
                    "digest_sha256": sha256_digest,
                    "name": artifact_name,
                    "size_bytes": domain_artifact.size_bytes,
                },
            )
            session.commit()
        except Exception as e:
            print(f"[AUDIT LOG ERROR] {e}")

        return artifact_model


@router.get("", response_model=list[ArtifactResponse])
async def list_artifacts(
    current_user: AuthUser = Depends(require_permission(Permission.VERIFICATION_READ)),
):
    """Lists all artifacts belonging to caller's active tenant organization."""
    db_mgr = DatabaseManager()
    with db_mgr.get_session() as session:
        db_mgr.set_tenant_context(session, current_user.organization_id)
        stmt = (
            select(ArtifactModel)
            .where(ArtifactModel.organization_id == current_user.organization_id)
            .order_by(ArtifactModel.created_at.desc())
        )
        artifacts = session.scalars(stmt).all()
        return list(artifacts)
