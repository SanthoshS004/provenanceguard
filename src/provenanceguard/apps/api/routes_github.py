"""REST API Route Handlers for GitHub Build Artifact Ingestion & CI/CD Integrations."""

import datetime
import os
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select

from provenanceguard.apps.api.auth import AuthUser, require_permission
from provenanceguard.apps.api.rbac import Permission
from provenanceguard.core.artifacts.ingestion import ingest_artifact
from provenanceguard.core.domain.exceptions import IngestionRejectedError
from provenanceguard.infrastructure.database.models import (
    ArtifactModel,
    GitHubIntegrationModel,
    ProjectModel,
    VerificationRunModel,
)
from provenanceguard.infrastructure.database.outbox_repository import OutboxRepository
from provenanceguard.infrastructure.database.repositories import (
    ArtifactRepository,
    AuditLogRepository,
    ProjectRepository,
)
from provenanceguard.infrastructure.database.session import DatabaseManager
from provenanceguard.infrastructure.database.tenant_context import TenantContext
from provenanceguard.infrastructure.queue.arq_dispatcher import ARQTaskDispatcher
from provenanceguard.infrastructure.queue.dispatcher import JobPayload
from provenanceguard.infrastructure.storage.filesystem import FilesystemStorageDriver
from provenanceguard.infrastructure.storage.s3 import MinIOStorageDriver
from provenanceguard.integrations.github.service import (
    GitHubAuthenticationError,
    GitHubIntegrationError,
    GitHubIntegrationService,
    GitHubResourceNotFoundError,
)

router = APIRouter(prefix="/api/v1/ci/github", tags=["github-ci"])


class GitHubConfigRequest(BaseModel):
    repository: str
    default_branch: str = "main"
    project_id: Optional[uuid.UUID] = None

    model_config = ConfigDict(extra="forbid")


def get_storage_driver():
    """Factory creating MinIOStorageDriver with safe local Filesystem fallback."""
    endpoint = os.getenv("PG_MINIO_ENDPOINT", "localhost:9000")
    access_key = os.getenv("PG_MINIO_ACCESS_KEY", "minioadmin")
    secret_key = os.getenv("PG_MINIO_SECRET_KEY", "minioadminpassword")
    bucket_name = os.getenv("PG_MINIO_BUCKET", "provenanceguard-artifacts")
    try:
        driver = MinIOStorageDriver(
            endpoint=endpoint,
            access_key=access_key,
            secret_key=secret_key,
            bucket_name=bucket_name,
        )
        return driver
    except Exception:
        from pathlib import Path
        storage_dir = Path("scratch/storage")
        return FilesystemStorageDriver(storage_dir)


async def in_transaction_dispatch_verification(
    session, tenant_ctx: TenantContext, org_id: uuid.UUID, project_id: uuid.UUID, artifact_id: uuid.UUID
) -> str:
    """Helper creating VerificationRun, Outbox Event, and Redis dispatch."""
    run_id = uuid.uuid4()
    run = VerificationRunModel(
        id=run_id,
        organization_id=org_id,
        project_id=project_id,
        production_artifact_id=artifact_id,
        reference_artifact_id=None,
        status="QUEUED",
        decision="PENDING",
        risk_score=0,
        attempt_count=1,
    )
    session.add(run)
    session.flush()

    payload = JobPayload(
        verification_run_id=run_id,
        organization_id=org_id,
        project_id=project_id,
        attempt=1,
    )

    outbox_repo = OutboxRepository(tenant_context=tenant_ctx)
    outbox_event = outbox_repo.create_event(
        session=session,
        aggregate_type="VerificationRun",
        aggregate_id=run_id,
        project_id=project_id,
        event_type="VERIFICATION_REQUESTED",
        payload_dict=payload.model_dump(mode="json"),
    )
    session.commit()

    try:
        dispatcher = ARQTaskDispatcher()
        await dispatcher.dispatch_verification_job(payload)
        outbox_repo.mark_dispatched(session, outbox_event.id)
        session.commit()
    except Exception:
        pass

    return str(run_id)


@router.post("/artifacts", status_code=status.HTTP_201_CREATED)
async def push_github_artifact(
    file: UploadFile = File(...),
    project_id: Optional[uuid.UUID] = Form(None),
    name: Optional[str] = Form(None),
    version: str = Form("1.0.0"),
    claimed_digest: Optional[str] = Form(None),
    repository: Optional[str] = Form(None),
    branch: Optional[str] = Form(None),
    commit_sha: Optional[str] = Form(None),
    workflow_run_id: Optional[str] = Form(None),
    workflow_name: Optional[str] = Form(None),
    build_number: Optional[str] = Form(None),
    artifact_type: str = Form("BUILD_ARTIFACT"),
    current_user: AuthUser = Depends(require_permission(Permission.VERIFICATION_CREATE)),
):
    """PRIMARY PUSH ROUTE: GitHub Actions uploads compiled build artifact + Git metadata."""
    org_id = current_user.organization_id
    db_mgr = DatabaseManager()

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
                    detail=f"Project '{project_id}' not found.",
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
                    detail="No active project found for tenant organization.",
                )

    artifact_name = name or file.filename or "build-artifact.bin"
    storage_driver = get_storage_driver()

    try:
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

    sha256_digest = next(
        (d.value for d in domain_artifact.digests if "SHA256" in str(d.algorithm).upper()),
        domain_artifact.digests[0].value if domain_artifact.digests else "",
    )

    tenant_ctx = TenantContext(organization_id=org_id, project_id=target_project_id)

    with db_mgr.get_session() as session:
        db_mgr.set_tenant_context(session, org_id)
        artifact_repo = ArtifactRepository(tenant_ctx)

        existing = artifact_repo.get_by_digest(session, sha256_digest)
        if existing:
            artifact_model = existing
            if repository:
                artifact_model.git_repository = repository
            if branch:
                artifact_model.git_branch = branch
            if commit_sha:
                artifact_model.git_commit_sha = commit_sha
            if workflow_run_id:
                artifact_model.git_workflow_run_id = workflow_run_id
            if workflow_name:
                artifact_model.git_workflow_name = workflow_name
            if build_number:
                artifact_model.git_build_number = build_number
            session.commit()
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
                git_repository=repository,
                git_branch=branch,
                git_commit_sha=commit_sha,
                git_workflow_run_id=workflow_run_id,
                git_workflow_name=workflow_name,
                git_build_number=build_number,
                artifact_type=artifact_type,
            )
            session.commit()

        # Audit Event Logging
        try:
            audit_repo = AuditLogRepository(tenant_ctx)
            audit_repo.log_event(
                session=session,
                actor_id=str(current_user.user_id),
                action="GITHUB_ARTIFACT_COLLECTED",
                resource=f"artifact:{artifact_model.id}",
                result="SUCCESS",
                metadata_json={
                    "mode": "PUSH",
                    "digest_sha256": sha256_digest,
                    "repository": repository,
                    "branch": branch,
                    "commit_sha": commit_sha,
                    "workflow_run_id": workflow_run_id,
                },
            )
            session.commit()
        except Exception as e:
            print(f"[AUDIT LOG ERROR] {e}")

        # Dispatch verification run
        run_id_str = await in_transaction_dispatch_verification(
            session=session,
            tenant_ctx=tenant_ctx,
            org_id=org_id,
            project_id=target_project_id,
            artifact_id=artifact_model.id,
        )

        return {
            "artifact_id": str(artifact_model.id),
            "verification_run_id": run_id_str,
            "commit_sha": commit_sha,
            "digest_sha256": sha256_digest,
            "status": "QUEUED",
        }


@router.post("/config")
async def configure_github_integration(
    req: GitHubConfigRequest,
    current_user: AuthUser = Depends(require_permission(Permission.POLICY_MANAGE)),
):
    """Configures GitHub repository settings for tenant organization."""
    org_id = current_user.organization_id
    db_mgr = DatabaseManager()

    if "/" not in req.repository:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Repository name must be in 'owner/repository' format.",
        )

    with db_mgr.get_session() as session:
        db_mgr.set_tenant_context(session, org_id)

        target_project_id = req.project_id
        if not target_project_id:
            repo = ProjectRepository(TenantContext(organization_id=org_id))
            projects = repo.list_by_organization(session)
            if not projects:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="No project found for organization.",
                )
            target_project_id = projects[0].id

        stmt = select(GitHubIntegrationModel).where(
            GitHubIntegrationModel.organization_id == org_id,
            GitHubIntegrationModel.project_id == target_project_id,
        )
        existing = session.scalar(stmt)
        if existing:
            existing.repository = req.repository
            existing.default_branch = req.default_branch
            existing.updated_at = datetime.datetime.now(datetime.timezone.utc)
            config_model = existing
        else:
            config_model = GitHubIntegrationModel(
                organization_id=org_id,
                project_id=target_project_id,
                repository=req.repository,
                default_branch=req.default_branch,
            )
            session.add(config_model)
        session.commit()

        # Audit Event Logging
        try:
            tenant_ctx = TenantContext(organization_id=org_id, project_id=target_project_id)
            audit_repo = AuditLogRepository(tenant_ctx)
            audit_repo.log_event(
                session=session,
                actor_id=str(current_user.user_id),
                action="GITHUB_REPOSITORY_VALIDATED",
                resource=f"github_integration:{config_model.id}",
                result="SUCCESS",
                metadata_json={
                    "repository": req.repository,
                    "branch": req.default_branch,
                },
            )
            session.commit()
        except Exception as e:
            print(f"[AUDIT LOG ERROR] {e}")

        return {
            "status": "CONFIGURED",
            "repository": config_model.repository,
            "default_branch": config_model.default_branch,
        }


@router.get("/status")
async def get_github_integration_status(
    current_user: AuthUser = Depends(require_permission(Permission.VERIFICATION_READ)),
):
    """Returns repository connection status, latest commit, workflow run, and verification decision."""
    org_id = current_user.organization_id
    db_mgr = DatabaseManager()

    token_configured = bool(os.getenv("GITHUB_TOKEN", "").strip())
    gh_service = GitHubIntegrationService()

    with db_mgr.get_session() as session:
        db_mgr.set_tenant_context(session, org_id)

        stmt = select(GitHubIntegrationModel).where(
            GitHubIntegrationModel.organization_id == org_id
        ).order_by(GitHubIntegrationModel.updated_at.desc())
        integration = session.scalar(stmt)

        repo_name = integration.repository if integration else os.getenv("GITHUB_REPOSITORY", "owner/repository")
        branch_name = integration.default_branch if integration else os.getenv("GITHUB_BRANCH", "main")

        # Get latest GitHub artifact from DB
        art_stmt = (
            select(ArtifactModel)
            .where(
                ArtifactModel.organization_id == org_id,
                ArtifactModel.git_repository.isnot(None),
            )
            .order_by(ArtifactModel.created_at.desc())
        )
        latest_artifact = session.scalar(art_stmt)

        latest_run = None
        if latest_artifact:
            run_stmt = select(VerificationRunModel).where(
                VerificationRunModel.production_artifact_id == latest_artifact.id
            ).order_by(VerificationRunModel.created_at.desc())
            latest_run = session.scalar(run_stmt)

        status_info = {
            "token_configured": token_configured,
            "connection_status": "CONNECTED" if token_configured else "NO_GITHUB_TOKEN",
            "repository": repo_name,
            "branch": branch_name,
            "latest_commit_sha": latest_artifact.git_commit_sha if latest_artifact else None,
            "workflow_name": latest_artifact.git_workflow_name if latest_artifact else None,
            "workflow_run_id": latest_artifact.git_workflow_run_id if latest_artifact else None,
            "artifact_name": latest_artifact.name if latest_artifact else None,
            "artifact_collection_status": "COLLECTED" if latest_artifact else "IDLE",
            "verification_status": latest_run.status if latest_run else "NONE",
            "verification_decision": latest_run.decision if latest_run else "NONE",
            "risk_score": latest_run.risk_score if latest_run else 0,
            "verification_run_id": str(latest_run.id) if latest_run else None,
        }

        # Try live GitHub API status if token is present
        if token_configured and repo_name != "owner/repository":
            try:
                commit_info = gh_service.get_latest_commit(repo_name, branch_name)
                status_info["latest_commit_sha"] = commit_info["sha"]
                status_info["commit_message"] = commit_info["message"]
                status_info["connection_status"] = "CONNECTED"
            except GitHubResourceNotFoundError:
                status_info["connection_status"] = "REPOSITORY_NOT_FOUND"
            except GitHubAuthenticationError:
                status_info["connection_status"] = "INVALID_GITHUB_TOKEN"
            except Exception:
                pass

        return status_info


@router.post("/collect", status_code=status.HTTP_201_CREATED)
async def pull_github_artifact(
    current_user: AuthUser = Depends(require_permission(Permission.VERIFICATION_CREATE)),
):
    """SECONDARY PULL ROUTE: Pulls build artifact directly from GitHub API."""
    org_id = current_user.organization_id
    db_mgr = DatabaseManager()

    token = os.getenv("GITHUB_TOKEN", "").strip()
    if not token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="NO_GITHUB_TOKEN: GITHUB_TOKEN environment variable is not configured for PULL mode.",
        )

    gh_service = GitHubIntegrationService(token=token)

    with db_mgr.get_session() as session:
        db_mgr.set_tenant_context(session, org_id)

        stmt = select(GitHubIntegrationModel).where(
            GitHubIntegrationModel.organization_id == org_id
        ).order_by(GitHubIntegrationModel.updated_at.desc())
        integration = session.scalar(stmt)

        repo = integration.repository if integration else os.getenv("GITHUB_REPOSITORY")
        branch = integration.default_branch if integration else os.getenv("GITHUB_BRANCH", "main")

        if not repo or "/" not in repo:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="REPOSITORY_NOT_FOUND: Please configure a valid GitHub repository first.",
            )

        repo_proj_id = integration.project_id if integration else None
        if not repo_proj_id:
            projects = ProjectRepository(TenantContext(organization_id=org_id)).list_by_organization(session)
            if not projects:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No project found.")
            repo_proj_id = projects[0].id

    try:
        commit_info = gh_service.get_latest_commit(repo, branch)
        workflow_run = gh_service.get_latest_workflow_run(repo, branch)
        artifacts_list = gh_service.get_workflow_artifacts(repo, workflow_run["id"])
        
        target_art_id = artifacts_list[0]["id"]
        file_bytes, filename = gh_service.download_and_extract_artifact(repo, target_art_id)
    except GitHubResourceNotFoundError as err:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err)) from err
    except GitHubAuthenticationError as err:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(err)) from err
    except Exception as err:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"DOWNLOAD_FAILED: {str(err)}") from err

    import io
    file_stream = io.BytesIO(file_bytes)
    storage_driver = get_storage_driver()

    try:
        domain_artifact = ingest_artifact(
            stream_or_path=file_stream,
            organization_id=str(org_id),
            project_id=str(repo_proj_id),
            name=filename,
            version="1.0.0",
            storage_driver=storage_driver,
        )
    except Exception as err:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Artifact ingestion failed: {str(err)}") from err

    sha256_digest = next(
        (d.value for d in domain_artifact.digests if "SHA256" in str(d.algorithm).upper()),
        domain_artifact.digests[0].value if domain_artifact.digests else "",
    )

    tenant_ctx = TenantContext(organization_id=org_id, project_id=repo_proj_id)

    with db_mgr.get_session() as session:
        db_mgr.set_tenant_context(session, org_id)
        artifact_repo = ArtifactRepository(tenant_ctx)

        existing = artifact_repo.get_by_digest(session, sha256_digest)
        if existing:
            artifact_model = existing
        else:
            artifact_model = artifact_repo.create_artifact(
                session=session,
                name=domain_artifact.name,
                version=domain_artifact.version,
                media_type="application/octet-stream",
                digest_sha256=sha256_digest,
                size_bytes=domain_artifact.size_bytes,
                storage_path=domain_artifact.storage_reference,
                git_repository=repo,
                git_branch=branch,
                git_commit_sha=commit_info["sha"],
                git_workflow_run_id=workflow_run["id"],
                git_workflow_name=workflow_run["name"],
                git_build_number=workflow_run["run_number"],
                artifact_type="BUILD_ARTIFACT",
            )
            session.commit()

        # Audit Event Logging
        try:
            audit_repo = AuditLogRepository(tenant_ctx)
            audit_repo.log_event(
                session=session,
                actor_id=str(current_user.user_id),
                action="GITHUB_ARTIFACT_COLLECTED",
                resource=f"artifact:{artifact_model.id}",
                result="SUCCESS",
                metadata_json={
                    "mode": "PULL",
                    "digest_sha256": sha256_digest,
                    "repository": repo,
                    "branch": branch,
                    "commit_sha": commit_info["sha"],
                    "workflow_run_id": workflow_run["id"],
                },
            )
            session.commit()
        except Exception as e:
            print(f"[AUDIT LOG ERROR] {e}")

        # Dispatch verification
        run_id_str = await in_transaction_dispatch_verification(
            session=session,
            tenant_ctx=tenant_ctx,
            org_id=org_id,
            project_id=repo_proj_id,
            artifact_id=artifact_model.id,
        )

        return {
            "artifact_id": str(artifact_model.id),
            "verification_run_id": run_id_str,
            "commit_sha": commit_info["sha"],
            "digest_sha256": sha256_digest,
            "status": "QUEUED",
        }


@router.post("/demo-collect", status_code=status.HTTP_201_CREATED)
async def demo_collect_github_artifact(
    current_user: AuthUser = Depends(require_permission(Permission.VERIFICATION_CREATE)),
):
    """LOCAL DEMONSTRATION MODE: Collects safe demo fixture through full real verification pipeline."""
    org_id = current_user.organization_id
    db_mgr = DatabaseManager()

    gh_service = GitHubIntegrationService()
    file_bytes, filename, git_meta = gh_service.demo_collect_artifact()

    with db_mgr.get_session() as session:
        db_mgr.set_tenant_context(session, org_id)
        projects = ProjectRepository(TenantContext(organization_id=org_id)).list_by_organization(session)
        if not projects:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No active project found for tenant.")
        target_project_id = projects[0].id

    import io
    file_stream = io.BytesIO(file_bytes)
    storage_driver = get_storage_driver()

    try:
        domain_artifact = ingest_artifact(
            stream_or_path=file_stream,
            organization_id=str(org_id),
            project_id=str(target_project_id),
            name=filename,
            version="1.0.0-demo",
            storage_driver=storage_driver,
        )
    except Exception as err:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Demo artifact ingestion failed: {str(err)}",
        ) from err

    sha256_digest = next(
        (d.value for d in domain_artifact.digests if "SHA256" in str(d.algorithm).upper()),
        domain_artifact.digests[0].value if domain_artifact.digests else "",
    )

    tenant_ctx = TenantContext(organization_id=org_id, project_id=target_project_id)

    with db_mgr.get_session() as session:
        db_mgr.set_tenant_context(session, org_id)
        artifact_repo = ArtifactRepository(tenant_ctx)

        existing = artifact_repo.get_by_digest(session, sha256_digest)
        if existing:
            artifact_model = existing
        else:
            artifact_model = artifact_repo.create_artifact(
                session=session,
                name=domain_artifact.name,
                version=domain_artifact.version,
                media_type="application/x-elf",
                digest_sha256=sha256_digest,
                size_bytes=domain_artifact.size_bytes,
                storage_path=domain_artifact.storage_reference,
                git_repository=git_meta["repository"],
                git_branch=git_meta["branch"],
                git_commit_sha=git_meta["commit_sha"],
                git_workflow_run_id=git_meta["workflow_run_id"],
                git_workflow_name=git_meta["workflow_name"],
                git_build_number=git_meta["build_number"],
                artifact_type="BUILD_ARTIFACT",
            )
            session.commit()

        # Audit Event Logging
        try:
            audit_repo = AuditLogRepository(tenant_ctx)
            audit_repo.log_event(
                session=session,
                actor_id=str(current_user.user_id),
                action="GITHUB_ARTIFACT_COLLECTED",
                resource=f"artifact:{artifact_model.id}",
                result="SUCCESS",
                metadata_json={
                    "mode": "DEMO",
                    "digest_sha256": sha256_digest,
                    "repository": git_meta["repository"],
                    "branch": git_meta["branch"],
                    "commit_sha": git_meta["commit_sha"],
                    "workflow_run_id": git_meta["workflow_run_id"],
                },
            )
            session.commit()
        except Exception as e:
            print(f"[AUDIT LOG ERROR] {e}")

        # Dispatch verification
        run_id_str = await in_transaction_dispatch_verification(
            session=session,
            tenant_ctx=tenant_ctx,
            org_id=org_id,
            project_id=target_project_id,
            artifact_id=artifact_model.id,
        )

        return {
            "artifact_id": str(artifact_model.id),
            "verification_run_id": run_id_str,
            "commit_sha": git_meta["commit_sha"],
            "digest_sha256": sha256_digest,
            "status": "QUEUED",
            "is_demo": True,
        }
