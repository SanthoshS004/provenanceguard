"""Integration tests for GitHub CI/CD build artifact ingestion, PUSH/PULL workflows, and API routes."""

import os
import uuid
import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch
from sqlalchemy import select

from provenanceguard.apps.api.auth import mint_dev_token
from provenanceguard.apps.api.main import app
from provenanceguard.apps.api.rbac import Role
from provenanceguard.infrastructure.database.models import (
    ArtifactModel,
    AuditLogModel,
    GitHubIntegrationModel,
    OrganizationModel,
    ProjectModel,
    VerificationRunModel,
)
from provenanceguard.infrastructure.database.session import Base, DatabaseManager


@pytest.fixture(scope="module", autouse=True)
def setup_sqlite_db():
    """Initializes in-memory/file SQLite test database for router tests."""
    db_file = "scratch/test_github_routes.db"
    os.makedirs("scratch", exist_ok=True)
    db_url = f"sqlite:///{db_file}"
    db_mgr = DatabaseManager(db_url=db_url)
    Base.metadata.create_all(bind=db_mgr.engine)

    with patch("provenanceguard.apps.api.routes_github.DatabaseManager", return_value=db_mgr), \
         patch("provenanceguard.apps.api.routes_artifacts.DatabaseManager", return_value=db_mgr):
        yield db_mgr

    if os.path.exists(db_file):
        try:
            os.remove(db_file)
        except Exception:
            pass


@pytest.fixture
def setup_test_tenant(setup_sqlite_db):
    """Sets up a test Organization and Project in SQLite database."""
    db_mgr = setup_sqlite_db
    org_id = uuid.uuid4()
    proj_id = uuid.uuid4()

    with db_mgr.get_session() as session:
        org = OrganizationModel(id=org_id, name=f"TestOrg-{org_id.hex[:6]}", slug=f"test-org-{org_id.hex[:6]}")
        session.add(org)
        session.flush()

        proj = ProjectModel(id=proj_id, organization_id=org_id, name="Test Project")
        session.add(proj)
        session.commit()

    token = mint_dev_token(user_id="test-admin", organization_id=org_id, role=Role.ADMIN)
    return {"org_id": org_id, "project_id": proj_id, "token": token, "db_mgr": db_mgr}


def test_push_github_artifact_route_success(setup_test_tenant):
    """Verifies PRIMARY PUSH endpoint receives artifact + Git metadata and creates VerificationRun."""
    client = TestClient(app)
    org_id = setup_test_tenant["org_id"]
    proj_id = setup_test_tenant["project_id"]
    token = setup_test_tenant["token"]
    db_mgr = setup_test_tenant["db_mgr"]

    headers = {
        "Authorization": f"Bearer {token}",
        "X-Organization-ID": str(org_id),
    }

    file_content = b"\x7fELF\x02\x01\x01\x00TestBinaryPayloadForGitHubPush"
    files = {"file": ("app-release-v1.0.0.bin", file_content, "application/octet-stream")}
    data = {
        "project_id": str(proj_id),
        "name": "app-release-v1.0.0.bin",
        "version": "1.0.0",
        "repository": "test-owner/test-repo",
        "branch": "main",
        "commit_sha": "b2c3d4e5f678901234567890abcdef1234567890",
        "workflow_run_id": "88888",
        "workflow_name": "Build & Test",
        "build_number": "12",
        "artifact_type": "BUILD_ARTIFACT",
    }

    with patch("provenanceguard.apps.api.routes_github.DatabaseManager", return_value=db_mgr):
        resp = client.post("/api/v1/ci/github/artifacts", headers=headers, files=files, data=data)
        assert resp.status_code == 201, f"Response: {resp.text}"
        body = resp.json()

        assert "artifact_id" in body
        assert "verification_run_id" in body
        assert body["status"] == "QUEUED"
        assert body["commit_sha"] == "b2c3d4e5f678901234567890abcdef1234567890"

        with db_mgr.get_session() as session:
            db_mgr.set_tenant_context(session, org_id)
            art = session.scalar(select(ArtifactModel).where(ArtifactModel.id == uuid.UUID(body["artifact_id"])))
            assert art is not None
            assert art.git_repository == "test-owner/test-repo"
            assert art.git_branch == "main"
            assert art.git_commit_sha == "b2c3d4e5f678901234567890abcdef1234567890"
            assert art.git_workflow_run_id == "88888"


def test_demo_collect_github_artifact_route(setup_test_tenant):
    """Verifies Local Demonstration Mode collects demo fixture through full verification pipeline."""
    client = TestClient(app)
    org_id = setup_test_tenant["org_id"]
    token = setup_test_tenant["token"]
    db_mgr = setup_test_tenant["db_mgr"]

    headers = {
        "Authorization": f"Bearer {token}",
        "X-Organization-ID": str(org_id),
    }

    with patch("provenanceguard.apps.api.routes_github.DatabaseManager", return_value=db_mgr):
        resp = client.post("/api/v1/ci/github/demo-collect", headers=headers)
        assert resp.status_code == 201
        body = resp.json()

        assert "artifact_id" in body
        assert "verification_run_id" in body
        assert body["is_demo"] is True
        assert body["status"] == "QUEUED"

        with db_mgr.get_session() as session:
            db_mgr.set_tenant_context(session, org_id)
            audit_stmt = select(AuditLogModel).where(
                AuditLogModel.organization_id == org_id,
                AuditLogModel.action == "GITHUB_ARTIFACT_COLLECTED",
            )
            logs = session.scalars(audit_stmt).all()
            assert len(logs) > 0


def test_github_config_and_status_routes(setup_test_tenant):
    """Verifies /api/v1/ci/github/config and /status routes."""
    client = TestClient(app)
    org_id = setup_test_tenant["org_id"]
    proj_id = setup_test_tenant["project_id"]
    token = setup_test_tenant["token"]
    db_mgr = setup_test_tenant["db_mgr"]

    headers = {
        "Authorization": f"Bearer {token}",
        "X-Organization-ID": str(org_id),
    }

    with patch("provenanceguard.apps.api.routes_github.DatabaseManager", return_value=db_mgr):
        config_resp = client.post(
            "/api/v1/ci/github/config",
            headers=headers,
            json={
                "repository": "company/core-service",
                "default_branch": "release",
                "project_id": str(proj_id),
            },
        )
        assert config_resp.status_code == 200
        assert config_resp.json()["status"] == "CONFIGURED"

        status_resp = client.get("/api/v1/ci/github/status", headers=headers)
        assert status_resp.status_code == 200
        status_body = status_resp.json()
        assert status_body["repository"] == "company/core-service"
        assert status_body["branch"] == "release"
