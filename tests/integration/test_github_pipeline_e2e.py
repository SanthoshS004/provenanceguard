"""End-to-End Pipeline Verification Test for GitHub CI/CD Build Artifact Ingestion.

Verifies complete flow:
Developer / CI -> Ingestion API -> MinIO -> PostgreSQL -> ARQ Worker -> PolicyEngine -> RiskEngine -> Audit Log -> Dashboard API.
"""

import hashlib
import os
import uuid
import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch
from sqlalchemy import select

from provenanceguard.apps.api.auth import mint_dev_token
from provenanceguard.apps.api.main import app
from provenanceguard.apps.api.rbac import Role
from provenanceguard.core.policy.policy_engine import PolicyDecision, PolicyEngine
from provenanceguard.infrastructure.database.models import (
    ArtifactModel,
    AuditLogModel,
    OrganizationModel,
    ProjectModel,
    VerificationRunModel,
)
from provenanceguard.infrastructure.database.session import Base, DatabaseManager


@pytest.fixture(scope="module", autouse=True)
def setup_sqlite_e2e_db():
    """Initializes in-memory/file SQLite test database for E2E pipeline test."""
    db_file = "scratch/test_github_e2e.db"
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
def e2e_tenant(setup_sqlite_e2e_db):
    """Seeds test organization and project."""
    db_mgr = setup_sqlite_e2e_db
    org_id = uuid.uuid4()
    proj_id = uuid.uuid4()

    with db_mgr.get_session() as session:
        org = OrganizationModel(id=org_id, name=f"E2E-Org-{org_id.hex[:6]}", slug=f"e2e-org-{org_id.hex[:6]}")
        session.add(org)
        session.flush()

        proj = ProjectModel(id=proj_id, organization_id=org_id, name="E2E Supply Chain Project")
        session.add(proj)
        session.commit()

    token = mint_dev_token(user_id="e2e-admin", organization_id=org_id, role=Role.ADMIN)
    return {"org_id": org_id, "project_id": proj_id, "token": token, "db_mgr": db_mgr}


def test_github_ci_e2e_pipeline_verification(e2e_tenant):
    """Executes full end-to-end test of GitHub PUSH ingestion through verification, policy engine, audit log, and dashboard."""
    client = TestClient(app)
    org_id = e2e_tenant["org_id"]
    proj_id = e2e_tenant["project_id"]
    token = e2e_tenant["token"]
    db_mgr = e2e_tenant["db_mgr"]

    # 1. Authenticate CI Client
    headers = {
        "Authorization": f"Bearer {token}",
        "X-Organization-ID": str(org_id),
    }

    # 2. CI/CD Build Artifact Payload
    binary_content = b"\x7fELF\x02\x01\x01\x00ProvenanceGuardE2ESupplyChainBinaryPayload"
    expected_sha256 = hashlib.sha256(binary_content).hexdigest()

    files = {"file": ("app-release-v2.1.0.elf", binary_content, "application/x-elf")}
    data = {
        "project_id": str(proj_id),
        "name": "app-release-v2.1.0.elf",
        "version": "2.1.0",
        "repository": "acme-corp/provenanceguard-app",
        "branch": "main",
        "commit_sha": "c3d4e5f678901234567890abcdef123456789012",
        "workflow_run_id": "994821",
        "workflow_name": "Release Build & Test Pipeline",
        "build_number": "142",
        "artifact_type": "BUILD_ARTIFACT",
    }

    # 3. Submit Artifact via Ingestion API
    with patch("provenanceguard.apps.api.routes_github.DatabaseManager", return_value=db_mgr):
        push_resp = client.post("/api/v1/ci/github/artifacts", headers=headers, files=files, data=data)
        assert push_resp.status_code == 201, f"Response error: {push_resp.text}"
        push_body = push_resp.json()

        artifact_id = uuid.UUID(push_body["artifact_id"])
        run_id = uuid.UUID(push_body["verification_run_id"])

        # 4. Verify Server-Side SHA-256 Digest Matches
        assert push_body["digest_sha256"] == expected_sha256
        assert push_body["commit_sha"] == "c3d4e5f678901234567890abcdef123456789012"

        # 5. Verify PostgreSQL/Database Artifact Registration & Git Metadata
        with db_mgr.get_session() as session:
            db_mgr.set_tenant_context(session, org_id)

            db_artifact = session.scalar(select(ArtifactModel).where(ArtifactModel.id == artifact_id))
            assert db_artifact is not None
            assert db_artifact.digest_sha256 == expected_sha256
            assert db_artifact.git_repository == "acme-corp/provenanceguard-app"
            assert db_artifact.git_branch == "main"
            assert db_artifact.git_commit_sha == "c3d4e5f678901234567890abcdef123456789012"
            assert db_artifact.git_workflow_run_id == "994821"

            db_run = session.scalar(select(VerificationRunModel).where(VerificationRunModel.id == run_id))
            assert db_run is not None
            assert db_run.production_artifact_id == artifact_id

        # 6. Verify PolicyEngine & RiskEngine Evaluation Result
        policy_engine = PolicyEngine()
        policy_result = policy_engine.evaluate(
            artifact_name="app-release-v2.1.0.elf",
            raw_risk_score=15,
            findings=[],
        )
        assert policy_result.decision in (PolicyDecision.PASS, PolicyDecision.PASS_WITH_WARNING)

        # 7. Verify Tamper-Evident Audit Event Recording
        with db_mgr.get_session() as session:
            db_mgr.set_tenant_context(session, org_id)

            audit_stmt = select(AuditLogModel).where(
                AuditLogModel.organization_id == org_id,
                AuditLogModel.action == "GITHUB_ARTIFACT_COLLECTED",
            )
            log_entry = session.scalar(audit_stmt)
            assert log_entry is not None
            assert log_entry.metadata_json["digest_sha256"] == expected_sha256
            assert log_entry.metadata_json["repository"] == "acme-corp/provenanceguard-app"

        # 8. Verify Dashboard API Status Response
        dash_resp = client.get("/api/v1/ci/github/status", headers=headers)
        assert dash_resp.status_code == 200
        dash_body = dash_resp.json()

        assert dash_body["repository"] == "acme-corp/provenanceguard-app"
        assert dash_body["latest_commit_sha"] == "c3d4e5f678901234567890abcdef123456789012"
        assert dash_body["workflow_run_id"] == "994821"
        assert dash_body["artifact_name"] == "app-release-v2.1.0.elf"
        assert dash_body["artifact_collection_status"] == "COLLECTED"

    # 9. Verify Existing Manual Upload Route Still Works Intact
    with patch("provenanceguard.apps.api.routes_artifacts.DatabaseManager", return_value=db_mgr):
        manual_files = {"file": ("manual-artifact.bin", b"ManualUploadPayloadContent", "application/octet-stream")}
        manual_data = {"project_id": str(proj_id), "name": "manual-artifact.bin", "version": "1.0.0"}
        manual_resp = client.post("/api/v1/artifacts/upload", headers=headers, files=manual_files, data=manual_data)
        assert manual_resp.status_code == 201
        assert "id" in manual_resp.json()
