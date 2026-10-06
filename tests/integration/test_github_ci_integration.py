"""
Integration Test Suite for Automatic GitHub Actions CI/CD Artifact Collection & Verification (v1.1.0).
"""

import hashlib
import json
import uuid
import pytest
from fastapi.testclient import TestClient
from pathlib import Path

from provenanceguard.apps.api.main import app
from provenanceguard.apps.api.auth import mint_dev_token
from provenanceguard.integrations.github.ci_action import (
    GitHubCIRunner,
    ProvenanceGuardCIClient,
    sanitize_github_output,
)
from provenanceguard.infrastructure.database.models import (
    ApiKeyModel,
    ArtifactModel,
    AuditLogModel,
    OrganizationModel,
    ProjectModel,
    VerificationRunModel,
)
from provenanceguard.infrastructure.database.session import DatabaseManager


@pytest.fixture
def test_setup():
    """Sets up a clean organization, project, and API key in PostgreSQL database."""
    db_mgr = DatabaseManager()
    org_id = uuid.uuid4()
    proj_id = uuid.uuid4()
    key_uuid = uuid.uuid4()
    raw_key = f"pg_live_{uuid.uuid4().hex}"
    key_hash = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()

    with db_mgr.get_session() as session:
        org = OrganizationModel(id=org_id, name=f"Org-{org_id.hex[:6]}", slug=f"org-{org_id.hex[:6]}")
        session.add(org)
        session.commit()

        db_mgr.set_tenant_context(session, org_id)
        proj = ProjectModel(id=proj_id, organization_id=org_id, name="CI Test Project")
        session.add(proj)
        session.commit()

        api_key_record = ApiKeyModel(
            id=key_uuid,
            organization_id=org_id,
            project_id=proj_id,
            name="CI API Key",
            prefix=raw_key[:12],
            key_hash=key_hash,
            role="SECURITY_ANALYST",
            scopes_json=["*"],
        )
        session.add(api_key_record)
        session.commit()

    return {
        "org_id": org_id,
        "proj_id": proj_id,
        "raw_key": raw_key,
        "key_id": key_uuid,
    }


def test_sanitize_github_output():
    """Verifies workflow command injection sanitization."""
    raw = "malicious::command\n%0A%0D"
    clean = sanitize_github_output(raw)
    assert "::" not in clean
    assert "\n" not in clean
    assert "%0A" not in clean


def test_ci_artifact_upload_and_verification_success(test_setup, tmp_path):
    """Verifies end-to-end REST API upload, verification creation, and polling from CI runner."""
    raw_key = test_setup["raw_key"]
    proj_id = str(test_setup["proj_id"])
    org_id = test_setup["org_id"]

    # Create dummy artifact file
    art_file = tmp_path / "ci_app.bin"
    art_file.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"A" * 100)

    client = TestClient(app)

    # 1. Upload Artifact via REST API with API Key header
    with open(art_file, "rb") as f:
        upload_resp = client.post(
            "/api/v1/artifacts/upload",
            files={"file": ("ci_app.bin", f, "application/octet-stream")},
            data={"project_id": proj_id, "version": "1.1.0"},
            headers={"X-API-Key": raw_key},
        )

    assert upload_resp.status_code == 201
    upload_data = upload_resp.json()
    assert upload_data["name"] == "ci_app.bin"
    assert upload_data["version"] == "1.1.0"
    assert "digest_sha256" in upload_data

    artifact_id = upload_data["id"]

    # 2. Submit Verification Run
    ver_resp = client.post(
        "/api/v1/verifications",
        json={
            "organization_id": str(org_id),
            "project_id": proj_id,
            "production_artifact_id": artifact_id,
        },
        headers={"X-API-Key": raw_key},
    )

    assert ver_resp.status_code == 202
    ver_data = ver_resp.json()
    assert "verification_run_id" in ver_data
    assert ver_data["status"] == "QUEUED"

    run_id = ver_data["verification_run_id"]

    # 3. Retrieve Verification Run Status
    get_resp = client.get(
        f"/api/v1/verifications/{run_id}",
        headers={"X-API-Key": raw_key},
    )
    assert get_resp.status_code == 200
    assert get_resp.json()["id"] == run_id


def test_ci_authentication_failure(test_setup, tmp_path):
    """Verifies that requests with invalid API keys are rejected with 401 Unauthorized."""
    art_file = tmp_path / "ci_app.bin"
    art_file.write_bytes(b"\x7fELF\x02\x01\x01\x00")

    client = TestClient(app)

    with open(art_file, "rb") as f:
        resp = client.post(
            "/api/v1/artifacts/upload",
            files={"file": ("ci_app.bin", f, "application/octet-stream")},
            headers={"X-API-Key": "pg_live_invalid_key_12345"},
        )

    assert resp.status_code == 401
    assert "Invalid or non-existent API key" in resp.json()["detail"]


def test_ci_cross_tenant_project_access_denied(test_setup, tmp_path):
    """Verifies that API keys scoped to one tenant/project cannot manipulate another project."""
    raw_key = test_setup["raw_key"]
    foreign_proj_id = str(uuid.uuid4())

    art_file = tmp_path / "ci_app.bin"
    art_file.write_bytes(b"\x7fELF\x02\x01\x01\x00")

    client = TestClient(app)

    with open(art_file, "rb") as f:
        resp = client.post(
            "/api/v1/artifacts/upload",
            files={"file": ("ci_app.bin", f, "application/octet-stream")},
            data={"project_id": foreign_proj_id},
            headers={"X-API-Key": raw_key},
        )

    assert resp.status_code == 403
    assert "restricted to project" in resp.json()["detail"]


def test_ci_audit_event_recorded(test_setup, tmp_path):
    """Verifies that CI artifact upload generates an ARTIFACT_INGESTED audit log record."""
    raw_key = test_setup["raw_key"]
    proj_id = str(test_setup["proj_id"])
    org_id = test_setup["org_id"]

    art_file = tmp_path / "ci_app.bin"
    art_file.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"X" * 50)

    client = TestClient(app)

    with open(art_file, "rb") as f:
        client.post(
            "/api/v1/artifacts/upload",
            files={"file": ("ci_app.bin", f, "application/octet-stream")},
            data={"project_id": proj_id},
            headers={"X-API-Key": raw_key},
        )

    # Inspect PostgreSQL Audit Log Stream
    db_mgr = DatabaseManager()
    with db_mgr.get_session() as session:
        db_mgr.set_tenant_context(session, org_id)
        audits = (
            session.query(AuditLogModel)
            .filter(AuditLogModel.action == "ARTIFACT_INGESTED")
            .order_by(AuditLogModel.created_at.desc())
            .all()
        )

        assert len(audits) >= 1
        latest = audits[0]
        assert latest.result == "SUCCESS"
        assert "ci_app.bin" in str(latest.metadata_json)
