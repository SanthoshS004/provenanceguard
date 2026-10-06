"""Unit and Security Integration Tests for API Key Issuance, One-Time Plaintext Reveal, Hashing, Revocation, and GitHub Actions PUSH Authentication."""

import hashlib
import os
import uuid
import pytest
from pathlib import Path
from fastapi.testclient import TestClient
from unittest.mock import patch
from sqlalchemy import select

from provenanceguard.apps.api.auth import mint_dev_token, resolve_api_key
from provenanceguard.apps.api.main import app
from provenanceguard.apps.api.rbac import Role
from provenanceguard.infrastructure.database.models import (
    ApiKeyModel,
    ArtifactModel,
    AuditLogModel,
    OrganizationModel,
    ProjectModel,
)
from provenanceguard.infrastructure.database.session import Base, DatabaseManager
from provenanceguard.infrastructure.storage.filesystem import FilesystemStorageDriver


@pytest.fixture(scope="module", autouse=True)
def setup_key_test_db():
    """Initializes in-memory/file SQLite test database for API key security tests."""
    db_file = "scratch/test_api_key_issuance.db"
    os.makedirs("scratch", exist_ok=True)
    db_url = f"sqlite:///{db_file}"
    db_mgr = DatabaseManager(db_url=db_url)
    Base.metadata.create_all(bind=db_mgr.engine)

    fs_driver = FilesystemStorageDriver(Path("scratch/storage"))

    with patch("provenanceguard.apps.api.routes_auth.DatabaseManager", return_value=db_mgr), \
         patch("provenanceguard.apps.api.routes_github.DatabaseManager", return_value=db_mgr), \
         patch("provenanceguard.apps.api.routes_github.get_storage_driver", return_value=fs_driver), \
         patch("provenanceguard.apps.api.auth.DatabaseManager", return_value=db_mgr):
        yield db_mgr

    if os.path.exists(db_file):
        try:
            os.remove(db_file)
        except Exception:
            pass


@pytest.fixture
def key_test_tenant(setup_key_test_db):
    """Seeds test organization and project."""
    db_mgr = setup_key_test_db
    org_id = uuid.uuid4()
    proj_id = uuid.uuid4()

    with db_mgr.get_session() as session:
        org = OrganizationModel(id=org_id, name=f"KeyOrg-{org_id.hex[:6]}", slug=f"key-org-{org_id.hex[:6]}")
        session.add(org)
        session.flush()

        proj = ProjectModel(id=proj_id, organization_id=org_id, name="Key Test Project")
        session.add(proj)
        session.commit()

    token = mint_dev_token(user_id="admin-key-issuer", organization_id=org_id, role=Role.ADMIN)
    return {"org_id": org_id, "project_id": proj_id, "token": token, "db_mgr": db_mgr}


def test_api_key_issuance_one_time_reveal_and_hashing(key_test_tenant):
    """Test 1-3: Authenticated user creates key; raw key returned ONCE; DB contains ONLY SHA-256 hash."""
    client = TestClient(app)
    org_id = key_test_tenant["org_id"]
    token = key_test_tenant["token"]
    db_mgr = key_test_tenant["db_mgr"]

    headers = {
        "Authorization": f"Bearer {token}",
        "X-Organization-ID": str(org_id),
    }

    # Issue API Key
    with patch("provenanceguard.apps.api.routes_auth.DatabaseManager", return_value=db_mgr):
        resp = client.post(
            "/api/v1/auth/api-keys",
            headers=headers,
            json={
                "name": "CI/CD Deployment Key",
                "role": "SECURITY_ANALYST",
            },
        )
        assert resp.status_code == 201, f"Response: {resp.text}"
        data = resp.json()

        assert "api_key" in data
        raw_key = data["api_key"]
        assert raw_key.startswith("pg_live_")
        assert "key_hash" not in data

        # Verify DB contains ONLY SHA-256 hash, NOT raw_key
        with db_mgr.get_session() as session:
            db_mgr.set_tenant_context(session, org_id)
            db_record = session.scalar(select(ApiKeyModel).where(ApiKeyModel.id == uuid.UUID(data["id"])))
            assert db_record is not None
            expected_hash = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
            assert db_record.key_hash == expected_hash
            assert raw_key not in db_record.key_hash

        # Verify listing keys NEVER returns raw plaintext key or hash
        list_resp = client.get("/api/v1/auth/api-keys", headers=headers)
        assert list_resp.status_code == 200
        list_data = list_resp.json()
        assert len(list_data) >= 1
        issued_item = [k for k in list_data if k["id"] == data["id"]][0]
        assert "api_key" not in issued_item
        assert "key_hash" not in issued_item


def test_unauthenticated_api_key_creation_rejected():
    """Test 2: Unauthenticated user cannot create API key (401)."""
    client = TestClient(app)
    resp = client.post("/api/v1/auth/api-keys", json={"name": "Illegal Key", "role": "DEVELOPER"})
    assert resp.status_code == 401


def test_issued_api_key_authenticates_github_push(key_test_tenant):
    """Test 4 & 8: Issued X-API-Key authenticates successfully for POST /api/v1/ci/github/artifacts."""
    client = TestClient(app)
    org_id = key_test_tenant["org_id"]
    proj_id = key_test_tenant["project_id"]
    token = key_test_tenant["token"]
    db_mgr = key_test_tenant["db_mgr"]
    fs_driver = FilesystemStorageDriver(Path("scratch/storage"))

    headers_jwt = {
        "Authorization": f"Bearer {token}",
        "X-Organization-ID": str(org_id),
    }

    with patch("provenanceguard.apps.api.routes_auth.DatabaseManager", return_value=db_mgr):
        resp = client.post(
            "/api/v1/auth/api-keys",
            headers=headers_jwt,
            json={
                "name": "GitHub Actions Push Key",
                "role": "SECURITY_ANALYST",
                "project_id": str(proj_id),
            },
        )
        assert resp.status_code == 201
        issued_key = resp.json()["api_key"]

    # Use issued X-API-Key to authenticate POST /api/v1/ci/github/artifacts
    push_headers = {
        "X-API-Key": issued_key,
        "X-Organization-ID": str(org_id),
    }
    file_content = b"\x7fELF\x02\x01\x01\x00BinaryPayloadWithIssuedApiKey"
    files = {"file": ("app-ci-release.bin", file_content, "application/octet-stream")}
    data = {
        "project_id": str(proj_id),
        "name": "app-ci-release.bin",
        "version": "1.0.0",
        "repository": "test-org/push-repo",
        "branch": "main",
        "commit_sha": "d4e5f678901234567890abcdef12345678901234",
        "workflow_run_id": "77712",
        "artifact_type": "BUILD_ARTIFACT",
    }

    with patch("provenanceguard.apps.api.routes_github.DatabaseManager", return_value=db_mgr), \
         patch("provenanceguard.apps.api.routes_github.get_storage_driver", return_value=fs_driver), \
         patch("provenanceguard.apps.api.auth.DatabaseManager", return_value=db_mgr):
        push_resp = client.post("/api/v1/ci/github/artifacts", headers=push_headers, files=files, data=data)
        assert push_resp.status_code == 201, f"Push response: {push_resp.text}"
        assert push_resp.json()["status"] == "QUEUED"


def test_invalid_and_revoked_api_key_rejected(key_test_tenant):
    """Test 5-6 & 9: Invalid or revoked API key is rejected (401)."""
    client = TestClient(app)
    org_id = key_test_tenant["org_id"]
    token = key_test_tenant["token"]
    db_mgr = key_test_tenant["db_mgr"]

    # 1. Invalid key rejected
    bad_resp = client.post(
        "/api/v1/ci/github/artifacts",
        headers={"X-API-Key": "pg_live_00000000000000000000000000000000"},
        files={"file": ("test.bin", b"data", "application/octet-stream")},
    )
    assert bad_resp.status_code == 401

    # 2. Issue and then Revoke key
    headers_jwt = {"Authorization": f"Bearer {token}", "X-Organization-ID": str(org_id)}
    with patch("provenanceguard.apps.api.routes_auth.DatabaseManager", return_value=db_mgr):
        create_resp = client.post(
            "/api/v1/auth/api-keys",
            headers=headers_jwt,
            json={"name": "Temporary Key", "role": "SECURITY_ANALYST"},
        )
        key_id = create_resp.json()["id"]
        raw_key = create_resp.json()["api_key"]

        # Revoke key
        del_resp = client.delete(f"/api/v1/auth/api-keys/{key_id}", headers=headers_jwt)
        assert del_resp.status_code == 204

    # 3. Revoked key authentication fails
    with patch("provenanceguard.apps.api.auth.DatabaseManager", return_value=db_mgr):
        revoked_resp = client.post(
            "/api/v1/ci/github/artifacts",
            headers={"X-API-Key": raw_key},
            files={"file": ("test.bin", b"data", "application/octet-stream")},
        )
        assert revoked_resp.status_code == 401


def test_cross_tenant_api_key_access_denied(key_test_tenant):
    """Test 7: API key cannot access another tenant's resources (403/401)."""
    client = TestClient(app)
    org_id_a = key_test_tenant["org_id"]
    token_a = key_test_tenant["token"]
    db_mgr = key_test_tenant["db_mgr"]
    fs_driver = FilesystemStorageDriver(Path("scratch/storage"))

    # Create Org B
    org_id_b = uuid.uuid4()
    with db_mgr.get_session() as session:
        session.add(OrganizationModel(id=org_id_b, name=f"OrgB-{org_id_b.hex[:4]}", slug=f"orgb-{org_id_b.hex[:4]}"))
        session.commit()

    # Issue key for Org A
    headers_a = {"Authorization": f"Bearer {token_a}", "X-Organization-ID": str(org_id_a)}
    with patch("provenanceguard.apps.api.routes_auth.DatabaseManager", return_value=db_mgr):
        create_resp = client.post(
            "/api/v1/auth/api-keys",
            headers=headers_a,
            json={"name": "Org A Key", "role": "SECURITY_ANALYST"},
        )
        raw_key_a = create_resp.json()["api_key"]

    # Org A key attempts to access Org B with header mismatch
    with patch("provenanceguard.apps.api.routes_github.DatabaseManager", return_value=db_mgr), \
         patch("provenanceguard.apps.api.routes_github.get_storage_driver", return_value=fs_driver), \
         patch("provenanceguard.apps.api.auth.DatabaseManager", return_value=db_mgr):
        cross_resp = client.post(
            "/api/v1/ci/github/artifacts",
            headers={"X-API-Key": raw_key_a, "X-Organization-ID": str(org_id_b)},
            files={"file": ("test.bin", b"data", "application/octet-stream")},
        )
        assert cross_resp.status_code in (401, 403)
