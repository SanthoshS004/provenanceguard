"""Integration Tests for FastAPI Verification Endpoints."""

import time
import uuid

from fastapi.testclient import TestClient
from sqlalchemy import text

from provenanceguard.apps.api.auth import mint_dev_token
from provenanceguard.apps.api.main import app
from provenanceguard.apps.api.rbac import Role
from provenanceguard.infrastructure.database.session import DatabaseManager


def test_api_verification_submission_and_retrieval_flow():
    client = TestClient(app)
    db_mgr = DatabaseManager()

    org_id = uuid.uuid4()
    proj_id = uuid.uuid4()
    art_id = uuid.uuid4()

    ins_org = (
        "INSERT INTO organizations (id, name, slug, created_at) "
        "VALUES (CAST(:id AS uuid), :name, :slug, NOW())"
    )
    ins_proj = (
        "INSERT INTO projects (id, organization_id, name, created_at) "
        "VALUES (CAST(:id AS uuid), CAST(:org_id AS uuid), :name, NOW())"
    )
    ins_art = (
        "INSERT INTO artifacts "
        "(id, project_id, organization_id, name, version, media_type, "
        "digest_sha256, size_bytes, storage_path, created_at) "
        "VALUES (CAST(:id AS uuid), CAST(:proj_id AS uuid), CAST(:org_id AS uuid), "
        "'art', '1.0', 'application/vnd.elf', :digest, 100, '/path', NOW())"
    )

    with db_mgr.get_session() as session:
        session.execute(
            text(ins_org),
            {
                "id": str(org_id),
                "name": f"Org_{str(org_id)[:8]}",
                "slug": f"slug_{str(org_id)[:8]}",
            },
        )
        session.execute(
            text(ins_proj),
            {"id": str(proj_id), "org_id": str(org_id), "name": "P1"},
        )
        session.execute(
            text(ins_art),
            {"id": str(art_id), "proj_id": str(proj_id), "org_id": str(org_id), "digest": "e" * 64},
        )
        session.commit()

    token = mint_dev_token("user-test", org_id, Role.DEVELOPER)

    payload = {
        "organization_id": str(org_id),
        "project_id": str(proj_id),
        "production_artifact_id": str(art_id),
    }

    resp = client.post(
        "/api/v1/verifications",
        headers={"Authorization": f"Bearer {token}"},
        json=payload,
    )
    assert resp.status_code == 202
    data = resp.json()
    assert "job_id" in data
    assert "verification_run_id" in data
    assert data["status"] == "QUEUED"

    run_id = data["verification_run_id"]

    get_resp = client.get(
        f"/api/v1/verifications/{run_id}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert get_resp.status_code == 200
    run_data = get_resp.json()
    assert run_data["id"] == run_id
    assert run_data["status"] == "QUEUED"

    list_resp = client.get(
        "/api/v1/verifications",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert list_resp.status_code == 200
    assert len(list_resp.json()) >= 1


def test_api_verification_submission_latency_performance():
    """Measures end-to-end API verification task submission latency to verify NFR-004 (< 15s)."""
    client = TestClient(app)
    db_mgr = DatabaseManager()

    org_id = uuid.uuid4()
    proj_id = uuid.uuid4()
    art_id = uuid.uuid4()

    ins_org = (
        "INSERT INTO organizations (id, name, slug, created_at) "
        "VALUES (CAST(:id AS uuid), :name, :slug, NOW())"
    )
    ins_proj = (
        "INSERT INTO projects (id, organization_id, name, created_at) "
        "VALUES (CAST(:id AS uuid), CAST(:org_id AS uuid), :name, NOW())"
    )
    ins_art = (
        "INSERT INTO artifacts "
        "(id, project_id, organization_id, name, version, media_type, "
        "digest_sha256, size_bytes, storage_path, created_at) "
        "VALUES (CAST(:id AS uuid), CAST(:proj_id AS uuid), CAST(:org_id AS uuid), "
        "'art', '1.0', 'application/vnd.elf', :digest, 100, '/path', NOW())"
    )

    with db_mgr.get_session() as session:
        session.execute(
            text(ins_org),
            {
                "id": str(org_id),
                "name": f"Org_{str(org_id)[:8]}",
                "slug": f"slug_{str(org_id)[:8]}",
            },
        )
        session.execute(
            text(ins_proj),
            {"id": str(proj_id), "org_id": str(org_id), "name": "P1"},
        )
        session.execute(
            text(ins_art),
            {"id": str(art_id), "proj_id": str(proj_id), "org_id": str(org_id), "digest": "f" * 64},
        )
        session.commit()

    token = mint_dev_token("user-test-perf", org_id, Role.DEVELOPER)

    payload = {
        "organization_id": str(org_id),
        "project_id": str(proj_id),
        "production_artifact_id": str(art_id),
    }

    start_time = time.perf_counter()
    resp = client.post(
        "/api/v1/verifications",
        headers={"Authorization": f"Bearer {token}"},
        json=payload,
    )
    elapsed = time.perf_counter() - start_time

    assert resp.status_code == 202
    assert elapsed < 15.0  # NFR-004 Acceptance Criterion: < 15.0 seconds
