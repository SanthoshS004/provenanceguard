"""Security Tests for API Containment & Authentication Security."""

import uuid

from fastapi.testclient import TestClient
from sqlalchemy import text

from provenanceguard.apps.api.auth import mint_dev_token
from provenanceguard.apps.api.main import ConfigurationError, app, check_security_configuration
from provenanceguard.apps.api.rbac import Role
from provenanceguard.infrastructure.database.models import VerificationRunModel
from provenanceguard.infrastructure.database.session import DatabaseManager


def test_production_mode_unauthenticated_api_fail_closed(monkeypatch):
    """Verifies API security configuration fails closed when PG_ENV=production and public key is missing."""
    monkeypatch.setenv("PG_ENV", "production")
    monkeypatch.delenv("PG_JWT_PUBLIC_KEY", raising=False)

    try:
        check_security_configuration()
        assert False, "Expected ConfigurationError when PG_JWT_PUBLIC_KEY is missing in production"
    except ConfigurationError:
        pass


def test_api_cross_tenant_access_denial():
    """Verifies GET /api/v1/verifications/{id} denies cross-tenant access."""
    client = TestClient(app)

    db_mgr = DatabaseManager()
    org_a = uuid.uuid4()
    org_b = uuid.uuid4()
    proj_id = uuid.uuid4()
    run_id = uuid.uuid4()
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
            {"id": str(org_a), "name": f"Org_{str(org_a)[:8]}", "slug": f"slug_{str(org_a)[:8]}"},
        )
        session.execute(
            text(ins_org),
            {"id": str(org_b), "name": f"Org_{str(org_b)[:8]}", "slug": f"slug_{str(org_b)[:8]}"},
        )
        session.execute(
            text(ins_proj),
            {"id": str(proj_id), "org_id": str(org_a), "name": "P1"},
        )
        session.execute(
            text(ins_art),
            {"id": str(art_id), "proj_id": str(proj_id), "org_id": str(org_a), "digest": "d" * 64},
        )

        run = VerificationRunModel(
            id=run_id,
            organization_id=org_a,
            project_id=proj_id,
            production_artifact_id=art_id,
            status="QUEUED",
            decision="PENDING",
            risk_score=0,
            attempt_count=1,
        )
        session.add(run)
        session.commit()

    token_a = mint_dev_token("user-a", org_a, Role.SECURITY_ANALYST)
    token_b = mint_dev_token("user-b", org_b, Role.SECURITY_ANALYST)

    # Cross-tenant access attempt by org_b token must be denied (404 / 403)
    resp = client.get(
        f"/api/v1/verifications/{run_id}",
        headers={"Authorization": f"Bearer {token_b}"},
    )
    assert resp.status_code == 404

    # Tenant org_a token succeeds
    resp = client.get(
        f"/api/v1/verifications/{run_id}",
        headers={"Authorization": f"Bearer {token_a}"},
    )
    assert resp.status_code == 200
    assert resp.json()["id"] == str(run_id)
