"""API Key & PostgreSQL SECURITY DEFINER Security Test Suite for ProvenanceGuard."""

import datetime
import hashlib
import uuid
from datetime import timezone

from fastapi.testclient import TestClient
from sqlalchemy import text

from provenanceguard.apps.api.auth import mint_dev_token
from provenanceguard.apps.api.main import app
from provenanceguard.apps.api.rbac import Role
from provenanceguard.infrastructure.database.models import (
    ApiKeyModel,
    OrganizationModel,
    ProjectModel,
)
from provenanceguard.infrastructure.database.session import DatabaseManager

client = TestClient(app)


def test_app_role_has_no_bypassrls_and_security_definer_function_properties():
    """Verifies that provenanceguard_app HAS NO BYPASSRLS and lookup_api_key_by_hash is SECURITY DEFINER."""
    db_mgr = DatabaseManager()
    if db_mgr.db_url.startswith("sqlite"):
        return  # SQLite does not have PostgreSQL roles or pg_proc

    with db_mgr.get_session() as session:
        # 1. Verify provenanceguard_app does NOT have BYPASSRLS
        query_role = text(
            "SELECT rolname, rolbypassrls FROM pg_roles WHERE rolname = 'provenanceguard_app'"
        )
        row_role = session.execute(query_role).fetchone()
        if row_role:
            rolname, rolbypassrls = row_role
            assert rolbypassrls is False, (
                f"CRITICAL SECURITY REJECTION: Role '{rolname}' has BYPASSRLS=True!"
            )

        # 2. Verify lookup_api_key_by_hash is SECURITY DEFINER and has search_path set
        query_proc = text(
            "SELECT prosecdef, proconfig FROM pg_proc WHERE proname = 'lookup_api_key_by_hash'"
        )
        row_proc = session.execute(query_proc).fetchone()
        if row_proc:
            prosecdef, proconfig = row_proc
            assert prosecdef is True, "lookup_api_key_by_hash MUST be SECURITY DEFINER!"
            assert proconfig is not None and any("search_path=" in c for c in proconfig), (
                "lookup_api_key_by_hash MUST have fixed search_path set!"
            )

        # 3. Verify PUBLIC has no execute privilege on lookup_api_key_by_hash
        query_pub_priv = text(
            "SELECT has_function_privilege('public', 'lookup_api_key_by_hash(char)', 'EXECUTE')"
        )
        pub_priv = session.execute(query_pub_priv).scalar()
        assert pub_priv is False, (
            "PUBLIC role MUST NOT have EXECUTE privilege on lookup_api_key_by_hash!"
        )


def test_api_key_creation_plaintext_returned_once_and_hash_unexposed():
    """Verifies plaintext key is returned on creation but excluded from list, and key_hash is never exposed."""
    org_id = uuid.uuid4()
    admin_token = mint_dev_token("user-admin", org_id, Role.ADMIN)

    # 1. Create Organization in DB
    db_mgr = DatabaseManager()
    with db_mgr.get_session() as session:
        org = OrganizationModel(
            id=org_id, name=f"Org_{org_id.hex[:8]}", slug=f"slug_{org_id.hex[:8]}"
        )
        session.add(org)
        session.commit()

    # 2. Create API key via POST /api/v1/auth/api-keys
    create_resp = client.post(
        "/api/v1/auth/api-keys",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"name": "test-key-1", "role": "SECURITY_ANALYST"},
    )
    assert create_resp.status_code == 201
    data = create_resp.json()
    assert "api_key" in data
    assert data["api_key"].startswith("pg_live_")
    assert "key_hash" not in data

    raw_key = data["api_key"]

    # 3. List API keys via GET /api/v1/auth/api-keys
    list_resp = client.get(
        "/api/v1/auth/api-keys",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert list_resp.status_code == 200
    keys_list = list_resp.json()
    assert len(keys_list) >= 1
    target_key = next(k for k in keys_list if k["name"] == "test-key-1")
    assert "api_key" not in target_key
    assert "key_hash" not in target_key

    # 4. Verify authenticating with raw_key works
    ver_resp = client.get(
        "/api/v1/verifications",
        headers={"X-API-Key": raw_key},
    )
    assert ver_resp.status_code == 200


def test_invalid_api_key_hash_rejection_401():
    """Verifies non-existent API key is rejected with HTTP 401."""
    resp = client.get(
        "/api/v1/verifications",
        headers={"X-API-Key": "pg_live_00000000000000000000000000000000"},
    )
    assert resp.status_code == 401
    assert "Invalid or non-existent API key" in resp.json()["detail"]


def test_revoked_api_key_rejection_401():
    """Verifies revoked API key is rejected with HTTP 401."""
    org_id = uuid.uuid4()
    admin_token = mint_dev_token("user-admin", org_id, Role.ADMIN)

    db_mgr = DatabaseManager()
    with db_mgr.get_session() as session:
        org = OrganizationModel(
            id=org_id, name=f"Org_{org_id.hex[:8]}", slug=f"slug_{org_id.hex[:8]}"
        )
        session.add(org)
        session.commit()

    create_resp = client.post(
        "/api/v1/auth/api-keys",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"name": "key-to-revoke", "role": "SECURITY_ANALYST"},
    )
    assert create_resp.status_code == 201
    key_id = create_resp.json()["id"]
    raw_key = create_resp.json()["api_key"]

    # Revoke key
    del_resp = client.delete(
        f"/api/v1/auth/api-keys/{key_id}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert del_resp.status_code in (200, 204)

    # Authenticate with revoked key must fail
    resp = client.get(
        "/api/v1/verifications",
        headers={"X-API-Key": raw_key},
    )
    assert resp.status_code == 401
    assert "revoked" in resp.json()["detail"].lower()


def test_expired_api_key_rejection_401():
    """Verifies expired API key is rejected with HTTP 401."""
    org_id = uuid.uuid4()
    raw_key = f"pg_live_{uuid.uuid4().hex}"
    key_hash = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
    expired_time = datetime.datetime.now(timezone.utc) - datetime.timedelta(days=1)

    db_mgr = DatabaseManager()
    with db_mgr.get_session() as session:
        db_mgr.set_tenant_context(session, org_id)

        org = OrganizationModel(
            id=org_id, name=f"Org_{org_id.hex[:8]}", slug=f"slug_{org_id.hex[:8]}"
        )
        session.add(org)

        expired_key = ApiKeyModel(
            id=uuid.uuid4(),
            organization_id=org_id,
            name="expired-key",
            prefix="pg_live_1111",
            key_hash=key_hash,
            role="SECURITY_ANALYST",
            scopes_json=[],
            created_at=expired_time - datetime.timedelta(days=10),
            expires_at=expired_time,
            revoked_at=None,
        )
        session.add(expired_key)
        session.commit()

    resp = client.get(
        "/api/v1/verifications",
        headers={"X-API-Key": raw_key},
    )
    assert resp.status_code == 401
    assert "expired" in resp.json()["detail"].lower()


def test_project_scoped_api_key_exact_semantics_scenarios():
    """Verifies exact project-scoped API key authorization semantics (Scenarios A, B, C, D, E)."""
    org_a = uuid.uuid4()
    org_b = uuid.uuid4()
    proj_a = uuid.uuid4()
    proj_b = uuid.uuid4()
    proj_b_org_b = uuid.uuid4()

    db_mgr = DatabaseManager()
    with db_mgr.get_session() as session:
        oa = OrganizationModel(id=org_a, name=f"Org_{org_a.hex[:8]}", slug=f"slug_{org_a.hex[:8]}")
        ob = OrganizationModel(id=org_b, name=f"Org_{org_b.hex[:8]}", slug=f"slug_{org_b.hex[:8]}")
        session.add_all([oa, ob])
        session.flush()

        pa = ProjectModel(id=proj_a, organization_id=org_a, name="Project A")
        pb = ProjectModel(id=proj_b, organization_id=org_a, name="Project B")
        pb_ob = ProjectModel(id=proj_b_org_b, organization_id=org_b, name="Project B Org B")
        session.add_all([pa, pb, pb_ob])
        session.commit()

    admin_token_a = mint_dev_token("admin-a", org_a, Role.ADMIN)

    # 1. Create Project-A-scoped API key
    key_resp_a = client.post(
        "/api/v1/auth/api-keys",
        headers={"Authorization": f"Bearer {admin_token_a}"},
        json={"name": "key-proj-a", "role": "DEVELOPER", "project_id": str(proj_a)},
    )
    assert key_resp_a.status_code == 201
    key_proj_a = key_resp_a.json()["api_key"]

    # 2. Create Organization-Wide API key (project_id = NULL)
    key_resp_org = client.post(
        "/api/v1/auth/api-keys",
        headers={"Authorization": f"Bearer {admin_token_a}"},
        json={"name": "key-org-wide", "role": "DEVELOPER", "project_id": None},
    )
    assert key_resp_org.status_code == 201
    key_org_wide = key_resp_org.json()["api_key"]

    # --- Scenario A: Org A / Project A / Project-A-scoped key -> Permitted ---
    art_a = uuid.uuid4()
    with db_mgr.get_session() as session:
        db_mgr.set_tenant_context(session, org_a)
        session.execute(
            text(
                "INSERT INTO artifacts (id, project_id, organization_id, name, version, media_type, digest_sha256, size_bytes, storage_path, created_at) "
                "VALUES (CAST(:id AS uuid), CAST(:proj_id AS uuid), CAST(:org_id AS uuid), 'artA', '1.0', 'app/elf', :digest, 10, '/p', NOW())"
            ),
            {"id": str(art_a), "proj_id": str(proj_a), "org_id": str(org_a), "digest": "a" * 64},
        )
        session.commit()

    resp_a = client.post(
        "/api/v1/verifications",
        headers={"X-API-Key": key_proj_a},
        json={
            "organization_id": str(org_a),
            "project_id": str(proj_a),
            "production_artifact_id": str(art_a),
        },
    )
    assert resp_a.status_code == 202

    # --- Scenario B: Org A / Project B / Project-A-scoped key -> 403 ---
    resp_b = client.post(
        "/api/v1/verifications",
        headers={"X-API-Key": key_proj_a},
        json={
            "organization_id": str(org_a),
            "project_id": str(proj_b),
            "production_artifact_id": str(art_a),
        },
    )
    assert resp_b.status_code == 403

    # --- Scenario C: Org B / Project A -> 403 (Cross-tenant or client org mismatch) ---
    resp_c = client.post(
        "/api/v1/verifications",
        headers={"X-API-Key": key_proj_a},
        json={
            "organization_id": str(org_b),  # Attempting to act as Org B
            "project_id": str(proj_a),
            "production_artifact_id": str(art_a),
        },
    )
    assert resp_c.status_code == 403

    # --- Scenario D: Org A / Organization-wide key -> Permitted according to role + scopes ---
    art_b = uuid.uuid4()
    with db_mgr.get_session() as session:
        db_mgr.set_tenant_context(session, org_a)
        session.execute(
            text(
                "INSERT INTO artifacts (id, project_id, organization_id, name, version, media_type, digest_sha256, size_bytes, storage_path, created_at) "
                "VALUES (CAST(:id AS uuid), CAST(:proj_id AS uuid), CAST(:org_id AS uuid), 'artB', '1.0', 'app/elf', :digest, 10, '/p', NOW())"
            ),
            {"id": str(art_b), "proj_id": str(proj_b), "org_id": str(org_a), "digest": "b" * 64},
        )
        session.commit()

    resp_d = client.post(
        "/api/v1/verifications",
        headers={"X-API-Key": key_org_wide},
        json={
            "organization_id": str(org_a),
            "project_id": str(proj_b),
            "production_artifact_id": str(art_b),
        },
    )
    assert resp_d.status_code == 202

    # --- Scenario E: Attempt to create a key for unauthorized project -> 403 ---
    # E1: Org A admin trying to create key for Org B's project (proj_b_org_b) -> 403
    resp_e1 = client.post(
        "/api/v1/auth/api-keys",
        headers={"Authorization": f"Bearer {admin_token_a}"},
        json={"name": "key-unauth-proj", "role": "DEVELOPER", "project_id": str(proj_b_org_b)},
    )
    assert resp_e1.status_code == 403

    # E2: Project-A-scoped key trying to mint a new key for Project B -> 403
    key_proj_a_admin_resp = client.post(
        "/api/v1/auth/api-keys",
        headers={"Authorization": f"Bearer {admin_token_a}"},
        json={"name": "admin-proj-a-key", "role": "ADMIN", "project_id": str(proj_a)},
    )
    raw_proj_a_admin_key = key_proj_a_admin_resp.json()["api_key"]

    resp_e2 = client.post(
        "/api/v1/auth/api-keys",
        headers={"X-API-Key": raw_proj_a_admin_key},
        json={"name": "key-illegal-mint", "role": "DEVELOPER", "project_id": str(proj_b)},
    )
    assert resp_e2.status_code == 403


def test_role_delegation_privilege_escalation_prevention_403():
    """Verifies SECURITY_ANALYST cannot issue ADMIN keys, and DEVELOPER cannot issue keys."""
    org_id = uuid.uuid4()
    sec_analyst_token = mint_dev_token("sec-analyst", org_id, Role.SECURITY_ANALYST)
    developer_token = mint_dev_token("dev-user", org_id, Role.DEVELOPER)

    # 1. SECURITY_ANALYST attempting to create ADMIN key -> HTTP 403
    resp_admin = client.post(
        "/api/v1/auth/api-keys",
        headers={"Authorization": f"Bearer {sec_analyst_token}"},
        json={"name": "escalated-key", "role": "ADMIN"},
    )
    assert resp_admin.status_code == 403
    assert "Role delegation forbidden" in resp_admin.json()["detail"]

    # 2. DEVELOPER attempting to create any API key -> HTTP 403
    resp_dev = client.post(
        "/api/v1/auth/api-keys",
        headers={"Authorization": f"Bearer {developer_token}"},
        json={"name": "dev-mint-attempt", "role": "DEVELOPER"},
    )
    assert resp_dev.status_code == 403
    assert (
        "Insufficient permissions" in resp_dev.json()["detail"]
        or "forbidden" in resp_dev.json()["detail"].lower()
    )
