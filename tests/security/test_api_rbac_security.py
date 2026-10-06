"""Comprehensive RBAC & Tenant Authorization Security Test Suite for ProvenanceGuard."""

import uuid

from fastapi.testclient import TestClient
from sqlalchemy import text

from provenanceguard.apps.api.auth import mint_dev_token
from provenanceguard.apps.api.main import app
from provenanceguard.apps.api.rbac import Permission, Role, get_effective_permissions
from provenanceguard.infrastructure.database.session import DatabaseManager

client = TestClient(app)


def test_rbac_all_six_roles_permissions_matrix():
    """Matrix test validating effective permissions for all six standard system roles."""
    roles_expected_perms = {
        Role.ADMIN: {
            Permission.VERIFICATION_CREATE,
            Permission.VERIFICATION_READ,
            Permission.POLICY_MANAGE,
            Permission.AUDIT_READ,
            Permission.API_KEY_MANAGE,
            Permission.ORG_ADMIN,
        },
        Role.SECURITY_ANALYST: {
            Permission.VERIFICATION_CREATE,
            Permission.VERIFICATION_READ,
            Permission.POLICY_MANAGE,
            Permission.AUDIT_READ,
            Permission.API_KEY_MANAGE,
        },
        Role.DEVELOPER: {
            Permission.VERIFICATION_CREATE,
            Permission.VERIFICATION_READ,
        },
        Role.AUDITOR: {
            Permission.VERIFICATION_READ,
            Permission.AUDIT_READ,
        },
        Role.VIEWER: {
            Permission.VERIFICATION_READ,
        },
        Role.CI_SERVICE: {
            Permission.VERIFICATION_CREATE,
            Permission.VERIFICATION_READ,
        },
    }

    for role, expected in roles_expected_perms.items():
        effective = get_effective_permissions(role, scopes=None)
        assert effective == expected, (
            f"Role {role} permission mismatch: got {effective}, expected {expected}"
        )


def test_unauthenticated_request_rejected_401():
    """Verifies that missing authentication headers produce an immediate HTTP 401."""
    resp = client.get("/api/v1/verifications")
    assert resp.status_code == 401
    assert "Authorization header or X-API-Key required" in resp.json()["detail"]


def test_insufficient_role_rejected_403():
    """Verifies VIEWER role attempting to create verification is denied with HTTP 403."""
    org_id = uuid.uuid4()
    viewer_token = mint_dev_token("viewer-user", org_id, Role.VIEWER)

    resp = client.post(
        "/api/v1/verifications",
        headers={"Authorization": f"Bearer {viewer_token}"},
        json={
            "organization_id": str(org_id),
            "project_id": str(uuid.uuid4()),
            "production_artifact_id": str(uuid.uuid4()),
        },
    )
    assert resp.status_code == 403
    assert "Insufficient permissions" in resp.json()["detail"]


def test_client_supplied_organization_id_mismatch_denied_403():
    """Verifies client-supplied organization_id mismatching AuthUser identity returns HTTP 403."""
    org_a = uuid.uuid4()
    org_b = uuid.uuid4()
    token_a = mint_dev_token("user-a", org_a, Role.DEVELOPER)

    resp = client.post(
        "/api/v1/verifications",
        headers={"Authorization": f"Bearer {token_a}"},
        json={
            "organization_id": str(org_b),  # Client attempt to override tenant identity
            "project_id": str(uuid.uuid4()),
            "production_artifact_id": str(uuid.uuid4()),
        },
    )
    assert resp.status_code == 403
    assert "organization_id" in resp.json()["detail"].lower()


def test_scope_intersection_semantics():
    """Verifies that narrow credential scopes restrict base role permissions ($Role \\cap Scopes$)."""
    org_id = uuid.uuid4()
    # SECURITY_ANALYST base role would normally allow API_KEY_MANAGE, but credential scope restricts to VERIFICATION_READ
    narrow_token = mint_dev_token(
        "user-narrow", org_id, Role.SECURITY_ANALYST, scopes=["VERIFICATION_READ"]
    )

    # Attempt API key management with narrow token -> HTTP 403
    resp = client.get(
        "/api/v1/auth/api-keys",
        headers={"Authorization": f"Bearer {narrow_token}"},
    )
    assert resp.status_code == 403
    assert "Insufficient permissions" in resp.json()["detail"]


def test_auth_tenant_context_transaction_local():
    """Verifies app.current_tenant_id resets after transaction completes (is_local=true)."""
    db_mgr = DatabaseManager()
    if db_mgr.db_url.startswith("sqlite"):
        return

    org_id = uuid.uuid4()
    with db_mgr.get_session() as session:
        db_mgr.set_tenant_context(session, org_id)
        val = session.execute(
            text("SELECT current_setting('app.current_tenant_id', true)")
        ).scalar()
        assert val == str(org_id)

    # In a new session/transaction, app.current_tenant_id must be empty/None
    with db_mgr.get_session() as session:
        val_new = session.execute(
            text("SELECT current_setting('app.current_tenant_id', true)")
        ).scalar()
        assert val_new is None or val_new == ""


def test_connection_pool_tenant_context_leakage_prevention():
    """Verifies tenant context does not leak across pooled database connections."""
    db_mgr = DatabaseManager()
    if db_mgr.db_url.startswith("sqlite"):
        return

    org_a = uuid.uuid4()
    org_b = uuid.uuid4()

    # Transaction 1 sets Org A
    with db_mgr.get_session() as session1:
        db_mgr.set_tenant_context(session1, org_a)

    # Transaction 2 sets Org B
    with db_mgr.get_session() as session2:
        db_mgr.set_tenant_context(session2, org_b)
        val_b = session2.execute(
            text("SELECT current_setting('app.current_tenant_id', true)")
        ).scalar()
        assert val_b == str(org_b)

    # Transaction 3 with no setting must be clean
    with db_mgr.get_session() as session3:
        val_clean = session3.execute(
            text("SELECT current_setting('app.current_tenant_id', true)")
        ).scalar()
        assert val_clean is None or val_clean == ""
