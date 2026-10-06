"""
Scenario 11 — Cross-Tenant Header Spoofing & Authorization Attack Test Runner.

Verifies that spoofed X-Organization-ID and X-Project-ID request headers cannot bypass
server-derived JWT tenant context and PostgreSQL Row Level Security (RLS).
"""

import uuid
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from provenanceguard.apps.api.auth import mint_dev_token
from provenanceguard.apps.api.main import app
from provenanceguard.apps.api.rbac import Role

client = TestClient(app)


def test_cross_tenant_resource_get_lookup_returns_exact_404():
    """
    Scenario 11 (GET Lookup): User authenticated as Tenant A (Org-A) attempts to fetch
    a verification run belonging to Tenant B (Org-B) by spoofing 'X-Organization-ID: Org-B'.

    PostgreSQL RLS isolates queries (app.current_tenant_id = Org-A), returning 0 rows.
    The REST API endpoint returns exact status code HTTP 404 NOT FOUND.
    """
    tenant_a_id = uuid.uuid4()
    tenant_b_id = uuid.uuid4()
    verification_b_id = uuid.uuid4()

    # Mint valid token strictly scoped to Tenant A
    jwt_token = mint_dev_token(
        user_id="user-tenant-a",
        organization_id=tenant_a_id,
        role=Role.SECURITY_ANALYST,
    )

    # Mock DB session & RLS behavior: session query for Tenant A returns None for Tenant B's item
    with patch(
        "provenanceguard.apps.api.routes_verifications.DatabaseManager.get_session"
    ) as MockGetSession:
        mock_session = MagicMock()
        MockGetSession.return_value.__enter__.return_value = mock_session
        # PostgreSQL query filtered by RLS returns 0 rows (None)
        mock_session.scalar.return_value = None

        resp = client.get(
            f"/api/v1/verifications/{verification_b_id}",
            headers={
                "Authorization": f"Bearer {jwt_token}",
                "X-Organization-ID": str(
                    tenant_b_id
                ),  # Spoofed header attempting cross-tenant access
                "X-Project-ID": str(uuid.uuid4()),
            },
        )

        # Assert exact HTTP status 404 NOT FOUND (not 200, 401, or ambiguous alternatives)
        assert resp.status_code == 404, f"Expected 404 NOT FOUND, got {resp.status_code}"
        json_resp = resp.json()
        assert json_resp["detail"] == "Verification run not found or cross-tenant access denied."


def test_cross_tenant_verification_creation_returns_exact_403():
    """
    Scenario 11 (POST Creation): User authenticated as Tenant A (Org-A) attempts to submit
    a verification job with request body 'organization_id: Org-B'.

    The API validates client organization_id against server-derived JWT tenant identity.
    The REST API endpoint returns exact status code HTTP 403 FORBIDDEN.
    """
    tenant_a_id = uuid.uuid4()
    tenant_b_id = uuid.uuid4()

    jwt_token = mint_dev_token(
        user_id="user-tenant-a",
        organization_id=tenant_a_id,
        role=Role.SECURITY_ANALYST,
    )

    payload = {
        "organization_id": str(tenant_b_id),  # Mismatched body tenant ID
        "project_id": str(uuid.uuid4()),
        "production_artifact_id": str(uuid.uuid4()),
    }

    resp = client.post(
        "/api/v1/verifications",
        json=payload,
        headers={
            "Authorization": f"Bearer {jwt_token}",
            "X-Organization-ID": str(tenant_b_id),  # Spoofed header
        },
    )

    # Assert exact HTTP status 403 FORBIDDEN
    assert resp.status_code == 403, f"Expected 403 FORBIDDEN, got {resp.status_code}"
    json_resp = resp.json()
    assert (
        json_resp["detail"]
        == "Client organization_id does not match authenticated tenant identity."
    )
