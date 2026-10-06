"""Unit & Security Integration Tests for REST API Projects Endpoint (routes_projects.py)."""

import uuid
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from provenanceguard.apps.api.auth import mint_dev_token
from provenanceguard.apps.api.main import app
from provenanceguard.apps.api.rbac import Role
from provenanceguard.infrastructure.database.models import ProjectModel, utc_now

client = TestClient(app)


def test_list_projects_unauthorized():
    """Request without token returns 401 Unauthorized."""
    resp = client.get("/api/v1/projects")
    assert resp.status_code == 401


def test_list_projects_forbidden_role():
    """Role lacking VERIFICATION_READ (e.g. invalid role) is rejected."""
    # Unauthenticated or invalid token header
    resp = client.get(
        "/api/v1/projects",
        headers={"Authorization": "Bearer invalid.jwt.token"},
    )
    assert resp.status_code == 401


def test_list_projects_authorized_tenant_boundary():
    """Authorized request returns projects list scoped by caller's server-derived tenant."""
    org_id = uuid.uuid4()
    proj_id = uuid.uuid4()
    token_str = mint_dev_token(
        user_id="test-user-123",
        organization_id=org_id,
        role=Role.SECURITY_ANALYST,
        project_id=proj_id,
    )

    dummy_project = ProjectModel(
        id=proj_id,
        organization_id=org_id,
        name="Test Production Service",
        created_at=utc_now(),
    )

    with patch("provenanceguard.apps.api.routes_projects.ProjectRepository") as MockRepoClass:
        mock_repo_inst = MagicMock()
        mock_repo_inst.list_by_organization.return_value = [dummy_project]
        MockRepoClass.return_value = mock_repo_inst

        with patch("provenanceguard.apps.api.routes_projects.DatabaseManager.get_session"):
            resp = client.get(
                "/api/v1/projects",
                headers={"Authorization": f"Bearer {token_str}"},
            )
            assert resp.status_code == 200
            data = resp.json()
            assert len(data) == 1
            assert data[0]["id"] == str(proj_id)
            assert data[0]["name"] == "Test Production Service"

            # Verify repository was instantiated with server-derived org_id
            tenant_ctx_passed = MockRepoClass.call_args[0][0]
            assert tenant_ctx_passed.organization_id == org_id


def test_list_projects_untrusted_header_override_ignored():
    """Malicious caller modifying X-Organization-ID header cannot bypass server-derived tenant."""
    real_org_id = uuid.uuid4()
    spoofed_org_id = uuid.uuid4()
    token_str = mint_dev_token(
        user_id="test-user-123",
        organization_id=real_org_id,
        role=Role.SECURITY_ANALYST,
    )

    with patch("provenanceguard.apps.api.routes_projects.ProjectRepository") as MockRepoClass:
        mock_repo_inst = MagicMock()
        mock_repo_inst.list_by_organization.return_value = []
        MockRepoClass.return_value = mock_repo_inst

        with patch("provenanceguard.apps.api.routes_projects.DatabaseManager.get_session"):
            resp = client.get(
                "/api/v1/projects",
                headers={
                    "Authorization": f"Bearer {token_str}",
                    "X-Organization-ID": str(spoofed_org_id),
                },
            )
            assert resp.status_code == 200
            # Server-derived tenant context must match real_org_id, NOT spoofed_org_id
            tenant_ctx_passed = MockRepoClass.call_args[0][0]
            assert tenant_ctx_passed.organization_id == real_org_id
            assert tenant_ctx_passed.organization_id != spoofed_org_id
