"""Unit & Security Integration Tests for REST API Audit Log Endpoint (routes_audit.py)."""

import uuid
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from provenanceguard.apps.api.auth import mint_dev_token
from provenanceguard.apps.api.main import app
from provenanceguard.apps.api.rbac import Role
from provenanceguard.infrastructure.database.models import AuditLogModel, utc_now

client = TestClient(app)


def test_audit_log_unauthorized():
    """Request without token returns 401 Unauthorized."""
    resp = client.get("/api/v1/audit-log")
    assert resp.status_code == 401


def test_audit_log_insufficient_permissions():
    """Developer role lacking AUDIT_READ returns 403 Forbidden."""
    org_id = uuid.uuid4()
    token_str = mint_dev_token(user_id="test-user-123", organization_id=org_id, role=Role.DEVELOPER)
    resp = client.get(
        "/api/v1/audit-log",
        headers={"Authorization": f"Bearer {token_str}"},
    )
    assert resp.status_code == 403


def test_audit_log_query_success_and_bounded_pagination():
    """Auditor role can query audit log stream with bounded pagination limits."""
    org_id = uuid.uuid4()
    token_str = mint_dev_token(user_id="test-user-123", organization_id=org_id, role=Role.AUDITOR)

    dummy_log = AuditLogModel(
        id=uuid.uuid4(),
        organization_id=org_id,
        sequence_number=1,
        actor_id="user-123",
        action="VERIFICATION_RUN",
        resource="artifact-abc",
        result="PASS",
        previous_hash="0" * 64,
        current_hash="0" * 64,
        created_at=utc_now(),
        metadata_json={"risk_score": 10},
    )

    with patch("provenanceguard.apps.api.routes_audit.AuditLogRepository") as MockRepoClass:
        mock_repo_inst = MagicMock()
        mock_repo_inst.query_events.return_value = ([dummy_log], 1)
        MockRepoClass.return_value = mock_repo_inst

        with patch("provenanceguard.apps.api.routes_audit.DatabaseManager.get_session"):
            # Query within le=100 boundary returns 200
            resp = client.get(
                "/api/v1/audit-log?limit=100&offset=0",
                headers={"Authorization": f"Bearer {token_str}"},
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data["total"] == 1
            assert data["limit"] == 100
            assert len(data["items"]) == 1
            assert data["items"][0]["action"] == "VERIFICATION_RUN"

            # Query exceeding le=100 boundary is rejected by FastAPI with 422
            resp_exceed = client.get(
                "/api/v1/audit-log?limit=500&offset=0",
                headers={"Authorization": f"Bearer {token_str}"},
            )
            assert resp_exceed.status_code == 422


def test_audit_log_tenant_isolation_untrusted_header_override():
    """Audit log queries enforce server-derived tenant isolation and ignore header spoofing."""
    real_org_id = uuid.uuid4()
    spoofed_org_id = uuid.uuid4()
    token_str = mint_dev_token(
        user_id="test-user-123", organization_id=real_org_id, role=Role.AUDITOR
    )

    with patch("provenanceguard.apps.api.routes_audit.AuditLogRepository") as MockRepoClass:
        mock_repo_inst = MagicMock()
        mock_repo_inst.query_events.return_value = ([], 0)
        MockRepoClass.return_value = mock_repo_inst

        with patch("provenanceguard.apps.api.routes_audit.DatabaseManager.get_session"):
            resp = client.get(
                "/api/v1/audit-log",
                headers={
                    "Authorization": f"Bearer {token_str}",
                    "X-Organization-ID": str(spoofed_org_id),
                },
            )
            assert resp.status_code == 200
            tenant_ctx_passed = MockRepoClass.call_args[0][0]
            assert tenant_ctx_passed.organization_id == real_org_id
            assert tenant_ctx_passed.organization_id != spoofed_org_id
