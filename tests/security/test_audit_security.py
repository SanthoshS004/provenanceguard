"""Audit log immutability and sanitization security tests for ProvenanceGuard."""

import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from provenanceguard.apps.api.auth import mint_dev_token
from provenanceguard.apps.api.main import app
from provenanceguard.apps.api.rbac import Role
from provenanceguard.infrastructure.database.models import (
    AuditLogModel,
    Base,
    OrganizationModel,
)
from provenanceguard.infrastructure.database.repositories import (
    AuditImmutabilityError,
    AuditLogRepository,
)
from provenanceguard.infrastructure.database.session import DatabaseManager
from provenanceguard.infrastructure.database.tenant_context import TenantContext

client = TestClient(app)


def test_audit_log_append_only_and_sanitization_security():
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()

    org_id = uuid.uuid4()
    tenant_ctx = TenantContext(organization_id=org_id)
    audit_repo = AuditLogRepository(tenant_context=tenant_ctx)

    raw_metadata = {
        "user_email": "alice@example.com",
        "api_key": "secret_api_key_12345",
        "nested": {"password": "super_secret_password"},
    }

    entry = audit_repo.log_event(
        session=session,
        actor_id="user_123",
        action="LOGIN",
        resource="portal",
        result="SUCCESS",
        metadata_json=raw_metadata,
    )
    session.commit()

    assert entry.id is not None
    assert entry.metadata_json["user_email"] == "alice@example.com"
    assert entry.metadata_json["api_key"] == "[REDACTED]"
    assert entry.metadata_json["nested"]["password"] == "[REDACTED]"

    with pytest.raises(AuditImmutabilityError):
        audit_repo.update()

    with pytest.raises(AuditImmutabilityError):
        audit_repo.delete()

    session.close()


def test_audit_log_secret_exclusion_comprehensive():
    """Verifies that raw JWTs, raw API keys, Authorization headers, and secrets are NEVER logged in audit records."""
    org_id = uuid.uuid4()
    db_mgr = DatabaseManager()

    with db_mgr.get_session() as session:
        org = OrganizationModel(
            id=org_id, name=f"Org_{org_id.hex[:8]}", slug=f"slug_{org_id.hex[:8]}"
        )
        session.add(org)
        session.commit()

    admin_token = mint_dev_token("user-admin-audit", org_id, Role.ADMIN)
    viewer_token = mint_dev_token("user-viewer-audit", org_id, Role.VIEWER)
    bad_token = (
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJtYWxpY2lvdXMiLCJpc3MiOiJiYWQifQ.fake"
    )

    # 1. Successful JWT Authentication
    res_succ_jwt = client.get(
        "/api/v1/verifications", headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert res_succ_jwt.status_code == 200

    # 2. Failed JWT Authentication
    res_fail_jwt = client.get(
        "/api/v1/verifications", headers={"Authorization": f"Bearer {bad_token}"}
    )
    assert res_fail_jwt.status_code == 401

    # 3. API Key Creation
    res_key_create = client.post(
        "/api/v1/auth/api-keys",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"name": "audit-test-key", "role": "SECURITY_ANALYST"},
    )
    assert res_key_create.status_code == 201
    key_data = res_key_create.json()
    raw_api_key = key_data["api_key"]
    key_id = key_data["id"]

    # 4. API Key Authentication
    res_key_auth = client.get("/api/v1/verifications", headers={"X-API-Key": raw_api_key})
    assert res_key_auth.status_code == 200

    # 5. API Key Revocation
    res_key_revoke = client.delete(
        f"/api/v1/auth/api-keys/{key_id}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert res_key_revoke.status_code in (200, 204)

    # 6. RBAC Denial
    res_rbac_deny = client.post(
        "/api/v1/verifications",
        headers={"Authorization": f"Bearer {viewer_token}"},
        json={
            "organization_id": str(org_id),
            "project_id": str(uuid.uuid4()),
            "production_artifact_id": str(uuid.uuid4()),
        },
    )
    assert res_rbac_deny.status_code == 403

    # Inspect all audit logs recorded for this tenant organization
    with db_mgr.get_session() as session:
        db_mgr.set_tenant_context(session, org_id)
        audit_rows = session.scalars(
            select(AuditLogModel).where(AuditLogModel.organization_id == org_id)
        ).all()

        for row in audit_rows:
            meta_str = str(row.metadata_json or {})
            full_row_str = f"{row.actor_id} {row.action} {row.resource} {row.result} {meta_str}"

            # ASSERT SECRETS DO NOT APPEAR IN AUDIT LOGS
            assert admin_token not in full_row_str, "CRITICAL: Raw admin JWT leaked into audit log!"
            assert viewer_token not in full_row_str, (
                "CRITICAL: Raw viewer JWT leaked into audit log!"
            )
            assert bad_token not in full_row_str, "CRITICAL: Malicious JWT leaked into audit log!"
            assert raw_api_key not in full_row_str, "CRITICAL: Raw API key leaked into audit log!"
            assert "Authorization" not in meta_str, (
                "CRITICAL: Authorization header leaked into audit log!"
            )
            assert "Bearer " not in full_row_str, (
                "CRITICAL: Bearer token prefix leaked into audit log!"
            )
