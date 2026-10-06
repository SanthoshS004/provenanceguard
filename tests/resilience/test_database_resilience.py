"""Phase 18 Database Fault Injection & Transactional Invariant Tests.

Verifies exact HTTP 500 status code on database disconnections,
asserts zero leakage of tracebacks/credentials in responses,
and validates transactional rollback atomicity.
"""

import uuid
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.exc import OperationalError

from provenanceguard.apps.api.auth import mint_dev_token
from provenanceguard.apps.api.main import app
from provenanceguard.apps.api.rbac import Role
from provenanceguard.infrastructure.database.models import (
    ArtifactModel,
    OrganizationModel,
    OutboxEventModel,
    ProjectModel,
    VerificationRunModel,
)
from provenanceguard.infrastructure.database.session import DatabaseManager


@pytest.fixture
def api_client():
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture
def auth_headers():
    org_id = uuid.UUID("00000000-0000-0000-0000-000000000001")
    token = mint_dev_token(user_id="test-user", organization_id=org_id, role=Role.ADMIN)
    return {"Authorization": f"Bearer {token}"}


def test_database_disconnection_returns_exact_http_500_and_no_leakage(api_client, auth_headers):
    """Verifies API returns exact HTTP 500 on database failure without leaking stack traces or SQL strings."""
    with patch(
        "provenanceguard.apps.api.routes_verifications.DatabaseManager.get_session",
        side_effect=OperationalError("SELECT 1", {}, Exception("Connection refused")),
    ):
        payload = {
            "organization_id": "00000000-0000-0000-0000-000000000001",
            "project_id": "00000000-0000-0000-0000-000000000002",
            "production_artifact_id": str(uuid.uuid4()),
        }
        response = api_client.post("/api/v1/verifications", json=payload, headers=auth_headers)

        assert response.status_code == 500

        body_text = response.text.lower()
        assert "traceback" not in body_text
        assert "connection refused" not in body_text
        assert "select 1" not in body_text
        assert "password" not in body_text
        assert "postgres" not in body_text


def test_database_transactional_rollback_invariants():
    """Verifies that database exceptions during creation result in complete transaction rollback."""
    db_mgr = DatabaseManager()
    org_id = uuid.uuid4()
    proj_id = uuid.uuid4()
    art_id = uuid.uuid4()
    run_id = uuid.uuid4()

    with db_mgr.get_session() as session:
        org = OrganizationModel(
            id=org_id, name=f"Org_{str(org_id)[:8]}", slug=f"slug_{str(org_id)[:8]}"
        )
        session.add(org)
        session.flush()

        proj = ProjectModel(id=proj_id, organization_id=org_id, name="P1")
        session.add(proj)
        session.flush()

        art = ArtifactModel(
            id=art_id,
            project_id=proj_id,
            organization_id=org_id,
            name="art",
            version="1.0",
            media_type="application/vnd.elf",
            digest_sha256="b" * 64,
            size_bytes=100,
            storage_path="/path",
        )
        session.add(art)
        session.flush()

        try:
            with session.begin_nested():
                run = VerificationRunModel(
                    id=run_id,
                    organization_id=org_id,
                    project_id=proj_id,
                    production_artifact_id=art_id,
                    status="QUEUED",
                    decision="PENDING",
                    risk_score=0,
                    attempt_count=1,
                )
                session.add(run)
                session.flush()
                raise OperationalError("FORCE ROLLBACK", {}, Exception("Simulated DB Crash"))
        except OperationalError:
            session.rollback()

        query_run = session.query(VerificationRunModel).filter_by(id=run_id).first()
        assert query_run is None

        query_outbox = session.query(OutboxEventModel).filter_by(aggregate_id=run_id).first()
        assert query_outbox is None
