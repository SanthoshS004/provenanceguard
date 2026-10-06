"""Phase 18 Malformed & Corrupt Payload Resilience Tests.

Verifies exact HTTP 400 / 422 status on malformed JSON bytes and
exact HTTP 422 status on Pydantic request schema validation failures.
"""

import uuid

import pytest
from fastapi.testclient import TestClient

from provenanceguard.apps.api.auth import mint_dev_token
from provenanceguard.apps.api.main import app
from provenanceguard.apps.api.rbac import Role


@pytest.fixture
def api_client():
    return TestClient(app)


@pytest.fixture
def auth_headers():
    org_id = uuid.UUID("00000000-0000-0000-0000-000000000001")
    token = mint_dev_token(user_id="test-user", organization_id=org_id, role=Role.ADMIN)
    return {"Authorization": f"Bearer {token}"}


def test_malformed_json_bytes_returns_exact_http_400_or_422(api_client, auth_headers):
    """Verifies that submitting raw non-JSON byte payloads returns exact HTTP 400 Bad Request or HTTP 422 Unprocessable Entity."""
    raw_headers = dict(auth_headers)
    raw_headers["Content-Type"] = "application/json"

    response = api_client.post(
        "/api/v1/verifications",
        content=b"{ invalid json payload syntax ...",
        headers=raw_headers,
    )
    assert response.status_code in (400, 422)
    assert "detail" in response.json()


def test_invalid_schema_fields_returns_exact_http_422(api_client, auth_headers):
    """Verifies that submitting schema-invalid JSON returns exact HTTP 422 Unprocessable Entity."""
    payload = {
        "organization_id": "invalid-uuid-format",
        "project_id": "00000000-0000-0000-0000-000000000002",
        "production_artifact_id": "00000000-0000-0000-0000-000000000003",
    }
    response = api_client.post("/api/v1/verifications", json=payload, headers=auth_headers)
    assert response.status_code == 422
    assert "detail" in response.json()


def test_prohibited_extra_fields_returns_exact_http_422(api_client, auth_headers):
    """Verifies that extra forbidden body fields return exact HTTP 422 Unprocessable Entity."""
    payload = {
        "organization_id": "00000000-0000-0000-0000-000000000001",
        "project_id": "00000000-0000-0000-0000-000000000002",
        "production_artifact_id": "00000000-0000-0000-0000-000000000003",
        "unauthorized_extra_field": "malicious_injection",
    }
    response = api_client.post("/api/v1/verifications", json=payload, headers=auth_headers)
    assert response.status_code == 422
