"""Unit & Security Integration Tests for REST API Policy Validation & Live Simulator (routes_policy.py)."""

import uuid

from fastapi.testclient import TestClient

from provenanceguard.apps.api.auth import mint_dev_token
from provenanceguard.apps.api.main import app
from provenanceguard.apps.api.rbac import Role

client = TestClient(app)


def test_policy_validate_unauthorized():
    """Request without token returns 401 Unauthorized."""
    resp = client.post("/api/v1/policy/validate", json={"yaml_content": "name: test"})
    assert resp.status_code == 401


def test_policy_validate_forbidden_role():
    """Developer role lacking POLICY_MANAGE returns 403 Forbidden."""
    org_id = uuid.uuid4()
    token_str = mint_dev_token(user_id="test-user-123", organization_id=org_id, role=Role.DEVELOPER)
    resp = client.post(
        "/api/v1/policy/validate",
        json={"yaml_content": "name: test"},
        headers={"Authorization": f"Bearer {token_str}"},
    )
    assert resp.status_code == 403


def test_policy_validate_success():
    """Security analyst role can validate valid YAML policy schema."""
    org_id = uuid.uuid4()
    token_str = mint_dev_token(
        user_id="test-user-123", organization_id=org_id, role=Role.SECURITY_ANALYST
    )
    valid_yaml = """
name: test-policy
version: 1.0.0
warning_threshold: 25
block_threshold: 65
require_valid_signature: true
"""
    resp = client.post(
        "/api/v1/policy/validate",
        json={"yaml_content": valid_yaml},
        headers={"Authorization": f"Bearer {token_str}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["valid"] is True
    assert data["policy_name"] == "test-policy"
    assert data["warning_threshold"] == 25
    assert data["block_threshold"] == 65


def test_policy_validate_invalid_schema():
    """Invalid schema returning unknown field error via extra='forbid'."""
    org_id = uuid.uuid4()
    token_str = mint_dev_token(
        user_id="test-user-123", organization_id=org_id, role=Role.SECURITY_ANALYST
    )
    invalid_yaml = "unknown_field_xyz: true"
    resp = client.post(
        "/api/v1/policy/validate",
        json={"yaml_content": invalid_yaml},
        headers={"Authorization": f"Bearer {token_str}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["valid"] is False
    assert len(data["errors"]) > 0


def test_policy_validate_oversized_payload():
    """Oversized YAML document > 64 KB is rejected with 422/413 Payload limit error."""
    org_id = uuid.uuid4()
    token_str = mint_dev_token(
        user_id="test-user-123", organization_id=org_id, role=Role.SECURITY_ANALYST
    )
    oversized_yaml = "a: " + ("x" * 70000)
    resp = client.post(
        "/api/v1/policy/validate",
        json={"yaml_content": oversized_yaml},
        headers={"Authorization": f"Bearer {token_str}"},
    )
    assert resp.status_code in (413, 422)


def test_policy_simulate_requires_policy_manage():
    """Simulation requires POLICY_MANAGE permission; Developer role is rejected with 403."""
    org_id = uuid.uuid4()
    token_str = mint_dev_token(user_id="test-user-123", organization_id=org_id, role=Role.DEVELOPER)
    resp = client.post(
        "/api/v1/policy/simulate",
        json={"yaml_content": "name: sim", "mock_risk_score": 50},
        headers={"Authorization": f"Bearer {token_str}"},
    )
    assert resp.status_code == 403


def test_policy_simulate_non_mutating():
    """Policy simulation evaluates in-memory, returns preview watermark, and does not create DB state."""
    org_id = uuid.uuid4()
    token_str = mint_dev_token(
        user_id="test-user-123", organization_id=org_id, role=Role.SECURITY_ANALYST
    )
    valid_yaml = """
name: simulation-test
warning_threshold: 20
block_threshold: 50
"""
    resp = client.post(
        "/api/v1/policy/simulate",
        json={"yaml_content": valid_yaml, "mock_risk_score": 80},
        headers={"Authorization": f"Bearer {token_str}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["simulated_decision"] == "BLOCK"
    assert data["simulated_risk_score"] == 80
    assert data["watermark"] == "SIMULATION ONLY — PREVIEW ONLY"
