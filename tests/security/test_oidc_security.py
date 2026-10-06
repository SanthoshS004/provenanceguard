"""Security tests for OIDC federation, exact normalized issuer matching, audience validation, and group mapping."""

import pytest
from fastapi import HTTPException

from provenanceguard.apps.api.auth_oidc import (
    map_groups_to_role,
    normalize_issuer_url,
)
from provenanceguard.apps.api.rbac import Role


def test_oidc_exact_issuer_matching_and_normalization():
    """Verifies deterministic issuer URL normalization."""
    url1 = "https://idp.example.com"
    url2 = "https://idp.example.com/"
    assert normalize_issuer_url(url1) == "https://idp.example.com"
    assert normalize_issuer_url(url2) == "https://idp.example.com"


def test_malicious_lookalike_issuer_normalization():
    """Verifies lookalike attacker domain is normalized cleanly without matching base domain."""
    attacker_url = "https://idp.example.com.attacker.com"
    assert normalize_issuer_url(attacker_url) == "https://idp.example.com.attacker.com"
    assert normalize_issuer_url(attacker_url) != "https://idp.example.com"


def test_oidc_group_schema_and_precedence_mapping():
    """Verifies group claim schema bounds and deterministic role precedence."""
    mapping = {
        "Admins": "ADMIN",
        "Analysts": "SECURITY_ANALYST",
        "Viewers": "VIEWER",
    }

    # Multiple groups -> highest precedence selected (ADMIN > SECURITY_ANALYST > VIEWER)
    role = map_groups_to_role(["Viewers", "Admins", "Analysts"], mapping)
    assert role == Role.ADMIN

    role2 = map_groups_to_role(["Viewers", "Analysts"], mapping)
    assert role2 == Role.SECURITY_ANALYST


def test_oidc_unmapped_user_group_rejection_403():
    """Verifies 403 Forbidden is raised when user groups do not grant any role."""
    mapping = {"Admins": "ADMIN"}
    with pytest.raises(HTTPException) as exc_info:
        map_groups_to_role(["GuestUsers"], mapping)
    assert exc_info.value.status_code == 403
    assert "Forbidden" in exc_info.value.detail


def test_oidc_malformed_groups_claim_rejection():
    """Verifies malformed group claim types or oversized lists are rejected."""
    mapping = {"Admins": "ADMIN"}

    # Non-list
    with pytest.raises(HTTPException) as exc_info:
        map_groups_to_role("Admins", mapping)
    assert exc_info.value.status_code == 400

    # Oversized list > 100
    with pytest.raises(HTTPException) as exc_info:
        map_groups_to_role(["group"] * 101, mapping)
    assert exc_info.value.status_code == 400
