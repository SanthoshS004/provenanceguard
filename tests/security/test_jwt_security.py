"""Comprehensive RS256 JWT Security Test Suite for ProvenanceGuard."""

import datetime
import uuid
from datetime import timezone

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from provenanceguard.apps.api.auth import mint_dev_token
from provenanceguard.apps.api.main import app
from provenanceguard.apps.api.rbac import Role

client = TestClient(app)


def test_valid_rs256_jwt_authentication_success():
    """Verifies that a properly signed RS256 JWT authenticates successfully."""
    org_id = uuid.uuid4()
    token = mint_dev_token("user-valid", org_id, Role.SECURITY_ANALYST)

    resp = client.get("/api/v1/verifications", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


def test_wrong_rsa_public_key_rejection_401():
    """Verifies that a JWT signed with an unknown RSA key is rejected with HTTP 401."""
    org_id = uuid.uuid4()
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    other_pem = other_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    token = mint_dev_token("user-badkey", org_id, Role.SECURITY_ANALYST, private_key_pem=other_pem)

    resp = client.get("/api/v1/verifications", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 401
    assert "Invalid or expired credentials" in resp.json().get(
        "detail", ""
    ) or "JWT" in resp.json().get("detail", "")


def test_hs256_algorithm_rejection_401():
    """Verifies that an HS256 JWT is explicitly rejected with HTTP 401."""
    now = datetime.datetime.now(timezone.utc)
    payload = {
        "iss": "provenanceguard",
        "aud": "provenanceguard-api",
        "sub": "user-hs256",
        "exp": int((now + datetime.timedelta(seconds=3600)).timestamp()),
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "organization_id": str(uuid.uuid4()),
        "role": "SECURITY_ANALYST",
        "jti": str(uuid.uuid4()),
    }
    hs256_token = jwt.encode(payload, "secret-key-1234567890-super-secret", algorithm="HS256")

    resp = client.get("/api/v1/verifications", headers={"Authorization": f"Bearer {hs256_token}"})
    assert resp.status_code == 401
    assert "RS256" in resp.json()["detail"] or "algorithm" in resp.json()["detail"]


def test_alg_none_rejection_401():
    """Verifies that a JWT with alg=none is explicitly rejected with HTTP 401."""
    now = datetime.datetime.now(timezone.utc)
    payload = {
        "iss": "provenanceguard",
        "aud": "provenanceguard-api",
        "sub": "user-none",
        "exp": int((now + datetime.timedelta(seconds=3600)).timestamp()),
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "organization_id": str(uuid.uuid4()),
        "role": "SECURITY_ANALYST",
        "jti": str(uuid.uuid4()),
    }
    none_token = jwt.encode(payload, "", algorithm="none")

    resp = client.get("/api/v1/verifications", headers={"Authorization": f"Bearer {none_token}"})
    assert resp.status_code == 401
    assert "RS256" in resp.json()["detail"] or "algorithm" in resp.json()["detail"]


def test_expired_jwt_rejection_401():
    """Verifies that an expired RS256 JWT is rejected with HTTP 401."""
    org_id = uuid.uuid4()
    expired_token = mint_dev_token(
        "user-expired", org_id, Role.SECURITY_ANALYST, expires_in_seconds=-3600
    )

    resp = client.get("/api/v1/verifications", headers={"Authorization": f"Bearer {expired_token}"})
    assert resp.status_code == 401
    assert "expired" in resp.json()["detail"].lower()


def test_wrong_issuer_rejection_401():
    """Verifies that a JWT with an invalid issuer is rejected with HTTP 401."""
    org_id = uuid.uuid4()
    bad_iss_token = mint_dev_token(
        "user-badiss", org_id, Role.SECURITY_ANALYST, issuer="malicious-issuer"
    )

    resp = client.get("/api/v1/verifications", headers={"Authorization": f"Bearer {bad_iss_token}"})
    assert resp.status_code == 401
    assert "issuer" in resp.json()["detail"].lower()


def test_wrong_audience_rejection_401():
    """Verifies that a JWT with an invalid audience is rejected with HTTP 401."""
    org_id = uuid.uuid4()
    bad_aud_token = mint_dev_token(
        "user-badaud", org_id, Role.SECURITY_ANALYST, audience="malicious-audience"
    )

    resp = client.get("/api/v1/verifications", headers={"Authorization": f"Bearer {bad_aud_token}"})
    assert resp.status_code == 401
    assert "audience" in resp.json()["detail"].lower()


def test_oversized_jwt_rejection_401():
    """Verifies that an oversized JWT (> 8 KB) is rejected with HTTP 401."""
    oversized_token = "eyJ" + "a" * 8200

    resp = client.get(
        "/api/v1/verifications", headers={"Authorization": f"Bearer {oversized_token}"}
    )
    assert resp.status_code == 401
    assert "8 KB" in resp.json()["detail"] or "Malformed" in resp.json()["detail"]


def test_missing_issuer_rejection_401():
    """Verifies that a JWT missing the required iss claim is rejected with HTTP 401."""
    from provenanceguard.apps.api.auth import get_jwt_private_key

    now = datetime.datetime.now(timezone.utc)
    priv_key = get_jwt_private_key()
    payload = {
        "aud": "provenanceguard-api",
        "sub": "user-noiss",
        "exp": int((now + datetime.timedelta(seconds=3600)).timestamp()),
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "organization_id": str(uuid.uuid4()),
        "role": "SECURITY_ANALYST",
        "jti": str(uuid.uuid4()),
    }
    token = jwt.encode(payload, priv_key, algorithm="RS256")
    resp = client.get("/api/v1/verifications", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 401


def test_missing_audience_rejection_401():
    """Verifies that a JWT missing the required aud claim is rejected with HTTP 401."""
    from provenanceguard.apps.api.auth import get_jwt_private_key

    now = datetime.datetime.now(timezone.utc)
    priv_key = get_jwt_private_key()
    payload = {
        "iss": "provenanceguard",
        "sub": "user-noaud",
        "exp": int((now + datetime.timedelta(seconds=3600)).timestamp()),
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "organization_id": str(uuid.uuid4()),
        "role": "SECURITY_ANALYST",
        "jti": str(uuid.uuid4()),
    }
    token = jwt.encode(payload, priv_key, algorithm="RS256")
    resp = client.get("/api/v1/verifications", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 401
