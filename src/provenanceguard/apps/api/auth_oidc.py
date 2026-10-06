"""OIDC / OAuth2 Enterprise Identity Provider Federation Module.

Implements exact normalized issuer matching, server-derived tenant identity,
dual-stage SSRF JWKS fetching via IPPinningTransport, strict RS256 validation,
audience enforcement, group claim schema validation, and deterministic role precedence mapping.
"""

from __future__ import annotations

import os
import time
import urllib.parse
from typing import Any
from uuid import UUID

import jwt
from fastapi import HTTPException, status
from sqlalchemy import text
from sqlalchemy.orm import Session

from provenanceguard.apps.api.auth import AuthUser
from provenanceguard.apps.api.rbac import Role
from provenanceguard.infrastructure.network.ssrf_guard import (
    IPPinningTransport,
    WebhookURLSecurityPolicy,
)


def normalize_issuer_url(url: str) -> str:
    """Normalizes OIDC issuer URL deterministically.

    Requires HTTPS in production, strips trailing slashes, and enforces valid URL structure.
    """
    if not url or not url.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="OIDC issuer URL cannot be empty.",
        )

    clean_url = url.strip()
    try:
        parsed = urllib.parse.urlparse(clean_url)
    except Exception as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid OIDC issuer URL format: {err}",
        ) from err

    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="OIDC issuer URL scheme must be HTTP or HTTPS.",
        )

    env = os.environ.get("PG_ENV", "production").lower()
    if env == "production" and scheme != "https":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Production OIDC issuer URL strictly requires HTTPS.",
        )

    netloc = parsed.netloc.lower()
    path = parsed.path.rstrip("/")
    normalized = f"{scheme}://{netloc}{path}"
    return normalized


# Role precedence hierarchy for group mapping
ROLE_PRECEDENCE = [
    Role.ADMIN,
    Role.SECURITY_ANALYST,
    Role.DEVELOPER,
    Role.AUDITOR,
    Role.CI_SERVICE,
    Role.VIEWER,
]


class JWKSKeyFetcher:
    """SSRF-protected JWKS key fetcher with IP pinning and caching."""

    _cache: dict[str, tuple[float, dict[str, Any]]] = {}
    _last_refresh: dict[str, float] = {}

    @classmethod
    def fetch_jwks_keys(cls, jwks_uri: str) -> dict[str, Any]:
        """Fetches JWKS keys from remote URI via IPPinningTransport."""
        now = time.time()

        # Check cache (1 hour TTL)
        if jwks_uri in cls._cache:
            cached_time, keys_map = cls._cache[jwks_uri]
            if now - cached_time < 3600:
                return keys_map

        # Rate limit force refresh (1 per 60s per URI)
        last_ref = cls._last_refresh.get(jwks_uri, 0.0)
        if jwks_uri in cls._cache and (now - last_ref < 60):
            return cls._cache[jwks_uri][1]

        # SSRF creation/fetch time check
        WebhookURLSecurityPolicy.validate_url(jwks_uri)

        # Synchronous fetch wrapper for httpx IPPinningTransport
        import httpx

        transport = IPPinningTransport()
        try:
            with httpx.Client(transport=transport, timeout=10.0) as client:
                resp = client.get(jwks_uri)
                if resp.status_code != 200:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail=f"Failed to fetch JWKS from URI '{jwks_uri}': HTTP {resp.status_code}",
                    )

                if len(resp.content) > 131072:  # 128 KB limit
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="JWKS payload size exceeds maximum limit of 128 KB.",
                    )

                jwks_data = resp.json()
        except Exception as err:
            if isinstance(err, HTTPException):
                raise err
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"JWKS fetch failed: {err}",
            ) from err

        keys = jwks_data.get("keys", [])
        if not isinstance(keys, list) or len(keys) > 20:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="JWKS payload invalid or contains > 20 keys.",
            )

        keys_map: dict[str, Any] = {}
        for k in keys:
            kid = k.get("kid")
            if kid:
                keys_map[kid] = k

        cls._cache[jwks_uri] = (now, keys_map)
        cls._last_refresh[jwks_uri] = now
        return keys_map


def map_groups_to_role(groups: Any, group_role_map: dict[str, str]) -> Role:
    """Validates group claim schema and maps groups to highest-precedence Role."""
    if not isinstance(groups, list):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="OIDC 'groups' claim must be an array of strings.",
        )

    if len(groups) > 100:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="OIDC 'groups' claim exceeds maximum count of 100 groups.",
        )

    matched_roles: set[Role] = set()
    for g in groups:
        if not isinstance(g, str):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="All items in OIDC 'groups' claim must be strings.",
            )
        if len(g) > 256:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Group name in OIDC 'groups' claim exceeds 256 characters limit.",
            )

        if g in group_role_map:
            role_name = group_role_map[g]
            try:
                matched_roles.add(Role(role_name))
            except ValueError:
                pass

    if not matched_roles:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: User groups do not map to any authorized role for this organization.",
        )

    # Evaluate deterministic precedence hierarchy
    for role in ROLE_PRECEDENCE:
        if role in matched_roles:
            return role

    return Role.VIEWER


def validate_oidc_jwt(token: str, db_session: Session) -> AuthUser:
    """Validates an external federated OIDC JWT against active database IdP configurations.

    Enforces exact normalized issuer matching, server-derived tenant identity,
    audience validation, RS256 signature verification, and group claim role mapping.
    """
    if len(token) > 8192:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token size exceeds maximum threshold of 8 KB.",
        )

    try:
        unverified_header = jwt.get_unverified_header(token)
        unverified_claims = jwt.decode(token, options={"verify_signature": False})
    except Exception as err:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Malformed JWT token: {err}",
        ) from err

    alg = unverified_header.get("alg")
    if alg != "RS256":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Unsupported algorithm '{alg}'. Federated OIDC requires RS256.",
        )

    raw_iss = unverified_claims.get("iss")
    if not raw_iss:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="JWT token missing required 'iss' claim.",
        )

    normalized_iss = normalize_issuer_url(str(raw_iss))

    # Query active IdP configuration by exact normalized issuer
    query = text(
        "SELECT id, organization_id, client_id, jwks_uri, subject_claim, group_claim, group_role_map_json "
        "FROM idp_configurations WHERE issuer = :iss AND is_active = TRUE"
    )
    row = db_session.execute(query, {"iss": normalized_iss}).fetchone()

    if not row:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"No active IdP configuration found for issuer '{normalized_iss}'.",
        )

    (
        idp_id,
        server_derived_org_id,
        expected_client_id,
        jwks_uri,
        subject_claim_name,
        group_claim_name,
        group_role_map,
    ) = row

    server_org_id = UUID(str(server_derived_org_id))

    # Validate Audience
    aud_claim = unverified_claims.get("aud")
    if not aud_claim:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="JWT token missing required 'aud' claim.",
        )

    aud_matched = False
    if isinstance(aud_claim, str) and aud_claim == expected_client_id:
        aud_matched = True
    elif isinstance(aud_claim, list) and expected_client_id in aud_claim:
        aud_matched = True

    if not aud_matched:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token audience. Expected client_id '{expected_client_id}'.",
        )

    # Resolve JWKS public key by kid
    kid = unverified_header.get("kid")
    jwks_keys = JWKSKeyFetcher.fetch_jwks_keys(jwks_uri)

    if not kid or kid not in jwks_keys:
        # Retry once by forcing cache update
        JWKSKeyFetcher._cache.pop(jwks_uri, None)
        jwks_keys = JWKSKeyFetcher.fetch_jwks_keys(jwks_uri)

    if not kid or kid not in jwks_keys:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Key ID '{kid}' not found in JWKS from '{jwks_uri}'.",
        )

    jwk_dict = jwks_keys[kid]
    try:
        public_key = jwt.algorithms.RSAAlgorithm.from_jwk(jwk_dict)
    except Exception as err:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Failed to parse public key from JWK: {err}",
        ) from err

    # Validate Signature & Expiration
    try:
        verified_claims = jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            options={"verify_signature": True, "verify_aud": False, "verify_iss": False},
            leeway=60,
        )
    except jwt.ExpiredSignatureError as err:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Federated OIDC token has expired.",
        ) from err
    except Exception as err:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"OIDC signature verification failed: {err}",
        ) from err

    # Extract subject & groups
    sub_val = verified_claims.get(subject_claim_name) or verified_claims.get("sub")
    if not sub_val:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="OIDC token missing subject claim.",
        )

    groups_val = verified_claims.get(group_claim_name) or []
    group_map = group_role_map if isinstance(group_role_map, dict) else {}
    user_role = map_groups_to_role(groups_val, group_map)

    return AuthUser(
        user_id=str(sub_val),
        organization_id=server_org_id,
        project_scope_id=None,
        role=user_role,
        scopes=[],
        auth_type="oidc_jwt",
    )
