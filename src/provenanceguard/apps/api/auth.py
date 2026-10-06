"""Authentication & Identity Resolution Module for ProvenanceGuard.

Implements strict RS256 JWT validation, least-privilege SECURITY DEFINER API key resolution,
server-derived identity context, transaction-local tenant context initialization,
and permission enforcement.
"""

from __future__ import annotations

import datetime
import hashlib
import os
import uuid
from dataclasses import dataclass
from datetime import timezone
from typing import Callable, Optional
from uuid import UUID

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy import text
from sqlalchemy.orm import Session

from provenanceguard.apps.api.rbac import (
    Permission,
    Role,
    get_effective_permissions,
)
from provenanceguard.infrastructure.database.session import DatabaseManager


class ConfigurationError(RuntimeError):
    """Raised when security configuration is invalid or missing in production."""

    pass


# Development/Test RSA key pair cache for local execution when env vars are unconfigured
_DEV_RSA_PRIVATE_KEY: Optional[str] = None
_DEV_RSA_PUBLIC_KEY: Optional[str] = None


def get_dev_rsa_keypair() -> tuple[str, str]:
    """Generates or retrieves in-memory RSA 2048 key pair for development/testing."""
    global _DEV_RSA_PRIVATE_KEY, _DEV_RSA_PUBLIC_KEY
    if _DEV_RSA_PRIVATE_KEY is None or _DEV_RSA_PUBLIC_KEY is None:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem_private = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")

        pem_public = (
            private_key.public_key()
            .public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode("utf-8")
        )
        _DEV_RSA_PRIVATE_KEY = pem_private
        _DEV_RSA_PUBLIC_KEY = pem_public

    return _DEV_RSA_PRIVATE_KEY, _DEV_RSA_PUBLIC_KEY


def get_jwt_public_key() -> str:
    """Retrieves RS256 public verification key with strict production fail-closed enforcement."""
    env = os.getenv("PG_ENV", "development").lower()
    pub_key = os.getenv("PG_JWT_PUBLIC_KEY")

    if pub_key and pub_key.strip():
        # Clean up line breaks if passed via env var
        formatted_key = pub_key.strip().replace("\\n", "\n")
        if "BEGIN PUBLIC KEY" not in formatted_key and "BEGIN RSA PUBLIC KEY" not in formatted_key:
            if env == "production":
                raise ConfigurationError(
                    "CRITICAL SECURITY FAILURE: PG_JWT_PUBLIC_KEY is malformed in production mode."
                )
        return formatted_key

    if env == "production":
        raise ConfigurationError(
            "CRITICAL SECURITY FAILURE: PG_JWT_PUBLIC_KEY must be configured in production mode."
        )

    _, dev_public = get_dev_rsa_keypair()
    return dev_public


def get_jwt_private_key() -> str:
    """Retrieves RS256 private key for dev/test token signing."""
    priv_key = os.getenv("PG_JWT_PRIVATE_KEY")
    if priv_key and priv_key.strip():
        return priv_key.strip().replace("\\n", "\n")

    dev_private, _ = get_dev_rsa_keypair()
    return dev_private


@dataclass(frozen=True)
class AuthUser:
    """Server-derived authenticated identity value object."""

    user_id: str
    organization_id: UUID
    project_scope_id: UUID | None
    role: Role
    scopes: list[str]
    auth_type: str  # "jwt" or "api_key"

    def has_permission(self, permission: Permission) -> bool:
        """Evaluates whether user identity possesses permission via role permission ∩ scopes."""
        effective = get_effective_permissions(self.role, self.scopes)
        return permission in effective


def mint_dev_token(
    user_id: str,
    organization_id: UUID | str,
    role: Role | str,
    project_id: UUID | str | None = None,
    scopes: list[str] | None = None,
    expires_in_seconds: int = 3600,
    private_key_pem: str | None = None,
    issuer: str = "provenanceguard",
    audience: str = "provenanceguard-api",
) -> str:
    """Mints an RS256 JWT for development or automated testing suites."""
    env = os.getenv("PG_ENV", "development").lower()
    enable_dev_issuance = os.getenv("ENABLE_DEV_TOKEN_ISSUANCE", "true").lower() in ("true", "1")

    if env == "production" and not enable_dev_issuance:
        raise ConfigurationError(
            "Dev token issuance endpoint/helper is disabled in production mode."
        )

    key_to_use = private_key_pem or get_jwt_private_key()
    now = datetime.datetime.now(timezone.utc)
    exp = now + datetime.timedelta(seconds=expires_in_seconds)

    payload = {
        "iss": issuer,
        "aud": audience,
        "sub": str(user_id),
        "exp": int(exp.timestamp()),
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "organization_id": str(organization_id),
        "role": role.value if isinstance(role, Role) else str(role),
        "jti": str(uuid.uuid4()),
    }
    if project_id:
        payload["project_id"] = str(project_id)
    if scopes:
        payload["scopes"] = scopes

    return jwt.encode(payload, key_to_use, algorithm="RS256")


def validate_rs256_jwt(token: str) -> AuthUser:
    """Validates RS256 JWT signature, headers, claims, and returns server-derived AuthUser.

    Strictly rejects non-RS256 algorithms (HS256, alg=none, etc.) and oversized payloads.
    """
    if len(token) > 8192:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token size exceeds maximum threshold of 8 KB.",
        )

    try:
        header = jwt.get_unverified_header(token)
    except Exception as err:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Malformed JWT header.",
        ) from err

    alg = header.get("alg")
    if alg != "RS256":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Unsupported or weak JWT algorithm '{alg}'. RS256 is strictly required.",
        )

    pub_key = get_jwt_public_key()
    expected_issuer = os.getenv("PG_JWT_ISSUER", "provenanceguard")
    expected_audience = os.getenv("PG_JWT_AUDIENCE", "provenanceguard-api")

    try:
        claims = jwt.decode(
            token,
            pub_key,
            algorithms=["RS256"],
            options={
                "verify_signature": True,
                "require": [
                    "iss",
                    "aud",
                    "sub",
                    "exp",
                    "iat",
                    "nbf",
                    "organization_id",
                    "role",
                    "jti",
                ],
            },
            issuer=expected_issuer,
            audience=expected_audience,
            leeway=60,
        )
    except jwt.ExpiredSignatureError as err:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="JWT token has expired."
        ) from err
    except jwt.InvalidIssuerError as err:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token issuer."
        ) from err
    except jwt.InvalidAudienceError as err:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token audience."
        ) from err
    except Exception as err:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=f"JWT validation failed: {err}"
        ) from err

    try:
        user_id = str(claims["sub"])
        org_id = UUID(claims["organization_id"])
        role_str = str(claims["role"])
        role_enum = Role(role_str)
        project_scope_id = UUID(claims["project_id"]) if "project_id" in claims else None
        scopes = claims.get("scopes", [])
    except Exception as err:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Invalid claims in JWT: {err}"
        ) from err

    return AuthUser(
        user_id=user_id,
        organization_id=org_id,
        project_scope_id=project_scope_id,
        role=role_enum,
        scopes=scopes,
        auth_type="jwt",
    )


def resolve_api_key(raw_key: str, db_session: Session) -> AuthUser:
    """Resolves API key via SHA-256 hash using least-privilege SECURITY DEFINER database function."""
    if not (raw_key.startswith("pg_live_") or raw_key.startswith("pg_")):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key format.",
        )

    key_hash = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()

    # Query via SECURITY DEFINER function
    try:
        query = text(
            "SELECT id, organization_id, project_id, role, scopes_json, expires_at, revoked_at "
            "FROM lookup_api_key_by_hash(:hash)"
        )
        row = db_session.execute(query, {"hash": key_hash}).fetchone()
    except Exception:
        # Fallback for SQLite in-memory unit testing where PostgreSQL functions do not exist
        fallback_query = text(
            "SELECT id, organization_id, project_id, role, scopes_json, expires_at, revoked_at "
            "FROM api_keys WHERE key_hash = :hash"
        )
        row = db_session.execute(fallback_query, {"hash": key_hash}).fetchone()

    if not row:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or non-existent API key.",
        )

    # row layout: (id, organization_id, project_id, role, scopes_json, expires_at, revoked_at)
    key_id, org_id_str, proj_id_str, role_str, scopes, expires_at, revoked_at = row

    if revoked_at is not None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key has been revoked.",
        )

    if expires_at is not None:
        if isinstance(expires_at, str):
            expires_dt = datetime.datetime.fromisoformat(expires_at)
        else:
            expires_dt = expires_at
        if expires_dt.tzinfo is None:
            expires_dt = expires_dt.replace(tzinfo=timezone.utc)

        if expires_dt < datetime.datetime.now(timezone.utc):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="API key has expired.",
            )

    org_id = UUID(str(org_id_str))
    proj_id = UUID(str(proj_id_str)) if proj_id_str else None
    role_enum = Role(str(role_str))
    scopes_list = scopes if isinstance(scopes, list) else []

    return AuthUser(
        user_id=str(key_id),
        organization_id=org_id,
        project_scope_id=proj_id,
        role=role_enum,
        scopes=scopes_list,
        auth_type="api_key",
    )


def get_current_user(
    request: Request,
    authorization: Optional[str] = Header(None, alias="Authorization"),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
) -> AuthUser:
    """FastAPI dependency to extract, authenticate, and resolve server-derived user identity.

    Sets transaction-local tenant context (`app.current_tenant_id`) on active DB session.
    """
    token_or_key: Optional[str] = None

    if x_api_key:
        token_or_key = x_api_key.strip()
    elif authorization:
        parts = authorization.strip().split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            token_or_key = parts[1].strip()
        elif len(parts) == 1:
            token_or_key = parts[0].strip()

    if not token_or_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header or X-API-Key required.",
        )

    db_mgr = DatabaseManager()
    with db_mgr.get_session() as session:
        if token_or_key.startswith("pg_live_") or token_or_key.startswith("pg_"):
            user = resolve_api_key(token_or_key, session)
        else:
            try:
                user = validate_rs256_jwt(token_or_key)
            except Exception as local_err:
                from provenanceguard.apps.api.auth_oidc import validate_oidc_jwt

                try:
                    user = validate_oidc_jwt(token_or_key, session)
                except Exception:
                    raise local_err from None

        # Validate tenant isolation if X-Organization-ID header is explicitly supplied
        x_org_hdr = request.headers.get("X-Organization-ID")
        if x_org_hdr:
            try:
                target_org_id = UUID(x_org_hdr)
                if target_org_id != user.organization_id:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="Access denied: organization tenant mismatch.",
                    )
            except ValueError:
                pass

        # Set transaction-local tenant context immediately upon identity resolution
        db_mgr.set_tenant_context(session, user.organization_id)
        return user


def require_permission(permission: Permission) -> Callable[[AuthUser], AuthUser]:
    """Dependency factory enforcing granular RBAC permission policy."""

    def dependency(user: AuthUser = Depends(get_current_user)) -> AuthUser:
        if not user.has_permission(permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Forbidden: Insufficient permissions. Required: {permission.value}",
            )
        return user

    return dependency
