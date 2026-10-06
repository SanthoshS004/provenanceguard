"""REST API Authentication Routes Module for ProvenanceGuard.

Implements dev token issuance, stateful API key creation with role delegation rules,
key listing, key revocation, and security audit event logging.
"""

from __future__ import annotations

import datetime
import hashlib
import os
import secrets
import uuid
from datetime import timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from provenanceguard.apps.api.auth import (
    AuthUser,
    ConfigurationError,
    mint_dev_token,
    require_permission,
)
from provenanceguard.apps.api.rbac import Permission, Role, can_delegate_role
from provenanceguard.infrastructure.database.models import ApiKeyModel, ProjectModel, utc_now
from provenanceguard.infrastructure.database.repositories import AuditLogRepository
from provenanceguard.infrastructure.database.session import DatabaseManager
from provenanceguard.infrastructure.database.tenant_context import TenantContext

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


class DevTokenRequest(BaseModel):
    organization_id: uuid.UUID
    role: Role
    user_id: Optional[str] = None
    project_id: Optional[uuid.UUID] = None
    scopes: Optional[list[str]] = None
    expires_in_seconds: int = Field(default=3600, ge=60, le=86400)

    model_config = ConfigDict(extra="forbid")


class DevTokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class CreateApiKeyRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    role: Role
    project_id: Optional[uuid.UUID] = None
    scopes: Optional[list[str]] = None
    expires_in_days: Optional[int] = Field(default=None, ge=1, le=365)

    model_config = ConfigDict(extra="forbid")


class CreateApiKeyResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    project_id: Optional[uuid.UUID] = None
    name: str
    prefix: str
    role: str
    scopes: list[str]
    created_at: datetime.datetime
    expires_at: Optional[datetime.datetime] = None
    api_key: str  # Plaintext key returned exactly ONCE

    model_config = ConfigDict(extra="ignore")


class ApiKeySummaryResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    project_id: Optional[uuid.UUID] = None
    name: str
    prefix: str
    role: str
    scopes: list[str]
    created_at: datetime.datetime
    expires_at: Optional[datetime.datetime] = None
    revoked_at: Optional[datetime.datetime] = None

    model_config = ConfigDict(extra="ignore")


@router.post("/token", response_model=DevTokenResponse, status_code=status.HTTP_200_OK)
async def issue_dev_token(req: DevTokenRequest):
    """Mints RS256 JWT for development and integration test suites."""
    env = os.getenv("PG_ENV", "development").lower()
    enable_dev = os.getenv("ENABLE_DEV_TOKEN_ISSUANCE", "true").lower() in ("true", "1")

    if env == "production" and not enable_dev:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Dev token issuance endpoint is disabled in production mode.",
        )

    user_id = req.user_id or f"user-dev-{uuid.uuid4().hex[:8]}"
    try:
        token = mint_dev_token(
            user_id=user_id,
            organization_id=req.organization_id,
            role=req.role,
            project_id=req.project_id,
            scopes=req.scopes,
            expires_in_seconds=req.expires_in_seconds,
        )
    except ConfigurationError as err:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(err),
        ) from err

    return DevTokenResponse(access_token=token, expires_in=req.expires_in_seconds)


@router.post("/api-keys", response_model=CreateApiKeyResponse, status_code=status.HTTP_201_CREATED)
async def create_api_key(
    req: CreateApiKeyRequest,
    current_user: AuthUser = Depends(require_permission(Permission.API_KEY_MANAGE)),
):
    """Creates stateful API key with role delegation privilege enforcement."""
    # Enforce Role Delegation matrix
    if not can_delegate_role(current_user.role, req.role):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Role delegation forbidden: Role '{current_user.role.value}' cannot issue API key with role '{req.role.value}'.",
        )

    # Generate 32 random hex character key
    random_hex = secrets.token_hex(16)
    raw_key = f"pg_live_{random_hex}"
    prefix = f"pg_live_{random_hex[:4]}"
    key_hash = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()

    now = datetime.datetime.now(timezone.utc)
    expires_at = None
    if req.expires_in_days:
        expires_at = now + datetime.timedelta(days=req.expires_in_days)

    db_mgr = DatabaseManager()
    with db_mgr.get_session() as session:
        db_mgr.set_tenant_context(session, current_user.organization_id)

        # Validate project ownership if project_id is provided
        if req.project_id is not None:
            proj = session.scalar(
                select(ProjectModel).where(
                    ProjectModel.id == req.project_id,
                    ProjectModel.organization_id == current_user.organization_id,
                )
            )
            if not proj:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Forbidden: Project does not belong to authorized tenant organization or does not exist.",
                )
            if (
                current_user.project_scope_id is not None
                and req.project_id != current_user.project_scope_id
            ):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Forbidden: Credential scope restricted to project '{current_user.project_scope_id}'.",
                )

        # Check duplicate name for tenant
        existing = session.scalar(
            select(ApiKeyModel).where(
                ApiKeyModel.organization_id == current_user.organization_id,
                ApiKeyModel.name == req.name,
            )
        )
        if existing:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"API key with name '{req.name}' already exists for this organization.",
            )

        api_key_record = ApiKeyModel(
            id=uuid.uuid4(),
            organization_id=current_user.organization_id,
            project_id=req.project_id,
            name=req.name,
            prefix=prefix,
            key_hash=key_hash,
            role=req.role.value,
            scopes_json=req.scopes or [],
            created_at=now,
            expires_at=expires_at,
            revoked_at=None,
        )
        session.add(api_key_record)

        # Log security audit event
        audit_repo = AuditLogRepository(
            tenant_context=TenantContext(organization_id=current_user.organization_id)
        )
        audit_repo.log_event(
            session=session,
            actor_id=current_user.user_id,
            action="API_KEY_CREATED",
            resource=f"api_key:{api_key_record.id}",
            result="SUCCESS",
            metadata_json={
                "name": req.name,
                "prefix": prefix,
                "role": req.role.value,
                "project_id": str(req.project_id) if req.project_id else None,
            },
        )
        try:
            session.commit()
        except IntegrityError as err:
            session.rollback()
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="API key creation failed due to database constraint conflict.",
            ) from err

        return CreateApiKeyResponse(
            id=api_key_record.id,
            organization_id=api_key_record.organization_id,
            project_id=api_key_record.project_id,
            name=api_key_record.name,
            prefix=api_key_record.prefix,
            role=api_key_record.role,
            scopes=api_key_record.scopes_json,
            created_at=api_key_record.created_at,
            expires_at=api_key_record.expires_at,
            api_key=raw_key,
        )


@router.get("/api-keys", response_model=list[ApiKeySummaryResponse])
async def list_api_keys(
    current_user: AuthUser = Depends(require_permission(Permission.API_KEY_MANAGE)),
):
    """Lists API keys owned by authenticated tenant organization."""
    db_mgr = DatabaseManager()
    with db_mgr.get_session() as session:
        db_mgr.set_tenant_context(session, current_user.organization_id)

        keys = session.scalars(
            select(ApiKeyModel).where(ApiKeyModel.organization_id == current_user.organization_id)
        ).all()
        return [
            ApiKeySummaryResponse(
                id=k.id,
                organization_id=k.organization_id,
                project_id=k.project_id,
                name=k.name,
                prefix=k.prefix,
                role=k.role,
                scopes=k.scopes_json,
                created_at=k.created_at,
                expires_at=k.expires_at,
                revoked_at=k.revoked_at,
            )
            for k in keys
        ]


@router.delete("/api-keys/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_api_key(
    key_id: uuid.UUID,
    current_user: AuthUser = Depends(require_permission(Permission.API_KEY_MANAGE)),
):
    """Revokes an API key for authenticated tenant organization."""
    db_mgr = DatabaseManager()
    with db_mgr.get_session() as session:
        db_mgr.set_tenant_context(session, current_user.organization_id)

        key_record = session.scalar(
            select(ApiKeyModel).where(
                ApiKeyModel.id == key_id,
                ApiKeyModel.organization_id == current_user.organization_id,
            )
        )
        if not key_record:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="API key not found or cross-tenant access denied.",
            )

        if key_record.revoked_at is None:
            key_record.revoked_at = utc_now()
            audit_repo = AuditLogRepository(
                tenant_context=TenantContext(organization_id=current_user.organization_id)
            )
            audit_repo.log_event(
                session=session,
                actor_id=current_user.user_id,
                action="API_KEY_REVOKED",
                resource=f"api_key:{key_id}",
                result="SUCCESS",
                metadata_json={"prefix": key_record.prefix, "name": key_record.name},
            )
            session.commit()
