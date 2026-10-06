"""ADMIN-only IdP Configuration Endpoints.

Provides CRUD operations for tenant OIDC IdP configurations.
Enforces ORG_ADMIN permission, creation-time SSRF validation for JWKS URIs,
exact normalized issuer uniqueness, and soft deactivation on DELETE.
"""

from __future__ import annotations

import uuid
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import text

from provenanceguard.apps.api.auth import AuthUser, require_permission
from provenanceguard.apps.api.auth_oidc import normalize_issuer_url
from provenanceguard.apps.api.rbac import Permission
from provenanceguard.infrastructure.database.models import AuditLogModel, IdPConfigModel
from provenanceguard.infrastructure.database.session import DatabaseManager
from provenanceguard.infrastructure.network.ssrf_guard import WebhookURLSecurityPolicy

router = APIRouter(prefix="/api/v1/auth/idp-configurations", tags=["idp-configurations"])


class IdPCreateRequest(BaseModel):
    name: str = Field(..., max_length=255)
    issuer: str = Field(..., max_length=1024)
    client_id: str = Field(..., max_length=255)
    jwks_uri: str = Field(..., max_length=1024)
    subject_claim: str = Field(default="sub", max_length=50)
    group_claim: str = Field(default="groups", max_length=50)
    group_role_map: dict[str, str] = Field(
        ..., example={"Admins": "ADMIN", "Analysts": "SECURITY_ANALYST"}
    )


class IdPUpdateRequest(BaseModel):
    name: str | None = Field(default=None, max_length=255)
    issuer: str | None = Field(default=None, max_length=1024)
    client_id: str | None = Field(default=None, max_length=255)
    jwks_uri: str | None = Field(default=None, max_length=1024)
    subject_claim: str | None = Field(default=None, max_length=50)
    group_claim: str | None = Field(default=None, max_length=50)
    group_role_map: dict[str, str] | None = None
    is_active: bool | None = None


class IdPResponse(BaseModel):
    id: str
    organization_id: str
    name: str
    issuer: str
    client_id: str
    jwks_uri: str
    subject_claim: str
    group_claim: str
    group_role_map: dict[str, str]
    is_active: bool
    created_at: str


@router.post("", response_model=IdPResponse, status_code=status.HTTP_201_CREATED)
def create_idp_configuration(
    payload: IdPCreateRequest,
    current_user: AuthUser = Depends(require_permission(Permission.ORG_ADMIN)),
) -> Any:
    """Creates a new OIDC IdP configuration for the authenticated tenant."""
    # 1. Creation-time SSRF validation for JWKS URI
    WebhookURLSecurityPolicy.validate_url(payload.jwks_uri)

    # 2. Normalize issuer URL
    normalized_iss = normalize_issuer_url(payload.issuer)

    db_mgr = DatabaseManager()
    with db_mgr.get_session() as session:
        db_mgr.set_tenant_context(session, current_user.organization_id)

        # 3. Check for existing active configuration with same normalized issuer
        check_query = text(
            "SELECT id FROM idp_configurations "
            "WHERE organization_id = :org_id AND issuer = :iss AND is_active = TRUE"
        )
        existing = session.execute(
            check_query, {"org_id": current_user.organization_id, "iss": normalized_iss}
        ).fetchone()

        if existing:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"An active IdP configuration already exists for issuer '{normalized_iss}'.",
            )

        config_id = uuid.uuid4()
        config = IdPConfigModel(
            id=config_id,
            organization_id=current_user.organization_id,
            name=payload.name,
            issuer=normalized_iss,
            client_id=payload.client_id,
            jwks_uri=payload.jwks_uri,
            subject_claim=payload.subject_claim,
            group_claim=payload.group_claim,
            group_role_map_json=payload.group_role_map,
            is_active=True,
        )
        session.add(config)

        # Record Audit Log
        audit = AuditLogModel(
            organization_id=current_user.organization_id,
            actor_id=current_user.user_id,
            action="IDP_CONFIGURATION_CREATED",
            resource=f"idp_configuration:{config_id}",
            result="SUCCESS",
            metadata_json={"name": payload.name, "issuer": normalized_iss},
        )
        session.add(audit)
        session.commit()

        return IdPResponse(
            id=str(config.id),
            organization_id=str(config.organization_id),
            name=config.name,
            issuer=config.issuer,
            client_id=config.client_id,
            jwks_uri=config.jwks_uri,
            subject_claim=config.subject_claim,
            group_claim=config.group_claim,
            group_role_map=config.group_role_map_json,
            is_active=config.is_active,
            created_at=config.created_at.isoformat(),
        )


@router.get("", response_model=list[IdPResponse])
def list_idp_configurations(
    current_user: AuthUser = Depends(require_permission(Permission.ORG_ADMIN)),
) -> Any:
    """Lists all IdP configurations for the current tenant."""
    db_mgr = DatabaseManager()
    with db_mgr.get_session() as session:
        db_mgr.set_tenant_context(session, current_user.organization_id)
        configs = (
            session.query(IdPConfigModel)
            .filter(IdPConfigModel.organization_id == current_user.organization_id)
            .all()
        )
        return [
            IdPResponse(
                id=str(c.id),
                organization_id=str(c.organization_id),
                name=c.name,
                issuer=c.issuer,
                client_id=c.client_id,
                jwks_uri=c.jwks_uri,
                subject_claim=c.subject_claim,
                group_claim=c.group_claim,
                group_role_map=c.group_role_map_json,
                is_active=c.is_active,
                created_at=c.created_at.isoformat(),
            )
            for c in configs
        ]


@router.get("/{config_id}", response_model=IdPResponse)
def get_idp_configuration(
    config_id: UUID,
    current_user: AuthUser = Depends(require_permission(Permission.ORG_ADMIN)),
) -> Any:
    """Gets details for a specific IdP configuration."""
    db_mgr = DatabaseManager()
    with db_mgr.get_session() as session:
        db_mgr.set_tenant_context(session, current_user.organization_id)
        config = (
            session.query(IdPConfigModel)
            .filter(
                IdPConfigModel.id == config_id,
                IdPConfigModel.organization_id == current_user.organization_id,
            )
            .first()
        )
        if not config:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="IdP configuration not found."
            )

        return IdPResponse(
            id=str(config.id),
            organization_id=str(config.organization_id),
            name=config.name,
            issuer=config.issuer,
            client_id=config.client_id,
            jwks_uri=config.jwks_uri,
            subject_claim=config.subject_claim,
            group_claim=config.group_claim,
            group_role_map=config.group_role_map_json,
            is_active=config.is_active,
            created_at=config.created_at.isoformat(),
        )


@router.patch("/{config_id}", response_model=IdPResponse)
def update_idp_configuration(
    config_id: UUID,
    payload: IdPUpdateRequest,
    current_user: AuthUser = Depends(require_permission(Permission.ORG_ADMIN)),
) -> Any:
    """Updates an existing IdP configuration."""
    db_mgr = DatabaseManager()
    with db_mgr.get_session() as session:
        db_mgr.set_tenant_context(session, current_user.organization_id)
        config = (
            session.query(IdPConfigModel)
            .filter(
                IdPConfigModel.id == config_id,
                IdPConfigModel.organization_id == current_user.organization_id,
            )
            .first()
        )
        if not config:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="IdP configuration not found."
            )

        if payload.jwks_uri is not None:
            WebhookURLSecurityPolicy.validate_url(payload.jwks_uri)
            config.jwks_uri = payload.jwks_uri

        if payload.issuer is not None:
            normalized_iss = normalize_issuer_url(payload.issuer)
            config.issuer = normalized_iss

        if payload.name is not None:
            config.name = payload.name
        if payload.client_id is not None:
            config.client_id = payload.client_id
        if payload.subject_claim is not None:
            config.subject_claim = payload.subject_claim
        if payload.group_claim is not None:
            config.group_claim = payload.group_claim
        if payload.group_role_map is not None:
            config.group_role_map_json = payload.group_role_map
        if payload.is_active is not None:
            config.is_active = payload.is_active

        session.commit()
        return IdPResponse(
            id=str(config.id),
            organization_id=str(config.organization_id),
            name=config.name,
            issuer=config.issuer,
            client_id=config.client_id,
            jwks_uri=config.jwks_uri,
            subject_claim=config.subject_claim,
            group_claim=config.group_claim,
            group_role_map=config.group_role_map_json,
            is_active=config.is_active,
            created_at=config.created_at.isoformat(),
        )


@router.delete("/{config_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_idp_configuration(
    config_id: UUID,
    current_user: AuthUser = Depends(require_permission(Permission.ORG_ADMIN)),
) -> None:
    """Soft deactivates an IdP configuration (UPDATE is_active = False). NO physical SQL DELETE."""
    db_mgr = DatabaseManager()
    with db_mgr.get_session() as session:
        db_mgr.set_tenant_context(session, current_user.organization_id)
        config = (
            session.query(IdPConfigModel)
            .filter(
                IdPConfigModel.id == config_id,
                IdPConfigModel.organization_id == current_user.organization_id,
            )
            .first()
        )
        if not config:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="IdP configuration not found."
            )

        # Controlled soft deactivation
        config.is_active = False

        audit = AuditLogModel(
            organization_id=current_user.organization_id,
            actor_id=current_user.user_id,
            action="IDP_CONFIGURATION_DISABLED",
            resource=f"idp_configuration:{config_id}",
            result="SUCCESS",
            metadata_json={"is_active": False},
        )
        session.add(audit)
        session.commit()
