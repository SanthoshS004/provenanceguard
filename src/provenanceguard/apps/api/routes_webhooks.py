"""Webhook Subscriptions & Test Delivery Endpoints.

Provides endpoints for managing webhook subscriptions, soft deactivation on DELETE,
and sending test pings through the complete production security pipeline.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from provenanceguard.apps.api.auth import AuthUser, require_permission
from provenanceguard.apps.api.rbac import Permission
from provenanceguard.infrastructure.database.models import (
    AuditLogModel,
    WebhookDeliveryModel,
    WebhookSubscriptionModel,
)
from provenanceguard.infrastructure.database.session import DatabaseManager
from provenanceguard.infrastructure.network.ssrf_guard import WebhookURLSecurityPolicy
from provenanceguard.infrastructure.webhooks.webhook_crypto import WebhookCrypto
from provenanceguard.infrastructure.webhooks.webhook_dispatcher import (
    ALLOWED_EVENT_TYPES,
    WebhookDispatcher,
)

router = APIRouter(prefix="/api/v1/webhooks/subscriptions", tags=["webhooks"])


class SubscriptionCreateRequest(BaseModel):
    name: str = Field(..., max_length=255)
    target_url: str = Field(..., max_length=1024)
    events: list[str] = Field(..., example=["VERIFICATION_COMPLETED", "FINDING_DETECTED"])


class SubscriptionCreateResponse(BaseModel):
    id: str
    organization_id: str
    name: str
    target_url: str
    events: list[str]
    is_active: bool
    created_at: str
    secret: str = Field(
        description="Plaintext webhook secret. Returned EXACTLY ONCE upon creation."
    )


class SubscriptionResponse(BaseModel):
    id: str
    organization_id: str
    name: str
    target_url: str
    events: list[str]
    is_active: bool
    created_at: str


class TestDeliveryResponse(BaseModel):
    delivery_id: str
    subscription_id: str
    status: str
    last_status_code: int | None
    error_summary: str | None


@router.post("", response_model=SubscriptionCreateResponse, status_code=status.HTTP_201_CREATED)
def create_webhook_subscription(
    payload: SubscriptionCreateRequest,
    current_user: AuthUser = Depends(require_permission(Permission.API_KEY_MANAGE)),
) -> Any:
    """Creates a new webhook subscription and returns plaintext secret EXACTLY ONCE."""
    # 1. Creation-time SSRF validation
    validated_url = WebhookURLSecurityPolicy.validate_url(payload.target_url)

    # Validate events
    for evt in payload.events:
        if evt not in ALLOWED_EVENT_TYPES:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid event_type '{evt}'. Allowed: {sorted(ALLOWED_EVENT_TYPES)}",
            )

    # 2. Generate cryptographically random secret and encrypt via AES-256-GCM
    plaintext_secret = WebhookCrypto.generate_secret()
    version, nonce, ciphertext, fingerprint = WebhookCrypto.encrypt_secret(plaintext_secret)

    db_mgr = DatabaseManager()
    with db_mgr.get_session() as session:
        db_mgr.set_tenant_context(session, current_user.organization_id)

        sub_id = uuid.uuid4()
        now = datetime.now(timezone.utc)

        sub = WebhookSubscriptionModel(
            id=sub_id,
            organization_id=current_user.organization_id,
            name=payload.name,
            target_url=validated_url,
            secret_key_version=version,
            secret_nonce=nonce,
            encrypted_secret=ciphertext,
            secret_fingerprint=fingerprint,
            events_json=payload.events,
            is_active=True,
            created_at=now,
            updated_at=now,
        )
        session.add(sub)

        audit = AuditLogModel(
            organization_id=current_user.organization_id,
            actor_id=current_user.user_id,
            action="WEBHOOK_SUBSCRIPTION_CREATED",
            resource=f"webhook_subscription:{sub_id}",
            result="SUCCESS",
            metadata_json={"name": payload.name, "target_url": validated_url},
        )
        session.add(audit)
        session.commit()

        return SubscriptionCreateResponse(
            id=str(sub.id),
            organization_id=str(sub.organization_id),
            name=sub.name,
            target_url=sub.target_url,
            events=sub.events_json,
            is_active=sub.is_active,
            created_at=sub.created_at.isoformat(),
            secret=plaintext_secret,
        )


@router.get("", response_model=list[SubscriptionResponse])
def list_webhook_subscriptions(
    current_user: AuthUser = Depends(require_permission(Permission.API_KEY_MANAGE)),
) -> Any:
    """Lists webhook subscriptions for the authenticated tenant."""
    db_mgr = DatabaseManager()
    with db_mgr.get_session() as session:
        db_mgr.set_tenant_context(session, current_user.organization_id)
        subs = (
            session.query(WebhookSubscriptionModel)
            .filter(WebhookSubscriptionModel.organization_id == current_user.organization_id)
            .all()
        )
        return [
            SubscriptionResponse(
                id=str(s.id),
                organization_id=str(s.organization_id),
                name=s.name,
                target_url=s.target_url,
                events=s.events_json,
                is_active=s.is_active,
                created_at=s.created_at.isoformat(),
            )
            for s in subs
        ]


@router.get("/{subscription_id}", response_model=SubscriptionResponse)
def get_webhook_subscription(
    subscription_id: UUID,
    current_user: AuthUser = Depends(require_permission(Permission.API_KEY_MANAGE)),
) -> Any:
    """Gets details for a specific webhook subscription."""
    db_mgr = DatabaseManager()
    with db_mgr.get_session() as session:
        db_mgr.set_tenant_context(session, current_user.organization_id)
        sub = (
            session.query(WebhookSubscriptionModel)
            .filter(
                WebhookSubscriptionModel.id == subscription_id,
                WebhookSubscriptionModel.organization_id == current_user.organization_id,
            )
            .first()
        )
        if not sub:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Webhook subscription not found."
            )

        return SubscriptionResponse(
            id=str(sub.id),
            organization_id=str(sub.organization_id),
            name=sub.name,
            target_url=sub.target_url,
            events=sub.events_json,
            is_active=sub.is_active,
            created_at=sub.created_at.isoformat(),
        )


@router.delete("/{subscription_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_webhook_subscription(
    subscription_id: UUID,
    current_user: AuthUser = Depends(require_permission(Permission.API_KEY_MANAGE)),
) -> None:
    """Soft deactivates a webhook subscription (UPDATE is_active = False). NO physical SQL DELETE."""
    db_mgr = DatabaseManager()
    with db_mgr.get_session() as session:
        db_mgr.set_tenant_context(session, current_user.organization_id)
        sub = (
            session.query(WebhookSubscriptionModel)
            .filter(
                WebhookSubscriptionModel.id == subscription_id,
                WebhookSubscriptionModel.organization_id == current_user.organization_id,
            )
            .first()
        )
        if not sub:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Webhook subscription not found."
            )

        sub.is_active = False

        audit = AuditLogModel(
            organization_id=current_user.organization_id,
            actor_id=current_user.user_id,
            action="WEBHOOK_SUBSCRIPTION_DISABLED",
            resource=f"webhook_subscription:{subscription_id}",
            result="SUCCESS",
            metadata_json={"is_active": False},
        )
        session.add(audit)
        session.commit()


@router.post("/{subscription_id}/test", response_model=TestDeliveryResponse)
def test_webhook_subscription(
    subscription_id: UUID,
    current_user: AuthUser = Depends(require_permission(Permission.API_KEY_MANAGE)),
) -> Any:
    """Sends a test ping through the complete production security pipeline."""
    db_mgr = DatabaseManager()
    with db_mgr.get_session() as session:
        db_mgr.set_tenant_context(session, current_user.organization_id)
        sub = (
            session.query(WebhookSubscriptionModel)
            .filter(
                WebhookSubscriptionModel.id == subscription_id,
                WebhookSubscriptionModel.organization_id == current_user.organization_id,
            )
            .first()
        )
        if not sub:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Webhook subscription not found."
            )

        # Create test delivery record
        delivery_id = uuid.uuid4()
        event_id = uuid.uuid4()
        delivery = WebhookDeliveryModel(
            id=delivery_id,
            subscription_id=sub.id,
            organization_id=current_user.organization_id,
            event_id=event_id,
            event_type="VERIFICATION_COMPLETED",
            status="PENDING",
            attempt_count=0,
        )
        session.add(delivery)
        session.commit()

        # Dispatch via production delivery engine
        WebhookDispatcher.dispatch_delivery(delivery.id, session, test_mode=True)

        session.refresh(delivery)
        return TestDeliveryResponse(
            delivery_id=str(delivery.id),
            subscription_id=str(sub.id),
            status=delivery.status,
            last_status_code=delivery.last_status_code,
            error_summary=delivery.error_summary,
        )
