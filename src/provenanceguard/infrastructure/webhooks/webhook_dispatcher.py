"""Webhook Event Dispatcher & Delivery Engine.

Implements atomic worker delivery claims, stale DISPATCHING recovery,
AES-256-GCM secret decryption, SSRF IP-pinning transport delivery,
canonical HMAC-SHA256 signature generation, idempotent delivery state machine,
and HTTP 410 subscription auto-deactivation.
"""

from __future__ import annotations

import datetime
import hashlib
import hmac
import json
import time
from datetime import timezone
from typing import Any
from uuid import UUID

import httpx
from sqlalchemy import text
from sqlalchemy.orm import Session

from provenanceguard.infrastructure.database.models import (
    OutboxEventModel,
    WebhookDeliveryModel,
    WebhookSubscriptionModel,
)
from provenanceguard.infrastructure.network.ssrf_guard import IPPinningTransport
from provenanceguard.infrastructure.webhooks.webhook_crypto import WebhookCrypto

# Allowed event types for bounded envelope
ALLOWED_EVENT_TYPES = {
    "VERIFICATION_COMPLETED",
    "FINDING_DETECTED",
    "API_KEY_REVOKED",
}


def claim_delivery(delivery_id: UUID, session: Session) -> bool:
    """Attempts atomic worker delivery claim.

    Returns True ONLY if current worker successfully claimed the delivery row.
    """
    claim_query = text(
        "UPDATE webhook_deliveries "
        "SET status = 'DISPATCHING', "
        "    attempt_count = attempt_count + 1, "
        "    last_attempt_at = NOW() "
        "WHERE id = :delivery_id "
        "  AND status IN ('PENDING', 'RETRY_PENDING') "
        "  AND attempt_count < 5 "
        "RETURNING id;"
    )
    result = session.execute(claim_query, {"delivery_id": delivery_id}).fetchone()
    session.commit()
    return result is not None


def recover_stale_claims(session: Session) -> int:
    """Resets DISPATCHING claims stuck for > 300 seconds due to worker crashes."""
    recovery_query = text(
        "UPDATE webhook_deliveries "
        "SET status = CASE WHEN attempt_count < 5 THEN 'RETRY_PENDING' ELSE 'FAILED' END, "
        "    error_summary = 'Dispatch timeout: worker claim expired' "
        "WHERE status = 'DISPATCHING' "
        "  AND last_attempt_at < NOW() - INTERVAL '300 seconds';"
    )
    result = session.execute(recovery_query)
    session.commit()
    return result.rowcount if hasattr(result, "rowcount") else 0


def sanitize_payload_data(data: dict[str, Any]) -> dict[str, Any]:
    """Filters out any potentially sensitive fields (JWTs, secrets, private keys)."""
    forbidden_keys = {
        "jwt",
        "token",
        "secret",
        "api_key",
        "private_key",
        "password",
        "authorization",
    }
    sanitized: dict[str, Any] = {}
    for k, v in data.items():
        if k.lower() in forbidden_keys:
            continue
        if isinstance(v, dict):
            sanitized[k] = sanitize_payload_data(v)
        elif isinstance(v, list):
            sanitized[k] = [
                sanitize_payload_data(item) if isinstance(item, dict) else item for item in v
            ]
        else:
            sanitized[k] = v
    return sanitized


class WebhookDispatcher:
    """Handles dispatching webhook notifications to registered subscription endpoints."""

    @classmethod
    def create_deliveries_for_outbox_event(
        cls, outbox_event: OutboxEventModel, session: Session
    ) -> list[WebhookDeliveryModel]:
        """Creates PENDING delivery records for matching active subscriptions."""
        if outbox_event.event_type not in ALLOWED_EVENT_TYPES:
            return []

        # Find active subscriptions subscribed to this event_type
        subscriptions = (
            session.query(WebhookSubscriptionModel)
            .filter(
                WebhookSubscriptionModel.organization_id == outbox_event.organization_id,
                WebhookSubscriptionModel.is_active.is_(True),
            )
            .all()
        )

        created_deliveries: list[WebhookDeliveryModel] = []
        for sub in subscriptions:
            events_list = sub.events_json if isinstance(sub.events_json, list) else []
            if outbox_event.event_type not in events_list:
                continue

            # Idempotent insert: check existing
            existing = (
                session.query(WebhookDeliveryModel)
                .filter(
                    WebhookDeliveryModel.subscription_id == sub.id,
                    WebhookDeliveryModel.event_id == outbox_event.id,
                )
                .first()
            )
            if existing:
                created_deliveries.append(existing)
                continue

            delivery = WebhookDeliveryModel(
                subscription_id=sub.id,
                organization_id=outbox_event.organization_id,
                event_id=outbox_event.id,
                event_type=outbox_event.event_type,
                status="PENDING",
                attempt_count=0,
            )
            session.add(delivery)
            created_deliveries.append(delivery)

        session.commit()
        return created_deliveries

    @classmethod
    def dispatch_delivery(
        cls, delivery_id: UUID, session: Session, test_mode: bool = False
    ) -> bool:
        """Executes delivery pipeline after acquiring atomic worker claim.

        Returns True if delivery completed (DELIVERED or DISABLED), False if skipped or failed.
        """
        # 1. Atomic DB worker claim
        if not claim_delivery(delivery_id, session):
            # Worker failed to claim delivery - MUST NOT send HTTP request!
            return False

        delivery = (
            session.query(WebhookDeliveryModel)
            .filter(WebhookDeliveryModel.id == delivery_id)
            .first()
        )
        if not delivery:
            return False

        subscription = (
            session.query(WebhookSubscriptionModel)
            .filter(WebhookSubscriptionModel.id == delivery.subscription_id)
            .first()
        )
        if not subscription or not subscription.is_active:
            delivery.status = "DISABLED"
            delivery.error_summary = "Subscription inactive or missing."
            session.commit()
            return False

        # 2. Decrypt secret via AES-256-GCM
        try:
            secret_str = WebhookCrypto.decrypt_secret(
                version=subscription.secret_key_version,
                nonce=subscription.secret_nonce,
                encrypted_secret=subscription.encrypted_secret,
            )
        except Exception as err:
            delivery.status = "FAILED"
            delivery.error_summary = f"Secret decryption failed: {err}"
            session.commit()
            return False

        # 3. Format canonical envelope
        now_str = datetime.datetime.now(timezone.utc).isoformat()
        payload_data = {"test_ping": True} if test_mode else {"event_id": str(delivery.event_id)}
        sanitized_data = sanitize_payload_data(payload_data)

        envelope = {
            "event_id": str(delivery.event_id),
            "event_type": delivery.event_type,
            "occurred_at": now_str,
            "organization_id": str(delivery.organization_id),
            "data": sanitized_data,
        }
        raw_body = json.dumps(envelope, separators=(",", ":"))

        # 4. Canonical HMAC-SHA256 signature
        timestamp = str(int(time.time()))
        signature_input = f"{timestamp}.{raw_body}".encode("utf-8")
        signature = hmac.new(
            secret_str.encode("utf-8"), signature_input, hashlib.sha256
        ).hexdigest()

        headers = {
            "Content-Type": "application/json",
            "X-ProvenanceGuard-Signature": f"sha256={signature}",
            "X-ProvenanceGuard-Timestamp": timestamp,
            "X-ProvenanceGuard-Event-ID": str(delivery.event_id),
        }

        # 5. Delivery via SSRF IP-Pinning Transport
        transport = IPPinningTransport()
        try:
            with httpx.Client(transport=transport, timeout=10.0) as client:
                resp = client.post(
                    subscription.target_url, content=raw_body.encode("utf-8"), headers=headers
                )
                delivery.last_status_code = resp.status_code

                if 200 <= resp.status_code < 300:
                    delivery.status = "DELIVERED"
                    delivery.error_summary = None
                elif resp.status_code == 410:  # Gone
                    delivery.status = "DISABLED"
                    delivery.error_summary = "HTTP 410 Gone: Target subscription disabled."
                    subscription.is_active = False
                else:
                    if delivery.attempt_count < 5:
                        delivery.status = "RETRY_PENDING"
                        backoff = 2**delivery.attempt_count * 10
                        delivery.next_attempt_at = datetime.datetime.now(
                            timezone.utc
                        ) + datetime.timedelta(seconds=backoff)
                        delivery.error_summary = f"HTTP {resp.status_code}: Transient failure"
                    else:
                        delivery.status = "FAILED"
                        delivery.error_summary = f"HTTP {resp.status_code}: Failed after 5 attempts"
        except Exception as err:
            delivery.last_status_code = 0
            if delivery.attempt_count < 5:
                delivery.status = "RETRY_PENDING"
                backoff = 2**delivery.attempt_count * 10
                delivery.next_attempt_at = datetime.datetime.now(timezone.utc) + datetime.timedelta(
                    seconds=backoff
                )
                delivery.error_summary = f"Delivery exception: {err}"
            else:
                delivery.status = "FAILED"
                delivery.error_summary = f"Delivery exception after 5 attempts: {err}"

        session.commit()
        return delivery.status in ("DELIVERED", "DISABLED")
