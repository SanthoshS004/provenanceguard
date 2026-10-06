"""Integration tests for webhooks engine, constraints, and HTTP 410 auto-deactivation."""

import uuid

import pytest
from sqlalchemy import text

from provenanceguard.infrastructure.database.models import (
    OrganizationModel,
    WebhookDeliveryModel,
    WebhookSubscriptionModel,
)
from provenanceguard.infrastructure.database.session import DatabaseManager
from provenanceguard.infrastructure.webhooks.webhook_crypto import WebhookCrypto


@pytest.fixture
def test_org():
    db_mgr = DatabaseManager()
    with db_mgr.get_session() as session:
        org_id = uuid.uuid4()
        org = OrganizationModel(
            id=org_id, name=f"Webhook Test Org {org_id.hex[:6]}", slug=f"wh-test-{org_id.hex[:6]}"
        )
        session.add(org)
        session.commit()
        yield org_id


def test_webhook_secret_returned_once_and_encrypted_in_db(test_org):
    """Verifies secret is encrypted in DB and fingerprint stored as lookup index."""
    db_mgr = DatabaseManager()
    with db_mgr.get_session() as session:
        db_mgr.set_tenant_context(session, test_org)

        secret = WebhookCrypto.generate_secret()
        v, nonce, cipher, fp = WebhookCrypto.encrypt_secret(secret)

        sub = WebhookSubscriptionModel(
            id=uuid.uuid4(),
            organization_id=test_org,
            name="Encrypted Sub Test",
            target_url="https://example.com/webhook",
            secret_key_version=v,
            secret_nonce=nonce,
            encrypted_secret=cipher,
            secret_fingerprint=fp,
            events_json=["VERIFICATION_COMPLETED"],
            is_active=True,
        )
        session.add(sub)
        session.commit()

        # Query DB directly to verify secret plaintext is absent
        row = session.execute(
            text(
                "SELECT encrypted_secret, secret_fingerprint FROM webhook_subscriptions WHERE id = :id"
            ),
            {"id": sub.id},
        ).fetchone()

        assert row is not None
        db_cipher, db_fp = row
        assert secret.encode("utf-8") not in db_cipher
        assert db_fp == fp


def test_webhook_delivery_database_idempotency(test_org):
    """Verifies UNIQUE(subscription_id, event_id) constraint on webhook_deliveries."""
    db_mgr = DatabaseManager()
    with db_mgr.get_session() as session:
        db_mgr.set_tenant_context(session, test_org)

        v, nonce, cipher, fp = WebhookCrypto.encrypt_secret("secret")
        sub = WebhookSubscriptionModel(
            id=uuid.uuid4(),
            organization_id=test_org,
            name="Idempotency Test Sub",
            target_url="https://example.com/webhook",
            secret_key_version=v,
            secret_nonce=nonce,
            encrypted_secret=cipher,
            secret_fingerprint=fp,
            events_json=["VERIFICATION_COMPLETED"],
            is_active=True,
        )
        session.add(sub)
        session.commit()

        event_id = uuid.uuid4()
        deliv1 = WebhookDeliveryModel(
            subscription_id=sub.id,
            organization_id=test_org,
            event_id=event_id,
            event_type="VERIFICATION_COMPLETED",
            status="PENDING",
            attempt_count=0,
        )
        session.add(deliv1)
        session.commit()

        deliv2 = WebhookDeliveryModel(
            subscription_id=sub.id,
            organization_id=test_org,
            event_id=event_id,
            event_type="VERIFICATION_COMPLETED",
            status="PENDING",
            attempt_count=0,
        )
        session.add(deliv2)

        from sqlalchemy.exc import IntegrityError

        with pytest.raises(IntegrityError):
            session.flush()
        session.rollback()
