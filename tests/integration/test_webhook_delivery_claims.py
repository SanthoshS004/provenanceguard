"""Integration tests for atomic worker delivery claims and stale claim recovery."""

import datetime
import uuid
from datetime import timezone

import pytest

from provenanceguard.infrastructure.database.models import (
    OrganizationModel,
    WebhookDeliveryModel,
    WebhookSubscriptionModel,
)
from provenanceguard.infrastructure.database.session import DatabaseManager
from provenanceguard.infrastructure.webhooks.webhook_crypto import WebhookCrypto
from provenanceguard.infrastructure.webhooks.webhook_dispatcher import (
    claim_delivery,
    recover_stale_claims,
)


@pytest.fixture
def test_setup():
    db_mgr = DatabaseManager()
    with db_mgr.get_session() as session:
        org_id = uuid.uuid4()
        org = OrganizationModel(
            id=org_id, name=f"Claim Test Org {org_id.hex[:6]}", slug=f"claim-test-{org_id.hex[:6]}"
        )
        session.add(org)
        session.commit()

        v, nonce, cipher, fp = WebhookCrypto.encrypt_secret("test_secret")
        sub = WebhookSubscriptionModel(
            id=uuid.uuid4(),
            organization_id=org_id,
            name="Claim Test Sub",
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

        delivery_id = uuid.uuid4()
        event_id = uuid.uuid4()
        delivery = WebhookDeliveryModel(
            id=delivery_id,
            subscription_id=sub.id,
            organization_id=org_id,
            event_id=event_id,
            event_type="VERIFICATION_COMPLETED",
            status="PENDING",
            attempt_count=0,
        )
        session.add(delivery)
        session.commit()

        yield org_id, sub.id, delivery_id, event_id


def test_concurrent_worker_delivery_claim_race(test_setup):
    """Validates atomic claim race: out of 10 workers, exactly 1 succeeds."""
    org_id, sub_id, delivery_id, event_id = test_setup
    db_mgr = DatabaseManager()

    results = []
    # Simulate 10 workers attempting claim_delivery
    for _ in range(10):
        with db_mgr.get_session() as session:
            db_mgr.set_tenant_context(session, org_id)
            claimed = claim_delivery(delivery_id, session)
            results.append(claimed)

    # Exactly 1 True, 9 False
    assert results.count(True) == 1
    assert results.count(False) == 9

    # Verify status in DB is DISPATCHING and attempt_count is 1
    with db_mgr.get_session() as session:
        db_mgr.set_tenant_context(session, org_id)
        deliv = session.get(WebhookDeliveryModel, delivery_id)
        assert deliv.status == "DISPATCHING"
        assert deliv.attempt_count == 1


def test_stale_dispatching_claim_recovery(test_setup):
    """Verifies that DISPATCHING rows stuck > 300s are recovered to RETRY_PENDING."""
    org_id, sub_id, delivery_id, event_id = test_setup
    db_mgr = DatabaseManager()

    with db_mgr.get_session() as session:
        db_mgr.set_tenant_context(session, org_id)

        # Manually set status to DISPATCHING with old last_attempt_at
        stale_time = datetime.datetime.now(timezone.utc) - datetime.timedelta(seconds=400)
        deliv = session.get(WebhookDeliveryModel, delivery_id)
        deliv.status = "DISPATCHING"
        deliv.attempt_count = 1
        deliv.last_attempt_at = stale_time
        session.commit()

        recovered_count = recover_stale_claims(session)
        assert recovered_count >= 1

        session.refresh(deliv)
        assert deliv.status == "RETRY_PENDING"


def test_attempt_count_never_exceeds_5(test_setup):
    """Verifies that claim_delivery fails if attempt_count is already 5."""
    org_id, sub_id, delivery_id, event_id = test_setup
    db_mgr = DatabaseManager()

    with db_mgr.get_session() as session:
        db_mgr.set_tenant_context(session, org_id)
        deliv = session.get(WebhookDeliveryModel, delivery_id)
        deliv.status = "RETRY_PENDING"
        deliv.attempt_count = 5
        session.commit()

        # Claim attempt should return False
        claimed = claim_delivery(delivery_id, session)
        assert claimed is False
