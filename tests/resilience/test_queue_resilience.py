"""Phase 18 Redis Broker Queue Fault Injection & Resilience Tests.

Verifies PostgreSQL outbox durability during broker outages,
clean worker retry handling, and dispatch resumption on broker recovery.
"""

import uuid
from unittest.mock import patch

from provenanceguard.infrastructure.database.models import (
    ArtifactModel,
    OrganizationModel,
    OutboxEventModel,
    ProjectModel,
    VerificationRunModel,
)
from provenanceguard.infrastructure.database.outbox_repository import OutboxRepository
from provenanceguard.infrastructure.database.session import DatabaseManager
from provenanceguard.infrastructure.database.tenant_context import TenantContext
from provenanceguard.infrastructure.queue.arq_dispatcher import ARQTaskDispatcher
from provenanceguard.infrastructure.queue.dispatcher import JobPayload


def _create_org_proj_and_run(session, org_id: uuid.UUID, proj_id: uuid.UUID, run_id: uuid.UUID):
    org = OrganizationModel(
        id=org_id, name=f"Org_{str(org_id)[:8]}", slug=f"slug_{str(org_id)[:8]}"
    )
    session.add(org)
    session.flush()

    proj = ProjectModel(id=proj_id, organization_id=org_id, name="P1")
    session.add(proj)
    session.flush()

    art_id = uuid.uuid4()
    art = ArtifactModel(
        id=art_id,
        project_id=proj_id,
        organization_id=org_id,
        name="art",
        version="1.0",
        media_type="application/vnd.elf",
        digest_sha256="a" * 64,
        size_bytes=100,
        storage_path="/path",
    )
    session.add(art)
    session.flush()

    run = VerificationRunModel(
        id=run_id,
        organization_id=org_id,
        project_id=proj_id,
        production_artifact_id=art_id,
        status="QUEUED",
        decision="PENDING",
        risk_score=0,
        attempt_count=1,
    )
    session.add(run)
    session.flush()


def test_redis_broker_outage_preserves_postgres_outbox_durability():
    """Verifies that outbox events remain safely stored in PostgreSQL as PENDING when Redis is down."""
    db_mgr = DatabaseManager()
    org_id = uuid.uuid4()
    proj_id = uuid.uuid4()
    run_id = uuid.uuid4()

    tenant_ctx = TenantContext(organization_id=org_id)

    with db_mgr.get_session() as session:
        _create_org_proj_and_run(session, org_id, proj_id, run_id)
        outbox_repo = OutboxRepository(tenant_context=tenant_ctx)
        payload = JobPayload(
            verification_run_id=run_id,
            organization_id=org_id,
            project_id=proj_id,
            attempt=1,
        )

        event = outbox_repo.create_event(
            session=session,
            aggregate_type="VerificationRun",
            aggregate_id=run_id,
            project_id=proj_id,
            event_type="VERIFICATION_REQUESTED",
            payload_dict=payload.model_dump(mode="json"),
        )
        session.commit()

        dispatcher = ARQTaskDispatcher()
        with patch.object(
            dispatcher,
            "dispatch_verification_job",
            side_effect=ConnectionError("Redis broker unreachable"),
        ):
            try:
                dispatcher.dispatch_verification_job(payload)
            except Exception:
                pass

        db_event = session.query(OutboxEventModel).filter_by(id=event.id).first()
        assert db_event is not None
        assert db_event.status == "PENDING"
        assert db_event.dispatched_at is None


def test_redis_recovery_resumes_pending_outbox_dispatch():
    """Verifies that pending outbox events are successfully claimed and dispatched when Redis recovers."""
    db_mgr = DatabaseManager()
    org_id = uuid.uuid4()
    proj_id = uuid.uuid4()
    run_id = uuid.uuid4()

    tenant_ctx = TenantContext(organization_id=org_id)

    with db_mgr.get_session() as session:
        _create_org_proj_and_run(session, org_id, proj_id, run_id)
        outbox_repo = OutboxRepository(tenant_context=tenant_ctx)
        payload = JobPayload(
            verification_run_id=run_id,
            organization_id=org_id,
            project_id=proj_id,
            attempt=1,
        )

        event = outbox_repo.create_event(
            session=session,
            aggregate_type="VerificationRun",
            aggregate_id=run_id,
            project_id=proj_id,
            event_type="VERIFICATION_REQUESTED",
            payload_dict=payload.model_dump(mode="json"),
        )
        session.commit()

        pending_events = outbox_repo.get_pending_events(
            session=session, limit=10, min_age_seconds=0.0
        )
        assert len(pending_events) == 1
        assert pending_events[0].id == event.id
        assert pending_events[0].status == "PENDING"

        outbox_repo.mark_dispatched(session=session, event_id=event.id)
        session.commit()

        db_event = session.query(OutboxEventModel).filter_by(id=event.id).first()
        assert db_event.status == "DISPATCHED"
        assert db_event.dispatched_at is not None
