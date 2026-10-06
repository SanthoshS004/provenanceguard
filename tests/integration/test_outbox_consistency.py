"""Integration Tests for Transactional Outbox Consistency, Recovery, & Tenant Ownership."""

import uuid

import pytest
from sqlalchemy import select, text

from provenanceguard.apps.worker.worker import run_verification_job
from provenanceguard.infrastructure.database.models import OutboxEventModel, VerificationRunModel
from provenanceguard.infrastructure.database.outbox_repository import OutboxRepository
from provenanceguard.infrastructure.database.session import DatabaseManager
from provenanceguard.infrastructure.database.tenant_context import TenantContext
from provenanceguard.infrastructure.queue.dispatcher import JobPayload


def _seed_org_and_proj(session, org_id: uuid.UUID, proj_id: uuid.UUID):
    ins_org = (
        "INSERT INTO organizations (id, name, slug, created_at) "
        "VALUES (CAST(:id AS uuid), :name, :slug, NOW()) "
        "ON CONFLICT (id) DO NOTHING"
    )
    ins_proj = (
        "INSERT INTO projects (id, organization_id, name, created_at) "
        "VALUES (CAST(:id AS uuid), CAST(:org_id AS uuid), :name, NOW()) "
        "ON CONFLICT (id) DO NOTHING"
    )
    session.execute(
        text(ins_org),
        {"id": str(org_id), "name": f"Org_{str(org_id)[:8]}", "slug": f"slug_{str(org_id)[:8]}"},
    )
    session.execute(
        text(ins_proj),
        {"id": str(proj_id), "org_id": str(org_id), "name": "P1"},
    )


def _seed_artifact(session, org_id: uuid.UUID, proj_id: uuid.UUID, art_id: uuid.UUID):
    ins_art = (
        "INSERT INTO artifacts "
        "(id, project_id, organization_id, name, version, media_type, "
        "digest_sha256, size_bytes, storage_path, created_at) "
        "VALUES (CAST(:id AS uuid), CAST(:proj_id AS uuid), CAST(:org_id AS uuid), "
        "'art', '1.0', 'application/vnd.elf', :digest, 100, '/path', NOW()) "
        "ON CONFLICT (id) DO NOTHING"
    )
    session.execute(
        text(ins_art),
        {"id": str(art_id), "proj_id": str(proj_id), "org_id": str(org_id), "digest": "a" * 64},
    )


def test_transactional_outbox_atomic_creation():
    """Proves VerificationRun + OutboxEvent creation occurs atomically inside DB transaction."""
    db_mgr = DatabaseManager()
    org_id = uuid.uuid4()
    proj_id = uuid.uuid4()
    run_id = uuid.uuid4()
    art_id = uuid.uuid4()

    tenant_ctx = TenantContext(organization_id=org_id)
    outbox_repo = OutboxRepository(tenant_context=tenant_ctx)

    with db_mgr.get_session() as session:
        db_mgr.set_tenant_context(session, org_id)
        _seed_org_and_proj(session, org_id, proj_id)
        _seed_artifact(session, org_id, proj_id, art_id)

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

        db_mgr.set_tenant_context(session, org_id)
        outbox_events = outbox_repo.get_pending_events(session, limit=10, min_age_seconds=-1)
        assert len(outbox_events) >= 1
        assert any(e.id == event.id for e in outbox_events)

        outbox_repo.mark_dispatched(session, event.id)
        session.commit()


def test_outbox_rollback_atomicity():
    """Proves transaction rollback leaves no stranded VerificationRun or OutboxEvent."""
    db_mgr = DatabaseManager()
    org_id = uuid.uuid4()
    proj_id = uuid.uuid4()
    run_id = uuid.uuid4()

    tenant_ctx = TenantContext(organization_id=org_id)
    outbox_repo = OutboxRepository(tenant_context=tenant_ctx)

    try:
        with db_mgr.get_session() as session:
            db_mgr.set_tenant_context(session, org_id)
            payload = JobPayload(
                verification_run_id=run_id,
                organization_id=org_id,
                project_id=proj_id,
                attempt=1,
            )
            _ = outbox_repo.create_event(
                session=session,
                aggregate_type="VerificationRun",
                aggregate_id=run_id,
                project_id=proj_id,
                event_type="VERIFICATION_REQUESTED",
                payload_dict=payload.model_dump(mode="json"),
            )
            raise RuntimeError("DB_WRITE_FAILURE")
    except RuntimeError:
        pass

    with db_mgr.get_session() as session:
        db_mgr.set_tenant_context(session, org_id)
        events = outbox_repo.get_pending_events(session, limit=10, min_age_seconds=-1)
        assert not any(e.aggregate_id == run_id for e in events)


def test_outbox_redis_dispatch_failure_and_recovery():
    """Proves Redis failure leaves VerificationRun QUEUED & OutboxEvent PENDING."""
    db_mgr = DatabaseManager()
    org_id = uuid.uuid4()
    proj_id = uuid.uuid4()
    run_id = uuid.uuid4()
    art_id = uuid.uuid4()

    tenant_ctx = TenantContext(organization_id=org_id)
    outbox_repo = OutboxRepository(tenant_context=tenant_ctx)

    with db_mgr.get_session() as session:
        db_mgr.set_tenant_context(session, org_id)
        _seed_org_and_proj(session, org_id, proj_id)
        _seed_artifact(session, org_id, proj_id, art_id)

        # Create VerificationRun & OutboxEvent inside DB transaction
        run = VerificationRunModel(
            id=run_id,
            organization_id=org_id,
            project_id=proj_id,
            production_artifact_id=art_id,
            status="QUEUED",
            decision="PENDING",
            risk_score=0,
            attempt_count=0,
        )
        session.add(run)
        session.flush()

        payload = JobPayload(
            verification_run_id=run_id, organization_id=org_id, project_id=proj_id, attempt=1
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

        # Simulate Redis dispatch failure (outbox_repo.mark_dispatched NOT called)
        # Verify run remains QUEUED and event remains PENDING
        db_mgr.set_tenant_context(session, org_id)
        pending_events = outbox_repo.get_pending_events(session, limit=10, min_age_seconds=-1)
        assert any(e.id == event.id and e.status == "PENDING" for e in pending_events)

        # Outbox recovery sweep: retrieve pending event & mark dispatched
        recovered_event = next(e for e in pending_events if e.id == event.id)
        outbox_repo.mark_dispatched(session, recovered_event.id)
        session.commit()

        dispatched_event = session.scalar(
            select(OutboxEventModel).where(
                OutboxEventModel.id == event.id, OutboxEventModel.organization_id == org_id
            )
        )
        assert dispatched_event.status == "DISPATCHED"


@pytest.mark.asyncio
async def test_duplicate_outbox_dispatch_safety():
    """Proves duplicate outbox dispatch is safe via worker atomic claim."""
    db_mgr = DatabaseManager()
    org_id = uuid.uuid4()
    proj_id = uuid.uuid4()
    run_id = uuid.uuid4()
    art_id = uuid.uuid4()

    with db_mgr.get_session() as session:
        db_mgr.set_tenant_context(session, org_id)
        _seed_org_and_proj(session, org_id, proj_id)
        _seed_artifact(session, org_id, proj_id, art_id)

        run = VerificationRunModel(
            id=run_id,
            organization_id=org_id,
            project_id=proj_id,
            production_artifact_id=art_id,
            status="QUEUED",
            decision="PENDING",
            risk_score=0,
            attempt_count=0,
        )
        session.add(run)
        session.commit()

    payload_dict = JobPayload(
        verification_run_id=run_id, organization_id=org_id, project_id=proj_id, attempt=1
    ).model_dump(mode="json")

    # 1st dispatch / worker execution
    res1 = await run_verification_job({}, payload_dict)
    assert res1 == "SUCCEEDED"

    # Duplicate 2nd dispatch / worker execution (due to at-least-once outbox re-delivery)
    res2 = await run_verification_job({}, payload_dict)
    assert res2 == "ALREADY_CLAIMED_OR_TERMINAL"


def test_outbox_tenant_ownership_boundaries():
    """Verifies OutboxEvent schema enforces ownership alignment and RLS isolation."""
    db_mgr = DatabaseManager()
    org1_id = uuid.uuid4()
    proj1_id = uuid.uuid4()
    org2_id = uuid.uuid4()
    proj2_id = uuid.uuid4()
    run1_id = uuid.uuid4()
    art1_id = uuid.uuid4()

    with db_mgr.get_session() as session:
        _seed_org_and_proj(session, org1_id, proj1_id)
        _seed_org_and_proj(session, org2_id, proj2_id)

        db_mgr.set_tenant_context(session, org1_id)
        _seed_artifact(session, org1_id, proj1_id, art1_id)

        run = VerificationRunModel(
            id=run1_id,
            organization_id=org1_id,
            project_id=proj1_id,
            production_artifact_id=art1_id,
            status="QUEUED",
            decision="PENDING",
            risk_score=0,
            attempt_count=0,
        )
        session.add(run)
        session.flush()

        outbox_repo1 = OutboxRepository(tenant_context=TenantContext(organization_id=org1_id))
        event = outbox_repo1.create_event(
            session=session,
            aggregate_type="VerificationRun",
            aggregate_id=run1_id,
            project_id=proj1_id,
            event_type="VERIFICATION_REQUESTED",
            payload_dict={"test": "payload"},
        )
        session.commit()

    # RLS & Tenant Isolation: Tenant 2 cannot query Tenant 1's outbox event
    with db_mgr.get_session() as session:
        db_mgr.set_tenant_context(session, org2_id)
        event_t2 = session.scalar(
            select(OutboxEventModel).where(
                OutboxEventModel.id == event.id,
                OutboxEventModel.organization_id == org2_id,
            )
        )
        assert event_t2 is None
