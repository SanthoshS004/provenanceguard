"""Integration Tests for Worker Execution, Atomic Claims, Isolation & Retries."""

import asyncio
import uuid

import pytest
import sqlalchemy.orm
from arq import Retry
from sqlalchemy import text

from provenanceguard.apps.worker.worker import run_verification_job
from provenanceguard.infrastructure.database.models import VerificationRunModel
from provenanceguard.infrastructure.database.session import DatabaseManager
from provenanceguard.infrastructure.queue.dispatcher import JobPayload

orig_execute = sqlalchemy.orm.Session.execute


def _seed_org_and_proj(
    session, org_id: uuid.UUID, proj_id: uuid.UUID, org_name=None, proj_name="P1"
):
    name = org_name or f"Org_{str(org_id)[:8]}"
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
        {"id": str(org_id), "name": name, "slug": f"slug_{str(org_id)[:8]}"},
    )
    session.execute(
        text(ins_proj),
        {"id": str(proj_id), "org_id": str(org_id), "name": proj_name},
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
        {"id": str(art_id), "proj_id": str(proj_id), "org_id": str(org_id), "digest": "b" * 64},
    )


@pytest.mark.asyncio
async def test_worker_concurrent_atomic_claim_idempotency():
    """Proves two concurrent workers claiming the same VerificationRun results in 1 execution."""
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
            attempt_count=1,
        )
        session.add(run)
        session.commit()

    payload_dict = JobPayload(
        verification_run_id=run_id,
        organization_id=org_id,
        project_id=proj_id,
        attempt=1,
    ).model_dump(mode="json")

    res1, res2 = await asyncio.gather(
        run_verification_job({}, payload_dict),
        run_verification_job({}, payload_dict),
    )

    results = {res1, res2}
    assert "SUCCEEDED" in results
    assert "ALREADY_CLAIMED_OR_TERMINAL" in results

    with db_mgr.get_session() as session:
        db_mgr.set_tenant_context(session, org_id)
        db_run = session.scalar(
            text("SELECT status FROM verification_runs WHERE id = CAST(:id AS uuid)"),
            {"id": str(run_id)},
        )
        assert db_run == "SUCCEEDED"


@pytest.mark.asyncio
async def test_worker_tenant_and_project_isolation_matrix():
    """Verifies isolation matrix (Correct/Wrong Org & Project, Attacker Payload)."""
    db_mgr = DatabaseManager()
    org1_id = uuid.uuid4()
    proj1_id = uuid.uuid4()
    org2_id = uuid.uuid4()
    proj2_id = uuid.uuid4()
    art1_id = uuid.uuid4()

    with db_mgr.get_session() as session:
        db_mgr.set_tenant_context(session, org1_id)
        _seed_org_and_proj(session, org1_id, proj1_id)
        _seed_org_and_proj(session, org2_id, proj2_id)
        _seed_artifact(session, org1_id, proj1_id, art1_id)

    # Setup Run 1 for Org1/Proj1
    run1_id = uuid.uuid4()
    with db_mgr.get_session() as session:
        db_mgr.set_tenant_context(session, org1_id)
        run1 = VerificationRunModel(
            id=run1_id,
            organization_id=org1_id,
            project_id=proj1_id,
            production_artifact_id=art1_id,
            status="QUEUED",
            decision="PENDING",
            risk_score=0,
            attempt_count=0,
        )
        session.add(run1)
        session.commit()

    # A. Correct Org + Correct Project + Correct Run -> Success
    p_a = JobPayload(
        verification_run_id=run1_id, organization_id=org1_id, project_id=proj1_id, attempt=1
    ).model_dump(mode="json")
    res_a = await run_verification_job({}, p_a)
    assert res_a == "SUCCEEDED"

    # Setup Run 2 for Org1/Proj1 (for isolation testing)
    run2_id = uuid.uuid4()
    with db_mgr.get_session() as session:
        db_mgr.set_tenant_context(session, org1_id)
        run2 = VerificationRunModel(
            id=run2_id,
            organization_id=org1_id,
            project_id=proj1_id,
            production_artifact_id=art1_id,
            status="QUEUED",
            decision="PENDING",
            risk_score=0,
            attempt_count=0,
        )
        session.add(run2)
        session.commit()

    # B. Correct Org + Wrong Project -> Fails
    p_b = JobPayload(
        verification_run_id=run2_id, organization_id=org1_id, project_id=proj2_id, attempt=1
    ).model_dump(mode="json")
    res_b = await run_verification_job({}, p_b)
    assert res_b == "ALREADY_CLAIMED_OR_TERMINAL"

    # C. Wrong Org + Correct Project -> Fails
    p_c = JobPayload(
        verification_run_id=run2_id, organization_id=org2_id, project_id=proj1_id, attempt=1
    ).model_dump(mode="json")
    res_c = await run_verification_job({}, p_c)
    assert res_c == "ALREADY_CLAIMED_OR_TERMINAL"

    # D. Wrong Org + Wrong Project -> Fails
    p_d = JobPayload(
        verification_run_id=run2_id, organization_id=org2_id, project_id=proj2_id, attempt=1
    ).model_dump(mode="json")
    res_d = await run_verification_job({}, p_d)
    assert res_d == "ALREADY_CLAIMED_OR_TERMINAL"

    # E. Attacker payload claiming victim's run -> Rejected by RLS & claim query
    p_e = JobPayload(
        verification_run_id=run2_id, organization_id=org2_id, project_id=proj2_id, attempt=1
    ).model_dump(mode="json")
    res_e = await run_verification_job({}, p_e)
    assert res_e == "ALREADY_CLAIMED_OR_TERMINAL"

    # Verify run2 remains unchanged in QUEUED state
    with db_mgr.get_session() as session:
        db_mgr.set_tenant_context(session, org1_id)
        status2 = session.scalar(
            text("SELECT status FROM verification_runs WHERE id = CAST(:id AS uuid)"),
            {"id": str(run2_id)},
        )
        assert status2 == "QUEUED"

    # F. Connection pool reuse does not leak tenant context
    with db_mgr.get_session() as session:
        db_mgr.set_tenant_context(session, org1_id)
    with db_mgr.get_session() as session:
        curr_tenant = session.scalar(text("SELECT current_setting('app.current_tenant_id', true)"))
        assert curr_tenant is None or curr_tenant == ""


@pytest.mark.asyncio
async def test_worker_retry_state_machine_and_max_attempts(monkeypatch):
    """Proves transient failure -> RETRY_PENDING -> retry re-claim -> max attempts -> FAILED."""
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

    p1 = JobPayload(
        verification_run_id=run_id, organization_id=org_id, project_id=proj_id, attempt=1
    ).model_dump(mode="json")

    # Attempt 1: Cause complete_stmt execution to raise ConnectionError
    with monkeypatch.context() as m:

        def failing_execute1(self_session, statement, *args, **kwargs):
            if "SUCCEEDED" in str(statement):
                raise ConnectionError("Simulated DB connection drop")
            return orig_execute(self_session, statement, *args, **kwargs)

        m.setattr("sqlalchemy.orm.Session.execute", failing_execute1)

        with pytest.raises(Retry):
            await run_verification_job({}, p1)

    # Verify PostgreSQL state after Attempt 1 failure: status = RETRY_PENDING, attempt_count = 1
    with db_mgr.get_session() as session:
        db_mgr.set_tenant_context(session, org_id)
        row = session.execute(
            text(
                "SELECT status, attempt_count FROM verification_runs WHERE id = CAST(:id AS uuid)"
            ),
            {"id": str(run_id)},
        ).one()
        assert row.status == "RETRY_PENDING"
        assert row.attempt_count == 1

    # Attempt 2: Retry claim with attempt = 2
    p2 = JobPayload(
        verification_run_id=run_id, organization_id=org_id, project_id=proj_id, attempt=2
    ).model_dump(mode="json")

    with monkeypatch.context() as m:

        def failing_execute2(self_session, statement, *args, **kwargs):
            if "SUCCEEDED" in str(statement):
                raise TimeoutError("Simulated network timeout")
            return orig_execute(self_session, statement, *args, **kwargs)

        m.setattr("sqlalchemy.orm.Session.execute", failing_execute2)

        with pytest.raises(Retry):
            await run_verification_job({}, p2)

    # Verify PostgreSQL state after Attempt 2 failure: status = RETRY_PENDING, attempt_count = 2
    with db_mgr.get_session() as session:
        db_mgr.set_tenant_context(session, org_id)
        row = session.execute(
            text(
                "SELECT status, attempt_count FROM verification_runs WHERE id = CAST(:id AS uuid)"
            ),
            {"id": str(run_id)},
        ).one()
        assert row.status == "RETRY_PENDING"
        assert row.attempt_count == 2

    # Attempt 3: Max attempt (attempt = 3). Next transient error transitions to FAILED
    p3 = JobPayload(
        verification_run_id=run_id, organization_id=org_id, project_id=proj_id, attempt=3
    ).model_dump(mode="json")

    with monkeypatch.context() as m:

        def failing_execute3(self_session, statement, *args, **kwargs):
            if "SUCCEEDED" in str(statement):
                raise OSError("Simulated disk error")
            return orig_execute(self_session, statement, *args, **kwargs)

        m.setattr("sqlalchemy.orm.Session.execute", failing_execute3)

        res3 = await run_verification_job({}, p3)
        assert res3 == "FAILED"

    # Verify PostgreSQL state after Attempt 3 failure: status = FAILED, decision = REJECT
    with db_mgr.get_session() as session:
        db_mgr.set_tenant_context(session, org_id)
        row = session.execute(
            text(
                "SELECT status, decision, attempt_count "
                "FROM verification_runs WHERE id = CAST(:id AS uuid)"
            ),
            {"id": str(run_id)},
        ).one()
        assert row.status == "FAILED"
        assert row.decision == "REJECT"
        assert row.attempt_count == 3


@pytest.mark.asyncio
async def test_worker_graceful_shutdown_recovery(monkeypatch):
    """Proves SIGTERM / CancelledError during execution resets status back to QUEUED."""
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

    p = JobPayload(
        verification_run_id=run_id, organization_id=org_id, project_id=proj_id, attempt=1
    ).model_dump(mode="json")

    # Simulate CancelledError during complete_stmt execution (graceful shutdown signal)
    with monkeypatch.context() as m:

        def cancelling_execute(self_session, statement, *args, **kwargs):
            if "SUCCEEDED" in str(statement):
                raise asyncio.CancelledError("Worker received SIGTERM")
            return orig_execute(self_session, statement, *args, **kwargs)

        m.setattr("sqlalchemy.orm.Session.execute", cancelling_execute)

        with pytest.raises(asyncio.CancelledError):
            await run_verification_job({}, p)

    # Verify PostgreSQL status was reset back to QUEUED and NOT left in RUNNING or SUCCEEDED
    with db_mgr.get_session() as session:
        db_mgr.set_tenant_context(session, org_id)
        status = session.scalar(
            text("SELECT status FROM verification_runs WHERE id = CAST(:id AS uuid)"),
            {"id": str(run_id)},
        )
        assert status == "QUEUED"
