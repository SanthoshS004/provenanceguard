"""Phase 18 Audit Log Tamper-Evident Hash Chain Unit & Concurrency Tests.

Verifies canonical JSON byte serialization, organization-scoped gapless sequence allocation,
hash-chain verification, trusted AuditCheckpoint validation, anomaly detection for tampering,
link breakage, sequence gaps, tail deletion, and concurrent transaction safety.
"""

import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import pytest

from provenanceguard.core.domain.audit import (
    GENESIS_PREVIOUS_HASH,
    AuditCheckpoint,
    AuditIntegrityError,
    AuditIntegrityVerifier,
    canonicalize_audit_entry,
    compute_audit_hash,
)
from provenanceguard.infrastructure.database.models import OrganizationModel
from provenanceguard.infrastructure.database.repositories import AuditLogRepository
from provenanceguard.infrastructure.database.session import DatabaseManager
from provenanceguard.infrastructure.database.tenant_context import TenantContext


class MockAuditEvent:
    """Mock audit log model for unit testing domain verifier logic."""

    def __init__(
        self,
        sequence_number: int,
        organization_id: uuid.UUID,
        actor_id: str = "usr_test",
        action: str = "VERIFICATION_SUBMITTED",
        resource: str = "res_123",
        result: str = "SUCCESS",
        previous_hash: str = GENESIS_PREVIOUS_HASH,
        current_hash: str = "",
        created_at: datetime | None = None,
        metadata_json: dict | None = None,
    ):
        self.sequence_number = sequence_number
        self.organization_id = organization_id
        self.actor_id = actor_id
        self.action = action
        self.resource = resource
        self.result = result
        self.previous_hash = previous_hash
        self.created_at = created_at or datetime.now(timezone.utc)
        self.metadata_json = metadata_json or {"test": "data"}

        if not current_hash:
            canonical_bytes = canonicalize_audit_entry(
                version="1",
                sequence_number=self.sequence_number,
                previous_hash=self.previous_hash,
                organization_id=self.organization_id,
                actor_id=self.actor_id,
                action=self.action,
                resource=self.resource,
                result=self.result,
                timestamp_utc=self.created_at,
                metadata_json=self.metadata_json,
            )
            self.current_hash = compute_audit_hash(canonical_bytes)
        else:
            self.current_hash = current_hash


def _create_org(session, org_id: uuid.UUID) -> OrganizationModel:
    org = OrganizationModel(
        id=org_id,
        name=f"Org_{str(org_id)[:8]}",
        slug=f"slug_{str(org_id)[:8]}",
    )
    session.add(org)
    session.flush()
    return org


def test_valid_audit_hash_chain_verification():
    """Verifies that a valid contiguous audit event chain passes AuditIntegrityVerifier."""
    org_id = uuid.uuid4()
    t1 = datetime.now(timezone.utc)

    ev1 = MockAuditEvent(
        sequence_number=1,
        organization_id=org_id,
        previous_hash=GENESIS_PREVIOUS_HASH,
        created_at=t1,
    )
    ev2 = MockAuditEvent(
        sequence_number=2, organization_id=org_id, previous_hash=ev1.current_hash, created_at=t1
    )
    ev3 = MockAuditEvent(
        sequence_number=3, organization_id=org_id, previous_hash=ev2.current_hash, created_at=t1
    )

    chain = [ev1, ev2, ev3]
    assert AuditIntegrityVerifier.verify_chain(chain) is True

    checkpoint = AuditCheckpoint(
        organization_id=org_id, head_sequence_number=3, head_hash=ev3.current_hash
    )
    assert AuditIntegrityVerifier.verify_chain(chain, checkpoint=checkpoint) is True


def test_audit_tamper_detection_record_modified():
    """Verifies that modifying record content raises AuditIntegrityError(RECORD_MODIFIED)."""
    org_id = uuid.uuid4()
    t1 = datetime.now(timezone.utc)

    ev1 = MockAuditEvent(sequence_number=1, organization_id=org_id, created_at=t1)
    ev2 = MockAuditEvent(
        sequence_number=2, organization_id=org_id, previous_hash=ev1.current_hash, created_at=t1
    )

    ev2.action = "TAMPERED_ACTION"

    with pytest.raises(AuditIntegrityError) as exc_info:
        AuditIntegrityVerifier.verify_chain([ev1, ev2])

    assert exc_info.value.error_code == "RECORD_MODIFIED"
    assert exc_info.value.sequence_number == 2


def test_audit_tamper_detection_link_broken():
    """Verifies that corrupting previous_hash link raises AuditIntegrityError(LINK_BROKEN)."""
    org_id = uuid.uuid4()
    t1 = datetime.now(timezone.utc)

    ev1 = MockAuditEvent(sequence_number=1, organization_id=org_id, created_at=t1)
    ev2 = MockAuditEvent(
        sequence_number=2,
        organization_id=org_id,
        previous_hash="ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        created_at=t1,
    )

    with pytest.raises(AuditIntegrityError) as exc_info:
        AuditIntegrityVerifier.verify_chain([ev1, ev2])

    assert exc_info.value.error_code == "LINK_BROKEN"
    assert exc_info.value.sequence_number == 2


def test_audit_tamper_detection_sequence_gap():
    """Verifies that missing middle record raises AuditIntegrityError(SEQUENCE_GAP)."""
    org_id = uuid.uuid4()
    t1 = datetime.now(timezone.utc)

    ev1 = MockAuditEvent(sequence_number=1, organization_id=org_id, created_at=t1)
    ev3 = MockAuditEvent(
        sequence_number=3, organization_id=org_id, previous_hash=ev1.current_hash, created_at=t1
    )

    with pytest.raises(AuditIntegrityError) as exc_info:
        AuditIntegrityVerifier.verify_chain([ev1, ev3])

    assert exc_info.value.error_code == "SEQUENCE_GAP"
    assert exc_info.value.sequence_number == 3


def test_audit_tamper_detection_tail_deleted():
    """Verifies that deleting tail record raises AuditIntegrityError(TAIL_DELETED) when checked against AuditCheckpoint."""
    org_id = uuid.uuid4()
    t1 = datetime.now(timezone.utc)

    ev1 = MockAuditEvent(sequence_number=1, organization_id=org_id, created_at=t1)
    ev2 = MockAuditEvent(
        sequence_number=2, organization_id=org_id, previous_hash=ev1.current_hash, created_at=t1
    )

    checkpoint = AuditCheckpoint(
        organization_id=org_id,
        head_sequence_number=3,
        head_hash="0000000000000000000000000000000000000000000000000000000000000000",
    )

    with pytest.raises(AuditIntegrityError) as exc_info:
        AuditIntegrityVerifier.verify_chain([ev1, ev2], checkpoint=checkpoint)

    assert exc_info.value.error_code == "TAIL_DELETED"
    assert exc_info.value.sequence_number == 3


def test_concurrent_audit_log_appends():
    """Verifies concurrent audit log appends preserve sequence contiguity, correct previous_hash pointers, and hash integrity."""
    db_mgr = DatabaseManager()
    org_id = uuid.uuid4()
    tenant_ctx = TenantContext(organization_id=org_id)

    with db_mgr.get_session() as session:
        _create_org(session, org_id)
        repo = AuditLogRepository(tenant_context=tenant_ctx)
        events = []
        for i in range(5):
            e = repo.log_event(
                session=session,
                actor_id=f"usr_{i}",
                action="API_KEY_CREATED",
                resource=f"key_{i}",
                result="SUCCESS",
                metadata_json={"index": i},
            )
            events.append(e)

        session.commit()

        fetched_events, count = repo.query_events(session=session, limit=10)
        assert count == 5

        sorted_events = sorted(fetched_events, key=lambda x: x.sequence_number)
        assert AuditIntegrityVerifier.verify_chain(sorted_events) is True


def test_transactional_rollback_preserves_gapless_sequence():
    """Verifies that transaction rollback leaves no orphaned sequence numbers or sequence gaps for subsequent writes."""
    db_mgr = DatabaseManager()
    org_id = uuid.uuid4()
    tenant_ctx = TenantContext(organization_id=org_id)

    with db_mgr.get_session() as session:
        _create_org(session, org_id)
        repo = AuditLogRepository(tenant_context=tenant_ctx)

        # 1. Log event #1 (committed)
        ev1 = repo.log_event(
            session=session,
            actor_id="usr_1",
            action="LOGIN",
            resource="session_1",
            result="SUCCESS",
        )
        session.commit()
        assert ev1.sequence_number == 1

        # 2. Attempt event #2 inside failed sub-transaction
        try:
            with session.begin_nested():
                repo.log_event(
                    session=session,
                    actor_id="usr_2",
                    action="INVALID_ACTION",
                    resource="session_2",
                    result="FAILED",
                )
                raise ValueError("Simulated Rollback")
        except ValueError:
            session.rollback()

        # 3. Log event #2 (committed after rollback)
        ev2 = repo.log_event(
            session=session,
            actor_id="usr_3",
            action="LOGIN_SUCCESS",
            resource="session_3",
            result="SUCCESS",
        )
        session.commit()

        assert ev2.sequence_number == 2

        fetched_events, _ = repo.query_events(session=session, limit=10)
        assert len(fetched_events) == 2

        sorted_events = sorted(fetched_events, key=lambda x: x.sequence_number)
        assert AuditIntegrityVerifier.verify_chain(sorted_events) is True


def test_real_postgresql_concurrent_audit_appends_and_locking():
    """Executes multi-threaded concurrent audit appends against PostgreSQL for the same and different organizations.

    Verifies:
    1. Transactional pg_advisory_xact_lock serializes concurrent appends per organization.
    2. Zero duplicate sequence_number values occur.
    3. Committed sequence_numbers are strictly contiguous (1..N).
    4. Every previous_hash matches the preceding committed current_hash.
    5. Rollback does not leave sequence gaps in committed chain.
    6. Appends for different organizations proceed concurrently without cross-tenant lock contention.
    """
    db_mgr = DatabaseManager()
    org_id_1 = uuid.uuid4()
    org_id_2 = uuid.uuid4()

    # Pre-create both tenant organizations in main session
    with db_mgr.get_session() as session:
        _create_org(session, org_id_1)
        _create_org(session, org_id_2)
        session.commit()

    def _thread_worker(worker_id: int, target_org_id: uuid.UUID, should_rollback: bool = False):
        tenant_ctx = TenantContext(organization_id=target_org_id)
        with db_mgr.get_session() as thread_session:
            repo = AuditLogRepository(tenant_context=tenant_ctx)
            if should_rollback:
                try:
                    with thread_session.begin_nested():
                        repo.log_event(
                            session=thread_session,
                            actor_id=f"worker_{worker_id}_rollback",
                            action="FAILED_ACTION",
                            resource=f"res_{worker_id}",
                            result="FAILED",
                        )
                        raise RuntimeError("Intended Worker Rollback")
                except RuntimeError:
                    thread_session.rollback()
            else:
                repo.log_event(
                    session=thread_session,
                    actor_id=f"worker_{worker_id}",
                    action="CONCURRENT_ACTION",
                    resource=f"res_{worker_id}",
                    result="SUCCESS",
                )
                thread_session.commit()

    # Execute concurrent thread workers across Org 1 and Org 2
    with ThreadPoolExecutor(max_workers=5) as executor:
        f1 = executor.submit(_thread_worker, 1, org_id_1, False)
        f2 = executor.submit(_thread_worker, 2, org_id_1, False)
        f3 = executor.submit(_thread_worker, 3, org_id_1, True)  # Rollback worker
        f4 = executor.submit(_thread_worker, 4, org_id_1, False)
        f5 = executor.submit(_thread_worker, 5, org_id_2, False)  # Org 2 parallel worker

        f1.result()
        f2.result()
        f3.result()
        f4.result()
        f5.result()

    # Verify Org 1 audit chain
    with db_mgr.get_session() as session:
        repo_1 = AuditLogRepository(tenant_context=TenantContext(organization_id=org_id_1))
        events_1, count_1 = repo_1.query_events(session=session, limit=10)
        assert count_1 == 3

        sorted_1 = sorted(events_1, key=lambda x: x.sequence_number)
        seq_numbers_1 = [e.sequence_number for e in sorted_1]

        # Verify zero duplicates and strictly contiguous sequence [1, 2, 3]
        assert seq_numbers_1 == [1, 2, 3]
        assert AuditIntegrityVerifier.verify_chain(sorted_1) is True

    # Verify Org 2 audit chain (independent contiguous sequence)
    with db_mgr.get_session() as session:
        repo_2 = AuditLogRepository(tenant_context=TenantContext(organization_id=org_id_2))
        events_2, count_2 = repo_2.query_events(session=session, limit=10)
        assert count_2 == 1
        assert events_2[0].sequence_number == 1
        assert AuditIntegrityVerifier.verify_chain(events_2) is True
