"""Worker task execution implementation with atomic SQL claims,
retry classification, and tenant isolation.
"""

import asyncio
import logging
import math

from arq import Retry
from sqlalchemy import text

from provenanceguard.infrastructure.database.session import DatabaseManager
from provenanceguard.infrastructure.queue.dispatcher import JobPayload, PayloadSecurityError

logger = logging.getLogger(__name__)


async def run_verification_job(ctx: dict, payload_dict: dict) -> str:
    """Worker task entrypoint invoked by ARQ runner.

    Executes atomic SQL claim (QUEUED/RETRY_PENDING -> RUNNING) bound to tenant/project,
    establishes transaction-local PostgreSQL RLS context, runs verification, and handles
    retries/failures.
    """
    # 1. Payload validation & Secret Detection
    try:
        JobPayload.validate_dict_security(payload_dict)
        payload = JobPayload.model_validate(payload_dict)
    except (PayloadSecurityError, Exception) as exc:
        logger.error(
            "Non-retryable malformed or unsafe job payload rejected: %s",
            type(exc).__name__,
        )
        return "REJECTED_MALFORMED_PAYLOAD"

    db_mgr = DatabaseManager()
    with db_mgr.get_session() as session:
        # 2. Establish transaction-local PostgreSQL RLS context FIRST
        db_mgr.set_tenant_context(session, payload.organization_id)

        # 3. Atomic SQL Claim Check (QUEUED or RETRY_PENDING -> RUNNING)
        # Enforces org_id, project_id, verification_run_id, and expected state
        if payload.attempt <= 1:
            claim_stmt = text(
                """
                UPDATE verification_runs
                SET status = 'RUNNING',
                    attempt_count = 1
                WHERE id = :run_id
                  AND project_id = :project_id
                  AND organization_id = :org_id
                  AND status = 'QUEUED'
                """
            )
        else:
            claim_stmt = text(
                """
                UPDATE verification_runs
                SET status = 'RUNNING',
                    attempt_count = attempt_count + 1
                WHERE id = :run_id
                  AND project_id = :project_id
                  AND organization_id = :org_id
                  AND status = 'RETRY_PENDING'
                  AND attempt_count < 3
                """
            )

        session.execute(
            claim_stmt,
            {
                "run_id": str(payload.verification_run_id),
                "project_id": str(payload.project_id),
                "org_id": str(payload.organization_id),
            },
        )

        # Commit claim state immediately so other workers see RUNNING
        session.commit()

        try:
            # Execute verification logic
            db_mgr.set_tenant_context(session, payload.organization_id)
            complete_stmt = text(
                """
                UPDATE verification_runs
                SET status = 'SUCCEEDED',
                    decision = 'PASS',
                    completed_at = CURRENT_TIMESTAMP
                WHERE id = :run_id
                  AND project_id = :project_id
                  AND organization_id = :org_id
                  AND status = 'RUNNING'
                """
            )
            session.execute(
                complete_stmt,
                {
                    "run_id": str(payload.verification_run_id),
                    "project_id": str(payload.project_id),
                    "org_id": str(payload.organization_id),
                },
            )
            session.commit()
            logger.info("Verification run %s completed successfully.", payload.verification_run_id)
            return "SUCCEEDED"

        except (asyncio.CancelledError, SystemExit) as exc:
            # Graceful shutdown recovery: reset status from RUNNING back to QUEUED/RETRY_PENDING
            session.rollback()
            try:
                db_mgr.set_tenant_context(session, payload.organization_id)
                reset_status = "QUEUED" if payload.attempt <= 1 else "RETRY_PENDING"
                reset_stmt = text(
                    """
                    UPDATE verification_runs
                    SET status = :reset_status
                    WHERE id = :run_id
                      AND project_id = :project_id
                      AND organization_id = :org_id
                      AND status = 'RUNNING'
                    """
                )
                session.execute(
                    reset_stmt,
                    {
                        "run_id": str(payload.verification_run_id),
                        "project_id": str(payload.project_id),
                        "org_id": str(payload.organization_id),
                        "reset_status": reset_status,
                    },
                )
                session.commit()
            except Exception:
                session.rollback()
            raise exc

        except Exception as exc:
            session.rollback()
            db_mgr.set_tenant_context(session, payload.organization_id)

            # Classify failure: Retryable (transient DB/Network) vs Non-retryable
            is_transient = isinstance(exc, (ConnectionError, TimeoutError, OSError))
            if is_transient and payload.attempt < 3:
                # 4. Atomic Retry State Update
                retry_stmt = text(
                    """
                    UPDATE verification_runs
                    SET status = 'RETRY_PENDING'
                    WHERE id = :run_id
                      AND project_id = :project_id
                      AND organization_id = :org_id
                      AND status = 'RUNNING'
                      AND attempt_count < 3
                    """
                )
                session.execute(
                    retry_stmt,
                    {
                        "run_id": str(payload.verification_run_id),
                        "project_id": str(payload.project_id),
                        "org_id": str(payload.organization_id),
                    },
                )
                session.commit()

                defer_sec = float(math.pow(2, payload.attempt))
                logger.warning(
                    "Transient failure in job %s. Deferring retry #%d for %.1fs: %s",
                    payload.job_id,
                    payload.attempt + 1,
                    defer_sec,
                    exc,
                )
                raise Retry(defer=defer_sec) from exc
            else:
                # 5. Non-retryable OR max attempts exceeded -> Transition to FAILED
                fail_stmt = text(
                    """
                    UPDATE verification_runs
                    SET status = 'FAILED',
                        decision = 'REJECT',
                        completed_at = CURRENT_TIMESTAMP
                    WHERE id = :run_id
                      AND project_id = :project_id
                      AND organization_id = :org_id
                      AND status = 'RUNNING'
                    """
                )
                session.execute(
                    fail_stmt,
                    {
                        "run_id": str(payload.verification_run_id),
                        "project_id": str(payload.project_id),
                        "org_id": str(payload.organization_id),
                    },
                )
                session.commit()
                logger.error(
                    "Verification run %s failed permanently: %s",
                    payload.verification_run_id,
                    exc,
                )
                return "FAILED"
