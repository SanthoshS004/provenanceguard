"""PostgreSQL Transactional Outbox Repository."""

import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, text, update
from sqlalchemy.orm import Session

from provenanceguard.infrastructure.database.models import OutboxEventModel
from provenanceguard.infrastructure.database.tenant_context import TenantContext


class OutboxRepository:
    """Manages creation, dispatch status, and recovery sweeping for transactional outbox events."""

    def __init__(self, tenant_context: TenantContext):
        self.tenant_context = tenant_context

    def create_event(
        self,
        session: Session,
        aggregate_type: str,
        aggregate_id: uuid.UUID,
        project_id: uuid.UUID,
        event_type: str,
        payload_dict: dict,
    ) -> OutboxEventModel:
        """Inserts an OutboxEvent record into PostgreSQL inside active transaction."""
        if session.bind is None or session.bind.dialect.name != "sqlite":
            session.execute(
                text("SELECT set_config('app.current_tenant_id', :org_id, true)"),
                {"org_id": str(self.tenant_context.organization_id)},
            )

        event = OutboxEventModel(
            id=uuid.uuid4(),
            organization_id=self.tenant_context.organization_id,
            project_id=project_id,
            aggregate_type=aggregate_type,
            aggregate_id=aggregate_id,
            event_type=event_type,
            payload_json=payload_dict,
            status="PENDING",
            attempts=0,
            created_at=datetime.now(timezone.utc),
        )
        session.add(event)
        return event

    def mark_dispatched(self, session: Session, event_id: uuid.UUID) -> None:
        """Marks an outbox event as DISPATCHED after successful Redis enqueue."""
        if session.bind is None or session.bind.dialect.name != "sqlite":
            session.execute(
                text("SELECT set_config('app.current_tenant_id', :org_id, true)"),
                {"org_id": str(self.tenant_context.organization_id)},
            )
        stmt = (
            update(OutboxEventModel)
            .where(
                OutboxEventModel.id == event_id,
                OutboxEventModel.organization_id == self.tenant_context.organization_id,
            )
            .values(status="DISPATCHED", dispatched_at=datetime.now(timezone.utc))
        )
        session.execute(stmt)

    def get_pending_events(
        self, session: Session, limit: int = 100, min_age_seconds: float = 30.0
    ) -> list[OutboxEventModel]:
        """Retrieves stale PENDING outbox events for recovery sweeping."""
        if session.bind is None or session.bind.dialect.name != "sqlite":
            session.execute(
                text("SELECT set_config('app.current_tenant_id', :org_id, true)"),
                {"org_id": str(self.tenant_context.organization_id)},
            )
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=min_age_seconds)
        stmt = (
            select(OutboxEventModel)
            .where(
                OutboxEventModel.organization_id == self.tenant_context.organization_id,
                OutboxEventModel.status == "PENDING",
                OutboxEventModel.created_at <= cutoff,
            )
            .limit(limit)
        )
        return list(session.scalars(stmt).all())
