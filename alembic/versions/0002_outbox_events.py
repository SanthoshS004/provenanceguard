"""Outbox events table, verification_runs attempt_count, composite FKs, and RLS policy.

Revision ID: 0002_outbox_events
Revises: 0001_initial_schema
Create Date: 2026-09-08 22:00:00.000000

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "0002_outbox_events"
down_revision: Union[str, None] = "0001_initial_schema"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Add attempt_count to verification_runs
    op.add_column(
        "verification_runs",
        sa.Column("attempt_count", sa.INT(), nullable=False, server_default="1"),
    )
    op.create_unique_constraint(
        "uq_verification_runs_id_project_id",
        "verification_runs",
        ["id", "project_id"],
    )

    # 2. Create outbox_events table
    op.create_table(
        "outbox_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("project_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("aggregate_type", sa.VARCHAR(50), nullable=False),
        sa.Column("aggregate_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("event_type", sa.VARCHAR(100), nullable=False),
        sa.Column("payload_json", postgresql.JSONB(), nullable=False),
        sa.Column("status", sa.VARCHAR(20), nullable=False, server_default="PENDING"),
        sa.Column("attempts", sa.INT(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("dispatched_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["aggregate_id", "project_id"],
            ["verification_runs.id", "verification_runs.project_id"],
            ondelete="RESTRICT",
            name="fk_outbox_events_verification_run_project",
        ),
        sa.ForeignKeyConstraint(
            ["project_id", "organization_id"],
            ["projects.id", "projects.organization_id"],
            ondelete="RESTRICT",
            name="fk_outbox_events_project_org",
        ),
    )

    # 3. Enable RLS on outbox_events
    op.execute("ALTER TABLE outbox_events ENABLE ROW LEVEL SECURITY;")
    op.execute(
        """
        CREATE POLICY outbox_events_select_policy ON outbox_events
        FOR SELECT USING (organization_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

        CREATE POLICY outbox_events_insert_policy ON outbox_events
        FOR INSERT WITH CHECK (organization_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

        CREATE POLICY outbox_events_update_policy ON outbox_events
        FOR UPDATE USING (organization_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
        WITH CHECK (organization_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);
        """
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS outbox_events CASCADE;")
    op.drop_constraint("uq_verification_runs_id_project_id", "verification_runs", type_="unique")
    op.drop_column("verification_runs", "attempt_count")
