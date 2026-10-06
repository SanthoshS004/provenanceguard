"""Add organization-scoped audit sequence_number, previous_hash, and current_hash columns and unique constraint.

Revision ID: 0005_audit_hash_chain
Revises: 0004_webhooks_and_idp
Create Date: 2026-09-10 20:00:00.000000

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0005_audit_hash_chain"
down_revision: Union[str, None] = "0004_webhooks_and_idp"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "audit_logs",
        sa.Column("sequence_number", sa.BIGINT(), nullable=False, server_default="1"),
    )
    op.add_column(
        "audit_logs",
        sa.Column(
            "previous_hash",
            sa.CHAR(64),
            nullable=False,
            server_default="0000000000000000000000000000000000000000000000000000000000000000",
        ),
    )
    op.add_column(
        "audit_logs",
        sa.Column(
            "current_hash",
            sa.CHAR(64),
            nullable=False,
            server_default="0000000000000000000000000000000000000000000000000000000000000000",
        ),
    )
    op.create_unique_constraint(
        "uq_audit_logs_org_sequence", "audit_logs", ["organization_id", "sequence_number"]
    )


def downgrade() -> None:
    op.drop_constraint("uq_audit_logs_org_sequence", "audit_logs", type_="unique")
    op.drop_column("audit_logs", "current_hash")
    op.drop_column("audit_logs", "previous_hash")
    op.drop_column("audit_logs", "sequence_number")
