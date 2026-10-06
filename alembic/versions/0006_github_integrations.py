"""Add github_integrations table and Git metadata columns to artifacts table.

Revision ID: 0006_github_integrations
Revises: 0005_audit_hash_chain
Create Date: 2026-09-18 21:00:00.000000

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "0006_github_integrations"
down_revision: Union[str, None] = "0005_audit_hash_chain"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add Git metadata columns to artifacts table
    op.add_column("artifacts", sa.Column("git_repository", sa.VARCHAR(255), nullable=True))
    op.add_column("artifacts", sa.Column("git_branch", sa.VARCHAR(255), nullable=True))
    op.add_column("artifacts", sa.Column("git_commit_sha", sa.VARCHAR(128), nullable=True))
    op.add_column("artifacts", sa.Column("git_workflow_run_id", sa.VARCHAR(128), nullable=True))
    op.add_column("artifacts", sa.Column("git_workflow_name", sa.VARCHAR(255), nullable=True))
    op.add_column("artifacts", sa.Column("git_build_number", sa.VARCHAR(64), nullable=True))
    op.add_column(
        "artifacts",
        sa.Column("artifact_type", sa.VARCHAR(50), nullable=False, server_default="BUILD_ARTIFACT"),
    )

    # Create github_integrations table
    op.create_table(
        "github_integrations",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            nullable=False,
        ),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("project_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("repository", sa.VARCHAR(255), nullable=False),
        sa.Column("default_branch", sa.VARCHAR(255), nullable=False, server_default="main"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("last_collected_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            ondelete="RESTRICT",
            name="fk_github_integrations_organization",
        ),
        sa.ForeignKeyConstraint(
            ["project_id"],
            ["projects.id"],
            ondelete="RESTRICT",
            name="fk_github_integrations_project",
        ),
        sa.UniqueConstraint(
            "organization_id", "project_id", name="uq_github_integrations_org_project"
        ),
    )


def downgrade() -> None:
    op.drop_table("github_integrations")
    op.drop_column("artifacts", "artifact_type")
    op.drop_column("artifacts", "git_build_number")
    op.drop_column("artifacts", "git_workflow_name")
    op.drop_column("artifacts", "git_workflow_run_id")
    op.drop_column("artifacts", "git_commit_sha")
    op.drop_column("artifacts", "git_branch")
    op.drop_column("artifacts", "git_repository")
