"""Initial schema, composite foreign keys, RLS policies, audit immutability triggers, and role grants.

Revision ID: 0001_initial_schema
Revises:
Create Date: 2026-09-08 20:50:00.000000

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "0001_initial_schema"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create organizations table
    op.create_table(
        "organizations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.VARCHAR(255), nullable=False, unique=True),
        sa.Column("slug", sa.VARCHAR(100), nullable=False, unique=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    # 2. Create projects table
    op.create_table(
        "projects",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("name", sa.VARCHAR(255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("id", "organization_id", name="uq_projects_id_organization_id"),
        sa.UniqueConstraint("organization_id", "name", name="uq_projects_organization_id_name"),
    )

    # 3. Create repositories table
    op.create_table(
        "repositories",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("project_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("remote_url", sa.VARCHAR(1024), nullable=False),
        sa.Column("default_branch", sa.VARCHAR(255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["project_id", "organization_id"],
            ["projects.id", "projects.organization_id"],
            ondelete="RESTRICT",
            name="fk_repositories_project_org",
        ),
    )

    # 4. Create builds table
    op.create_table(
        "builds",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("project_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("builder_image", sa.VARCHAR(1024), nullable=False),
        sa.Column("commit_sha", sa.VARCHAR(128), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["project_id", "organization_id"],
            ["projects.id", "projects.organization_id"],
            ondelete="RESTRICT",
            name="fk_builds_project_org",
        ),
    )

    # 5. Create artifacts table
    op.create_table(
        "artifacts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("project_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.VARCHAR(255), nullable=False),
        sa.Column("version", sa.VARCHAR(100), nullable=False),
        sa.Column("media_type", sa.VARCHAR(100), nullable=False),
        sa.Column("digest_sha256", sa.CHAR(64), nullable=False),
        sa.Column("size_bytes", sa.BIGINT(), nullable=False),
        sa.Column("storage_path", sa.VARCHAR(1024), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("id", "project_id", name="uq_artifacts_id_project_id"),
        sa.UniqueConstraint("project_id", "digest_sha256", name="uq_artifacts_project_digest"),
        sa.ForeignKeyConstraint(
            ["project_id", "organization_id"],
            ["projects.id", "projects.organization_id"],
            ondelete="RESTRICT",
            name="fk_artifacts_project_org",
        ),
        sa.CheckConstraint("size_bytes >= 0", name="ck_artifacts_size_non_negative"),
        sa.CheckConstraint("digest_sha256 ~ '^[a-f0-9]{64}$'", name="ck_artifacts_digest_sha256_format"),
    )

    # 6. Create verification_runs table
    op.create_table(
        "verification_runs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("project_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("production_artifact_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("reference_artifact_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("status", sa.VARCHAR(50), nullable=False),
        sa.Column("decision", sa.VARCHAR(50), nullable=False),
        sa.Column("risk_score", sa.INT(), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["production_artifact_id", "project_id"],
            ["artifacts.id", "artifacts.project_id"],
            ondelete="RESTRICT",
            name="fk_verification_runs_production_artifact_project",
        ),
        sa.ForeignKeyConstraint(
            ["reference_artifact_id", "project_id"],
            ["artifacts.id", "artifacts.project_id"],
            ondelete="RESTRICT",
            name="fk_verification_runs_reference_artifact_project",
        ),
        sa.ForeignKeyConstraint(
            ["project_id", "organization_id"],
            ["projects.id", "projects.organization_id"],
            ondelete="RESTRICT",
            name="fk_verification_runs_project_org",
        ),
    )

    # 7. Create findings table
    op.create_table(
        "findings",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("verification_run_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("severity", sa.VARCHAR(20), nullable=False),
        sa.Column("category", sa.VARCHAR(100), nullable=False),
        sa.Column("explanation", sa.TEXT(), nullable=False),
        sa.Column("remediation", sa.TEXT(), nullable=True),
        sa.Column("details_json", postgresql.JSONB(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["verification_run_id"],
            ["verification_runs.id"],
            ondelete="RESTRICT",
            name="fk_findings_verification_run",
        ),
    )

    # 8. Create audit_logs table
    op.create_table(
        "audit_logs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("actor_id", sa.VARCHAR(255), nullable=False),
        sa.Column("action", sa.VARCHAR(100), nullable=False),
        sa.Column("resource", sa.VARCHAR(255), nullable=False),
        sa.Column("result", sa.VARCHAR(50), nullable=False),
        sa.Column("metadata_json", postgresql.JSONB(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    # 9. Audit Immutability DB Trigger
    op.execute(
        """
        CREATE OR REPLACE FUNCTION prevent_audit_log_modification()
        RETURNS TRIGGER AS $$
        BEGIN
            RAISE EXCEPTION 'Audit log entries are immutable and cannot be updated or deleted.';
        END;
        $$ LANGUAGE plpgsql;

        CREATE TRIGGER trg_prevent_audit_log_modification
        BEFORE UPDATE OR DELETE ON audit_logs
        FOR EACH ROW EXECUTE FUNCTION prevent_audit_log_modification();

        DO $$
        BEGIN
            IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'provenanceguard_app') THEN
                REVOKE UPDATE, DELETE ON audit_logs FROM provenanceguard_app;
            END IF;
        END
        $$;
        """
    )

    # 10. Enable RLS on all tenant tables
    tables = ["organizations", "projects", "repositories", "builds", "artifacts", "verification_runs", "findings", "audit_logs"]
    for tbl in tables:
        op.execute(f"ALTER TABLE {tbl} ENABLE ROW LEVEL SECURITY;")

    # Add RLS policies for organizations
    op.execute(
        """
        CREATE POLICY org_select_policy ON organizations
        FOR SELECT USING (id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

        CREATE POLICY org_update_policy ON organizations
        FOR UPDATE USING (id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
        WITH CHECK (id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);
        """
    )

    # Add RLS policies for remaining tenant tables
    tenant_tables = ["projects", "repositories", "builds", "artifacts", "verification_runs", "findings", "audit_logs"]
    for tbl in tenant_tables:
        op.execute(
            f"""
            CREATE POLICY {tbl}_select_policy ON {tbl}
            FOR SELECT USING (organization_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

            CREATE POLICY {tbl}_insert_policy ON {tbl}
            FOR INSERT WITH CHECK (organization_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);
            """
        )
        if tbl != "audit_logs":
            op.execute(
                f"""
                CREATE POLICY {tbl}_update_policy ON {tbl}
                FOR UPDATE USING (organization_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
                WITH CHECK (organization_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);
                """
            )


def downgrade() -> None:
    tables = ["audit_logs", "findings", "verification_runs", "artifacts", "builds", "repositories", "projects", "organizations"]
    for tbl in tables:
        op.execute(f"DROP TABLE IF EXISTS {tbl} CASCADE;")
    op.execute("DROP FUNCTION IF EXISTS prevent_audit_log_modification CASCADE;")
