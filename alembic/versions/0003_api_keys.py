"""API keys table, RLS policies, least-privilege SECURITY DEFINER lookup function, and grants.

Revision ID: 0003_api_keys
Revises: 0002_outbox_events
Create Date: 2026-09-09 10:00:00.000000

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "0003_api_keys"
down_revision: Union[str, None] = "0002_outbox_events"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create api_keys table
    op.create_table(
        "api_keys",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "organization_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "project_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("projects.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column("name", sa.VARCHAR(255), nullable=False),
        sa.Column("prefix", sa.VARCHAR(16), nullable=False),
        sa.Column("key_hash", sa.CHAR(64), nullable=False, unique=True),
        sa.Column("role", sa.VARCHAR(50), nullable=False),
        sa.Column("scopes_json", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("organization_id", "name", name="uq_api_keys_org_name"),
    )

    # 2. Enable Row Level Security (RLS) on api_keys
    op.execute("ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;")

    # 3. Add RLS policies for tenant context scoping
    op.execute(
        """
        CREATE POLICY api_keys_select_policy ON api_keys
        FOR SELECT USING (organization_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

        CREATE POLICY api_keys_insert_policy ON api_keys
        FOR INSERT WITH CHECK (organization_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

        CREATE POLICY api_keys_update_policy ON api_keys
        FOR UPDATE USING (organization_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
        WITH CHECK (organization_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

        CREATE POLICY api_keys_delete_policy ON api_keys
        FOR DELETE USING (organization_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);
        """
    )

    # 4. Grants to application role if it exists
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'provenanceguard_app') THEN
                GRANT SELECT, INSERT, UPDATE, DELETE ON api_keys TO provenanceguard_app;
            END IF;
        END
        $$;
        """
    )

    # 5. Create SECURITY DEFINER lookup function with fixed search_path and minimal read-only fields
    op.execute(
        """
        CREATE OR REPLACE FUNCTION lookup_api_key_by_hash(p_key_hash CHAR(64))
        RETURNS TABLE (
            id UUID,
            organization_id UUID,
            project_id UUID,
            role VARCHAR(50),
            scopes_json JSONB,
            expires_at TIMESTAMPTZ,
            revoked_at TIMESTAMPTZ
        )
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = public, pg_temp
        AS $$
        BEGIN
            RETURN QUERY
            SELECT 
                k.id,
                k.organization_id,
                k.project_id,
                k.role,
                k.scopes_json,
                k.expires_at,
                k.revoked_at
            FROM api_keys k
            WHERE k.key_hash = p_key_hash;
        END;
        $$;

        REVOKE ALL ON FUNCTION lookup_api_key_by_hash(CHAR(64)) FROM PUBLIC;

        DO $$
        BEGIN
            IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'provenanceguard_app') THEN
                GRANT EXECUTE ON FUNCTION lookup_api_key_by_hash(CHAR(64)) TO provenanceguard_app;
            END IF;
        END
        $$;
        """
    )


def downgrade() -> None:
    op.execute("DROP FUNCTION IF EXISTS lookup_api_key_by_hash(CHAR(64)) CASCADE;")
    op.execute("DROP TABLE IF EXISTS api_keys CASCADE;")
