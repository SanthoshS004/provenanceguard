"""Webhooks and IdP configuration tables, RLS policies, constraints, partial indexes, and least-privilege grants (NO DELETE).

Revision ID: 0004_webhooks_and_idp
Revises: 0003_api_keys
Create Date: 2026-09-09 12:00:00.000000

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "0004_webhooks_and_idp"
down_revision: Union[str, None] = "0003_api_keys"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create webhook_subscriptions table
    op.create_table(
        "webhook_subscriptions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "organization_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("name", sa.VARCHAR(255), nullable=False),
        sa.Column("target_url", sa.VARCHAR(1024), nullable=False),
        sa.Column("secret_key_version", sa.INT(), nullable=False, server_default="1"),
        sa.Column("secret_nonce", sa.LargeBinary(), nullable=False),
        sa.Column("encrypted_secret", sa.LargeBinary(), nullable=False),
        sa.Column("secret_fingerprint", sa.CHAR(64), nullable=False),
        sa.Column("events_json", postgresql.JSONB(), nullable=False),
        sa.Column("is_active", sa.BOOLEAN(), nullable=False, server_default="true"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )

    # 2. Create webhook_deliveries table with CHECK constraints
    op.create_table(
        "webhook_deliveries",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "subscription_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("webhook_subscriptions.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "organization_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("event_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("event_type", sa.VARCHAR(100), nullable=False),
        sa.Column("status", sa.VARCHAR(20), nullable=False, server_default="PENDING"),
        sa.Column("attempt_count", sa.INT(), nullable=False, server_default="0"),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_status_code", sa.INT(), nullable=True),
        sa.Column("error_summary", sa.VARCHAR(255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("subscription_id", "event_id", name="uq_webhook_deliveries_sub_event"),
        sa.CheckConstraint("attempt_count >= 0 AND attempt_count <= 5", name="ck_webhook_deliveries_attempt_count"),
        sa.CheckConstraint(
            "status IN ('PENDING', 'DISPATCHING', 'DELIVERED', 'RETRY_PENDING', 'FAILED', 'DISABLED')",
            name="ck_webhook_deliveries_status",
        ),
        sa.CheckConstraint(
            "event_type IN ('VERIFICATION_COMPLETED', 'FINDING_DETECTED', 'API_KEY_REVOKED')",
            name="ck_webhook_deliveries_event_type",
        ),
    )

    # 3. Create idp_configurations table
    op.create_table(
        "idp_configurations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "organization_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("name", sa.VARCHAR(255), nullable=False),
        sa.Column("issuer", sa.VARCHAR(1024), nullable=False),
        sa.Column("client_id", sa.VARCHAR(255), nullable=False),
        sa.Column("jwks_uri", sa.VARCHAR(1024), nullable=False),
        sa.Column("subject_claim", sa.VARCHAR(50), nullable=False, server_default="sub"),
        sa.Column("group_claim", sa.VARCHAR(50), nullable=False, server_default="groups"),
        sa.Column("group_role_map_json", postgresql.JSONB(), nullable=False),
        sa.Column("is_active", sa.BOOLEAN(), nullable=False, server_default="true"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    # Create partial unique index on active IdP issuer per organization
    op.execute(
        """
        CREATE UNIQUE INDEX idx_idp_active_org_issuer 
        ON idp_configurations (organization_id, issuer) 
        WHERE is_active = TRUE;
        """
    )

    # 4. Enable Row Level Security (RLS) on all three tables
    op.execute("ALTER TABLE webhook_subscriptions ENABLE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE webhook_deliveries ENABLE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE idp_configurations ENABLE ROW LEVEL SECURITY;")

    # 5. Add RLS policies for tenant context scoping
    op.execute(
        """
        CREATE POLICY webhook_subscriptions_select_policy ON webhook_subscriptions
        FOR SELECT USING (organization_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

        CREATE POLICY webhook_subscriptions_insert_policy ON webhook_subscriptions
        FOR INSERT WITH CHECK (organization_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

        CREATE POLICY webhook_subscriptions_update_policy ON webhook_subscriptions
        FOR UPDATE USING (organization_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
        WITH CHECK (organization_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

        CREATE POLICY webhook_subscriptions_delete_policy ON webhook_subscriptions
        FOR DELETE USING (organization_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

        CREATE POLICY webhook_deliveries_select_policy ON webhook_deliveries
        FOR SELECT USING (organization_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

        CREATE POLICY webhook_deliveries_insert_policy ON webhook_deliveries
        FOR INSERT WITH CHECK (organization_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

        CREATE POLICY webhook_deliveries_update_policy ON webhook_deliveries
        FOR UPDATE USING (organization_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
        WITH CHECK (organization_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

        CREATE POLICY webhook_deliveries_delete_policy ON webhook_deliveries
        FOR DELETE USING (organization_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

        CREATE POLICY idp_configurations_select_policy ON idp_configurations
        FOR SELECT USING (organization_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

        CREATE POLICY idp_configurations_insert_policy ON idp_configurations
        FOR INSERT WITH CHECK (organization_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

        CREATE POLICY idp_configurations_update_policy ON idp_configurations
        FOR UPDATE USING (organization_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
        WITH CHECK (organization_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

        CREATE POLICY idp_configurations_delete_policy ON idp_configurations
        FOR DELETE USING (organization_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);
        """
    )

    # 6. Least-privilege Grants to application role (NO DELETE permission!)
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'provenanceguard_app') THEN
                GRANT SELECT, INSERT, UPDATE ON webhook_subscriptions TO provenanceguard_app;
                GRANT SELECT, INSERT, UPDATE ON webhook_deliveries TO provenanceguard_app;
                GRANT SELECT, INSERT, UPDATE ON idp_configurations TO provenanceguard_app;
            END IF;
        END
        $$;
        """
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_idp_active_org_issuer CASCADE;")
    op.execute("DROP TABLE IF EXISTS idp_configurations CASCADE;")
    op.execute("DROP TABLE IF EXISTS webhook_deliveries CASCADE;")
    op.execute("DROP TABLE IF EXISTS webhook_subscriptions CASCADE;")
