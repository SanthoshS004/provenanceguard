"""Database schema verification script for Phase 13."""

import os
from sqlalchemy import create_engine, text

def verify_database():
    host = os.getenv("PG_DB_HOST", "localhost")
    port = os.getenv("PG_DB_PORT", "5432")
    dbname = os.getenv("PG_DB_NAME", "provenanceguard_dev")
    user = os.getenv("PG_DB_USER", "provenanceguard_admin")
    password = os.getenv("PG_DB_PASSWORD", "pg_dev_password_change_me")
    sslmode = os.getenv("PG_SSL_MODE", "prefer")
    url = f"postgresql://{user}:{password}@{host}:{port}/{dbname}?sslmode={sslmode}"
    engine = create_engine(url)

    with engine.connect() as conn:
        print("=== DATABASE VERIFICATION ===")
        
        # 1. Tables exist
        tables = ["webhook_subscriptions", "webhook_deliveries", "idp_configurations"]
        for t in tables:
            res = conn.execute(text("SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = :t)"), {"t": t}).scalar()
            print(f"Table '{t}' exists: {res}")
            assert res is True

        # 2. RLS Enabled
        for t in tables:
            rls = conn.execute(text("SELECT relrowsecurity FROM pg_class WHERE relname = :t"), {"t": t}).scalar()
            print(f"Table '{t}' RLS enabled: {rls}")
            assert rls is True

        # 3. Grants to provenanceguard_app
        for t in tables:
            grants = conn.execute(text("SELECT privilege_type FROM information_schema.role_table_grants WHERE grantee = 'provenanceguard_app' AND table_name = :t"), {"t": t}).fetchall()
            privs = [g[0] for g in grants]
            print(f"Table '{t}' privileges for provenanceguard_app: {privs}")
            assert "DELETE" not in privs
            assert "SELECT" in privs
            assert "INSERT" in privs
            assert "UPDATE" in privs

        # 4. Check Constraints on webhook_deliveries
        constraints = conn.execute(text("SELECT conname FROM pg_constraint WHERE conrelid = 'webhook_deliveries'::regclass")).fetchall()
        c_names = [c[0] for c in constraints]
        print(f"webhook_deliveries constraints: {c_names}")
        assert "ck_webhook_deliveries_attempt_count" in c_names
        assert "ck_webhook_deliveries_status" in c_names
        assert "ck_webhook_deliveries_event_type" in c_names
        assert "uq_webhook_deliveries_sub_event" in c_names

        # 5. Partial Unique Index on idp_configurations
        indexes = conn.execute(text("SELECT indexname, indexdef FROM pg_indexes WHERE tablename = 'idp_configurations'")).fetchall()
        print("idp_configurations indexes:", indexes)
        active_idx = [idx for idx in indexes if idx[0] == "idx_idp_active_org_issuer"]
        assert len(active_idx) == 1
        assert "is_active = true" in active_idx[0][1].lower()

        print("=== ALL DATABASE VERIFICATIONS PASSED CLEANLY ===")

if __name__ == "__main__":
    verify_database()
