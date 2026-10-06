"""Script to initialize PostgreSQL database roles & grants for provenanceguard_app."""

import os
from sqlalchemy import create_engine, text


def setup_roles():
    host = os.getenv("PG_DB_HOST", "localhost")
    port = os.getenv("PG_DB_PORT", "5432")
    dbname = os.getenv("PG_DB_NAME", "provenanceguard_dev")
    admin_user = os.getenv("PG_DB_USER", "provenanceguard_admin")
    admin_password = os.getenv("PG_DB_PASSWORD", "pg_dev_password_change_me")
    sslmode = os.getenv("PG_SSL_MODE", "prefer")

    admin_url = f"postgresql://{admin_user}:{admin_password}@{host}:{port}/{dbname}?sslmode={sslmode}"
    engine = create_engine(admin_url, isolation_level="AUTOCOMMIT")

    with engine.connect() as conn:
        # Create migrator role
        conn.execute(
            text(
                """
                DO $$
                BEGIN
                    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'provenanceguard_migrator') THEN
                        CREATE ROLE provenanceguard_migrator WITH LOGIN PASSWORD 'migrator_dev_password_123';
                    END IF;
                END
                $$;
                """
            )
        )

        # Create app role (restricted, NO BYPASSRLS)
        conn.execute(
            text(
                """
                DO $$
                BEGIN
                    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'provenanceguard_app') THEN
                        CREATE ROLE provenanceguard_app WITH LOGIN NOBYPASSRLS PASSWORD 'app_dev_password_123';
                    END IF;
                END
                $$;
                """
            )
        )

        # Grant schema permissions
        conn.execute(text("GRANT ALL ON SCHEMA public TO provenanceguard_migrator;"))
        conn.execute(text("GRANT USAGE ON SCHEMA public TO provenanceguard_app;"))

        # Grant table permissions on existing tables in public schema
        conn.execute(text("GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO provenanceguard_app;"))
        conn.execute(text("REVOKE DELETE ON ALL TABLES IN SCHEMA public FROM provenanceguard_app;"))
        conn.execute(
            text(
                """
                DO $$
                BEGIN
                    IF EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'audit_logs') THEN
                        REVOKE UPDATE, DELETE ON audit_logs FROM provenanceguard_app;
                    END IF;
                END
                $$;
                """
            )
        )

        # Configure default privileges for future tables created by admin
        conn.execute(text("ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE ON TABLES TO provenanceguard_app;"))
        conn.execute(text("ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE DELETE ON TABLES FROM provenanceguard_app;"))

    print("PostgreSQL table permissions successfully granted to provenanceguard_app.")


if __name__ == "__main__":
    setup_roles()
