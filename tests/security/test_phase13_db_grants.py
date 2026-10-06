"""Security tests verifying Phase 10 least-privilege DB grant boundary for Phase 13 tables.

Proves that provenanceguard_app cannot execute physical DELETE SQL queries on
webhook_subscriptions, webhook_deliveries, or idp_configurations tables.
"""

import os

import pytest
import sqlalchemy
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker


def get_app_engine():
    host = os.getenv("PG_DB_HOST", "localhost")
    port = os.getenv("PG_DB_PORT", "5432")
    dbname = os.getenv("PG_DB_NAME", "provenanceguard_dev")
    user = os.getenv("PG_APP_USER", "provenanceguard_app")
    password = os.getenv("PG_APP_PASSWORD", "app_dev_password_123")
    sslmode = os.getenv("PG_SSL_MODE", "prefer")
    url = f"postgresql://{user}:{password}@{host}:{port}/{dbname}?sslmode={sslmode}"
    return create_engine(url, pool_pre_ping=True)


def is_postgres_available() -> bool:
    """Checks whether real PostgreSQL with provenanceguard_app role is available."""
    try:
        engine = get_app_engine()
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not is_postgres_available(),
    reason="Requires PostgreSQL with provenanceguard_app role configured",
)


def test_provenanceguard_app_cannot_delete_phase13_tables():
    """Verifies that physical DELETE SQL queries as provenanceguard_app raise a permission error."""
    engine = get_app_engine()
    SessionLocal = sessionmaker(bind=engine)
    session = SessionLocal()

    try:
        # Set tenant context
        session.execute(
            text(
                "SELECT set_config('app.current_tenant_id', '00000000-0000-0000-0000-000000000000', true)"
            )
        )

        # 1. Attempt DELETE on webhook_subscriptions
        with pytest.raises(sqlalchemy.exc.ProgrammingError) as exc_info:
            session.execute(
                text(
                    "DELETE FROM webhook_subscriptions WHERE id = '00000000-0000-0000-0000-000000000000'"
                )
            )
        assert "permission denied" in str(exc_info.value).lower()
        session.rollback()

        # 2. Attempt DELETE on webhook_deliveries
        with pytest.raises(sqlalchemy.exc.ProgrammingError) as exc_info:
            session.execute(
                text(
                    "DELETE FROM webhook_deliveries WHERE id = '00000000-0000-0000-0000-000000000000'"
                )
            )
        assert "permission denied" in str(exc_info.value).lower()
        session.rollback()

        # 3. Attempt DELETE on idp_configurations
        with pytest.raises(sqlalchemy.exc.ProgrammingError) as exc_info:
            session.execute(
                text(
                    "DELETE FROM idp_configurations WHERE id = '00000000-0000-0000-0000-000000000000'"
                )
            )
        assert "permission denied" in str(exc_info.value).lower()
        session.rollback()
    finally:
        session.close()
