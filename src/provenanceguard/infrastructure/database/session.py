"""Database Session & Connection Management Module for ProvenanceGuard.

Implements SQLAlchemy 2.0 engine creation, connection pooling,
transaction-local tenant context setting via set_config(..., true),
and session management context managers.
"""

from __future__ import annotations

import logging
import os
from contextlib import contextmanager
from typing import Generator
from uuid import UUID

from sqlalchemy import create_engine, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

logger = logging.getLogger(__name__)


class Base(DeclarativeBase):
    """SQLAlchemy Declarative Base class for all ORM models."""

    pass


class DatabaseManager:
    """Manages SQLAlchemy engine, connection pool, and session creation."""

    def __init__(self, db_url: str | None = None) -> None:
        if db_url is None:
            db_url = os.getenv("DATABASE_URL")
            if not db_url:
                host = os.getenv("PG_DB_HOST")
                if host:
                    port = os.getenv("PG_DB_PORT", "5432")
                    dbname = os.getenv("PG_DB_NAME", "provenanceguard_dev")
                    user = os.getenv("PG_DB_USER", "provenanceguard_admin")
                    password = os.getenv("PG_DB_PASSWORD")
                    if not password:
                        pwd_file = os.getenv("PG_DB_PASSWORD_FILE")
                        if pwd_file and os.path.exists(pwd_file):
                            try:
                                with open(pwd_file, "r", encoding="utf-8") as f:
                                    password = f.read().strip()
                            except Exception:
                                pass
                    if not password:
                        password = "pg_dev_password_change_me"
                    sslmode = os.getenv("PG_SSL_MODE", "prefer")
                    db_url = f"postgresql://{user}:{password}@{host}:{port}/{dbname}?sslmode={sslmode}"
                else:
                    db_url = os.getenv("PG_SQLITE_URL", "sqlite:///./provenanceguard_dev.db")

        self.db_url = db_url

        # Test engine creation and connection; fallback to SQLite if PostgreSQL fails
        if not self.db_url.startswith("sqlite"):
            try:
                test_engine = create_engine(
                    self.db_url,
                    pool_timeout=2,
                    echo=False,
                )
                with test_engine.connect() as conn:
                    conn.execute(text("SELECT 1"))
                self.engine = create_engine(
                    self.db_url,
                    pool_size=10,
                    max_overflow=20,
                    pool_timeout=30,
                    pool_recycle=1800,
                    pool_pre_ping=True,
                    echo=False,
                )
            except Exception:
                logger.info("PostgreSQL connection unavailable. Falling back to local SQLite database.")
                self.db_url = os.getenv("PG_SQLITE_URL", "sqlite:///./provenanceguard_dev.db")
                self.engine = create_engine(
                    self.db_url,
                    connect_args={"check_same_thread": False},
                    echo=False,
                )
        else:
            self.engine = create_engine(
                self.db_url,
                connect_args={"check_same_thread": False},
                echo=False,
            )

        self._session_factory = sessionmaker(
            bind=self.engine, autoflush=False, expire_on_commit=False
        )

    @contextmanager
    def get_session(self) -> Generator[Session, None, None]:
        """Transactional session context manager with clean rollback on error."""
        session: Session = self._session_factory()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def set_tenant_context(self, session: Session, organization_id: str | UUID) -> None:
        """Sets transaction-local PostgreSQL RLS context variable `app.current_tenant_id`.

        Uses `SELECT set_config('app.current_tenant_id', :org_id, true)` where `is_local=true`
        ensures the setting is automatically cleared upon transaction COMMIT or ROLLBACK.
        """
        org_str = str(organization_id)
        is_sqlite = (
            self.db_url.startswith("sqlite")
            or (session.bind is not None and session.bind.dialect.name == "sqlite")
        )
        if is_sqlite:
            return
        session.execute(
            text("SELECT set_config('app.current_tenant_id', :org_id, true)"),
            {"org_id": org_str},
        )
