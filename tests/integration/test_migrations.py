"""Integration Tests for Alembic Database Migrations."""

import os

import pytest
from alembic.config import Config

from alembic import command


def is_postgres_available():
    import socket

    host = os.getenv("PG_DB_HOST", "localhost")
    port = int(os.getenv("PG_DB_PORT", "5432"))
    try:
        with socket.create_connection((host, port), timeout=1):
            return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not is_postgres_available(),
    reason="PostgreSQL service unavailable for migration integration tests.",
)


def test_alembic_migration_upgrade_and_downgrade():
    alembic_cfg = Config("alembic.ini")
    # Test upgrade head
    command.upgrade(alembic_cfg, "head")

    # Test downgrade base
    command.downgrade(alembic_cfg, "base")

    # Test upgrade head again
    command.upgrade(alembic_cfg, "head")
