import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from provenanceguard.infrastructure.database.models import Base

config = context.config

if config.config_file_name:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def get_url():
    host = os.getenv("PG_DB_HOST", "localhost")
    port = os.getenv("PG_DB_PORT", "5432")
    dbname = os.getenv("PG_DB_NAME", "provenanceguard_dev")
    user = os.getenv("PG_DB_USER", "provenanceguard_admin")
    password = os.getenv("PG_DB_PASSWORD", "pg_dev_password_change_me")
    sslmode = os.getenv("PG_SSL_MODE", "prefer")
    return f"postgresql://{user}:{password}@{host}:{port}/{dbname}?sslmode={sslmode}"


def run_migrations_offline() -> None:
    url = get_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    configuration = config.get_section(config.config_ini_section, {})
    configuration["sqlalchemy.url"] = get_url()
    connectable = engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection, target_metadata=target_metadata
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
