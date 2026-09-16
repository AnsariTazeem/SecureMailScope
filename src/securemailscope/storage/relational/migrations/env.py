"""Alembic environment with explicit, validated connectivity only."""

from __future__ import annotations

from alembic import context
from sqlalchemy import Connection

# Import entities so all reviewed tables are registered on target metadata.
from securemailscope.storage.relational import entities as _entities  # noqa: F401
from securemailscope.storage.relational.config import (
    SQLiteDatabaseConfig,
    create_sqlite_engine,
)
from securemailscope.storage.relational.metadata import relational_metadata

target_metadata = relational_metadata


def _configure_connection(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
        render_as_batch=False,
        transaction_per_migration=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_offline() -> None:
    """Render SQL for the one explicitly configured local SQLite path."""
    settings = SQLiteDatabaseConfig.from_environment()
    context.configure(
        url=settings.sqlalchemy_url.render_as_string(hide_password=False),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run against a test-injected connection or the explicit local path."""
    supplied_connection = context.config.attributes.get("connection")
    if supplied_connection is not None:
        _configure_connection(supplied_connection)
        return

    settings = SQLiteDatabaseConfig.from_environment()
    engine = create_sqlite_engine(settings)
    try:
        with engine.connect() as connection:
            _configure_connection(connection)
    finally:
        engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
