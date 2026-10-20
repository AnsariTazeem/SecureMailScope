"""Read-only Alembic revision inspection for readiness and future adapters.

These helpers detect unversioned, outdated, and unknown database states.  They
never create tables, stamp revisions, or run migrations.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import Connection

BASELINE_REVISION = "9f3c2a1b7d4e"
FIRST_DURABLE_RESULT_REVISION = BASELINE_REVISION
PROJECTION_REVISION = "c7a91d4e2b60"
MIGRATIONS_PATH = Path(__file__).with_name("migrations")


class DatabaseRevisionError(RuntimeError):
    """A safe failure when the database is not at the reviewed migration head."""


class MigrationRevisionState(StrEnum):
    """Closed readiness states for the configured relational schema."""

    CURRENT = "current"
    OUTDATED = "outdated"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class DatabaseRevision:
    """Detected revision state without database URL or filesystem details."""

    state: MigrationRevisionState
    current_revisions: tuple[str, ...]
    head_revisions: tuple[str, ...]


def alembic_config(*, connection: Connection | None = None) -> Config:
    """Build secret-free programmatic Alembic configuration."""
    configuration = Config()
    configuration.set_main_option("script_location", str(MIGRATIONS_PATH))
    if connection is not None:
        configuration.attributes["connection"] = connection
    return configuration


def database_revision_state(connection: Connection) -> DatabaseRevision:
    """Inspect the database revision without applying or stamping migrations."""
    current = tuple(sorted(MigrationContext.configure(connection).get_current_heads()))
    scripts = ScriptDirectory.from_config(alembic_config())
    heads = tuple(sorted(scripts.get_heads()))
    known = {revision.revision for revision in scripts.walk_revisions()}

    if any(revision not in known for revision in current):
        state = MigrationRevisionState.UNKNOWN
    elif current == heads:
        state = MigrationRevisionState.CURRENT
    else:
        state = MigrationRevisionState.OUTDATED
    return DatabaseRevision(
        state=state,
        current_revisions=current,
        head_revisions=heads,
    )


def assert_database_at_head(connection: Connection) -> None:
    """Fail closed unless the database exactly matches the reviewed head."""
    revision = database_revision_state(connection)
    if revision.state is not MigrationRevisionState.CURRENT:
        raise DatabaseRevisionError("relational database migration revision is not current")
