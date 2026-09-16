"""Disposable-database tests for the V2-2 Slice 1 Alembic baseline."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from sqlalchemy import Connection, inspect, text

from securemailscope.storage.relational.config import (
    SQLITE_DATABASE_PATH_ENV,
    SQLiteDatabaseConfig,
    create_sqlite_engine,
)
from securemailscope.storage.relational.entities import AnalysisResultEntity
from securemailscope.storage.relational.metadata import relational_metadata
from securemailscope.storage.relational.revisions import (
    BASELINE_REVISION,
    DatabaseRevisionError,
    MigrationRevisionState,
    alembic_config,
    assert_database_at_head,
    database_revision_state,
)


def _upgrade(connection: Connection) -> None:
    command.upgrade(alembic_config(connection=connection), "head")


def _downgrade(connection: Connection) -> None:
    command.downgrade(alembic_config(connection=connection), "base")


@pytest.fixture
def migrated_connection(tmp_path: Path):
    settings = SQLiteDatabaseConfig.from_path(tmp_path / "migrated.sqlite3")
    engine = create_sqlite_engine(settings)
    try:
        with engine.connect() as connection:
            _upgrade(connection)
            yield connection
    finally:
        engine.dispose()


def test_clean_migration_creates_only_reviewed_application_table(
    migrated_connection: Connection,
) -> None:
    tables = inspect(migrated_connection).get_table_names()

    assert tables == ["alembic_version", "analysis_results"]


def test_migrated_constraints_and_indexes_match_declaration(
    migrated_connection: Connection,
) -> None:
    inspector = inspect(migrated_connection)
    columns = inspector.get_columns("analysis_results")

    assert [column["name"] for column in columns] == [
        "analysis_id",
        "analysis_fingerprint",
        "chain_schema_version",
        "canonical_chain",
        "chain_sha256",
        "created_at",
        "expires_at",
    ]
    assert inspector.get_pk_constraint("analysis_results")["constrained_columns"] == ["analysis_id"]
    assert inspector.get_unique_constraints("analysis_results") == [
        {
            "name": "uq_analysis_results_analysis_fingerprint",
            "column_names": ["analysis_fingerprint"],
        }
    ]
    assert {
        index["name"]: index["column_names"] for index in inspector.get_indexes("analysis_results")
    } == {
        "ix_analysis_results_created_at": ["created_at"],
        "ix_analysis_results_expires_at": ["expires_at"],
    }
    assert {
        constraint["name"] for constraint in inspector.get_check_constraints("analysis_results")
    } == {
        "ck_analysis_results_analysis_id_shape",
        "ck_analysis_results_analysis_fingerprint_shape",
        "ck_analysis_results_chain_schema_version_length",
        "ck_analysis_results_canonical_chain_not_empty",
        "ck_analysis_results_chain_sha256_shape",
        "ck_analysis_results_expiry_after_creation",
    }


def test_migration_revision_is_exact_and_readiness_check_is_read_only(
    migrated_connection: Connection,
) -> None:
    revision = database_revision_state(migrated_connection)

    assert revision.state is MigrationRevisionState.CURRENT
    assert revision.current_revisions == (BASELINE_REVISION,)
    assert revision.head_revisions == (BASELINE_REVISION,)
    assert_database_at_head(migrated_connection)


def test_empty_and_unknown_revision_states_fail_closed(tmp_path: Path) -> None:
    settings = SQLiteDatabaseConfig.from_path(tmp_path / "revision.sqlite3")
    engine = create_sqlite_engine(settings)
    try:
        with engine.connect() as connection:
            empty = database_revision_state(connection)
            assert empty.state is MigrationRevisionState.OUTDATED
            with pytest.raises(DatabaseRevisionError, match="revision is not current"):
                assert_database_at_head(connection)

            _upgrade(connection)
            connection.execute(
                text("UPDATE alembic_version SET version_num = :revision"),
                {"revision": "unknown_revision"},
            )
            unknown = database_revision_state(connection)
            assert unknown.state is MigrationRevisionState.UNKNOWN
            with pytest.raises(DatabaseRevisionError, match="revision is not current"):
                assert_database_at_head(connection)
    finally:
        engine.dispose()


def test_upgrade_at_head_is_idempotent_and_preserves_existing_row(
    migrated_connection: Connection,
) -> None:
    table = AnalysisResultEntity.__table__
    migrated_connection.execute(
        table.insert(),
        {
            "analysis_id": "ana_0123456789abcdef",
            "analysis_fingerprint": "a" * 64,
            "chain_schema_version": "1.0.0",
            "canonical_chain": b"{}",
            "chain_sha256": "b" * 64,
            "created_at": datetime(2026, 9, 16, 12, 0, tzinfo=UTC),
            "expires_at": None,
        },
    )
    migrated_connection.commit()

    _upgrade(migrated_connection)

    assert migrated_connection.execute(text("SELECT count(*) FROM analysis_results")).scalar() == 1
    assert database_revision_state(migrated_connection).state is MigrationRevisionState.CURRENT


def test_reviewed_downgrade_drops_only_result_table_then_reupgrade_restores_it(
    migrated_connection: Connection,
) -> None:
    _downgrade(migrated_connection)

    assert inspect(migrated_connection).get_table_names() == ["alembic_version"]
    assert database_revision_state(migrated_connection).state is MigrationRevisionState.OUTDATED

    _upgrade(migrated_connection)

    assert inspect(migrated_connection).get_table_names() == [
        "alembic_version",
        "analysis_results",
    ]
    assert database_revision_state(migrated_connection).state is MigrationRevisionState.CURRENT


def test_migrated_schema_has_no_diff_from_sqlalchemy_metadata(
    migrated_connection: Connection,
) -> None:
    context = MigrationContext.configure(
        migrated_connection,
        opts={"compare_type": True, "compare_server_default": True},
    )

    assert compare_metadata(context, relational_metadata) == []


def test_programmatic_migration_uses_only_injected_temporary_database(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    forbidden = tmp_path / "missing-production-parent" / "production.sqlite3"
    monkeypatch.setenv(SQLITE_DATABASE_PATH_ENV, str(forbidden))
    disposable = tmp_path / "disposable.sqlite3"
    engine = create_sqlite_engine(SQLiteDatabaseConfig.from_path(disposable))

    try:
        with engine.connect() as connection:
            _upgrade(connection)
            assert "analysis_results" in inspect(connection).get_table_names()
    finally:
        engine.dispose()

    assert disposable.exists()
    assert not forbidden.exists()


def test_alembic_ini_contains_no_database_url_or_secret() -> None:
    project_root = Path(__file__).resolve().parents[1]
    configuration = Config(project_root / "alembic.ini")

    assert configuration.get_main_option("sqlalchemy.url") in {None, ""}
    assert configuration.get_main_option("script_location").endswith(
        "src/securemailscope/storage/relational/migrations"
    )
