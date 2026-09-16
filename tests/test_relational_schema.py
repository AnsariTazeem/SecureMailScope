"""V2-2 Slice 1 relational metadata and local SQLite configuration tests."""

from __future__ import annotations

import os
import stat
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import inspect, select
from sqlalchemy.dialects import postgresql
from sqlalchemy.exc import IntegrityError, StatementError
from sqlalchemy.schema import CreateTable

from securemailscope.storage.relational import config as config_module
from securemailscope.storage.relational.config import (
    SQLITE_DATABASE_PATH_ENV,
    DatabaseConfigurationError,
    SQLiteDatabaseConfig,
    create_sqlite_engine,
)
from securemailscope.storage.relational.entities import AnalysisResultEntity


def _valid_row(**overrides: object) -> dict[str, object]:
    created_at = datetime(2026, 9, 16, 12, 0, tzinfo=UTC)
    row: dict[str, object] = {
        "analysis_id": "ana_0123456789abcdef",
        "analysis_fingerprint": "a" * 64,
        "chain_schema_version": "1.0.0",
        "canonical_chain": b'{"chain_schema_version":"1.0.0"}',
        "chain_sha256": "b" * 64,
        "created_at": created_at,
        "expires_at": created_at + timedelta(days=30),
    }
    row.update(overrides)
    return row


def test_configuration_requires_explicit_safe_absolute_local_path(tmp_path: Path) -> None:
    database_path = tmp_path / "results.sqlite3"
    settings = SQLiteDatabaseConfig.from_path(database_path)

    assert settings.database_path == database_path
    assert settings.sqlalchemy_url.drivername == "sqlite+pysqlite"
    assert settings.sqlalchemy_url.database == str(database_path)
    assert not database_path.exists()


def test_engine_construction_creates_neither_database_nor_schema(tmp_path: Path) -> None:
    database_path = tmp_path / "not-opened.sqlite3"
    settings = SQLiteDatabaseConfig.from_path(database_path)
    engine = create_sqlite_engine(settings)

    try:
        assert not database_path.exists()
    finally:
        engine.dispose()


@pytest.mark.parametrize(
    "path_factory",
    [
        lambda temporary: Path("relative.sqlite3"),
        lambda temporary: temporary / "missing" / "results.sqlite3",
        lambda temporary: temporary,
    ],
)
def test_configuration_rejects_malformed_paths_without_disclosing_them(
    tmp_path: Path,
    path_factory,
) -> None:
    candidate = path_factory(tmp_path)

    with pytest.raises(DatabaseConfigurationError) as exc:
        SQLiteDatabaseConfig.from_path(candidate)

    assert str(candidate) not in str(exc.value)


def test_configuration_rejects_symlink_target(tmp_path: Path) -> None:
    actual = tmp_path / "actual.sqlite3"
    actual.touch()
    link = tmp_path / "linked.sqlite3"
    link.symlink_to(actual)

    with pytest.raises(DatabaseConfigurationError, match="contains a symlink") as exc:
        SQLiteDatabaseConfig.from_path(link)
    assert str(link) not in str(exc.value)


def test_configuration_rejects_broken_symlink_target(tmp_path: Path) -> None:
    link = tmp_path / "broken.sqlite3"
    link.symlink_to(tmp_path / "missing.sqlite3")

    with pytest.raises(DatabaseConfigurationError, match="contains a symlink") as exc:
        SQLiteDatabaseConfig.from_path(link)
    assert str(link) not in str(exc.value)


def test_configuration_rejects_symlinked_parent_component(tmp_path: Path) -> None:
    real_parent = tmp_path / "real-parent"
    real_parent.mkdir(mode=0o700)
    linked_parent = tmp_path / "linked-parent"
    linked_parent.symlink_to(real_parent, target_is_directory=True)

    with pytest.raises(DatabaseConfigurationError, match="contains a symlink") as exc:
        SQLiteDatabaseConfig.from_path(linked_parent / "results.sqlite3")

    assert str(linked_parent) not in str(exc.value)


@pytest.mark.skipif(os.name != "posix", reason="POSIX mode-bit contract")
@pytest.mark.parametrize("unsafe_mode", [0o640, 0o604, 0o666])
def test_existing_database_with_group_or_other_permissions_is_rejected(
    tmp_path: Path,
    unsafe_mode: int,
) -> None:
    database_path = tmp_path / "insecure.sqlite3"
    database_path.touch(mode=0o600)
    database_path.chmod(unsafe_mode)

    with pytest.raises(DatabaseConfigurationError, match="file permissions are unsafe") as exc:
        SQLiteDatabaseConfig.from_path(database_path)

    assert str(database_path) not in str(exc.value)


@pytest.mark.skipif(os.name != "posix", reason="POSIX mode-bit contract")
@pytest.mark.parametrize("unsafe_mode", [0o770, 0o707, 0o777])
def test_group_or_world_writable_parent_is_rejected(
    tmp_path: Path,
    unsafe_mode: int,
) -> None:
    parent = tmp_path / "unsafe-parent"
    parent.mkdir(mode=0o700)
    parent.chmod(unsafe_mode)
    database_path = parent / "results.sqlite3"

    try:
        with pytest.raises(
            DatabaseConfigurationError,
            match="parent permissions are unsafe",
        ) as exc:
            SQLiteDatabaseConfig.from_path(database_path)
        assert str(database_path) not in str(exc.value)
    finally:
        parent.chmod(0o700)


def test_configuration_rejects_unwritable_parent_without_path_leak(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = tmp_path / "results.sqlite3"
    monkeypatch.setattr(config_module.os, "access", lambda path, mode: False)

    with pytest.raises(DatabaseConfigurationError) as exc:
        SQLiteDatabaseConfig.from_path(candidate)

    assert str(candidate) not in str(exc.value)


@pytest.mark.parametrize("timeout", [True, 0, -1, 60_001, 1.5])
def test_configuration_rejects_invalid_busy_timeout(tmp_path: Path, timeout: object) -> None:
    with pytest.raises(DatabaseConfigurationError, match="busy timeout is invalid"):
        SQLiteDatabaseConfig.from_path(  # type: ignore[arg-type]
            tmp_path / "results.sqlite3",
            busy_timeout_ms=timeout,
        )


def test_environment_configuration_has_no_default_database(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(SQLITE_DATABASE_PATH_ENV, raising=False)

    with pytest.raises(DatabaseConfigurationError, match="path is required"):
        SQLiteDatabaseConfig.from_environment()


def test_sqlite_engine_enables_foreign_keys_timeout_and_keeps_default_journal(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "results.sqlite3"
    settings = SQLiteDatabaseConfig.from_path(database_path, busy_timeout_ms=1_234)
    engine = create_sqlite_engine(settings)
    assert not database_path.exists()

    try:
        with engine.connect() as connection:
            assert connection.exec_driver_sql("PRAGMA foreign_keys").scalar_one() == 1
            assert connection.exec_driver_sql("PRAGMA busy_timeout").scalar_one() == 1_234
            assert connection.exec_driver_sql("PRAGMA journal_mode").scalar_one() == "delete"
            assert inspect(connection).get_table_names() == []
        if os.name == "posix":
            assert stat.S_IMODE(database_path.stat().st_mode) == 0o600
    finally:
        engine.dispose()


@pytest.mark.skipif(os.name != "posix", reason="POSIX connection-time permission contract")
def test_connection_revalidates_target_changed_after_configuration(tmp_path: Path) -> None:
    database_path = tmp_path / "changed.sqlite3"
    settings = SQLiteDatabaseConfig.from_path(database_path)
    engine = create_sqlite_engine(settings)
    database_path.touch(mode=0o600)
    database_path.chmod(0o644)

    try:
        with pytest.raises(DatabaseConfigurationError) as exc:
            engine.connect()
        assert str(database_path) not in str(exc.value)
    finally:
        engine.dispose()


@pytest.mark.skipif(os.name != "posix", reason="POSIX target-identity contract")
def test_connection_detects_target_replaced_during_sqlite_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database_path = tmp_path / "replaced-during-open.sqlite3"
    settings = SQLiteDatabaseConfig.from_path(database_path)
    real_connect = config_module.sqlite3.connect

    def replace_then_connect(database: object, **kwargs: object):
        database_path.unlink()
        database_path.touch(mode=0o600)
        database_path.chmod(0o600)
        return real_connect(database, **kwargs)

    monkeypatch.setattr(config_module.sqlite3, "connect", replace_then_connect)
    engine = create_sqlite_engine(settings)

    try:
        with pytest.raises(DatabaseConfigurationError, match="changed during connection") as exc:
            engine.connect()
        assert str(database_path) not in str(exc.value)
    finally:
        engine.dispose()


def test_metadata_declares_exact_columns_constraints_and_indexes() -> None:
    table = AnalysisResultEntity.__table__

    assert list(table.columns) == [
        table.c.analysis_id,
        table.c.analysis_fingerprint,
        table.c.chain_schema_version,
        table.c.canonical_chain,
        table.c.chain_sha256,
        table.c.created_at,
        table.c.expires_at,
    ]
    assert table.c.analysis_id.primary_key
    assert not table.c.analysis_id.nullable
    assert table.c.expires_at.nullable
    assert {index.name for index in table.indexes} == {
        "ix_analysis_results_created_at",
        "ix_analysis_results_expires_at",
    }
    assert {constraint.name for constraint in table.constraints} == {
        "pk_analysis_results",
        "uq_analysis_results_analysis_fingerprint",
        "ck_analysis_results_analysis_id_shape",
        "ck_analysis_results_analysis_fingerprint_shape",
        "ck_analysis_results_chain_schema_version_length",
        "ck_analysis_results_canonical_chain_not_empty",
        "ck_analysis_results_chain_sha256_shape",
        "ck_analysis_results_expiry_after_creation",
    }


def test_metadata_compiles_for_postgresql_without_postgresql_driver() -> None:
    table = AnalysisResultEntity.__table__
    ddl = str(CreateTable(table).compile(dialect=postgresql.dialect()))

    assert "BYTEA" in ddl
    assert ddl.count("TIMESTAMP WITH TIME ZONE") == 2
    assert "analysis_results" in ddl


def test_aware_utc_timestamps_round_trip_through_sqlite(tmp_path: Path) -> None:
    engine = create_sqlite_engine(SQLiteDatabaseConfig.from_path(tmp_path / "utc.sqlite3"))
    AnalysisResultEntity.metadata.create_all(engine)
    created_at = datetime(2026, 9, 16, 12, 34, 56, 123456, tzinfo=UTC)
    expires_at = created_at + timedelta(days=30)

    try:
        with engine.begin() as connection:
            connection.execute(
                AnalysisResultEntity.__table__.insert(),
                _valid_row(created_at=created_at, expires_at=expires_at),
            )
            stored = connection.execute(
                select(
                    AnalysisResultEntity.__table__.c.created_at,
                    AnalysisResultEntity.__table__.c.expires_at,
                )
            ).one()
        assert stored.created_at == created_at
        assert stored.created_at.tzinfo is UTC
        assert stored.expires_at == expires_at
        assert stored.expires_at is not None and stored.expires_at.tzinfo is UTC
    finally:
        engine.dispose()


def test_none_expiry_round_trips_as_none(tmp_path: Path) -> None:
    engine = create_sqlite_engine(SQLiteDatabaseConfig.from_path(tmp_path / "none.sqlite3"))
    AnalysisResultEntity.metadata.create_all(engine)

    try:
        with engine.begin() as connection:
            connection.execute(
                AnalysisResultEntity.__table__.insert(),
                _valid_row(expires_at=None),
            )
            expires_at = connection.execute(
                select(AnalysisResultEntity.__table__.c.expires_at)
            ).scalar_one_or_none()
        assert expires_at is None
    finally:
        engine.dispose()


@pytest.mark.parametrize(
    ("timestamp", "message"),
    [
        (datetime(2026, 9, 16, 12, 0), "timezone-aware UTC"),
        (
            datetime(2026, 9, 16, 12, 0, tzinfo=timezone(timedelta(hours=5, minutes=30))),
            "must use UTC",
        ),
        ("2026-09-16T12:00:00Z", "datetime or None"),
    ],
)
def test_non_utc_or_non_datetime_timestamps_are_rejected(
    tmp_path: Path,
    timestamp: object,
    message: str,
) -> None:
    engine = create_sqlite_engine(SQLiteDatabaseConfig.from_path(tmp_path / "invalid-time.sqlite3"))
    AnalysisResultEntity.metadata.create_all(engine)

    try:
        with engine.begin() as connection:
            with pytest.raises(StatementError, match=message):
                connection.execute(
                    AnalysisResultEntity.__table__.insert(),
                    _valid_row(created_at=timestamp),
                )
    finally:
        engine.dispose()


@pytest.mark.parametrize(
    "overrides",
    [
        {"analysis_id": "invalid"},
        {"analysis_id": "ana_gggggggggggggggg"},
        {"analysis_fingerprint": "A" * 64},
        {"analysis_fingerprint": "g" * 64},
        {"analysis_fingerprint": "a" * 63},
        {"chain_schema_version": "1.0"},
        {"chain_schema_version": "1.a.0"},
        {"chain_schema_version": "1..0"},
        {"canonical_chain": b""},
        {"chain_sha256": "B" * 64},
        {"chain_sha256": "g" * 64},
        {"chain_sha256": "b" * 63},
        {
            "created_at": datetime(2026, 9, 16, 12, 0, tzinfo=UTC),
            "expires_at": datetime(2026, 9, 16, 12, 0, tzinfo=UTC),
        },
    ],
)
def test_declared_checks_reject_invalid_rows(tmp_path: Path, overrides: dict[str, object]) -> None:
    settings = SQLiteDatabaseConfig.from_path(tmp_path / "checks.sqlite3")
    engine = create_sqlite_engine(settings)
    AnalysisResultEntity.metadata.create_all(engine)

    try:
        with engine.begin() as connection:
            with pytest.raises(IntegrityError):
                connection.execute(AnalysisResultEntity.__table__.insert(), _valid_row(**overrides))
    finally:
        engine.dispose()


def test_analysis_fingerprint_uniqueness_is_enforced(tmp_path: Path) -> None:
    settings = SQLiteDatabaseConfig.from_path(tmp_path / "unique.sqlite3")
    engine = create_sqlite_engine(settings)
    AnalysisResultEntity.metadata.create_all(engine)

    try:
        with engine.begin() as connection:
            connection.execute(AnalysisResultEntity.__table__.insert(), _valid_row())
            duplicate = _valid_row(
                analysis_id="ana_fedcba9876543210",
                chain_sha256="c" * 64,
            )
            with pytest.raises(IntegrityError):
                connection.execute(AnalysisResultEntity.__table__.insert(), duplicate)
    finally:
        engine.dispose()


def test_schema_creation_is_never_implicit_in_engine_construction(tmp_path: Path) -> None:
    settings = SQLiteDatabaseConfig.from_path(tmp_path / "empty.sqlite3")
    engine = create_sqlite_engine(settings)

    try:
        with engine.connect() as connection:
            assert inspect(connection).get_table_names() == []
            assert connection.execute(select(1)).scalar_one() == 1
    finally:
        engine.dispose()
