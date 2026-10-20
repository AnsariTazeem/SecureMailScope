"""Disposable-database tests for the V2-2 Slice 1 Alembic baseline."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from presentation_helpers import build_derived_chain, build_evaluated_chain
from sqlalchemy import Connection, inspect, select, text

from securemailscope.chain.canonical import canonical_json
from securemailscope.chain.models import ChainOfProof
from securemailscope.storage.models import AnalysisResultRegistration
from securemailscope.storage.relational.config import (
    SQLITE_DATABASE_PATH_ENV,
    SQLiteDatabaseConfig,
    create_sqlite_engine,
)
from securemailscope.storage.relational.entities import (
    AnalysisResultEntity,
    AnalysisResultProjectionEntity,
    AnalysisResultProtocolEntity,
)
from securemailscope.storage.relational.metadata import relational_metadata
from securemailscope.storage.relational.repository import RelationalAnalysisResultRepository
from securemailscope.storage.relational.revisions import (
    BASELINE_REVISION,
    FIRST_DURABLE_RESULT_REVISION,
    PROJECTION_REVISION,
    DatabaseRevisionError,
    MigrationRevisionState,
    alembic_config,
    assert_database_at_head,
    database_revision_state,
)

_FINGERPRINT = "a" * 64
_STORAGE_CREATED_AT = datetime(2026, 9, 16, 12, 0, tzinfo=UTC)


def _canonical_bytes(chain: ChainOfProof) -> bytes:
    return canonical_json(chain.model_dump(mode="python")).encode("utf-8")


def _insert_slice_2_result(
    connection: Connection,
    chain: ChainOfProof,
    *,
    canonical_chain: bytes | None = None,
    chain_sha256: str | None = None,
    chain_schema_version: str | None = None,
) -> None:
    stored_bytes = canonical_chain if canonical_chain is not None else _canonical_bytes(chain)
    connection.execute(
        AnalysisResultEntity.__table__.insert(),
        {
            "analysis_id": chain.analysis.analysis_id,
            "analysis_fingerprint": _FINGERPRINT,
            "chain_schema_version": chain_schema_version or chain.chain_schema_version,
            "canonical_chain": stored_bytes,
            "chain_sha256": chain_sha256 or hashlib.sha256(stored_bytes).hexdigest(),
            "created_at": _STORAGE_CREATED_AT,
            "expires_at": None,
        },
    )
    connection.commit()


def _assert_backfilled_projection(connection: Connection, chain: ChainOfProof) -> None:
    parent = connection.execute(select(AnalysisResultProjectionEntity.__table__)).mappings().one()
    protocols = tuple(
        connection.execute(
            select(AnalysisResultProtocolEntity.__table__.c.protocol).order_by(
                AnalysisResultProtocolEntity.__table__.c.protocol
            )
        ).scalars()
    )
    expected_maximum = max(
        (finding.severity.value for finding in chain.findings),
        key={"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.__getitem__,
        default=None,
    )
    assert dict(parent) == {
        "analysis_id": chain.analysis.analysis_id,
        "analysis_status": chain.analysis.analysis_status.value,
        "created_at": chain.analysis.created_at,
        "completed_at": chain.analysis.completed_at,
        "max_policy_severity": expected_maximum,
    }
    assert set(protocols) == {session.protocol.value for session in chain.sessions}


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

    assert tables == [
        "alembic_version",
        "analysis_result_projections",
        "analysis_result_protocols",
        "analysis_results",
    ]


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

    projection_columns = inspector.get_columns("analysis_result_projections")
    assert [column["name"] for column in projection_columns] == [
        "analysis_id",
        "analysis_status",
        "created_at",
        "completed_at",
        "max_policy_severity",
    ]
    assert inspector.get_pk_constraint("analysis_result_projections")["constrained_columns"] == [
        "analysis_id"
    ]
    assert {
        index["name"]: index["column_names"]
        for index in inspector.get_indexes("analysis_result_projections")
    } == {
        "ix_analysis_result_projections_analysis_status": ["analysis_status"],
        "ix_analysis_result_projections_created_at": ["created_at"],
        "ix_analysis_result_projections_max_policy_severity": ["max_policy_severity"],
    }
    assert {
        constraint["name"]
        for constraint in inspector.get_check_constraints("analysis_result_projections")
    } == {
        "ck_analysis_result_projections_analysis_id_shape",
        "ck_analysis_result_projections_analysis_status_allowed",
        "ck_analysis_result_projections_completion_not_before_creation",
        "ck_analysis_result_projections_max_policy_severity_allowed",
    }
    assert inspector.get_foreign_keys("analysis_result_projections") == [
        {
            "name": "fk_analysis_result_projections_analysis_id_analysis_results",
            "constrained_columns": ["analysis_id"],
            "referred_schema": None,
            "referred_table": "analysis_results",
            "referred_columns": ["analysis_id"],
            "options": {"ondelete": "CASCADE"},
        }
    ]

    assert [column["name"] for column in inspector.get_columns("analysis_result_protocols")] == [
        "analysis_id",
        "protocol",
    ]
    assert inspector.get_pk_constraint("analysis_result_protocols")["constrained_columns"] == [
        "analysis_id",
        "protocol",
    ]
    assert inspector.get_indexes("analysis_result_protocols") == [
        {
            "name": "ix_analysis_result_protocols_protocol",
            "column_names": ["protocol"],
            "unique": 0,
            "dialect_options": {},
        }
    ]
    assert {
        constraint["name"]
        for constraint in inspector.get_check_constraints("analysis_result_protocols")
    } == {"ck_analysis_result_protocols_protocol_allowed"}
    assert inspector.get_foreign_keys("analysis_result_protocols") == [
        {
            "name": ("fk_analysis_result_protocols_analysis_id_analysis_result_projections"),
            "constrained_columns": ["analysis_id"],
            "referred_schema": None,
            "referred_table": "analysis_result_projections",
            "referred_columns": ["analysis_id"],
            "options": {"ondelete": "CASCADE"},
        }
    ]


def test_migration_revision_is_exact_and_readiness_check_is_read_only(
    migrated_connection: Connection,
) -> None:
    revision = database_revision_state(migrated_connection)

    assert revision.state is MigrationRevisionState.CURRENT
    assert BASELINE_REVISION == FIRST_DURABLE_RESULT_REVISION
    assert revision.current_revisions == (PROJECTION_REVISION,)
    assert revision.head_revisions == (PROJECTION_REVISION,)
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
    chain = build_evaluated_chain()
    repository = RelationalAnalysisResultRepository(migrated_connection.engine)
    repository.register(AnalysisResultRegistration(analysis_fingerprint=_FINGERPRINT, chain=chain))

    _upgrade(migrated_connection)

    assert migrated_connection.execute(text("SELECT count(*) FROM analysis_results")).scalar() == 1
    assert (
        migrated_connection.execute(
            text("SELECT count(*) FROM analysis_result_projections")
        ).scalar()
        == 1
    )
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
        "analysis_result_projections",
        "analysis_result_protocols",
        "analysis_results",
    ]
    assert database_revision_state(migrated_connection).state is MigrationRevisionState.CURRENT


def test_base_to_first_revision_to_projection_head_and_one_revision_downgrade(
    tmp_path: Path,
) -> None:
    chain = build_evaluated_chain()
    engine = create_sqlite_engine(
        SQLiteDatabaseConfig.from_path(tmp_path / "revision-walk.sqlite3")
    )
    try:
        with engine.connect() as connection:
            command.upgrade(
                alembic_config(connection=connection),
                FIRST_DURABLE_RESULT_REVISION,
            )
            assert inspect(connection).get_table_names() == [
                "alembic_version",
                "analysis_results",
            ]
            first = database_revision_state(connection)
            assert first.state is MigrationRevisionState.OUTDATED
            assert first.current_revisions == (FIRST_DURABLE_RESULT_REVISION,)

            _insert_slice_2_result(connection, chain)

            command.upgrade(alembic_config(connection=connection), PROJECTION_REVISION)
            assert database_revision_state(connection).state is MigrationRevisionState.CURRENT
            assert "analysis_result_projections" in inspect(connection).get_table_names()
            _assert_backfilled_projection(connection, chain)

            repository = RelationalAnalysisResultRepository(engine)
            recovered = repository.get(chain.analysis.analysis_id)
            assert recovered is not None
            assert _canonical_bytes(recovered) == _canonical_bytes(chain)
            repository.register(
                AnalysisResultRegistration(
                    analysis_fingerprint=_FINGERPRINT,
                    chain=chain,
                )
            )

            command.downgrade(
                alembic_config(connection=connection),
                FIRST_DURABLE_RESULT_REVISION,
            )
            assert inspect(connection).get_table_names() == [
                "alembic_version",
                "analysis_results",
            ]
            assert (
                connection.execute(text("SELECT count(*) FROM analysis_results")).scalar_one() == 1
            )
            assert connection.execute(
                select(AnalysisResultEntity.__table__.c.canonical_chain)
            ).scalar_one() == _canonical_bytes(chain)
            assert database_revision_state(connection).state is MigrationRevisionState.OUTDATED

            command.upgrade(alembic_config(connection=connection), "head")
            assert database_revision_state(connection).state is MigrationRevisionState.CURRENT
            assert (
                connection.execute(text("SELECT count(*) FROM analysis_results")).scalar_one() == 1
            )
            assert (
                connection.execute(
                    text("SELECT count(*) FROM analysis_result_projections")
                ).scalar_one()
                == 1
            )
            _assert_backfilled_projection(connection, chain)
    finally:
        engine.dispose()


def test_projection_upgrade_backfills_no_finding_result_with_null_severity(
    tmp_path: Path,
) -> None:
    chain = build_derived_chain()
    engine = create_sqlite_engine(
        SQLiteDatabaseConfig.from_path(tmp_path / "no-findings-upgrade.sqlite3")
    )
    try:
        with engine.connect() as connection:
            command.upgrade(alembic_config(connection=connection), FIRST_DURABLE_RESULT_REVISION)
            _insert_slice_2_result(connection, chain)

            command.upgrade(alembic_config(connection=connection), PROJECTION_REVISION)

            _assert_backfilled_projection(connection, chain)
            assert (
                connection.execute(
                    select(AnalysisResultProjectionEntity.__table__.c.max_policy_severity)
                ).scalar_one_or_none()
                is None
            )
    finally:
        engine.dispose()


@pytest.mark.parametrize(
    "corruption",
    ["digest-mismatch", "malformed-json", "invalid-projected-enum"],
)
def test_projection_upgrade_fails_closed_for_unprojectable_existing_result(
    corruption: str,
    tmp_path: Path,
) -> None:
    chain = build_evaluated_chain()
    canonical_chain = _canonical_bytes(chain)
    digest: str | None = None
    if corruption == "digest-mismatch":
        digest = "f" * 64
    elif corruption == "malformed-json":
        canonical_chain = b"{"
    else:
        payload = chain.model_dump(mode="python")
        payload["analysis"]["analysis_status"] = "queued"
        canonical_chain = canonical_json(payload).encode("utf-8")

    engine = create_sqlite_engine(
        SQLiteDatabaseConfig.from_path(tmp_path / f"corrupt-{corruption}.sqlite3")
    )
    try:
        with engine.connect() as connection:
            command.upgrade(alembic_config(connection=connection), FIRST_DURABLE_RESULT_REVISION)
            _insert_slice_2_result(
                connection,
                chain,
                canonical_chain=canonical_chain,
                chain_sha256=digest,
            )

            with pytest.raises(
                RuntimeError,
                match="existing analysis result cannot be projected safely",
            ):
                command.upgrade(alembic_config(connection=connection), PROJECTION_REVISION)

            revision = database_revision_state(connection)
            assert revision.state is MigrationRevisionState.OUTDATED
            assert revision.current_revisions == (FIRST_DURABLE_RESULT_REVISION,)
            assert inspect(connection).get_table_names() == [
                "alembic_version",
                "analysis_results",
            ]
            assert (
                connection.execute(text("SELECT count(*) FROM analysis_results")).scalar_one() == 1
            )
    finally:
        engine.dispose()


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
