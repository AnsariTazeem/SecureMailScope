"""V2-2 Slice 2 durable completed-analysis repository tests."""

from __future__ import annotations

import hashlib
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path

import pytest
from alembic import command
from presentation_helpers import build_evaluated_chain
from pydantic import ValidationError
from sqlalchemy import Engine, event, func, select, text
from sqlalchemy.exc import OperationalError

from securemailscope.chain.canonical import canonical_json
from securemailscope.chain.invariants import assert_chain_valid
from securemailscope.chain.models import ChainOfProof
from securemailscope.storage.errors import (
    AnalysisResultConflictError,
    InvalidAnalysisResultError,
    StorageInternalError,
    StoredResultCorruptionError,
    UnsupportedStoredSchemaVersionError,
)
from securemailscope.storage.models import AnalysisResultRegistration
from securemailscope.storage.protocols import (
    AnalysisResultReader,
    DurableAnalysisResultRepository,
    FingerprintAwareAnalysisResultRegistry,
)
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
from securemailscope.storage.relational.repository import RelationalAnalysisResultRepository
from securemailscope.storage.relational.revisions import alembic_config

FINGERPRINT = "1" * 64
SECOND_FINGERPRINT = "2" * 64
CREATED_AT = datetime(2026, 9, 16, 12, 34, 56, 123456, tzinfo=UTC)
SAFE_MESSAGES = {
    "analysis result registration is invalid",
    "analysis result identity conflicts with stored content",
    "stored analysis result is corrupted",
    "stored analysis result schema is unsupported",
    "analysis result storage is unavailable",
}


def _canonical_bytes(chain: ChainOfProof) -> bytes:
    return canonical_json(chain.model_dump(mode="python")).encode("utf-8")


def _registration(
    chain: ChainOfProof,
    fingerprint: str = FINGERPRINT,
) -> AnalysisResultRegistration:
    return AnalysisResultRegistration(analysis_fingerprint=fingerprint, chain=chain)


def _migrate(engine: Engine) -> None:
    with engine.connect() as connection:
        command.upgrade(alembic_config(connection=connection), "head")


def _engine(database_path: Path) -> Engine:
    return create_sqlite_engine(SQLiteDatabaseConfig.from_path(database_path))


@pytest.fixture
def chain() -> ChainOfProof:
    return build_evaluated_chain()


@pytest.fixture
def migrated_engine(tmp_path: Path):
    engine = _engine(tmp_path / "results.sqlite3")
    _migrate(engine)
    try:
        yield engine
    finally:
        engine.dispose()


@pytest.fixture
def repository(migrated_engine: Engine) -> RelationalAnalysisResultRepository:
    return RelationalAnalysisResultRepository(migrated_engine, clock=lambda: CREATED_AT)


def _row(engine: Engine) -> dict[str, object]:
    with engine.connect() as connection:
        return dict(connection.execute(select(AnalysisResultEntity.__table__)).mappings().one())


def _row_count(engine: Engine) -> int:
    with engine.connect() as connection:
        return connection.execute(
            select(func.count()).select_from(AnalysisResultEntity.__table__)
        ).scalar_one()


def _projection_row(engine: Engine) -> dict[str, object]:
    with engine.connect() as connection:
        return dict(
            connection.execute(select(AnalysisResultProjectionEntity.__table__)).mappings().one()
        )


def _protocol_values(engine: Engine) -> set[str]:
    with engine.connect() as connection:
        return set(
            connection.execute(select(AnalysisResultProtocolEntity.__table__.c.protocol)).scalars()
        )


def _projection_row_count(engine: Engine) -> int:
    with engine.connect() as connection:
        return connection.execute(
            select(func.count()).select_from(AnalysisResultProjectionEntity.__table__)
        ).scalar_one()


def _replace_row_values(engine: Engine, **values: object) -> None:
    with engine.begin() as connection:
        connection.exec_driver_sql("PRAGMA ignore_check_constraints = ON")
        connection.execute(AnalysisResultEntity.__table__.update().values(**values))


def _replace_canonical_bytes(engine: Engine, value: bytes) -> None:
    _replace_row_values(
        engine,
        canonical_chain=value,
        chain_sha256=hashlib.sha256(value).hexdigest(),
    )


def test_registration_value_requires_explicit_validated_fingerprint(chain: ChainOfProof) -> None:
    registration = _registration(chain)

    assert registration.analysis_fingerprint == FINGERPRINT
    assert registration.chain is chain
    with pytest.raises(ValidationError, match="analysis_fingerprint"):
        AnalysisResultRegistration(analysis_fingerprint="invalid", chain=chain)
    with pytest.raises(ValidationError, match="extra"):
        AnalysisResultRegistration(
            analysis_fingerprint=FINGERPRINT,
            chain=chain,
            capture_path="/private/capture.pcap",  # type: ignore[call-arg]
        )


def test_relational_adapter_satisfies_segregated_durable_contracts(
    repository: RelationalAnalysisResultRepository,
) -> None:
    assert isinstance(repository, AnalysisResultReader)
    assert isinstance(repository, FingerprintAwareAnalysisResultRegistry)
    assert isinstance(repository, DurableAnalysisResultRepository)


def test_current_migrated_database_is_accepted(migrated_engine: Engine) -> None:
    RelationalAnalysisResultRepository(migrated_engine, clock=lambda: CREATED_AT)


def test_empty_database_is_rejected_without_automatic_migration(tmp_path: Path) -> None:
    engine = _engine(tmp_path / "empty.sqlite3")
    try:
        with pytest.raises(StorageInternalError, match="storage is unavailable"):
            RelationalAnalysisResultRepository(engine, clock=lambda: CREATED_AT)
        with engine.connect() as connection:
            assert (
                connection.execute(
                    text("SELECT name FROM sqlite_master WHERE type = 'table'")
                ).all()
                == []
            )
    finally:
        engine.dispose()


def test_unknown_database_revision_is_rejected(tmp_path: Path) -> None:
    engine = _engine(tmp_path / "unknown.sqlite3")
    _migrate(engine)
    try:
        with engine.begin() as connection:
            connection.execute(
                text("UPDATE alembic_version SET version_num = :revision"),
                {"revision": "unknown_revision"},
            )
        with pytest.raises(StorageInternalError, match="storage is unavailable"):
            RelationalAnalysisResultRepository(engine, clock=lambda: CREATED_AT)
    finally:
        engine.dispose()


def test_explicit_database_does_not_consult_default_or_environment_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    forbidden = tmp_path / "missing-production-parent" / "production.sqlite3"
    monkeypatch.setenv(SQLITE_DATABASE_PATH_ENV, str(forbidden))
    engine = _engine(tmp_path / "explicit.sqlite3")
    _migrate(engine)
    try:
        RelationalAnalysisResultRepository(engine, clock=lambda: CREATED_AT)
    finally:
        engine.dispose()
    assert not forbidden.exists()


def test_register_persists_exact_canonical_chain_digest_and_metadata(
    chain: ChainOfProof,
    repository: RelationalAnalysisResultRepository,
    migrated_engine: Engine,
) -> None:
    canonical = _canonical_bytes(chain)
    repository.register(_registration(chain))

    row = _row(migrated_engine)
    assert row == {
        "analysis_id": chain.analysis.analysis_id,
        "analysis_fingerprint": FINGERPRINT,
        "chain_schema_version": chain.chain_schema_version,
        "canonical_chain": canonical,
        "chain_sha256": hashlib.sha256(canonical).hexdigest(),
        "created_at": CREATED_AT,
        "expires_at": None,
    }
    assert row["created_at"].tzinfo is UTC  # type: ignore[union-attr]

    assert _projection_row(migrated_engine) == {
        "analysis_id": chain.analysis.analysis_id,
        "analysis_status": chain.analysis.analysis_status.value,
        "created_at": chain.analysis.created_at,
        "completed_at": chain.analysis.completed_at,
        "max_policy_severity": "high",
    }
    assert _protocol_values(migrated_engine) == {"smtp"}


def test_register_and_get_return_strict_isolated_snapshots(
    chain: ChainOfProof,
    repository: RelationalAnalysisResultRepository,
) -> None:
    repository.register(_registration(chain))

    first = repository.get(chain.analysis.analysis_id)
    assert first is not chain
    assert type(first) is ChainOfProof
    assert _canonical_bytes(first) == _canonical_bytes(chain)
    assert_chain_valid(first)
    original = list(first.protocol_events[0].evidence_ids)
    first.protocol_events[0].evidence_ids.append("ev_0000000000000000")
    second = repository.get(chain.analysis.analysis_id)
    assert second.protocol_events[0].evidence_ids == original
    assert_chain_valid(second)


def test_result_survives_engine_disposal_and_repository_reconstruction(
    tmp_path: Path,
    chain: ChainOfProof,
) -> None:
    database_path = tmp_path / "restart.sqlite3"
    first_engine = _engine(database_path)
    _migrate(first_engine)
    first = RelationalAnalysisResultRepository(first_engine, clock=lambda: CREATED_AT)
    first.register(_registration(chain))
    first_engine.dispose()

    second_engine = _engine(database_path)
    try:
        second = RelationalAnalysisResultRepository(second_engine, clock=lambda: CREATED_AT)
        assert _canonical_bytes(second.get(chain.analysis.analysis_id)) == _canonical_bytes(chain)
        assert _projection_row(second_engine)["analysis_id"] == chain.analysis.analysis_id
        assert _protocol_values(second_engine) == {"smtp"}
    finally:
        second_engine.dispose()


def test_valid_missing_analysis_id_returns_none(
    repository: RelationalAnalysisResultRepository,
) -> None:
    assert repository.get("ana_0000000000000000") is None


@pytest.mark.parametrize("analysis_id", ["invalid", "cap_0000000000000000"])
def test_malformed_or_non_analysis_id_returns_none_without_database_access(
    analysis_id: str,
    repository: RelationalAnalysisResultRepository,
    migrated_engine: Engine,
) -> None:
    statements: list[str] = []

    def record_statement(
        connection: object,
        cursor: object,
        statement: str,
        parameters: object,
        context: object,
        executemany: bool,
    ) -> None:
        del connection, cursor, parameters, context, executemany
        statements.append(statement)

    event.listen(migrated_engine, "before_cursor_execute", record_statement)
    try:
        assert repository.get(analysis_id) is None
    finally:
        event.remove(migrated_engine, "before_cursor_execute", record_statement)

    assert statements == []


def test_identical_registration_is_idempotent_and_preserves_creation_time(
    chain: ChainOfProof,
    migrated_engine: Engine,
) -> None:
    times = iter((CREATED_AT, datetime(2026, 9, 17, tzinfo=UTC)))
    repository = RelationalAnalysisResultRepository(migrated_engine, clock=lambda: next(times))
    registration = _registration(chain)
    repository.register(registration)
    repository.register(registration)

    assert _row_count(migrated_engine) == 1
    assert _row(migrated_engine)["created_at"] == CREATED_AT


def test_idempotent_registration_executes_no_update(
    chain: ChainOfProof,
    repository: RelationalAnalysisResultRepository,
    migrated_engine: Engine,
) -> None:
    statements: list[str] = []

    def record_statement(
        connection: object,
        cursor: object,
        statement: str,
        parameters: object,
        context: object,
        executemany: bool,
    ) -> None:
        del connection, cursor, parameters, context, executemany
        statements.append(statement)

    event.listen(migrated_engine, "before_cursor_execute", record_statement)
    try:
        registration = _registration(chain)
        repository.register(registration)
        repository.register(registration)
    finally:
        event.remove(migrated_engine, "before_cursor_execute", record_statement)

    assert not any(statement.lstrip().upper().startswith("UPDATE") for statement in statements)


def test_same_analysis_and_content_with_different_fingerprint_conflicts(
    chain: ChainOfProof,
    repository: RelationalAnalysisResultRepository,
    migrated_engine: Engine,
) -> None:
    repository.register(_registration(chain))
    original = _row(migrated_engine)

    with pytest.raises(AnalysisResultConflictError, match="identity conflicts") as captured:
        repository.register(_registration(chain, SECOND_FINGERPRINT))

    assert _row(migrated_engine) == original
    assert captured.value.__context__ is None


@pytest.mark.parametrize("different_fingerprint", [True, False])
def test_same_analysis_id_conflict_never_replaces_original(
    different_fingerprint: bool,
    chain: ChainOfProof,
    repository: RelationalAnalysisResultRepository,
    migrated_engine: Engine,
) -> None:
    repository.register(_registration(chain))
    original = _row(migrated_engine)
    conflicting = chain.model_copy(
        update={"execution": chain.execution.model_copy(update={"note": "different"})}
    )
    assert_chain_valid(conflicting)
    fingerprint = SECOND_FINGERPRINT if different_fingerprint else FINGERPRINT

    with pytest.raises(AnalysisResultConflictError, match="identity conflicts"):
        repository.register(_registration(conflicting, fingerprint))

    assert _row(migrated_engine) == original
    assert _row_count(migrated_engine) == 1


def test_same_fingerprint_with_different_analysis_id_conflicts_without_relabeling(
    chain: ChainOfProof,
    repository: RelationalAnalysisResultRepository,
    migrated_engine: Engine,
) -> None:
    second_chain = build_evaluated_chain(with_anomaly=True)
    assert second_chain.analysis.analysis_id != chain.analysis.analysis_id
    repository.register(_registration(chain))
    original = _row(migrated_engine)

    with pytest.raises(AnalysisResultConflictError, match="identity conflicts"):
        repository.register(_registration(second_chain))

    assert _row(migrated_engine) == original
    assert _row_count(migrated_engine) == 1


def test_invalid_incoming_chain_and_fingerprint_leave_row_count_unchanged(
    chain: ChainOfProof,
    repository: RelationalAnalysisResultRepository,
    migrated_engine: Engine,
) -> None:
    invalid_analysis = chain.analysis.model_copy(update={"chain_schema_version": "2.0.0"})
    invalid_chain = chain.model_copy(update={"analysis": invalid_analysis})
    copied_invalid = _registration(chain).model_copy(update={"chain": invalid_chain})
    copied_bad_fingerprint = _registration(chain).model_copy(
        update={"analysis_fingerprint": "private-content"}
    )

    for registration in (copied_invalid, copied_bad_fingerprint):
        with pytest.raises(InvalidAnalysisResultError, match="registration is invalid"):
            repository.register(registration)
    assert _row_count(migrated_engine) == 0


def test_clock_must_return_aware_utc_before_any_insert(
    chain: ChainOfProof,
    migrated_engine: Engine,
) -> None:
    repository = RelationalAnalysisResultRepository(
        migrated_engine,
        clock=lambda: datetime(2026, 9, 16, 12, 0),
    )
    with pytest.raises(StorageInternalError, match="storage is unavailable"):
        repository.register(_registration(chain))
    assert _row_count(migrated_engine) == 0


def test_database_revision_is_rechecked_for_every_operation(
    chain: ChainOfProof,
    repository: RelationalAnalysisResultRepository,
    migrated_engine: Engine,
) -> None:
    repository.register(_registration(chain))
    with migrated_engine.begin() as connection:
        connection.execute(
            text("UPDATE alembic_version SET version_num = :revision"),
            {"revision": "ahead_revision"},
        )

    with pytest.raises(StorageInternalError, match="storage is unavailable"):
        repository.get(chain.analysis.analysis_id)
    with pytest.raises(StorageInternalError, match="storage is unavailable"):
        repository.register(_registration(chain))


def test_digest_mismatch_is_stored_corruption(
    chain: ChainOfProof,
    repository: RelationalAnalysisResultRepository,
    migrated_engine: Engine,
) -> None:
    repository.register(_registration(chain))
    _replace_row_values(migrated_engine, chain_sha256="f" * 64)

    with pytest.raises(StoredResultCorruptionError, match="stored analysis result is corrupted"):
        repository.get(chain.analysis.analysis_id)


@pytest.mark.parametrize(
    "payload",
    [b"\xff", b"{", b'{"non_standard":NaN}'],
    ids=["malformed-utf8", "malformed-json", "non-standard-constant"],
)
def test_malformed_stored_bytes_are_corruption(
    payload: bytes,
    chain: ChainOfProof,
    repository: RelationalAnalysisResultRepository,
    migrated_engine: Engine,
) -> None:
    repository.register(_registration(chain))
    _replace_canonical_bytes(migrated_engine, payload)

    with pytest.raises(StoredResultCorruptionError, match="stored analysis result is corrupted"):
        repository.get(chain.analysis.analysis_id)


def test_noncanonical_otherwise_parseable_json_is_corruption(
    chain: ChainOfProof,
    repository: RelationalAnalysisResultRepository,
    migrated_engine: Engine,
) -> None:
    repository.register(_registration(chain))
    noncanonical = json.dumps(
        json.loads(_canonical_bytes(chain)),
        sort_keys=False,
        indent=2,
    ).encode()
    _replace_canonical_bytes(migrated_engine, noncanonical)

    with pytest.raises(StoredResultCorruptionError, match="stored analysis result is corrupted"):
        repository.get(chain.analysis.analysis_id)


def test_unsupported_declared_chain_schema_has_specific_integrity_error(
    chain: ChainOfProof,
    repository: RelationalAnalysisResultRepository,
    migrated_engine: Engine,
) -> None:
    repository.register(_registration(chain))
    _replace_row_values(migrated_engine, chain_schema_version="2.0.0")

    with pytest.raises(UnsupportedStoredSchemaVersionError, match="schema is unsupported"):
        repository.get(chain.analysis.analysis_id)


def test_row_and_chain_schema_mismatch_is_corruption(
    chain: ChainOfProof,
    repository: RelationalAnalysisResultRepository,
    migrated_engine: Engine,
) -> None:
    repository.register(_registration(chain))
    payload = chain.model_dump(mode="python")
    payload["analysis"]["chain_schema_version"] = "2.0.0"
    _replace_canonical_bytes(migrated_engine, canonical_json(payload).encode())

    with pytest.raises(StoredResultCorruptionError, match="stored analysis result is corrupted"):
        repository.get(chain.analysis.analysis_id)


def test_row_and_chain_analysis_id_mismatch_is_corruption(
    chain: ChainOfProof,
    repository: RelationalAnalysisResultRepository,
    migrated_engine: Engine,
) -> None:
    repository.register(_registration(chain))
    replacement_id = "ana_0123456789abcdef"
    with migrated_engine.begin() as connection:
        connection.execute(AnalysisResultProjectionEntity.__table__.delete())
    _replace_row_values(migrated_engine, analysis_id=replacement_id)

    with pytest.raises(StoredResultCorruptionError, match="stored analysis result is corrupted"):
        repository.get(replacement_id)


@pytest.mark.parametrize("mutation", ["structural", "invariant"])
def test_invalid_stored_chain_is_corruption(
    mutation: str,
    chain: ChainOfProof,
    repository: RelationalAnalysisResultRepository,
    migrated_engine: Engine,
) -> None:
    repository.register(_registration(chain))
    payload = chain.model_dump(mode="python")
    if mutation == "structural":
        del payload["captures"]
    else:
        payload["analysis"]["chain_schema_version"] = "2.0.0"
    _replace_canonical_bytes(migrated_engine, canonical_json(payload).encode())

    with pytest.raises(StoredResultCorruptionError, match="stored analysis result is corrupted"):
        repository.get(chain.analysis.analysis_id)


def test_unexpected_stored_sql_type_is_corruption(
    chain: ChainOfProof,
    repository: RelationalAnalysisResultRepository,
    migrated_engine: Engine,
) -> None:
    repository.register(_registration(chain))
    with migrated_engine.begin() as connection:
        connection.exec_driver_sql(
            "UPDATE analysis_results SET canonical_chain = ?, chain_sha256 = ?",
            (123, "a" * 64),
        )

    with pytest.raises(StoredResultCorruptionError, match="stored analysis result is corrupted"):
        repository.get(chain.analysis.analysis_id)


@pytest.mark.parametrize(
    ("column", "value"),
    [
        ("analysis_fingerprint", "not-a-fingerprint"),
        ("created_at", "not-a-timestamp"),
        ("expires_at", "not-a-timestamp"),
    ],
)
def test_untrusted_stored_metadata_types_are_corruption(
    column: str,
    value: str,
    chain: ChainOfProof,
    repository: RelationalAnalysisResultRepository,
    migrated_engine: Engine,
) -> None:
    repository.register(_registration(chain))
    statements = {
        "analysis_fingerprint": "UPDATE analysis_results SET analysis_fingerprint = ?",
        "created_at": "UPDATE analysis_results SET created_at = ?",
        "expires_at": "UPDATE analysis_results SET expires_at = ?",
    }
    with migrated_engine.begin() as connection:
        connection.exec_driver_sql("PRAGMA ignore_check_constraints = ON")
        connection.exec_driver_sql(statements[column], (value,))

    with pytest.raises(StoredResultCorruptionError, match="stored analysis result is corrupted"):
        repository.get(chain.analysis.analysis_id)


def test_corrupted_existing_row_blocks_idempotent_registration_and_is_not_replaced(
    chain: ChainOfProof,
    repository: RelationalAnalysisResultRepository,
    migrated_engine: Engine,
) -> None:
    registration = _registration(chain)
    repository.register(registration)
    _replace_row_values(migrated_engine, chain_sha256="f" * 64)
    corrupted = _row(migrated_engine)

    with pytest.raises(StoredResultCorruptionError):
        repository.register(registration)

    assert _row(migrated_engine) == corrupted
    assert _row_count(migrated_engine) == 1


def test_projection_insert_failure_rolls_back_canonical_result(
    chain: ChainOfProof,
    repository: RelationalAnalysisResultRepository,
    migrated_engine: Engine,
) -> None:
    private_detail = "projection INSERT private detail"

    def fail_projection_insert(
        connection: object,
        cursor: object,
        statement: str,
        parameters: object,
        context: object,
        executemany: bool,
    ) -> None:
        del connection, cursor, parameters, context, executemany
        if statement.lstrip().upper().startswith("INSERT INTO ANALYSIS_RESULT_PROJECTIONS"):
            raise RuntimeError(private_detail)

    event.listen(migrated_engine, "before_cursor_execute", fail_projection_insert)
    try:
        with pytest.raises(StorageInternalError, match="storage is unavailable") as captured:
            repository.register(_registration(chain))
    finally:
        event.remove(migrated_engine, "before_cursor_execute", fail_projection_insert)

    assert private_detail not in str(captured.value)
    assert _row_count(migrated_engine) == 0
    assert _projection_row_count(migrated_engine) == 0
    assert _protocol_values(migrated_engine) == set()


@pytest.mark.parametrize("table_name", ["analysis_result_projections", "analysis_result_protocols"])
def test_projection_select_failure_is_internal_and_preserves_stored_state(
    table_name: str,
    chain: ChainOfProof,
    repository: RelationalAnalysisResultRepository,
    migrated_engine: Engine,
) -> None:
    registration = _registration(chain)
    repository.register(registration)

    def stored_state() -> dict[str, list[dict[str, object]]]:
        with migrated_engine.connect() as connection:
            return {
                table.name: [
                    dict(row)
                    for row in connection.execute(
                        select(table).order_by(*table.primary_key.columns)
                    ).mappings()
                ]
                for table in (
                    AnalysisResultEntity.__table__,
                    AnalysisResultProjectionEntity.__table__,
                    AnalysisResultProtocolEntity.__table__,
                )
            }

    before = stored_state()
    private_detail = "database failure /private/results.sqlite3 password=synthetic-secret"
    failed_selects: list[str] = []

    def fail_projection_select(
        connection: object,
        cursor: object,
        statement: str,
        parameters: object,
        context: object,
        executemany: bool,
    ) -> None:
        del connection, cursor, context, executemany
        if statement.lstrip().upper().startswith("SELECT") and f"FROM {table_name}" in statement:
            failed_selects.append(statement)
            raise OperationalError(statement, parameters, RuntimeError(private_detail))

    event.listen(migrated_engine, "before_cursor_execute", fail_projection_select)
    try:
        with pytest.raises(StorageInternalError) as captured:
            repository.register(registration)
    finally:
        event.remove(migrated_engine, "before_cursor_execute", fail_projection_select)

    assert len(failed_selects) == 1
    assert not isinstance(captured.value, StoredResultCorruptionError)
    assert str(captured.value) == "analysis result storage is unavailable"
    assert private_detail not in str(captured.value)
    assert failed_selects[0] not in str(captured.value)
    assert captured.value.__cause__ is None
    assert captured.value.__suppress_context__ is True
    assert stored_state() == before
    recovered = repository.get(chain.analysis.analysis_id)
    assert recovered is not None
    assert _canonical_bytes(recovered) == _canonical_bytes(chain)


def test_missing_projection_is_corruption_during_idempotency_validation(
    chain: ChainOfProof,
    repository: RelationalAnalysisResultRepository,
    migrated_engine: Engine,
) -> None:
    registration = _registration(chain)
    repository.register(registration)
    with migrated_engine.begin() as connection:
        connection.execute(AnalysisResultProjectionEntity.__table__.delete())

    with pytest.raises(StoredResultCorruptionError):
        repository.register(registration)

    assert _row_count(migrated_engine) == 1
    assert _projection_row_count(migrated_engine) == 0


@pytest.mark.parametrize(
    ("column", "value"),
    [
        ("analysis_status", "failed"),
        ("created_at", datetime(2026, 1, 16, 1, 0, tzinfo=UTC)),
        ("completed_at", datetime(2026, 9, 16, 2, 0, tzinfo=UTC)),
        ("max_policy_severity", "critical"),
    ],
)
def test_wrong_projection_parent_value_is_corruption(
    column: str,
    value: object,
    chain: ChainOfProof,
    repository: RelationalAnalysisResultRepository,
    migrated_engine: Engine,
) -> None:
    registration = _registration(chain)
    repository.register(registration)
    with migrated_engine.begin() as connection:
        connection.execute(
            AnalysisResultProjectionEntity.__table__.update().values(**{column: value})
        )

    with pytest.raises(StoredResultCorruptionError):
        repository.register(registration)


@pytest.mark.parametrize("mutation", ["missing", "extra", "wrong", "malformed"])
def test_protocol_projection_mismatch_is_corruption(
    mutation: str,
    chain: ChainOfProof,
    repository: RelationalAnalysisResultRepository,
    migrated_engine: Engine,
) -> None:
    registration = _registration(chain)
    repository.register(registration)
    with migrated_engine.begin() as connection:
        if mutation == "missing":
            connection.execute(AnalysisResultProtocolEntity.__table__.delete())
        elif mutation == "extra":
            connection.execute(
                AnalysisResultProtocolEntity.__table__.insert(),
                {"analysis_id": chain.analysis.analysis_id, "protocol": "unknown"},
            )
        elif mutation == "wrong":
            connection.execute(
                AnalysisResultProtocolEntity.__table__.update().values(protocol="imap")
            )
        else:
            connection.exec_driver_sql("PRAGMA ignore_check_constraints = ON")
            connection.execute(
                AnalysisResultProtocolEntity.__table__.update().values(protocol="http")
            )

    with pytest.raises(StoredResultCorruptionError):
        repository.register(registration)


def test_wrong_projection_identity_is_corruption(
    chain: ChainOfProof,
    repository: RelationalAnalysisResultRepository,
    migrated_engine: Engine,
) -> None:
    registration = _registration(chain)
    repository.register(registration)
    with migrated_engine.begin() as connection:
        connection.execute(AnalysisResultProtocolEntity.__table__.delete())
    with migrated_engine.connect() as connection:
        connection.exec_driver_sql("PRAGMA foreign_keys = OFF")
        connection.execute(
            AnalysisResultProjectionEntity.__table__.update().values(
                analysis_id="ana_0123456789abcdef"
            )
        )
        connection.commit()

    with pytest.raises(StoredResultCorruptionError):
        repository.register(registration)


def test_canonical_get_remains_independent_from_projection_corruption(
    chain: ChainOfProof,
    repository: RelationalAnalysisResultRepository,
    migrated_engine: Engine,
) -> None:
    repository.register(_registration(chain))
    with migrated_engine.begin() as connection:
        connection.execute(AnalysisResultProtocolEntity.__table__.delete())

    recovered = repository.get(chain.analysis.analysis_id)

    assert recovered is not None
    assert _canonical_bytes(recovered) == _canonical_bytes(chain)
    assert_chain_valid(recovered)


def test_projection_corruption_precedes_same_id_content_conflict(
    chain: ChainOfProof,
    repository: RelationalAnalysisResultRepository,
    migrated_engine: Engine,
) -> None:
    repository.register(_registration(chain))
    with migrated_engine.begin() as connection:
        connection.execute(AnalysisResultProtocolEntity.__table__.delete())
    conflicting = chain.model_copy(
        update={"execution": chain.execution.model_copy(update={"note": "conflict"})}
    )
    assert_chain_valid(conflicting)

    with pytest.raises(StoredResultCorruptionError):
        repository.register(_registration(conflicting, SECOND_FINGERPRINT))


def test_projection_corruption_precedes_fingerprint_conflict(
    chain: ChainOfProof,
    repository: RelationalAnalysisResultRepository,
    migrated_engine: Engine,
) -> None:
    repository.register(_registration(chain))
    with migrated_engine.begin() as connection:
        connection.execute(AnalysisResultProtocolEntity.__table__.delete())
    different_analysis = build_evaluated_chain(with_anomaly=True)

    with pytest.raises(StoredResultCorruptionError):
        repository.register(_registration(different_analysis))


def test_storage_errors_use_fixed_path_sql_and_content_safe_messages(
    chain: ChainOfProof,
    repository: RelationalAnalysisResultRepository,
    migrated_engine: Engine,
) -> None:
    repository.register(_registration(chain))
    _replace_canonical_bytes(migrated_engine, b'{"secret":"private@example.test"}')

    with pytest.raises(StoredResultCorruptionError) as captured:
        repository.get(chain.analysis.analysis_id)
    message = str(captured.value)
    assert message in SAFE_MESSAGES
    assert str(migrated_engine.url.database) not in message
    assert "SELECT" not in message
    assert "analysis_results" not in message
    assert "private@example.test" not in message
    assert captured.value.__cause__ is None


def test_database_failure_is_translated_and_failed_transaction_rolls_back(
    chain: ChainOfProof,
    repository: RelationalAnalysisResultRepository,
    migrated_engine: Engine,
) -> None:
    private_detail = "INSERT secret SQL /private/results.sqlite3"

    def fail_after_insert(
        connection: object,
        cursor: object,
        statement: str,
        parameters: object,
        context: object,
        executemany: bool,
    ) -> None:
        del connection, cursor, parameters, context, executemany
        if statement.lstrip().upper().startswith("INSERT INTO ANALYSIS_RESULTS"):
            raise RuntimeError(private_detail)

    event.listen(migrated_engine, "after_cursor_execute", fail_after_insert)
    try:
        with pytest.raises(StorageInternalError) as captured:
            repository.register(_registration(chain))
    finally:
        event.remove(migrated_engine, "after_cursor_execute", fail_after_insert)

    assert str(captured.value) == "analysis result storage is unavailable"
    assert private_detail not in str(captured.value)
    assert captured.value.__cause__ is None
    assert _row_count(migrated_engine) == 0


def test_base_exception_from_clock_is_not_swallowed(
    chain: ChainOfProof,
    migrated_engine: Engine,
) -> None:
    def interrupted_clock() -> datetime:
        raise KeyboardInterrupt

    repository = RelationalAnalysisResultRepository(migrated_engine, clock=interrupted_clock)
    with pytest.raises(KeyboardInterrupt):
        repository.register(_registration(chain))


def test_concurrent_identical_registration_has_one_row_and_all_succeed(
    chain: ChainOfProof,
    repository: RelationalAnalysisResultRepository,
    migrated_engine: Engine,
) -> None:
    callers = 8
    barrier = threading.Barrier(callers)
    registration = _registration(chain)

    def register() -> str:
        barrier.wait()
        repository.register(registration)
        return "success"

    with ThreadPoolExecutor(max_workers=callers) as executor:
        outcomes = list(executor.map(lambda _: register(), range(callers)))

    assert outcomes == ["success"] * callers
    assert _row_count(migrated_engine) == 1
    assert _projection_row_count(migrated_engine) == 1
    assert _protocol_values(migrated_engine) == {"smtp"}
    assert _canonical_bytes(repository.get(chain.analysis.analysis_id)) == _canonical_bytes(chain)


def test_concurrent_conflicting_registration_has_one_winner_and_typed_conflicts(
    chain: ChainOfProof,
    repository: RelationalAnalysisResultRepository,
    migrated_engine: Engine,
) -> None:
    callers = 8
    barrier = threading.Barrier(callers)
    registrations = [
        _registration(
            chain.model_copy(
                update={
                    "execution": chain.execution.model_copy(update={"note": f"candidate-{index}"})
                }
            )
        )
        for index in range(callers)
    ]
    for registration in registrations:
        assert_chain_valid(registration.chain)

    def register(candidate: AnalysisResultRegistration) -> bytes | None:
        barrier.wait()
        try:
            repository.register(candidate)
        except AnalysisResultConflictError:
            return None
        return _canonical_bytes(candidate.chain)

    with ThreadPoolExecutor(max_workers=callers) as executor:
        outcomes = list(executor.map(register, registrations))

    winners = [outcome for outcome in outcomes if outcome is not None]
    assert len(winners) == 1
    assert _row_count(migrated_engine) == 1
    assert _projection_row_count(migrated_engine) == 1
    assert _protocol_values(migrated_engine) == {"smtp"}
    assert _canonical_bytes(repository.get(chain.analysis.analysis_id)) == winners[0]
