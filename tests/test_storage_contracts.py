"""Backend V2 storage protocols, taxonomy, and in-memory conformance tests."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import pytest
from httpx import ASGITransport, AsyncClient
from presentation_helpers import build_evaluated_chain

from securemailscope.api import create_app
from securemailscope.api.repository import (
    AnalysisChainRepository,
    InMemoryAnalysisChainRepository,
    RepositoryCapacityError,
    RepositoryConflictError,
    RepositoryInvalidChainError,
)
from securemailscope.chain.canonical import canonical_json
from securemailscope.chain.invariants import assert_chain_valid
from securemailscope.chain.models import ChainOfProof
from securemailscope.storage.errors import (
    AnalysisResultConflictError,
    AnalysisResultNotFoundError,
    InvalidAnalysisResultError,
    StorageApplicationError,
    StorageCapacityUnavailableError,
    StorageError,
    StorageIntegrityError,
    StorageInternalError,
    StoredResultCorruptionError,
    UnsupportedStoredSchemaVersionError,
)
from securemailscope.storage.protocols import (
    AnalysisResultReader,
    AnalysisResultRegistry,
    AnalysisResultRepository,
)


class _ReadOnlyResultSource:
    def get(self, analysis_id: str) -> ChainOfProof | None:
        return None


class _RegistryOnlyResultSink:
    def register(self, chain: ChainOfProof) -> None:
        assert_chain_valid(chain)


class _CorruptibleInMemoryRepository(InMemoryAnalysisChainRepository):
    """Test probe that corrupts state without adding a production mutation hook."""

    def replace_stored_for_test(self, analysis_id: str, chain: ChainOfProof) -> None:
        with self._lock:
            self._store[analysis_id] = chain


_PRIVATE_CORRUPTION_DETAIL = "malformed-secret-value"


class _SnapshotFailureValue:
    """Invalid nested value whose deep-copy failure is deterministic."""

    def __deepcopy__(self, memo: dict[int, object]) -> object:
        raise ValueError(_PRIVATE_CORRUPTION_DETAIL)


@pytest.fixture
def chain() -> ChainOfProof:
    return build_evaluated_chain()


def _canonical_chain_bytes(chain: ChainOfProof) -> bytes:
    return canonical_json(chain.model_dump(mode="python")).encode("utf-8")


def _with_snapshot_failure(chain: ChainOfProof) -> ChainOfProof:
    corrupted = chain.model_copy(deep=True)
    corrupted.captures[0].capture_warnings.append(  # type: ignore[arg-type]
        _SnapshotFailureValue()
    )
    return corrupted


def test_reader_registry_and_composite_protocols_are_actually_segregated() -> None:
    reader = _ReadOnlyResultSource()
    registry = _RegistryOnlyResultSink()

    assert isinstance(reader, AnalysisResultReader)
    assert not isinstance(reader, AnalysisResultRegistry)
    assert not isinstance(reader, AnalysisResultRepository)
    assert isinstance(registry, AnalysisResultRegistry)
    assert not isinstance(registry, AnalysisResultReader)
    assert not isinstance(registry, AnalysisResultRepository)


def test_in_memory_adapter_satisfies_new_and_legacy_contracts() -> None:
    repository = InMemoryAnalysisChainRepository(max_entries=2)

    assert isinstance(repository, AnalysisResultReader)
    assert isinstance(repository, AnalysisResultRegistry)
    assert isinstance(repository, AnalysisResultRepository)
    assert isinstance(repository, AnalysisChainRepository)


def test_register_then_retrieve_returns_isolated_validated_equivalent_content(
    chain: ChainOfProof,
) -> None:
    repository = InMemoryAnalysisChainRepository(max_entries=2)
    repository.register(chain)

    first = repository.get(chain.analysis.analysis_id)
    assert first is not None
    assert first is not chain
    assert _canonical_chain_bytes(first) == _canonical_chain_bytes(chain)
    assert_chain_valid(first)

    original_ids = list(first.protocol_events[0].evidence_ids)
    first.protocol_events[0].evidence_ids.append("ev_0000000000000000")
    second = repository.get(chain.analysis.analysis_id)
    assert second is not None
    assert second.protocol_events[0].evidence_ids == original_ids
    assert_chain_valid(second)


def test_copied_invalid_registration_is_rejected_before_state_change(
    chain: ChainOfProof,
) -> None:
    repository = InMemoryAnalysisChainRepository(max_entries=2)
    invalid_analysis = chain.analysis.model_copy(update={"chain_schema_version": "2.0.0"})
    invalid = chain.model_copy(update={"analysis": invalid_analysis})

    with pytest.raises(RepositoryInvalidChainError):
        repository.register(invalid)

    assert repository.count == 0
    assert repository.get(chain.analysis.analysis_id) is None


def test_serialization_level_invalid_registration_fails_closed(
    chain: ChainOfProof,
) -> None:
    repository = InMemoryAnalysisChainRepository(max_entries=2)
    corrupted = _with_snapshot_failure(chain)

    with pytest.raises(RepositoryInvalidChainError) as exc:
        repository.register(corrupted)

    assert isinstance(exc.value, InvalidAnalysisResultError)
    assert isinstance(exc.value.__cause__, ValueError)
    assert str(exc.value) == "chain failed invariant validation"
    assert _PRIVATE_CORRUPTION_DETAIL not in str(exc.value)
    assert repository.count == 0
    assert repository.get(chain.analysis.analysis_id) is None


def test_byte_equivalent_reconstructed_chain_registration_is_idempotent(
    chain: ChainOfProof,
) -> None:
    repository = InMemoryAnalysisChainRepository(max_entries=1)
    reconstructed = ChainOfProof.model_validate(chain.model_dump(mode="json"))
    assert reconstructed is not chain
    assert _canonical_chain_bytes(reconstructed) == _canonical_chain_bytes(chain)

    repository.register(chain)
    repository.register(reconstructed)

    assert repository.count == 1


def test_corrupted_internal_state_fails_closed_on_direct_read(chain: ChainOfProof) -> None:
    repository = _CorruptibleInMemoryRepository(max_entries=2)
    repository.register(chain)
    invalid_analysis = chain.analysis.model_copy(update={"chain_schema_version": "2.0.0"})
    corrupted = chain.model_copy(update={"analysis": invalid_analysis})
    repository.replace_stored_for_test(chain.analysis.analysis_id, corrupted)

    with pytest.raises(StoredResultCorruptionError):
        repository.get(chain.analysis.analysis_id)


def test_serialization_level_stored_corruption_fails_closed_on_direct_read(
    chain: ChainOfProof,
) -> None:
    repository = _CorruptibleInMemoryRepository(max_entries=2)
    repository.register(chain)
    repository.replace_stored_for_test(
        chain.analysis.analysis_id,
        _with_snapshot_failure(chain),
    )

    with pytest.raises(StoredResultCorruptionError) as exc:
        repository.get(chain.analysis.analysis_id)

    assert isinstance(exc.value, StorageIntegrityError)
    assert isinstance(exc.value.__cause__, ValueError)
    assert str(exc.value) == "stored result failed validation"
    assert _PRIVATE_CORRUPTION_DETAIL not in str(exc.value)
    assert repository.count == 1


async def test_corrupted_internal_state_preserves_v1_invalid_chain_error_envelope(
    chain: ChainOfProof,
) -> None:
    repository = _CorruptibleInMemoryRepository(max_entries=2)
    repository.register(chain)
    invalid_analysis = chain.analysis.model_copy(update={"chain_schema_version": "2.0.0"})
    repository.replace_stored_for_test(
        chain.analysis.analysis_id,
        chain.model_copy(update={"analysis": invalid_analysis}),
    )
    app = create_app(repository=repository)
    transport = ASGITransport(app=app, raise_app_exceptions=False)

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get(f"/api/v1/analyses/{chain.analysis.analysis_id}")

    assert response.status_code == 500
    assert response.json() == {
        "error": {"code": "invalid_chain", "message": "invalid stored chain"}
    }
    assert "2.0.0" not in response.text


async def test_serialization_level_corruption_preserves_v1_invalid_chain_error_envelope(
    chain: ChainOfProof,
) -> None:
    repository = _CorruptibleInMemoryRepository(max_entries=2)
    repository.register(chain)
    repository.replace_stored_for_test(
        chain.analysis.analysis_id,
        _with_snapshot_failure(chain),
    )
    app = create_app(repository=repository)
    transport = ASGITransport(app=app, raise_app_exceptions=False)

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get(f"/api/v1/analyses/{chain.analysis.analysis_id}")

    assert response.status_code == 500
    assert response.json() == {
        "error": {"code": "invalid_chain", "message": "invalid stored chain"}
    }
    assert _PRIVATE_CORRUPTION_DETAIL not in response.text
    assert "SnapshotFailureValue" not in response.text


def test_duplicate_registration_does_not_replace_corrupted_stored_state(
    chain: ChainOfProof,
) -> None:
    repository = _CorruptibleInMemoryRepository(max_entries=2)
    repository.register(chain)
    repository.replace_stored_for_test(
        chain.analysis.analysis_id,
        _with_snapshot_failure(chain),
    )

    with pytest.raises(StoredResultCorruptionError) as exc:
        repository.register(chain)

    assert not isinstance(exc.value, RepositoryConflictError)
    assert isinstance(exc.value.__cause__, ValueError)
    assert repository.count == 1
    with pytest.raises(StoredResultCorruptionError):
        repository.get(chain.analysis.analysis_id)


def test_concurrent_reads_and_registrations_cannot_replace_content(
    chain: ChainOfProof,
) -> None:
    repository = InMemoryAnalysisChainRepository(max_entries=2)
    repository.register(chain)
    conflicting = chain.model_copy(
        update={"execution": chain.execution.model_copy(update={"note": "conflict"})}
    )
    assert_chain_valid(conflicting)

    def read() -> str:
        result = repository.get(chain.analysis.analysis_id)
        assert result is not None
        assert_chain_valid(result)
        return "read"

    def register_duplicate() -> str:
        repository.register(chain)
        return "duplicate"

    def register_conflict() -> str:
        with pytest.raises(RepositoryConflictError):
            repository.register(conflicting)
        return "conflict"

    operations = [read] * 12 + [register_duplicate] * 12 + [register_conflict] * 12
    with ThreadPoolExecutor(max_workers=12) as executor:
        outcomes = list(executor.map(lambda operation: operation(), operations))

    assert outcomes.count("read") == 12
    assert outcomes.count("duplicate") == 12
    assert outcomes.count("conflict") == 12
    assert repository.count == 1
    stored = repository.get(chain.analysis.analysis_id)
    assert stored is not None
    assert _canonical_chain_bytes(stored) == _canonical_chain_bytes(chain)


def test_storage_error_taxonomy_and_legacy_compatibility_are_semantic() -> None:
    application_errors = (
        AnalysisResultNotFoundError,
        InvalidAnalysisResultError,
        AnalysisResultConflictError,
        StorageCapacityUnavailableError,
    )
    integrity_errors = (
        StoredResultCorruptionError,
        UnsupportedStoredSchemaVersionError,
    )

    assert all(issubclass(error, StorageApplicationError) for error in application_errors)
    assert all(issubclass(error, StorageIntegrityError) for error in integrity_errors)
    assert issubclass(StorageApplicationError, StorageError)
    assert issubclass(StorageIntegrityError, StorageError)
    assert issubclass(StorageInternalError, StorageError)
    assert not issubclass(StorageInternalError, StorageApplicationError)
    assert issubclass(RepositoryInvalidChainError, InvalidAnalysisResultError)
    assert issubclass(RepositoryConflictError, AnalysisResultConflictError)
    assert issubclass(RepositoryCapacityError, StorageCapacityUnavailableError)

    for error in (*application_errors, *integrity_errors, StorageInternalError):
        assert all(
            base.__module__ in {"builtins", "securemailscope.storage.errors"}
            for base in error.__mro__
        )
