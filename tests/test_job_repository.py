"""Backend V2 V2-1 Slice 3 job repository and concurrency contracts."""

from __future__ import annotations

import inspect
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from securemailscope.identity import is_job_id, new_job_id
from securemailscope.jobs import (
    InMemoryJobRepository,
    InvalidJobSnapshotError,
    JobCreator,
    JobIdentityConflictError,
    JobNotFoundError,
    JobReader,
    JobRepository,
    JobRepositoryCapacityUnavailableError,
    JobRevisionConflictError,
    JobSnapshot,
    JobState,
    JobUpdater,
    StoredJobCorruptionError,
)
from securemailscope.storage.errors import (
    StorageApplicationError,
    StorageCapacityUnavailableError,
    StorageIntegrityError,
)

SUBMITTED = datetime(2026, 9, 15, 10, 0, tzinfo=UTC)
JOB_ID = "job_0123456789abcdef0123456789abcdef"
SECOND_JOB_ID = "job_fedcba9876543210fedcba9876543210"
CAPTURE_SHA256 = "a" * 64
FINGERPRINT = "b" * 64
ANALYSIS_ID = "ana_0123456789abcdef"
PRIVATE_DETAIL = "/private/capture.pcapng AUTH secret malformed-value"


def accepted_job(job_id: str = JOB_ID, **updates: object) -> JobSnapshot:
    values: dict[str, object] = {
        "job_id": job_id,
        "state": JobState.ACCEPTED,
        "capture_sha256": CAPTURE_SHA256,
        "analysis_fingerprint": None,
        "analysis_id": None,
        "submitted_at": SUBMITTED,
        "started_at": None,
        "completed_at": None,
        "public_failure_code": None,
        "revision": 0,
    }
    values.update(updates)
    return JobSnapshot.model_validate(values)


def replacement(
    original: JobSnapshot,
    *,
    revision: int = 1,
    fingerprint: str | None = None,
) -> JobSnapshot:
    values = original.model_dump(mode="python")
    values.update(
        state=JobState.QUEUED,
        analysis_fingerprint=fingerprint,
        revision=revision,
    )
    return JobSnapshot.model_validate(values)


class _ReaderOnly:
    def get(self, job_id: str) -> JobSnapshot | None:
        return None


class _CreatorOnly:
    def create(self, snapshot: JobSnapshot) -> JobSnapshot:
        return snapshot


class _UpdaterOnly:
    def update(self, snapshot: JobSnapshot, *, expected_revision: int) -> JobSnapshot:
        return snapshot


class _CorruptibleRepository(InMemoryJobRepository):
    """Test probe for fail-closed reads without a production mutation hook."""

    def replace_stored_for_test(self, job_id: str, value: object) -> None:
        with self._lock:
            self._store[job_id] = value  # type: ignore[assignment]


class _DumpFailingJob(JobSnapshot):
    def model_dump(self, *args: object, **kwargs: object) -> dict[str, object]:
        raise ValueError(PRIVATE_DETAIL)


def dump_failing_job(snapshot: JobSnapshot) -> JobSnapshot:
    return _DumpFailingJob.model_validate(snapshot.model_dump(mode="python"))


def test_reader_creator_updater_and_composite_protocols_are_segregated() -> None:
    reader = _ReaderOnly()
    creator = _CreatorOnly()
    updater = _UpdaterOnly()

    assert isinstance(reader, JobReader)
    assert not isinstance(reader, JobCreator)
    assert not isinstance(reader, JobUpdater)
    assert not isinstance(reader, JobRepository)
    assert isinstance(creator, JobCreator)
    assert not isinstance(creator, JobReader)
    assert not isinstance(creator, JobUpdater)
    assert not isinstance(creator, JobRepository)
    assert isinstance(updater, JobUpdater)
    assert not isinstance(updater, JobReader)
    assert not isinstance(updater, JobCreator)
    assert not isinstance(updater, JobRepository)


def test_in_memory_adapter_satisfies_all_job_protocols() -> None:
    repository = InMemoryJobRepository(max_entries=2)

    assert isinstance(repository, JobReader)
    assert isinstance(repository, JobCreator)
    assert isinstance(repository, JobUpdater)
    assert isinstance(repository, JobRepository)


@pytest.mark.parametrize("max_entries", [0, -1, True, False, 1.0, "1"])
def test_constructor_requires_a_positive_non_boolean_integer(max_entries: object) -> None:
    with pytest.raises(ValueError, match="max_entries"):
        InMemoryJobRepository(max_entries=max_entries)  # type: ignore[arg-type]


def test_create_and_get_return_equivalent_isolated_snapshots() -> None:
    repository = InMemoryJobRepository(max_entries=2)
    incoming = accepted_job()

    created = repository.create(incoming)
    retrieved = repository.get(incoming.job_id)

    assert retrieved == incoming == created
    assert created is not incoming
    assert retrieved is not incoming
    assert retrieved is not created
    assert repository.count == 1


def test_caller_assignment_and_model_copy_cannot_mutate_stored_state() -> None:
    repository = InMemoryJobRepository(max_entries=2)
    incoming = accepted_job()
    repository.create(incoming)

    with pytest.raises(ValidationError):
        incoming.revision = 99
    copied = incoming.model_copy(update={"revision": 99, "capture_sha256": "c" * 64})

    stored = repository.get(JOB_ID)
    assert stored == accepted_job()
    assert copied.revision == 99
    assert stored is not copied


def test_byte_equivalent_create_is_idempotent() -> None:
    repository = InMemoryJobRepository(max_entries=1)
    first = accepted_job()
    equivalent = JobSnapshot.model_validate(first.model_dump(mode="python"))

    repository.create(first)
    returned = repository.create(equivalent)

    assert returned == first
    assert returned is not first
    assert repository.count == 1


def test_same_job_id_with_different_content_conflicts_without_replacement() -> None:
    repository = InMemoryJobRepository(max_entries=2)
    original = accepted_job()
    repository.create(original)
    conflicting = accepted_job(analysis_fingerprint=FINGERPRINT)

    with pytest.raises(JobIdentityConflictError):
        repository.create(conflicting)

    assert repository.get(JOB_ID) == original
    assert repository.count == 1


def test_capacity_has_no_eviction_and_idempotent_create_still_succeeds_when_full() -> None:
    repository = InMemoryJobRepository(max_entries=1)
    original = accepted_job()
    repository.create(original)

    duplicate = repository.create(JobSnapshot.model_validate(original.model_dump(mode="python")))
    with pytest.raises(JobRepositoryCapacityUnavailableError):
        repository.create(accepted_job(SECOND_JOB_ID))

    assert duplicate == original
    assert repository.get(JOB_ID) == original
    assert repository.get(SECOND_JOB_ID) is None
    assert repository.count == 1


def test_create_requires_revision_zero_and_is_atomic() -> None:
    repository = InMemoryJobRepository(max_entries=2)
    invalid = accepted_job(revision=1)

    with pytest.raises(InvalidJobSnapshotError, match="revision must be zero"):
        repository.create(invalid)

    assert repository.count == 0


def test_copied_invalid_snapshot_is_rejected_at_repository_boundary() -> None:
    repository = InMemoryJobRepository(max_entries=2)
    copied_invalid = accepted_job().model_copy(update={"state": "completed"})

    with pytest.raises(InvalidJobSnapshotError) as exc:
        repository.create(copied_invalid)

    assert isinstance(exc.value.__cause__, Exception)
    assert str(exc.value) == "job snapshot failed validation"
    assert repository.count == 0


def test_incoming_dump_failure_is_invalid_and_atomic_with_safe_message() -> None:
    repository = InMemoryJobRepository(max_entries=2)

    with pytest.raises(InvalidJobSnapshotError) as exc:
        repository.create(dump_failing_job(accepted_job()))

    assert isinstance(exc.value.__cause__, ValueError)
    assert str(exc.value) == "job snapshot failed validation"
    assert PRIVATE_DETAIL not in str(exc.value)
    assert repository.count == 0


def test_valid_expected_revision_update_succeeds_and_increments_exactly_once() -> None:
    repository = InMemoryJobRepository(max_entries=2)
    original = accepted_job()
    repository.create(original)
    queued = replacement(original, fingerprint=FINGERPRINT)

    updated = repository.update(queued, expected_revision=0)

    assert updated == queued
    assert updated is not queued
    assert updated.revision == 1
    assert repository.get(JOB_ID) == queued
    assert repository.count == 1


def test_repository_persists_valid_snapshots_without_deciding_transition_legality() -> None:
    repository = InMemoryJobRepository(max_entries=2)
    original = accepted_job()
    repository.create(original)
    direct_completion = JobSnapshot(
        job_id=original.job_id,
        state=JobState.COMPLETED,
        capture_sha256=original.capture_sha256,
        analysis_fingerprint=FINGERPRINT,
        analysis_id=ANALYSIS_ID,
        submitted_at=original.submitted_at,
        started_at=SUBMITTED + timedelta(seconds=1),
        completed_at=SUBMITTED + timedelta(seconds=2),
        public_failure_code=None,
        revision=1,
    )

    assert repository.update(direct_completion, expected_revision=0) == direct_completion


def test_stale_expected_revision_conflicts_and_preserves_current_snapshot() -> None:
    repository = InMemoryJobRepository(max_entries=2)
    original = accepted_job()
    queued = replacement(original, fingerprint=FINGERPRINT)
    repository.create(original)
    repository.update(queued, expected_revision=0)
    stale = replacement(original, fingerprint="c" * 64)

    with pytest.raises(JobRevisionConflictError):
        repository.update(stale, expected_revision=0)

    assert repository.get(JOB_ID) == queued


@pytest.mark.parametrize("revision", [0, 2, 5])
def test_skipped_or_nonadvancing_replacement_revision_is_invalid_and_atomic(
    revision: int,
) -> None:
    repository = InMemoryJobRepository(max_entries=2)
    original = accepted_job()
    repository.create(original)

    with pytest.raises(InvalidJobSnapshotError, match="advance exactly once"):
        repository.update(replacement(original, revision=revision), expected_revision=0)

    assert repository.get(JOB_ID) == original


@pytest.mark.parametrize("expected_revision", [True, False, -1, 0.0, "0"])
def test_invalid_expected_revision_is_rejected_without_state_change(
    expected_revision: object,
) -> None:
    repository = InMemoryJobRepository(max_entries=2)
    original = accepted_job()
    repository.create(original)

    with pytest.raises(InvalidJobSnapshotError, match="expected revision"):
        repository.update(
            replacement(original),
            expected_revision=expected_revision,  # type: ignore[arg-type]
        )

    assert repository.get(JOB_ID) == original


def test_update_missing_job_is_typed_not_found_and_never_upserts() -> None:
    repository = InMemoryJobRepository(max_entries=2)
    missing = replacement(accepted_job(SECOND_JOB_ID))

    with pytest.raises(JobNotFoundError):
        repository.update(missing, expected_revision=0)

    assert repository.get(SECOND_JOB_ID) is None
    assert repository.count == 0


def test_concurrent_same_revision_updates_have_exactly_one_winner() -> None:
    repository = InMemoryJobRepository(max_entries=2)
    original = accepted_job()
    repository.create(original)
    worker_count = 12
    barrier = threading.Barrier(worker_count)
    candidates = [
        replacement(original, fingerprint=f"{index + 1:064x}") for index in range(worker_count)
    ]

    def compete(candidate: JobSnapshot) -> tuple[str, JobSnapshot]:
        barrier.wait(timeout=5)
        try:
            return "winner", repository.update(candidate, expected_revision=0)
        except JobRevisionConflictError:
            return "conflict", candidate

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        outcomes = list(executor.map(compete, candidates))

    winners = [snapshot for outcome, snapshot in outcomes if outcome == "winner"]
    assert len(winners) == 1
    assert sum(outcome == "conflict" for outcome, _ in outcomes) == worker_count - 1
    stored = repository.get(JOB_ID)
    assert stored == winners[0]
    assert stored is not None and stored.revision == 1
    assert repository.count == 1


def test_non_job_object_in_internal_storage_fails_closed() -> None:
    repository = _CorruptibleRepository(max_entries=2)
    repository.replace_stored_for_test(JOB_ID, {"job_id": JOB_ID})

    with pytest.raises(StoredJobCorruptionError) as exc:
        repository.get(JOB_ID)

    assert isinstance(exc.value.__cause__, TypeError)
    assert str(exc.value) == "stored job failed validation"
    assert JOB_ID not in str(exc.value)
    assert repository.count == 1


def test_copied_invalid_stored_snapshot_fails_closed() -> None:
    repository = _CorruptibleRepository(max_entries=2)
    corrupted = accepted_job().model_copy(update={"capture_sha256": PRIVATE_DETAIL})
    repository.replace_stored_for_test(JOB_ID, corrupted)

    with pytest.raises(StoredJobCorruptionError) as exc:
        repository.get(JOB_ID)

    assert isinstance(exc.value.__cause__, ValidationError)
    assert PRIVATE_DETAIL not in str(exc.value)
    assert repository.count == 1


def test_serialization_level_stored_corruption_fails_closed_and_retains_cause() -> None:
    repository = _CorruptibleRepository(max_entries=2)
    repository.replace_stored_for_test(JOB_ID, dump_failing_job(accepted_job()))

    with pytest.raises(StoredJobCorruptionError) as exc:
        repository.get(JOB_ID)

    assert isinstance(exc.value.__cause__, ValueError)
    assert str(exc.value) == "stored job failed validation"
    assert PRIVATE_DETAIL not in str(exc.value)
    assert repository.count == 1


@pytest.mark.parametrize("corrupt_value", [None, "dump_failure"])
@pytest.mark.parametrize("operation", ["create", "update"])
def test_corrupt_existing_entry_cannot_be_replaced(
    operation: str,
    corrupt_value: object,
) -> None:
    repository = _CorruptibleRepository(max_entries=2)
    value = dump_failing_job(accepted_job()) if corrupt_value == "dump_failure" else None
    repository.replace_stored_for_test(JOB_ID, value)

    with pytest.raises(StoredJobCorruptionError):
        if operation == "create":
            repository.create(accepted_job())
        else:
            repository.update(replacement(accepted_job()), expected_revision=0)

    with pytest.raises(StoredJobCorruptionError):
        repository.get(JOB_ID)
    assert repository.count == 1


def test_valid_snapshot_stored_under_the_wrong_key_fails_closed() -> None:
    repository = _CorruptibleRepository(max_entries=2)
    repository.replace_stored_for_test(JOB_ID, accepted_job(SECOND_JOB_ID))

    with pytest.raises(StoredJobCorruptionError) as exc:
        repository.get(JOB_ID)

    assert isinstance(exc.value.__cause__, ValueError)
    assert JOB_ID not in str(exc.value)
    assert SECOND_JOB_ID not in str(exc.value)
    assert repository.count == 1


def test_job_error_taxonomy_reuses_storage_semantics_without_adapter_types() -> None:
    application_errors = (
        JobNotFoundError,
        InvalidJobSnapshotError,
        JobIdentityConflictError,
        JobRevisionConflictError,
        JobRepositoryCapacityUnavailableError,
    )

    assert all(issubclass(error, StorageApplicationError) for error in application_errors)
    assert issubclass(JobRepositoryCapacityUnavailableError, StorageCapacityUnavailableError)
    assert issubclass(StoredJobCorruptionError, StorageIntegrityError)
    for error in (*application_errors, StoredJobCorruptionError):
        assert "sql" not in error.__name__.lower()
        assert "database" not in error.__name__.lower()


def test_independently_accepted_uploads_have_distinct_valid_random_job_ids() -> None:
    job_ids = {new_job_id() for _ in range(32)}

    assert len(job_ids) == 32
    assert all(is_job_id(job_id) for job_id in job_ids)


def test_identical_capture_and_fingerprint_do_not_collapse_distinct_jobs() -> None:
    repository = InMemoryJobRepository(max_entries=2)
    first = accepted_job(new_job_id(), analysis_fingerprint=FINGERPRINT)
    second = accepted_job(new_job_id(), analysis_fingerprint=FINGERPRINT)

    repository.create(first)
    repository.create(second)

    assert first.job_id != second.job_id
    assert first.capture_sha256 == second.capture_sha256
    assert first.analysis_fingerprint == second.analysis_fingerprint
    assert repository.count == 2


def test_future_authorized_result_reuse_can_link_separate_jobs_to_one_result() -> None:
    repository = InMemoryJobRepository(max_entries=2)
    first_id = new_job_id()
    second_id = new_job_id()

    def completed(job_id: str) -> JobSnapshot:
        return JobSnapshot(
            job_id=job_id,
            state=JobState.COMPLETED,
            capture_sha256=CAPTURE_SHA256,
            analysis_fingerprint=FINGERPRINT,
            analysis_id=ANALYSIS_ID,
            submitted_at=SUBMITTED,
            started_at=SUBMITTED + timedelta(seconds=1),
            completed_at=SUBMITTED + timedelta(seconds=2),
            public_failure_code=None,
            revision=0,
        )

    repository.create(completed(first_id))
    repository.create(completed(second_id))

    assert repository.get(first_id).analysis_id == ANALYSIS_ID  # type: ignore[union-attr]
    assert repository.get(second_id).analysis_id == ANALYSIS_ID  # type: ignore[union-attr]
    assert repository.count == 2


def test_job_id_generation_accepts_no_identity_input_and_reveals_no_known_prefix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("securemailscope.identity.secrets.token_hex", lambda size: "0f" * size)

    generated = new_job_id()

    assert inspect.signature(new_job_id).parameters == {}
    assert generated == "job_" + "0f" * 16
    assert CAPTURE_SHA256[:16] not in generated
    assert FINGERPRINT[:16] not in generated
    assert ANALYSIS_ID.removeprefix("ana_") not in generated


def test_repository_exposes_no_capture_or_fingerprint_lookup_or_deduplication() -> None:
    repository = InMemoryJobRepository(max_entries=2)

    assert not hasattr(repository, "get_by_capture_sha256")
    assert not hasattr(repository, "get_by_analysis_fingerprint")
    assert not hasattr(repository, "find_reusable_result")
    assert not hasattr(repository, "idempotency_key")
