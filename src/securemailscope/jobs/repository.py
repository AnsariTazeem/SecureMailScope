"""Segregated job protocols and a bounded thread-safe in-memory adapter.

The repository is keyed only by random job ID.  It has no capture-digest or
analysis-fingerprint lookup and therefore performs no result reuse or global
deduplication.  Independently accepted uploads remain independent jobs even
when their capture bytes and eventual fingerprints are identical.
"""

from __future__ import annotations

import threading
from typing import Protocol, runtime_checkable

from securemailscope.chain.canonical import canonical_json
from securemailscope.jobs.errors import (
    InvalidJobSnapshotError,
    JobIdentityConflictError,
    JobNotFoundError,
    JobRepositoryCapacityUnavailableError,
    JobRevisionConflictError,
    StoredJobCorruptionError,
)
from securemailscope.jobs.models import JobSnapshot

_MISSING = object()


@runtime_checkable
class JobReader(Protocol):
    """Retrieve an isolated validated job snapshot when one exists."""

    def get(self, job_id: str) -> JobSnapshot | None: ...


@runtime_checkable
class JobCreator(Protocol):
    """Atomically create one revision-zero job without replacement or eviction."""

    def create(self, snapshot: JobSnapshot) -> JobSnapshot: ...


@runtime_checkable
class JobUpdater(Protocol):
    """Atomically replace one job when its expected revision is current."""

    def update(
        self,
        snapshot: JobSnapshot,
        *,
        expected_revision: int,
    ) -> JobSnapshot: ...


@runtime_checkable
class JobRepository(JobReader, JobCreator, JobUpdater, Protocol):
    """Composite contract for components that require all job operations."""


class InMemoryJobRepository:
    """Bounded in-memory adapter with atomic optimistic concurrency.

    Creation is byte-equivalent idempotent only for the same job ID and complete
    snapshot content.  Different content under that ID conflicts.  Updates are
    never creates: the stored revision must equal ``expected_revision`` and the
    replacement revision must equal ``expected_revision + 1``.  State-transition
    legality is deliberately outside this persistence boundary.
    """

    def __init__(self, max_entries: int = 32) -> None:
        if isinstance(max_entries, bool) or not isinstance(max_entries, int) or max_entries < 1:
            raise ValueError("max_entries must be an integer >= 1")
        self._max_entries = max_entries
        self._store: dict[str, JobSnapshot] = {}
        self._lock = threading.Lock()

    @property
    def max_entries(self) -> int:
        return self._max_entries

    @property
    def count(self) -> int:
        with self._lock:
            return len(self._store)

    def get(self, job_id: str) -> JobSnapshot | None:
        with self._lock:
            stored = self._store.get(job_id, _MISSING)
            if stored is _MISSING:
                return None
            snapshot, _ = self._validated_stored_snapshot(stored, expected_job_id=job_id)
            return snapshot

    def create(self, snapshot: JobSnapshot) -> JobSnapshot:
        """Create a revision-zero job; exact repeats under its ID are idempotent."""
        incoming, incoming_bytes = self._validated_incoming_snapshot(snapshot)
        if incoming.revision != 0:
            raise InvalidJobSnapshotError("new job revision must be zero")
        returned, _ = self._validated_incoming_snapshot(incoming)

        with self._lock:
            existing = self._store.get(incoming.job_id, _MISSING)
            if existing is not _MISSING:
                existing_snapshot, existing_bytes = self._validated_stored_snapshot(
                    existing,
                    expected_job_id=incoming.job_id,
                )
                if existing_bytes == incoming_bytes:
                    return existing_snapshot
                raise JobIdentityConflictError(
                    "a different job snapshot already exists under this job identity"
                )
            if len(self._store) >= self._max_entries:
                raise JobRepositoryCapacityUnavailableError(
                    "job repository capacity is unavailable"
                )
            self._store[incoming.job_id] = incoming
            return returned

    def update(
        self,
        snapshot: JobSnapshot,
        *,
        expected_revision: int,
    ) -> JobSnapshot:
        """Replace an existing snapshot using compare-and-swap revision rules."""
        self._validate_expected_revision(expected_revision)
        incoming, _ = self._validated_incoming_snapshot(snapshot)
        returned, _ = self._validated_incoming_snapshot(incoming)

        with self._lock:
            existing = self._store.get(incoming.job_id, _MISSING)
            if existing is _MISSING:
                raise JobNotFoundError("job does not exist")
            current, _ = self._validated_stored_snapshot(
                existing,
                expected_job_id=incoming.job_id,
            )
            if current.revision != expected_revision:
                raise JobRevisionConflictError("job revision does not match expected revision")
            if incoming.revision != expected_revision + 1:
                raise InvalidJobSnapshotError("replacement job revision must advance exactly once")
            self._store[incoming.job_id] = incoming
            return returned

    @staticmethod
    def _validate_expected_revision(expected_revision: int) -> None:
        if (
            isinstance(expected_revision, bool)
            or not isinstance(expected_revision, int)
            or expected_revision < 0
        ):
            raise InvalidJobSnapshotError("expected revision must be a non-negative integer")

    @classmethod
    def _validated_incoming_snapshot(
        cls,
        snapshot: JobSnapshot,
    ) -> tuple[JobSnapshot, bytes]:
        try:
            if not isinstance(snapshot, JobSnapshot):
                raise TypeError("incoming value is not a JobSnapshot")
            return cls._validated_snapshot_and_bytes(snapshot)
        except Exception as exc:
            raise InvalidJobSnapshotError("job snapshot failed validation") from exc

    @classmethod
    def _validated_stored_snapshot(
        cls,
        stored: object,
        *,
        expected_job_id: str,
    ) -> tuple[JobSnapshot, bytes]:
        try:
            if not isinstance(stored, JobSnapshot):
                raise TypeError("stored value is not a JobSnapshot")
            snapshot, serialized = cls._validated_snapshot_and_bytes(stored)
            if snapshot.job_id != expected_job_id:
                raise ValueError("stored job identity does not match its repository key")
            return snapshot, serialized
        except Exception as exc:
            raise StoredJobCorruptionError("stored job failed validation") from exc

    @staticmethod
    def _validated_snapshot_and_bytes(snapshot: JobSnapshot) -> tuple[JobSnapshot, bytes]:
        dumped = snapshot.model_dump(mode="python", warnings="error")
        validated = JobSnapshot.model_validate(dumped)
        serialized = canonical_json(validated.model_dump(mode="python")).encode("utf-8")
        return validated, serialized
