"""Backend V1 repository compatibility names and the in-memory implementation."""

from __future__ import annotations

import threading
from typing import Protocol, runtime_checkable

from securemailscope.chain.canonical import canonical_json
from securemailscope.chain.invariants import assert_chain_valid
from securemailscope.chain.models import ChainOfProof
from securemailscope.storage.errors import (
    AnalysisResultConflictError,
    InvalidAnalysisResultError,
    StorageCapacityUnavailableError,
    StorageIntegrityError,
    StoredResultCorruptionError,
)
from securemailscope.storage.protocols import AnalysisResultReader


class RepositoryCapacityError(StorageCapacityUnavailableError):
    """Raised when the repository is full and the entry is not a duplicate."""


class RepositoryInvalidChainError(InvalidAnalysisResultError):
    """Raised when a Chain fails invariant validation."""


class RepositoryConflictError(AnalysisResultConflictError):
    """Raised when a different Chain is already registered under the same key."""


@runtime_checkable
class AnalysisChainRepository(AnalysisResultReader, Protocol):
    """Legacy read-only protocol name retained for Backend V1 compatibility."""


class InMemoryAnalysisChainRepository:
    """Bounded, thread-safe, in-memory Chain-of-Proof repository.

    * ``register`` validates the Chain with ``assert_chain_valid``.
    * The repository key is ``chain.analysis.analysis_id``.
    * Identical registrations (same key, byte-identical chain) are idempotent.
    * Different chains under the same key are rejected.
    * Capacity is enforced; no silent eviction or replacement.
    * Registration and retrieval use isolated Pydantic deep snapshots.
    """

    def __init__(self, max_entries: int = 32) -> None:
        if max_entries < 1:
            raise ValueError("max_entries must be >= 1")
        self._max_entries = max_entries
        self._store: dict[str, ChainOfProof] = {}
        self._lock = threading.Lock()

    @property
    def max_entries(self) -> int:
        return self._max_entries

    @property
    def count(self) -> int:
        with self._lock:
            return len(self._store)

    def get(self, analysis_id: str) -> ChainOfProof | None:
        with self._lock:
            chain = self._store.get(analysis_id)
            if chain is None:
                return None
            snapshot, _ = self._validated_stored_snapshot(chain)
            return snapshot

    def register(self, chain: ChainOfProof) -> None:
        """Register a validated Chain. Idempotent for identical chains."""
        if not isinstance(chain, ChainOfProof):
            raise RepositoryInvalidChainError("registration requires a ChainOfProof")
        snapshot, snapshot_bytes = self._validated_incoming_snapshot(chain)
        key = snapshot.analysis.analysis_id
        with self._lock:
            existing = self._store.get(key)
            if existing is not None:
                _, existing_bytes = self._validated_stored_snapshot(existing)
                if existing_bytes == snapshot_bytes:
                    return
                raise RepositoryConflictError(
                    f"a different Chain is already registered under {key!r}"
                )
            if len(self._store) >= self._max_entries:
                raise RepositoryCapacityError(f"repository capacity {self._max_entries} reached")
            self._store[key] = snapshot

    @classmethod
    def _validated_incoming_snapshot(cls, chain: ChainOfProof) -> tuple[ChainOfProof, bytes]:
        try:
            return cls._validated_snapshot_and_bytes(chain)
        except StorageIntegrityError:
            raise
        except Exception as exc:
            raise RepositoryInvalidChainError("chain failed invariant validation") from exc

    @classmethod
    def _validated_stored_snapshot(cls, stored: object) -> tuple[ChainOfProof, bytes]:
        try:
            if not isinstance(stored, ChainOfProof):
                raise TypeError("stored result is not a ChainOfProof")
            return cls._validated_snapshot_and_bytes(stored)
        except StorageIntegrityError:
            raise
        except Exception as exc:
            raise StoredResultCorruptionError("stored result failed validation") from exc

    @staticmethod
    def _validated_snapshot_and_bytes(chain: ChainOfProof) -> tuple[ChainOfProof, bytes]:
        isolated = chain.model_copy(deep=True)
        dumped = isolated.model_dump(mode="python")
        snapshot = ChainOfProof.model_validate(dumped)
        assert_chain_valid(snapshot)
        canonical = canonical_json(snapshot.model_dump(mode="python")).encode("utf-8")
        return snapshot, canonical
