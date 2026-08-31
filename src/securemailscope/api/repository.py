"""Thread-safe analysis Chain repository protocol and in-memory implementation."""

from __future__ import annotations

import threading
from typing import Protocol, runtime_checkable

from securemailscope.chain.errors import ChainValidationError
from securemailscope.chain.invariants import assert_chain_valid
from securemailscope.chain.models import ChainOfProof


class RepositoryCapacityError(Exception):
    """Raised when the repository is full and the entry is not a duplicate."""


class RepositoryInvalidChainError(Exception):
    """Raised when a Chain fails invariant validation."""


class RepositoryConflictError(Exception):
    """Raised when a different Chain is already registered under the same key."""


@runtime_checkable
class AnalysisChainRepository(Protocol):
    """Read-only repository protocol for validated Chain-of-Proof objects."""

    def get(self, analysis_id: str) -> ChainOfProof | None: ...


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
            return chain.model_copy(deep=True) if chain is not None else None

    def register(self, chain: ChainOfProof) -> None:
        """Register a validated Chain. Idempotent for identical chains."""
        if not isinstance(chain, ChainOfProof):
            raise RepositoryInvalidChainError("registration requires a ChainOfProof")
        snapshot = chain.model_copy(deep=True)
        try:
            assert_chain_valid(snapshot)
        except ChainValidationError as exc:
            raise RepositoryInvalidChainError("chain failed invariant validation") from exc
        key = snapshot.analysis.analysis_id
        with self._lock:
            existing = self._store.get(key)
            if existing is not None:
                if existing == snapshot:
                    return
                raise RepositoryConflictError(
                    f"a different Chain is already registered under {key!r}"
                )
            if len(self._store) >= self._max_entries:
                raise RepositoryCapacityError(f"repository capacity {self._max_entries} reached")
            self._store[key] = snapshot
