"""Database-agnostic failures for analysis-job repositories.

Messages raised by the in-memory adapter are fixed and safe.  Adapter details,
malformed values, paths, payloads, and internal exception text remain available
only through exception chaining and must not cross a public boundary.
"""

from __future__ import annotations

from securemailscope.storage.errors import (
    StorageApplicationError,
    StorageCapacityUnavailableError,
    StorageIntegrityError,
)


class JobNotFoundError(StorageApplicationError):
    """The requested job does not exist in the caller's eventual scope."""


class InvalidJobSnapshotError(StorageApplicationError):
    """An incoming job snapshot or revision argument is invalid."""


class JobIdentityConflictError(StorageApplicationError):
    """One job ID is already associated with different snapshot content."""


class JobRevisionConflictError(StorageApplicationError):
    """An atomic update targeted a revision that is no longer current."""


class JobRepositoryCapacityUnavailableError(StorageCapacityUnavailableError):
    """The repository cannot accept another distinct job within its bound."""


class StoredJobCorruptionError(StorageIntegrityError):
    """Stored job state is malformed or violates the snapshot contract."""
