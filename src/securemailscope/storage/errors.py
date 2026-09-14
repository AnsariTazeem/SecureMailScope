"""Database-agnostic failures for completed-analysis storage.

Application-layer code may handle :class:`StorageApplicationError` subclasses
by category.  Their exception text is still internal and must be mapped to a
fixed public message at an HTTP or other untrusted boundary.

:class:`StorageIntegrityError` and :class:`StorageInternalError` identify
fail-closed conditions.  Callers must not return a result after either failure
and must never expose a nested adapter exception or its text publicly.
"""

from __future__ import annotations


class StorageError(Exception):
    """Base class for expected failures at a storage-domain boundary."""


class StorageApplicationError(StorageError):
    """An expected category that application services may handle explicitly."""


class AnalysisResultNotFoundError(StorageApplicationError):
    """A requested completed analysis result does not exist in the caller's scope."""


class InvalidAnalysisResultError(StorageApplicationError):
    """A result was rejected before registration because it was not valid."""


class AnalysisResultConflictError(StorageApplicationError):
    """The same analysis identity is already associated with different content."""


class StorageCapacityUnavailableError(StorageApplicationError):
    """Storage cannot accept another distinct completed result within its bounds."""


class StorageIntegrityError(StorageError):
    """Stored state failed an integrity, schema, digest, or domain validation check."""


class StoredResultCorruptionError(StorageIntegrityError):
    """Stored result state is malformed or violates the Chain invariants."""


class UnsupportedStoredSchemaVersionError(StorageIntegrityError):
    """Stored result bytes declare a schema version unsupported by this service."""


class StorageInternalError(StorageError):
    """A safe category for an adapter failure with no public implementation detail."""
