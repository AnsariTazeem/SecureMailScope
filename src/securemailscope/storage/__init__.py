"""Storage-domain contracts for completed SecureMailScope analyses."""

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

__all__ = [
    "AnalysisResultConflictError",
    "AnalysisResultNotFoundError",
    "AnalysisResultReader",
    "AnalysisResultRegistry",
    "AnalysisResultRepository",
    "InvalidAnalysisResultError",
    "StorageApplicationError",
    "StorageCapacityUnavailableError",
    "StorageError",
    "StorageIntegrityError",
    "StorageInternalError",
    "StoredResultCorruptionError",
    "UnsupportedStoredSchemaVersionError",
]
