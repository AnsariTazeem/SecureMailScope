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
from securemailscope.storage.models import AnalysisResultRegistration
from securemailscope.storage.projections import (
    AnalysisResultProjection,
    build_analysis_result_projection,
    maximum_policy_severity,
)
from securemailscope.storage.protocols import (
    AnalysisResultReader,
    AnalysisResultRegistry,
    AnalysisResultRepository,
    DurableAnalysisResultRepository,
    FingerprintAwareAnalysisResultRegistry,
)

__all__ = [
    "AnalysisResultConflictError",
    "AnalysisResultNotFoundError",
    "AnalysisResultReader",
    "AnalysisResultRegistration",
    "AnalysisResultProjection",
    "AnalysisResultRegistry",
    "AnalysisResultRepository",
    "DurableAnalysisResultRepository",
    "FingerprintAwareAnalysisResultRegistry",
    "InvalidAnalysisResultError",
    "StorageApplicationError",
    "StorageCapacityUnavailableError",
    "StorageError",
    "StorageIntegrityError",
    "StorageInternalError",
    "StoredResultCorruptionError",
    "UnsupportedStoredSchemaVersionError",
    "build_analysis_result_projection",
    "maximum_policy_severity",
]
