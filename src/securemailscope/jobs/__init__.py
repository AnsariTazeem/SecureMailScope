"""Persistence-neutral analysis-job domain and repository contracts."""

from securemailscope.jobs.enums import JobState
from securemailscope.jobs.errors import (
    InvalidJobSnapshotError,
    JobIdentityConflictError,
    JobNotFoundError,
    JobRepositoryCapacityUnavailableError,
    JobRevisionConflictError,
    StoredJobCorruptionError,
)
from securemailscope.jobs.models import PUBLIC_FAILURE_CODE_PATTERN, JobSnapshot
from securemailscope.jobs.repository import (
    InMemoryJobRepository,
    JobCreator,
    JobReader,
    JobRepository,
    JobUpdater,
)

__all__ = [
    "InMemoryJobRepository",
    "InvalidJobSnapshotError",
    "JobCreator",
    "JobIdentityConflictError",
    "JobNotFoundError",
    "JobReader",
    "JobRepository",
    "JobRepositoryCapacityUnavailableError",
    "JobRevisionConflictError",
    "JobSnapshot",
    "JobState",
    "JobUpdater",
    "PUBLIC_FAILURE_CODE_PATTERN",
    "StoredJobCorruptionError",
]
