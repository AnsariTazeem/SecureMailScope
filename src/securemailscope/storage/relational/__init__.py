"""Relational schema and migration foundations for completed analyses.

This package is an infrastructure boundary.  Its SQLAlchemy metadata, rows,
connection configuration, and Alembic revision checks must not leak into the
Chain, jobs, policy, orchestration, or API domain contracts.
"""

from securemailscope.storage.relational.config import (
    SQLITE_DATABASE_PATH_ENV,
    DatabaseConfigurationError,
    SQLiteDatabaseConfig,
    create_sqlite_engine,
)
from securemailscope.storage.relational.entities import (
    AnalysisResultEntity,
    AnalysisResultProjectionEntity,
    AnalysisResultProtocolEntity,
)
from securemailscope.storage.relational.metadata import RelationalBase, relational_metadata
from securemailscope.storage.relational.repository import RelationalAnalysisResultRepository
from securemailscope.storage.relational.revisions import (
    BASELINE_REVISION,
    FIRST_DURABLE_RESULT_REVISION,
    PROJECTION_REVISION,
    DatabaseRevisionError,
    MigrationRevisionState,
    assert_database_at_head,
    database_revision_state,
)

__all__ = [
    "BASELINE_REVISION",
    "SQLITE_DATABASE_PATH_ENV",
    "AnalysisResultEntity",
    "AnalysisResultProjectionEntity",
    "AnalysisResultProtocolEntity",
    "DatabaseConfigurationError",
    "DatabaseRevisionError",
    "FIRST_DURABLE_RESULT_REVISION",
    "MigrationRevisionState",
    "PROJECTION_REVISION",
    "RelationalBase",
    "RelationalAnalysisResultRepository",
    "SQLiteDatabaseConfig",
    "assert_database_at_head",
    "create_sqlite_engine",
    "database_revision_state",
    "relational_metadata",
]
