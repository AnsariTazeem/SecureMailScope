"""Infrastructure-only SQLAlchemy value types for relational storage."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import DateTime
from sqlalchemy.engine.interfaces import Dialect
from sqlalchemy.types import TypeDecorator


class UTCDateTime(TypeDecorator[datetime]):
    """Store only aware UTC datetimes and reconstruct SQLite values as UTC.

    SQLite's DBAPI returns SQLAlchemy ``DateTime`` values without timezone
    information. The bind contract guarantees stored values are UTC, so a
    naive SQLite result can be safely reattached to ``datetime.UTC``. Aware
    non-UTC inputs and results are rejected rather than normalized.
    """

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        del dialect
        if value is None:
            return None
        if not isinstance(value, datetime):
            raise TypeError("relational timestamp must be a datetime or None")
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("relational timestamp must be timezone-aware UTC")
        if value.utcoffset() != timedelta(0):
            raise ValueError("relational timestamp must use UTC")
        return value

    def process_result_value(self, value: Any, dialect: Dialect) -> datetime | None:
        del dialect
        if value is None:
            return None
        if not isinstance(value, datetime):
            raise TypeError("stored relational timestamp is not a datetime")
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        if value.utcoffset() != timedelta(0):
            raise ValueError("stored relational timestamp is not UTC")
        return value.replace(tzinfo=UTC)
