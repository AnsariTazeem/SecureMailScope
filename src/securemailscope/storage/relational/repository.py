"""Insert-only SQLAlchemy adapter for durable completed analysis results."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from typing import Any, NoReturn

from sqlalchemy import Engine, Select, select, type_coerce
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.types import NullType

from securemailscope.chain.canonical import canonical_json
from securemailscope.chain.ids import PREFIX_ANALYSIS, is_compact_id, is_sha256_digest
from securemailscope.chain.invariants import assert_chain_valid
from securemailscope.chain.models import CHAIN_SCHEMA_VERSION, ChainOfProof
from securemailscope.storage.errors import (
    AnalysisResultConflictError,
    InvalidAnalysisResultError,
    StorageError,
    StorageInternalError,
    StoredResultCorruptionError,
    UnsupportedStoredSchemaVersionError,
)
from securemailscope.storage.models import AnalysisResultRegistration
from securemailscope.storage.relational.entities import AnalysisResultEntity
from securemailscope.storage.relational.revisions import (
    DatabaseRevisionError,
    assert_database_at_head,
)

_INVALID_REGISTRATION = "analysis result registration is invalid"
_CONFLICT = "analysis result identity conflicts with stored content"
_CORRUPT = "stored analysis result is corrupted"
_UNSUPPORTED_SCHEMA = "stored analysis result schema is unsupported"
_UNAVAILABLE = "analysis result storage is unavailable"
_SQLITE_DATETIME_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{6}$")


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _reject_json_constant(value: str) -> NoReturn:
    del value
    raise ValueError("non-standard JSON constant")


class RelationalAnalysisResultRepository:
    """Durable analysis-result reader and fingerprint-aware registry.

    Construction and every operation that reaches relational storage fail
    closed unless the database is at the exact reviewed Alembic head.
    Migrations are never run by this adapter.
    """

    def __init__(
        self,
        engine: Engine,
        *,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        if not isinstance(engine, Engine) or not callable(clock):
            raise StorageInternalError(_UNAVAILABLE)
        self._engine = engine
        self._clock = clock
        self._assert_ready()

    def get(self, analysis_id: str) -> ChainOfProof | None:
        """Return an isolated validated Chain when one exists."""
        if not is_compact_id(PREFIX_ANALYSIS, analysis_id):
            return None
        try:
            with self._engine.connect() as connection:
                assert_database_at_head(connection)
                row = (
                    connection.execute(self._select_by_analysis_id(analysis_id))
                    .mappings()
                    .one_or_none()
                )
        except DatabaseRevisionError:
            raise StorageInternalError(_UNAVAILABLE) from None
        except SQLAlchemyError:
            raise StorageInternalError(_UNAVAILABLE) from None
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            raise
        except Exception:
            raise StorageInternalError(_UNAVAILABLE) from None
        if row is None:
            return None
        return self._validated_stored_chain(row, expected_analysis_id=analysis_id)

    def register(self, registration: AnalysisResultRegistration) -> None:
        """Insert a validated immutable result or resolve a uniqueness race."""
        validated, canonical_bytes, chain_sha256 = self._validated_registration(registration)
        created_at = self._created_at()
        chain = validated.chain
        values = {
            "analysis_id": chain.analysis.analysis_id,
            "analysis_fingerprint": validated.analysis_fingerprint,
            "chain_schema_version": chain.chain_schema_version,
            "canonical_chain": canonical_bytes,
            "chain_sha256": chain_sha256,
            "created_at": created_at,
            "expires_at": None,
        }

        try:
            with self._engine.begin() as connection:
                assert_database_at_head(connection)
                connection.execute(AnalysisResultEntity.__table__.insert(), values)
            return
        except IntegrityError:
            # The failed transaction has rolled back before collision resolution.
            pass
        except StorageError:
            raise
        except DatabaseRevisionError:
            raise StorageInternalError(_UNAVAILABLE) from None
        except SQLAlchemyError:
            raise StorageInternalError(_UNAVAILABLE) from None
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            raise
        except Exception:
            raise StorageInternalError(_UNAVAILABLE) from None
        self._resolve_collision(validated, canonical_bytes)

    def _assert_ready(self) -> None:
        try:
            with self._engine.connect() as connection:
                assert_database_at_head(connection)
        except StorageError:
            raise
        except (DatabaseRevisionError, SQLAlchemyError):
            raise StorageInternalError(_UNAVAILABLE) from None
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            raise
        except Exception:
            raise StorageInternalError(_UNAVAILABLE) from None

    @staticmethod
    def _select_by_analysis_id(analysis_id: str) -> Select[Any]:
        return RelationalAnalysisResultRepository._untrusted_row_select().where(
            AnalysisResultEntity.analysis_id == analysis_id
        )

    @staticmethod
    def _select_by_fingerprint(fingerprint: str) -> Select[Any]:
        return RelationalAnalysisResultRepository._untrusted_row_select().where(
            AnalysisResultEntity.analysis_fingerprint == fingerprint
        )

    @staticmethod
    def _untrusted_row_select() -> Select[Any]:
        table = AnalysisResultEntity.__table__
        return select(*(type_coerce(column, NullType()).label(column.name) for column in table.c))

    def _resolve_collision(
        self,
        incoming: AnalysisResultRegistration,
        incoming_bytes: bytes,
    ) -> None:
        try:
            with self._engine.connect() as connection:
                assert_database_at_head(connection)
                by_id = (
                    connection.execute(
                        self._select_by_analysis_id(incoming.chain.analysis.analysis_id)
                    )
                    .mappings()
                    .one_or_none()
                )
                if by_id is not None:
                    stored = self._validated_stored_chain(
                        by_id,
                        expected_analysis_id=incoming.chain.analysis.analysis_id,
                    )
                    if (
                        self._row_value(by_id, "analysis_fingerprint")
                        == incoming.analysis_fingerprint
                        and self._canonical_chain_bytes(stored) == incoming_bytes
                    ):
                        return
                    raise AnalysisResultConflictError(_CONFLICT)

                by_fingerprint = (
                    connection.execute(self._select_by_fingerprint(incoming.analysis_fingerprint))
                    .mappings()
                    .one_or_none()
                )
                if by_fingerprint is not None:
                    row_analysis_id = self._row_value(by_fingerprint, "analysis_id")
                    if not isinstance(row_analysis_id, str):
                        raise StoredResultCorruptionError(_CORRUPT)
                    self._validated_stored_chain(
                        by_fingerprint,
                        expected_analysis_id=row_analysis_id,
                    )
                    raise AnalysisResultConflictError(_CONFLICT)
                raise StorageInternalError(_UNAVAILABLE)
        except StorageError:
            raise
        except DatabaseRevisionError:
            raise StorageInternalError(_UNAVAILABLE) from None
        except SQLAlchemyError:
            raise StorageInternalError(_UNAVAILABLE) from None
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            raise
        except Exception:
            raise StoredResultCorruptionError(_CORRUPT) from None

    @classmethod
    def _validated_registration(
        cls,
        registration: AnalysisResultRegistration,
    ) -> tuple[AnalysisResultRegistration, bytes, str]:
        try:
            if not isinstance(registration, AnalysisResultRegistration):
                raise TypeError("wrong registration type")
            reconstructed = AnalysisResultRegistration.model_validate(
                registration.model_dump(mode="python"),
                strict=True,
            )
            chain = ChainOfProof.model_validate(
                reconstructed.chain.model_dump(mode="python"),
                strict=True,
            )
            assert_chain_valid(chain)
            if chain.chain_schema_version != CHAIN_SCHEMA_VERSION:
                raise ValueError("unsupported incoming schema")
            canonical_bytes = cls._canonical_chain_bytes(chain)
            digest = hashlib.sha256(canonical_bytes).hexdigest()
            return (
                AnalysisResultRegistration(
                    analysis_fingerprint=reconstructed.analysis_fingerprint,
                    chain=chain,
                ),
                canonical_bytes,
                digest,
            )
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            raise
        except Exception:
            raise InvalidAnalysisResultError(_INVALID_REGISTRATION) from None

    def _validated_stored_chain(
        self,
        row: Mapping[str, Any],
        *,
        expected_analysis_id: str,
    ) -> ChainOfProof:
        try:
            row_analysis_id = self._row_value(row, "analysis_id")
            fingerprint = self._row_value(row, "analysis_fingerprint")
            declared_schema = self._row_value(row, "chain_schema_version")
            canonical_bytes = self._row_value(row, "canonical_chain")
            stored_digest = self._row_value(row, "chain_sha256")
            created_at = self._row_value(row, "created_at")
            expires_at = self._row_value(row, "expires_at")

            if row_analysis_id != expected_analysis_id or not is_compact_id(
                PREFIX_ANALYSIS, row_analysis_id
            ):
                raise ValueError("row identity mismatch")
            if not isinstance(fingerprint, str) or not is_sha256_digest(fingerprint):
                raise ValueError("invalid stored fingerprint")
            if not isinstance(canonical_bytes, bytes) or not canonical_bytes:
                raise ValueError("invalid canonical bytes")
            if not isinstance(stored_digest, str) or not is_sha256_digest(stored_digest):
                raise ValueError("invalid stored digest")
            if hashlib.sha256(canonical_bytes).hexdigest() != stored_digest:
                raise ValueError("stored digest mismatch")
            if declared_schema != CHAIN_SCHEMA_VERSION:
                raise UnsupportedStoredSchemaVersionError(_UNSUPPORTED_SCHEMA)
            self._validate_stored_timestamps(created_at, expires_at)

            text = canonical_bytes.decode("utf-8", errors="strict")
            json.loads(text, parse_constant=_reject_json_constant)
            chain = ChainOfProof.model_validate_json(text, strict=True)
            assert_chain_valid(chain)
            recanonicalized = self._canonical_chain_bytes(chain)
            if recanonicalized != canonical_bytes:
                raise ValueError("stored bytes are not canonical")
            if chain.analysis.analysis_id != row_analysis_id:
                raise ValueError("Chain identity mismatch")
            if chain.chain_schema_version != declared_schema:
                raise ValueError("Chain schema mismatch")
            if chain.analysis.chain_schema_version != declared_schema:
                raise ValueError("manifest schema mismatch")
            return chain
        except UnsupportedStoredSchemaVersionError:
            raise
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            raise
        except Exception:
            raise StoredResultCorruptionError(_CORRUPT) from None

    @staticmethod
    def _row_value(row: Mapping[str, Any], name: str) -> Any:
        try:
            return row[name]
        except (KeyError, TypeError):
            raise StoredResultCorruptionError(_CORRUPT) from None

    @staticmethod
    def _canonical_chain_bytes(chain: ChainOfProof) -> bytes:
        return canonical_json(chain.model_dump(mode="python")).encode("utf-8")

    @staticmethod
    def _validate_stored_timestamps(created_at: object, expires_at: object) -> None:
        created = RelationalAnalysisResultRepository._stored_utc_datetime(created_at)
        if expires_at is None:
            return
        expiry = RelationalAnalysisResultRepository._stored_utc_datetime(expires_at)
        if expiry <= created:
            raise ValueError("invalid stored expiry time")

    @staticmethod
    def _stored_utc_datetime(value: object) -> datetime:
        if isinstance(value, datetime):
            if value.tzinfo is None or value.utcoffset() != timedelta(0):
                raise ValueError("invalid stored UTC timestamp")
            return value
        if isinstance(value, str) and _SQLITE_DATETIME_PATTERN.fullmatch(value):
            return datetime.strptime(value, "%Y-%m-%d %H:%M:%S.%f").replace(tzinfo=UTC)
        raise ValueError("invalid stored UTC timestamp")

    def _created_at(self) -> datetime:
        try:
            value = self._clock()
            if (
                not isinstance(value, datetime)
                or value.tzinfo is None
                or value.utcoffset() != timedelta(0)
            ):
                raise ValueError("clock must return aware UTC")
            return value
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            raise
        except Exception:
            raise StorageInternalError(_UNAVAILABLE) from None
