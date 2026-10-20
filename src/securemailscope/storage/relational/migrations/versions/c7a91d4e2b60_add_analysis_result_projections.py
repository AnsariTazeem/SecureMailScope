"""Add the initial indexed analysis-result projection.

Revision ID: c7a91d4e2b60
Revises: 9f3c2a1b7d4e
Create Date: 2026-09-17
"""

import hashlib
import json
import re
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any, NoReturn

import sqlalchemy as sa
from alembic import op

revision: str = "c7a91d4e2b60"
down_revision: str | Sequence[str] | None = "9f3c2a1b7d4e"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_SUPPORTED_CHAIN_SCHEMA = "1.0.0"
_CHAIN_SCHEMA_ID = "urn:securemailscope:schema:chain-of-proof:1.0.0"
_ANALYSIS_ID_PATTERN = re.compile(r"^ana_[0-9a-f]{16}$")
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_ANALYSIS_STATUSES = frozenset({"complete", "partial", "failed"})
_SEVERITY_RANK = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}
_PROTOCOL_ORDER = {
    "smtp": 0,
    "imap": 1,
    "pop3": 2,
    "unknown": 3,
}
_ROOT_KEYS = frozenset(
    {
        "schema_id",
        "chain_schema_version",
        "analysis",
        "execution",
        "captures",
        "sessions",
        "evidence",
        "protocol_events",
        "crypto_observations",
        "derived_facts",
        "rule_evaluations",
        "findings",
        "policy_risk",
        "anomaly_results",
        "recommendations",
        "artifacts",
    }
)
_ANALYSIS_KEYS = frozenset(
    {
        "analysis_id",
        "chain_schema_version",
        "analysis_status",
        "created_at",
        "started_at",
        "completed_at",
        "analyzer_version",
        "tshark_version",
        "rule_engine_status",
        "rule_pack_id",
        "rule_pack_version",
        "ml_engine_status",
        "model_id",
        "model_version",
        "configuration_digest",
        "tls13_authorized_secrets",
        "limitations",
    }
)
_UNPROJECTABLE_RESULT = "existing analysis result cannot be projected safely"


def _reject_json_constant(value: str) -> NoReturn:
    del value
    raise ValueError("non-standard JSON constant")


def _strict_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _canonical_utc_datetime(value: object) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError("timestamp is not canonical UTC")
    parsed = datetime.fromisoformat(f"{value[:-1]}+00:00")
    if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(parsed):
        raise ValueError("timestamp is not UTC-aware")
    if parsed.isoformat().replace("+00:00", "Z") != value:
        raise ValueError("timestamp is not canonical")
    return parsed


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _projection_from_stored_result(row: sa.RowMapping) -> tuple[dict[str, object], list[str]]:
    try:
        analysis_id = row["analysis_id"]
        declared_schema = row["chain_schema_version"]
        stored_bytes = row["canonical_chain"]
        stored_digest = row["chain_sha256"]
        if not isinstance(analysis_id, str) or _ANALYSIS_ID_PATTERN.fullmatch(analysis_id) is None:
            raise ValueError("invalid analysis identity")
        if declared_schema != _SUPPORTED_CHAIN_SCHEMA:
            raise ValueError("unsupported Chain schema")
        if isinstance(stored_bytes, memoryview):
            stored_bytes = stored_bytes.tobytes()
        if not isinstance(stored_bytes, bytes) or not stored_bytes:
            raise ValueError("invalid canonical Chain bytes")
        if not isinstance(stored_digest, str) or _SHA256_PATTERN.fullmatch(stored_digest) is None:
            raise ValueError("invalid stored Chain digest")
        if hashlib.sha256(stored_bytes).hexdigest() != stored_digest:
            raise ValueError("stored Chain digest mismatch")

        text = stored_bytes.decode("utf-8", errors="strict")
        document = json.loads(
            text,
            parse_constant=_reject_json_constant,
            object_pairs_hook=_strict_json_object,
        )
        if not isinstance(document, dict) or frozenset(document) != _ROOT_KEYS:
            raise ValueError("invalid Chain root")
        if _canonical_bytes(document) != stored_bytes:
            raise ValueError("stored Chain is not canonical")
        if document["schema_id"] != _CHAIN_SCHEMA_ID:
            raise ValueError("unsupported Chain schema identity")
        if document["chain_schema_version"] != declared_schema:
            raise ValueError("Chain schema mismatch")

        analysis = document["analysis"]
        if not isinstance(analysis, dict) or frozenset(analysis) != _ANALYSIS_KEYS:
            raise ValueError("invalid analysis manifest")
        if analysis["analysis_id"] != analysis_id:
            raise ValueError("Chain analysis identity mismatch")
        if analysis["chain_schema_version"] != declared_schema:
            raise ValueError("manifest schema mismatch")
        analysis_status = analysis["analysis_status"]
        if not isinstance(analysis_status, str) or analysis_status not in _ANALYSIS_STATUSES:
            raise ValueError("invalid analysis status")

        created_at = _canonical_utc_datetime(analysis["created_at"])
        started_at = _canonical_utc_datetime(analysis["started_at"])
        completed_value = analysis["completed_at"]
        completed_at = None if completed_value is None else _canonical_utc_datetime(completed_value)
        if started_at < created_at or (
            completed_at is not None and (completed_at < created_at or completed_at < started_at)
        ):
            raise ValueError("invalid analysis timestamp ordering")

        findings = document["findings"]
        if not isinstance(findings, list):
            raise ValueError("invalid findings collection")
        severities: list[str] = []
        for finding in findings:
            if not isinstance(finding, dict):
                raise ValueError("invalid finding")
            severity = finding.get("severity")
            if not isinstance(severity, str) or severity not in _SEVERITY_RANK:
                raise ValueError("invalid finding severity")
            severities.append(severity)
        max_policy_severity = (
            max(severities, key=_SEVERITY_RANK.__getitem__) if severities else None
        )

        sessions = document["sessions"]
        if not isinstance(sessions, list):
            raise ValueError("invalid sessions collection")
        protocols: set[str] = set()
        for session in sessions:
            if not isinstance(session, dict):
                raise ValueError("invalid session")
            protocol = session.get("protocol")
            if not isinstance(protocol, str) or protocol not in _PROTOCOL_ORDER:
                raise ValueError("invalid session protocol")
            protocols.add(protocol)

        return (
            {
                "analysis_id": analysis_id,
                "analysis_status": analysis_status,
                "created_at": created_at,
                "completed_at": completed_at,
                "max_policy_severity": max_policy_severity,
            },
            sorted(protocols, key=_PROTOCOL_ORDER.__getitem__),
        )
    except (KeyboardInterrupt, SystemExit, GeneratorExit):
        raise
    except Exception:
        raise RuntimeError(_UNPROJECTABLE_RESULT) from None


def _existing_result_projections(
    connection: sa.Connection,
) -> list[tuple[dict[str, object], list[str]]]:
    results = sa.table(
        "analysis_results",
        sa.column("analysis_id"),
        sa.column("chain_schema_version"),
        sa.column("canonical_chain"),
        sa.column("chain_sha256"),
    )
    rows = connection.execute(sa.select(*results.c).order_by(results.c.analysis_id)).mappings()
    return [_projection_from_stored_result(row) for row in rows]


def _allowed_characters_expression(column_expression: str, allowed: str) -> str:
    expression = column_expression
    for character in allowed:
        expression = f"replace({expression}, '{character}', '')"
    return expression


def upgrade() -> None:
    connection = op.get_bind()
    existing_projections = _existing_result_projections(connection)
    analysis_id_remainder = _allowed_characters_expression(
        "substr(analysis_id, 5)", "0123456789abcdef"
    )
    op.create_table(
        "analysis_result_projections",
        sa.Column("analysis_id", sa.String(length=20), nullable=False),
        sa.Column("analysis_status", sa.String(length=16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("max_policy_severity", sa.String(length=8), nullable=True),
        sa.CheckConstraint(
            "length(analysis_id) = 20 AND substr(analysis_id, 1, 4) = 'ana_' "
            f"AND length({analysis_id_remainder}) = 0",
            name=op.f("ck_analysis_result_projections_analysis_id_shape"),
        ),
        sa.CheckConstraint(
            "analysis_status IN ('complete', 'partial', 'failed')",
            name=op.f("ck_analysis_result_projections_analysis_status_allowed"),
        ),
        sa.CheckConstraint(
            "max_policy_severity IS NULL OR "
            "max_policy_severity IN ('critical', 'high', 'medium', 'low', 'info')",
            name=op.f("ck_analysis_result_projections_max_policy_severity_allowed"),
        ),
        sa.CheckConstraint(
            "completed_at IS NULL OR completed_at >= created_at",
            name=op.f("ck_analysis_result_projections_completion_not_before_creation"),
        ),
        sa.ForeignKeyConstraint(
            ["analysis_id"],
            ["analysis_results.analysis_id"],
            name=op.f("fk_analysis_result_projections_analysis_id_analysis_results"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint(
            "analysis_id",
            name=op.f("pk_analysis_result_projections"),
        ),
    )
    op.create_index(
        "ix_analysis_result_projections_created_at",
        "analysis_result_projections",
        ["created_at"],
        unique=False,
    )
    op.create_index(
        "ix_analysis_result_projections_analysis_status",
        "analysis_result_projections",
        ["analysis_status"],
        unique=False,
    )
    op.create_index(
        "ix_analysis_result_projections_max_policy_severity",
        "analysis_result_projections",
        ["max_policy_severity"],
        unique=False,
    )

    op.create_table(
        "analysis_result_protocols",
        sa.Column("analysis_id", sa.String(length=20), nullable=False),
        sa.Column("protocol", sa.String(length=8), nullable=False),
        sa.CheckConstraint(
            "protocol IN ('smtp', 'imap', 'pop3', 'unknown')",
            name=op.f("ck_analysis_result_protocols_protocol_allowed"),
        ),
        sa.ForeignKeyConstraint(
            ["analysis_id"],
            ["analysis_result_projections.analysis_id"],
            name=op.f("fk_analysis_result_protocols_analysis_id_analysis_result_projections"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint(
            "analysis_id",
            "protocol",
            name=op.f("pk_analysis_result_protocols"),
        ),
    )
    op.create_index(
        "ix_analysis_result_protocols_protocol",
        "analysis_result_protocols",
        ["protocol"],
        unique=False,
    )

    projection_table = sa.table(
        "analysis_result_projections",
        sa.column("analysis_id", sa.String(length=20)),
        sa.column("analysis_status", sa.String(length=16)),
        sa.column("created_at", sa.DateTime(timezone=True)),
        sa.column("completed_at", sa.DateTime(timezone=True)),
        sa.column("max_policy_severity", sa.String(length=8)),
    )
    protocol_table = sa.table(
        "analysis_result_protocols",
        sa.column("analysis_id", sa.String(length=20)),
        sa.column("protocol", sa.String(length=8)),
    )
    for projection, protocols in existing_projections:
        connection.execute(sa.insert(projection_table), projection)
        if protocols:
            connection.execute(
                sa.insert(protocol_table),
                [
                    {"analysis_id": projection["analysis_id"], "protocol": protocol}
                    for protocol in protocols
                ],
            )


def downgrade() -> None:
    op.drop_table("analysis_result_protocols")
    op.drop_table("analysis_result_projections")
