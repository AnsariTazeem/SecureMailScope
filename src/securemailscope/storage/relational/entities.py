"""Infrastructure-only SQLAlchemy entities for immutable completed results.

The table stores only the validated canonical Chain document and safe identity,
integrity, and retention metadata.  It deliberately contains no raw capture,
packet content, credential, filename, temporary path, job, or audit fields.

Rows are insert-only by storage contract.  A later repository adapter must not
update canonical bytes or their digest; this foundation does not claim that a
portable database constraint can prohibit every privileged SQL UPDATE.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import CheckConstraint, Index, LargeBinary, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from securemailscope.storage.relational.metadata import RelationalBase
from securemailscope.storage.relational.types import UTCDateTime

ANALYSIS_ID_LENGTH = 20
SHA256_HEX_LENGTH = 64
SCHEMA_VERSION_MAX_LENGTH = 32


def _allowed_characters_expression(column_expression: str, allowed: str) -> str:
    """Return portable SQL that removes every allowed character."""
    expression = column_expression
    for character in allowed:
        expression = f"replace({expression}, '{character}', '')"
    return expression


_ANALYSIS_ID_HEX_REMAINDER = _allowed_characters_expression(
    "substr(analysis_id, 5)", "0123456789abcdef"
)
_FINGERPRINT_REMAINDER = _allowed_characters_expression("analysis_fingerprint", "0123456789abcdef")
_DIGEST_REMAINDER = _allowed_characters_expression("chain_sha256", "0123456789abcdef")
_SCHEMA_VERSION_REMAINDER = _allowed_characters_expression("chain_schema_version", "0123456789.")


class AnalysisResultEntity(RelationalBase):
    """One immutable, final, canonical Chain-of-Proof result row."""

    __tablename__ = "analysis_results"
    __table_args__ = (
        UniqueConstraint(
            "analysis_fingerprint",
            name="uq_analysis_results_analysis_fingerprint",
        ),
        CheckConstraint(
            "length(analysis_id) = 20 AND substr(analysis_id, 1, 4) = 'ana_' "
            f"AND length({_ANALYSIS_ID_HEX_REMAINDER}) = 0",
            name="analysis_id_shape",
        ),
        CheckConstraint(
            f"length(analysis_fingerprint) = 64 AND length({_FINGERPRINT_REMAINDER}) = 0",
            name="analysis_fingerprint_shape",
        ),
        CheckConstraint(
            "length(chain_schema_version) BETWEEN 5 AND 32 "
            "AND chain_schema_version NOT LIKE '.%' "
            "AND chain_schema_version NOT LIKE '%.' "
            "AND chain_schema_version NOT LIKE '%..%' "
            "AND length(chain_schema_version) - "
            "length(replace(chain_schema_version, '.', '')) = 2 "
            f"AND length({_SCHEMA_VERSION_REMAINDER}) = 0",
            name="chain_schema_version_length",
        ),
        CheckConstraint(
            "length(canonical_chain) > 0",
            name="canonical_chain_not_empty",
        ),
        CheckConstraint(
            f"length(chain_sha256) = 64 AND length({_DIGEST_REMAINDER}) = 0",
            name="chain_sha256_shape",
        ),
        CheckConstraint(
            "expires_at IS NULL OR expires_at > created_at",
            name="expiry_after_creation",
        ),
        Index("ix_analysis_results_created_at", "created_at"),
        Index("ix_analysis_results_expires_at", "expires_at"),
    )

    analysis_id: Mapped[str] = mapped_column(String(ANALYSIS_ID_LENGTH), primary_key=True)
    analysis_fingerprint: Mapped[str] = mapped_column(String(SHA256_HEX_LENGTH), nullable=False)
    chain_schema_version: Mapped[str] = mapped_column(
        String(SCHEMA_VERSION_MAX_LENGTH), nullable=False
    )
    canonical_chain: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    chain_sha256: Mapped[str] = mapped_column(String(SHA256_HEX_LENGTH), nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
