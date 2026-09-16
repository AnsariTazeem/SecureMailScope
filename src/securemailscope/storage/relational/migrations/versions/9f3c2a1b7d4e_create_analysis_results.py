"""Create immutable completed analysis results.

Revision ID: 9f3c2a1b7d4e
Revises: None
Create Date: 2026-09-16
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "9f3c2a1b7d4e"
down_revision: str | Sequence[str] | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _allowed_characters_expression(column_expression: str, allowed: str) -> str:
    expression = column_expression
    for character in allowed:
        expression = f"replace({expression}, '{character}', '')"
    return expression


def upgrade() -> None:
    analysis_id_remainder = _allowed_characters_expression(
        "substr(analysis_id, 5)", "0123456789abcdef"
    )
    fingerprint_remainder = _allowed_characters_expression(
        "analysis_fingerprint", "0123456789abcdef"
    )
    digest_remainder = _allowed_characters_expression("chain_sha256", "0123456789abcdef")
    schema_version_remainder = _allowed_characters_expression("chain_schema_version", "0123456789.")
    op.create_table(
        "analysis_results",
        sa.Column("analysis_id", sa.String(length=20), nullable=False),
        sa.Column("analysis_fingerprint", sa.String(length=64), nullable=False),
        sa.Column("chain_schema_version", sa.String(length=32), nullable=False),
        sa.Column("canonical_chain", sa.LargeBinary(), nullable=False),
        sa.Column("chain_sha256", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "length(analysis_id) = 20 AND substr(analysis_id, 1, 4) = 'ana_' "
            f"AND length({analysis_id_remainder}) = 0",
            name=op.f("ck_analysis_results_analysis_id_shape"),
        ),
        sa.CheckConstraint(
            f"length(analysis_fingerprint) = 64 AND length({fingerprint_remainder}) = 0",
            name=op.f("ck_analysis_results_analysis_fingerprint_shape"),
        ),
        sa.CheckConstraint(
            "length(chain_schema_version) BETWEEN 5 AND 32 "
            "AND chain_schema_version NOT LIKE '.%' "
            "AND chain_schema_version NOT LIKE '%.' "
            "AND chain_schema_version NOT LIKE '%..%' "
            "AND length(chain_schema_version) - "
            "length(replace(chain_schema_version, '.', '')) = 2 "
            f"AND length({schema_version_remainder}) = 0",
            name=op.f("ck_analysis_results_chain_schema_version_length"),
        ),
        sa.CheckConstraint(
            "length(canonical_chain) > 0",
            name=op.f("ck_analysis_results_canonical_chain_not_empty"),
        ),
        sa.CheckConstraint(
            f"length(chain_sha256) = 64 AND length({digest_remainder}) = 0",
            name=op.f("ck_analysis_results_chain_sha256_shape"),
        ),
        sa.CheckConstraint(
            "expires_at IS NULL OR expires_at > created_at",
            name=op.f("ck_analysis_results_expiry_after_creation"),
        ),
        sa.PrimaryKeyConstraint("analysis_id", name="pk_analysis_results"),
        sa.UniqueConstraint(
            "analysis_fingerprint",
            name="uq_analysis_results_analysis_fingerprint",
        ),
    )
    op.create_index(
        "ix_analysis_results_created_at",
        "analysis_results",
        ["created_at"],
        unique=False,
    )
    op.create_index(
        "ix_analysis_results_expires_at",
        "analysis_results",
        ["expires_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_table("analysis_results")
