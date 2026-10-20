"""Persistence-neutral indexed projection for immutable analysis results.

The validated canonical :class:`ChainOfProof` remains authoritative.  This
module extracts only the small, safe field set needed by a future bounded
catalog and performs no policy, evidence, or database interpretation.
"""

from __future__ import annotations

from collections.abc import Iterable

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator

from securemailscope.chain.enums import AnalysisStatus, SeverityLevel
from securemailscope.chain.ids import COMPACT_ID_PATTERN, PREFIX_ANALYSIS
from securemailscope.chain.invariants import assert_chain_valid
from securemailscope.chain.models import ChainOfProof
from securemailscope.models import Protocol
from securemailscope.storage.errors import InvalidAnalysisResultError

_INVALID_PROJECTION_SOURCE = "analysis result projection source is invalid"

_SEVERITY_RANK = {
    SeverityLevel.INFO: 0,
    SeverityLevel.LOW: 1,
    SeverityLevel.MEDIUM: 2,
    SeverityLevel.HIGH: 3,
    SeverityLevel.CRITICAL: 4,
}

_PROTOCOL_ORDER = {
    Protocol.SMTP: 0,
    Protocol.IMAP: 1,
    Protocol.POP3: 2,
    Protocol.UNKNOWN: 3,
}


class AnalysisResultProjection(BaseModel):
    """Safe indexed fields deterministically copied from one validated Chain."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    analysis_id: str = Field(pattern=COMPACT_ID_PATTERN[PREFIX_ANALYSIS])
    analysis_status: AnalysisStatus
    created_at: AwareDatetime
    completed_at: AwareDatetime | None
    max_policy_severity: SeverityLevel | None
    protocols: tuple[Protocol, ...]

    @model_validator(mode="after")
    def _internally_consistent(self) -> AnalysisResultProjection:
        if self.completed_at is not None and self.completed_at < self.created_at:
            raise ValueError("completed_at must not precede created_at")
        if len(set(self.protocols)) != len(self.protocols):
            raise ValueError("protocol membership must be distinct")
        if tuple(sorted(self.protocols, key=_PROTOCOL_ORDER.__getitem__)) != self.protocols:
            raise ValueError("protocol membership must use canonical ordering")
        return self


def maximum_policy_severity(
    severities: Iterable[SeverityLevel],
) -> SeverityLevel | None:
    """Return the highest policy severity using the explicit policy ordering."""
    values = tuple(severities)
    if not values:
        return None
    return max(values, key=_SEVERITY_RANK.__getitem__)


def build_analysis_result_projection(chain: ChainOfProof) -> AnalysisResultProjection:
    """Strictly reconstruct, fully validate, then project one canonical result."""
    try:
        if not isinstance(chain, ChainOfProof):
            raise TypeError("projection source must be a ChainOfProof")
        reconstructed = ChainOfProof.model_validate(
            chain.model_dump(mode="python"),
            strict=True,
        )
        assert_chain_valid(reconstructed)
        protocols = tuple(
            sorted(
                {session.protocol for session in reconstructed.sessions},
                key=_PROTOCOL_ORDER.__getitem__,
            )
        )
        return AnalysisResultProjection(
            analysis_id=reconstructed.analysis.analysis_id,
            analysis_status=reconstructed.analysis.analysis_status,
            created_at=reconstructed.analysis.created_at,
            completed_at=reconstructed.analysis.completed_at,
            max_policy_severity=maximum_policy_severity(
                finding.severity for finding in reconstructed.findings
            ),
            protocols=protocols,
        )
    except (KeyboardInterrupt, SystemExit, GeneratorExit):
        raise
    except Exception:
        raise InvalidAnalysisResultError(_INVALID_PROJECTION_SOURCE) from None
