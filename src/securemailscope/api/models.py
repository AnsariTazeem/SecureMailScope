"""Strict, frozen Pydantic models for Commit 5B API responses."""

from __future__ import annotations

from typing import Annotated

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

from securemailscope.api.settings import ApiVersion
from securemailscope.chain.enums import (
    ChainObservability,
    EngineStatus,
    EventStatus,
    EvidenceRedaction,
    EvidenceSourceKind,
    LimitationCode,
    ProtocolEventType,
    ProtocolState,
)
from securemailscope.models import Direction, Protocol


class _ApiModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class HealthResponse(_ApiModel):
    status: str
    api_version: ApiVersion


class LimitationDetail(_ApiModel):
    code: LimitationCode
    summary: str
    detail: str


class PolicyRiskSummary(_ApiModel):
    policy_risk_id: str
    profile_id: str
    uncapped_score: int
    capped_score: int
    available: bool


class AnalysisSummary(_ApiModel):
    api_version: ApiVersion
    chain_schema_version: str
    analysis_id: str
    analyzer_version: str
    analysis_status: str
    rule_engine_status: EngineStatus
    ml_engine_status: EngineStatus
    capture_ids: list[str]
    session_ids: list[str]
    finding_ids: list[str]
    capture_count: int
    session_count: int
    evidence_count: int
    protocol_event_count: int
    derived_fact_count: int
    rule_evaluation_count: int
    finding_count: int
    recommendation_count: int
    policy_risk: PolicyRiskSummary | None
    limitations: list[LimitationDetail]


class SessionEventDetail(_ApiModel):
    event_id: str
    session_id: str
    protocol: Protocol
    sequence_index: int
    event_type: ProtocolEventType
    state_before: ProtocolState
    state_after: ProtocolState
    timestamp: AwareDatetime
    direction: Direction
    evidence_ids: list[str]
    event_status: EventStatus
    observability: ChainObservability
    limitations: list[LimitationDetail]


class SessionEventsResponse(_ApiModel):
    api_version: ApiVersion
    analysis_id: str
    session_id: str
    stable_session_key: str
    protocol: Protocol
    events: list[SessionEventDetail]


class SafeEvidenceDetail(_ApiModel):
    evidence_id: str
    capture_id: str
    capture_sha256: str
    session_id: str
    frame_numbers: list[Annotated[int, Field(ge=1)]]
    timestamp_start: AwareDatetime
    timestamp_end: AwareDatetime
    direction: Direction
    source_kind: EvidenceSourceKind
    source_field: str
    observability: ChainObservability
    redaction: EvidenceRedaction
