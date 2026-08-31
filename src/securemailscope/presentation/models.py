"""Strict immutable models for one evidence-backed finding presentation."""

from __future__ import annotations

from typing import Annotated

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, JsonValue

from securemailscope.chain.enums import (
    AnomalyBand,
    AutomationStatus,
    ChainObservability,
    ConfidenceLevel,
    EngineStatus,
    EventStatus,
    EvidenceRedaction,
    EvidenceSourceKind,
    FindingCategory,
    LimitationCode,
    ObservationKind,
    ProtocolEventType,
    RecommendationPriority,
    RecommendationScope,
    RuleOutcome,
    SeverityLevel,
)
from securemailscope.models import Direction, Protocol


class _PresentationModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class LimitationPresentation(_PresentationModel):
    code: LimitationCode
    summary: str
    detail: str


class StandardPresentation(_PresentationModel):
    id: str
    section: str | None


class FactPresentation(_PresentationModel):
    fact_id: str
    session_id: str
    fact_type: str
    value: JsonValue
    derivation_id: str
    derivation_version: str
    source_event_ids: list[str]
    source_observation_ids: list[str]
    source_fact_ids: list[str]
    observability: ChainObservability
    confidence_level: ConfidenceLevel
    confidence_basis: list[str]
    limitations: list[LimitationPresentation]


class EventPresentation(_PresentationModel):
    event_id: str
    session_id: str
    sequence_index: int
    event_type: ProtocolEventType
    timestamp: AwareDatetime
    direction: Direction
    evidence_ids: list[str]
    event_status: EventStatus
    observability: ChainObservability
    limitations: list[LimitationPresentation]


class ObservationPresentation(_PresentationModel):
    observation_id: str
    session_id: str
    kind: ObservationKind
    observability: ChainObservability
    evidence_ids: list[str]
    limitations: list[LimitationPresentation]


class EvidencePresentation(_PresentationModel):
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


class RecommendationPresentation(_PresentationModel):
    recommendation_id: str
    title: str
    summary: str
    priority: RecommendationPriority
    affected_finding_ids: list[str]
    action_steps: list[str]
    verification_steps: list[str]
    standards_references: list[StandardPresentation]
    scope: RecommendationScope
    automation_status: AutomationStatus


class PolicyRiskContributionPresentation(_PresentationModel):
    contribution_id: str
    rule_id: str
    rule_version: str
    finding_id: str
    severity: SeverityLevel
    policy_risk_contribution: int
    evidence_confidence: ConfidenceLevel
    confidence_factor: float
    confidence_adjusted_points: int


class PolicyRiskPresentation(_PresentationModel):
    policy_risk_id: str
    analysis_id: str
    profile_id: str
    uncapped_score: int
    capped_score: int
    contributions: list[PolicyRiskContributionPresentation]
    limitations: list[LimitationPresentation]


class AnomalyResultPresentation(_PresentationModel):
    anomaly_result_id: str
    session_id: str
    model_id: str
    model_version: str
    feature_schema_version: str
    raw_score: float
    normalized_score: float
    threshold: float
    band: AnomalyBand
    unusual_feature_indicators: list[str]
    linked_fact_ids: list[str]
    linked_observation_ids: list[str]
    evidence_ids: list[str]
    interpretation_note: str
    limitations: list[LimitationPresentation]


class MlAnomalyPresentation(_PresentationModel):
    engine_status: EngineStatus
    results: list[AnomalyResultPresentation]


class FindingPresentation(_PresentationModel):
    chain_schema_version: str
    analysis_id: str
    capture_id: str
    capture_sha256: str
    finding_id: str
    stable_finding_key: str
    session_id: str
    stable_session_key: str
    protocol: Protocol
    rule_evaluation_id: str
    rule_id: str
    rule_version: str
    rule_outcome: RuleOutcome
    title: str
    category: FindingCategory
    severity: SeverityLevel
    evidence_confidence: ConfidenceLevel
    observability: ChainObservability
    policy_risk_contribution: int
    rationale: str
    impact: str
    fact_ids: list[str]
    facts: list[FactPresentation]
    event_ids: list[str]
    events: list[EventPresentation]
    observation_ids: list[str]
    observations: list[ObservationPresentation]
    evidence_ids: list[str]
    evidence: list[EvidencePresentation]
    recommendation: RecommendationPresentation
    standards_references: list[StandardPresentation]
    limitations: list[LimitationPresentation]
    policy_risk: PolicyRiskPresentation | None
    ml_anomaly: MlAnomalyPresentation
    evaluated_at: AwareDatetime
    created_at: AwareDatetime


class FindingArtifact(_PresentationModel):
    filename: str
    media_type: str
    content: bytes
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    byte_length: int = Field(ge=0)


class FindingArtifactSet(_PresentationModel):
    json_artifact: FindingArtifact
    html_artifact: FindingArtifact
    pdf_artifact: FindingArtifact
