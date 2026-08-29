"""Strict, frozen Pydantic models for the Chain-of-Proof graph contract.

Implements the spec §4 node types with these rules:

* Every model is ``extra="forbid"`` and frozen.
* Datetimes are :class:`AwareDatetime` (naive datetimes are rejected).
* Typed JSON payloads (fact values, snapshots) use :class:`JsonValue`.
* Every field listed as "Required" in spec §4 is required in Pydantic and in
  the generated JSON Schema. Collections may be empty but their keys must be
  present, so collections have no default.
* Required-but-nullable fields (a value that is meaningful only to be *absent*)
  have no default and allow ``None``, so omitting the key is a schema error
  while an explicit ``null`` is valid. This is the explicit alternative to
  magic-string "-none" sentinels (e.g. ``rule_pack_id``/``rule_pack_version``).
* Capture and artifact SHA-256 digest fields use raw 64-lowercase-hex digests;
  stable semantic keys (``stable_session_key``/``stable_finding_key``) use the
  tagged ``sha256:<64 hex>`` form.
* Stable POC enums (``Direction``, ``Protocol``, ``CaptureFormat``,
  ``CompleteStatus``) are reused unchanged.

Policy-risk scoring rules belong to a later commit. This module stores declared
rule contribution inputs, confidence adjustment, caps, and final values, but
does not enforce deterministic scoring arithmetic.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    model_validator,
)

from securemailscope.chain.enums import (
    AnalysisStatus,
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
    ProtocolState,
    RecommendationPriority,
    RecommendationScope,
    RuleOutcome,
    RuleReasonCode,
    SeverityLevel,
    StageId,
    StageStatus,
    Tls13SecretsStatus,
)
from securemailscope.chain.ids import (
    COMPACT_ID_PATTERN,
    PREFIX_ANALYSIS,
    PREFIX_ANOMALY,
    PREFIX_ARTIFACT,
    PREFIX_CAPTURE,
    PREFIX_CRYPTO_OBSERVATION,
    PREFIX_EVIDENCE,
    PREFIX_FACT,
    PREFIX_FINDING,
    PREFIX_POLICY_CONTRIBUTION,
    PREFIX_POLICY_RISK,
    PREFIX_PROTOCOL_EVENT,
    PREFIX_RULE_EVALUATION,
    PREFIX_SESSION,
    RECOMMENDATION_PATTERN,
    SEMVER_PATTERN,
    SHA256_DIGEST_PATTERN,
    SHA256_KEY_PATTERN,
)
from securemailscope.models import CaptureFormat, CompleteStatus, Direction, Protocol

SCHEMA_ID = "urn:securemailscope:schema:chain-of-proof:1.0.0"
CHAIN_SCHEMA_VERSION = "1.0.0"

POLICY_RISK_CAP = 100

#: The mandatory, enforceable interpretation statement attached to every
#: anomaly result. It is a Literal so a document can neither omit nor replace
#: it with a weaker/free-form warning (spec §4.10, §11).
ANOMALY_INTERPRETATION_NOTE = "Anomalous behavior is not proof of malicious activity."


def _validate_engine_fields(
    status: EngineStatus,
    identity_id: str | None,
    identity_version: str | None,
    label: str,
) -> None:
    """Enforce engine identity semantics (spec §18 / failure semantics).

    - ``not_run``: identity fields must be null.
    - ``complete``/``partial``: versioned identity required (both set).
    - ``failed``/``unavailable``: identity optional (both null, or both set).
    Both fields must always be both-null or both-set.
    """
    id_field = f"{label}_id"
    version_field = f"{label}_version"
    if (identity_id is None) != (identity_version is None):
        raise ValueError(f"{id_field} and {version_field} must both be null or both set")
    if status is EngineStatus.NOT_RUN:
        if identity_id is not None or identity_version is not None:
            raise ValueError(
                f"{id_field} and {version_field} must be null when the {label} engine is not_run"
            )
    elif status in (EngineStatus.COMPLETE, EngineStatus.PARTIAL):
        if identity_id is None or identity_version is None:
            raise ValueError(
                f"{id_field} and {version_field} must both be set when the {label} "
                f"engine is {status.value}"
            )
    if identity_version is not None and not _is_semver(identity_version):
        raise ValueError(f"{version_field} is not semver: {identity_version!r}")


def _is_semver(value: str) -> bool:
    import re

    return re.fullmatch(SEMVER_PATTERN, value) is not None


class StandardsReference(BaseModel):
    """A standard citation used by findings/recommendations."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    section: str | None = None


class Endpoint(BaseModel):
    """One transport endpoint of a reconstructed session."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    ip: str
    port: int = Field(ge=0, le=65535)


class AnalysisLimitation(BaseModel):
    """A typed, reason-coded limitation on a value or conclusion.

    Used wherever the chain must state *why* something is not observable,
    incomplete, secret-protected, or not assessable instead of guessing.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: LimitationCode
    summary: str
    detail: str = ""


# ─────────────────────────────────────────────────────────────────────────────
#  §4.1 AnalysisManifest
# ─────────────────────────────────────────────────────────────────────────────


class AnalysisManifest(BaseModel):
    """Identifies a reproducible analysis execution (spec §4.1)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    analysis_id: str = Field(pattern=COMPACT_ID_PATTERN[PREFIX_ANALYSIS])
    chain_schema_version: str = Field(pattern=SEMVER_PATTERN)
    analysis_status: AnalysisStatus
    created_at: AwareDatetime
    started_at: AwareDatetime
    completed_at: AwareDatetime | None
    analyzer_version: str
    tshark_version: str | None
    rule_engine_status: EngineStatus
    rule_pack_id: str | None
    rule_pack_version: str | None
    ml_engine_status: EngineStatus
    model_id: str | None
    model_version: str | None
    configuration_digest: str = Field(pattern=SHA256_DIGEST_PATTERN)
    tls13_authorized_secrets: Tls13SecretsStatus
    limitations: list[AnalysisLimitation]

    @model_validator(mode="after")
    def _paired_engine_fields(self) -> AnalysisManifest:
        for status, id_field, version_field, label in (
            (
                self.rule_engine_status,
                self.rule_pack_id,
                self.rule_pack_version,
                "rule_pack",
            ),
            (self.ml_engine_status, self.model_id, self.model_version, "model"),
        ):
            _validate_engine_fields(status, id_field, version_field, label)
        return self


# ─────────────────────────────────────────────────────────────────────────────
#  §4.2 CaptureProvenance
# ─────────────────────────────────────────────────────────────────────────────


class CaptureProvenance(BaseModel):
    """Immutable capture provenance as computed by the intake stage (spec §4.2)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    capture_id: str = Field(pattern=COMPACT_ID_PATTERN[PREFIX_CAPTURE])
    original_filename_sanitized: str
    format: CaptureFormat
    size_bytes: int = Field(ge=0)
    sha256: str = Field(pattern=SHA256_DIGEST_PATTERN)
    packet_count: int = Field(ge=0)
    captured_at_start: AwareDatetime | None
    captured_at_end: AwareDatetime | None
    link_layer_types: list[str]
    snaplen: int | None
    truncated_packet_count: int = Field(ge=0)
    capture_warnings: list[str]
    ingestion_tool_versions: dict[str, str]


# ─────────────────────────────────────────────────────────────────────────────
#  §4.3 Session
# ─────────────────────────────────────────────────────────────────────────────


class Session(BaseModel):
    """One reconstructed transport session (spec §4.3)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    session_id: str = Field(pattern=COMPACT_ID_PATTERN[PREFIX_SESSION])
    stable_session_key: str = Field(pattern=SHA256_KEY_PATTERN)
    capture_id: str = Field(pattern=COMPACT_ID_PATTERN[PREFIX_CAPTURE])
    tcp_stream_id: int = Field(ge=0)
    source_endpoint: Endpoint
    destination_endpoint: Endpoint
    first_frame: int = Field(ge=1)
    last_frame: int = Field(ge=1)
    started_at: AwareDatetime
    ended_at: AwareDatetime
    packet_count: int = Field(ge=0)
    byte_count: int = Field(ge=0)
    protocol: Protocol
    protocol_confidence: ConfidenceLevel
    classification_evidence_ids: list[str]
    capture_completeness: CompleteStatus
    limitations: list[AnalysisLimitation]

    @model_validator(mode="after")
    def _frame_range(self) -> Session:
        if self.first_frame > self.last_frame:
            raise ValueError("first_frame must be <= last_frame")
        return self


# ─────────────────────────────────────────────────────────────────────────────
#  §4.4 EvidenceReference
# ─────────────────────────────────────────────────────────────────────────────


class EvidenceReference(BaseModel):
    """A precise reference back to directly observable capture evidence.

    (spec §4.4). An EvidenceReference is constrained to *directly observed*
    evidence: it must always be ``observability=observed``. Non-observed states
    are represented on the events/observations that reference it, never by
    fabricating a non-observed evidence entry. This is what makes the
    observability invariants internally consistent (there is no
    ``evidence.limitations`` field).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    evidence_id: str = Field(pattern=COMPACT_ID_PATTERN[PREFIX_EVIDENCE])
    capture_id: str = Field(pattern=COMPACT_ID_PATTERN[PREFIX_CAPTURE])
    capture_sha256: str = Field(pattern=SHA256_DIGEST_PATTERN)
    session_id: str = Field(pattern=COMPACT_ID_PATTERN[PREFIX_SESSION])
    frame_numbers: list[Annotated[int, Field(ge=1)]] = Field(min_length=1)
    occurrence_index: int = Field(ge=0)
    timestamp_start: AwareDatetime
    timestamp_end: AwareDatetime
    direction: Direction
    source_kind: EvidenceSourceKind
    source_field: str
    normalized_value: str
    safe_excerpt: str
    display_filter: str
    observability: Literal[ChainObservability.OBSERVED]
    redaction: EvidenceRedaction
    extractor_version: str


# ─────────────────────────────────────────────────────────────────────────────
#  §4.5 ProtocolEvent
# ─────────────────────────────────────────────────────────────────────────────


class ProtocolEvent(BaseModel):
    """An ordered protocol or TLS transition (spec §4.5)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: str = Field(pattern=COMPACT_ID_PATTERN[PREFIX_PROTOCOL_EVENT])
    session_id: str = Field(pattern=COMPACT_ID_PATTERN[PREFIX_SESSION])
    sequence_index: int = Field(ge=0)
    event_type: ProtocolEventType
    protocol: Protocol
    state_before: ProtocolState
    state_after: ProtocolState
    timestamp: AwareDatetime
    direction: Direction
    evidence_ids: list[str]
    event_status: EventStatus
    observability: ChainObservability
    limitations: list[AnalysisLimitation]


# ─────────────────────────────────────────────────────────────────────────────
#  §4.6 CryptoObservation
# ─────────────────────────────────────────────────────────────────────────────


class CryptoObservation(BaseModel):
    """Observable TLS/X.509 fact without policy judgment (spec §4.6)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    observation_id: str = Field(pattern=COMPACT_ID_PATTERN[PREFIX_CRYPTO_OBSERVATION])
    session_id: str = Field(pattern=COMPACT_ID_PATTERN[PREFIX_SESSION])
    kind: ObservationKind
    value: JsonValue
    normalized_value: str
    observability: ChainObservability
    evidence_ids: list[str]
    limitations: list[AnalysisLimitation]


# ─────────────────────────────────────────────────────────────────────────────
#  §4.7 DerivedFact
# ─────────────────────────────────────────────────────────────────────────────


class DerivedFact(BaseModel):
    """A deterministic conclusion from observations/events (spec §4.7)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    fact_id: str = Field(pattern=COMPACT_ID_PATTERN[PREFIX_FACT])
    session_id: str = Field(pattern=COMPACT_ID_PATTERN[PREFIX_SESSION])
    fact_type: str
    value: JsonValue
    derivation_id: str
    derivation_version: str = Field(pattern=SEMVER_PATTERN)
    source_event_ids: list[str]
    source_observation_ids: list[str]
    source_fact_ids: list[str]
    observability: ChainObservability
    confidence_level: ConfidenceLevel
    confidence_basis: list[str] = Field(min_length=1)
    limitations: list[AnalysisLimitation]


# ─────────────────────────────────────────────────────────────────────────────
#  §4.8 RuleEvaluation
# ─────────────────────────────────────────────────────────────────────────────


class RuleEvaluation(BaseModel):
    """Complete evaluation of one versioned policy rule (spec §4.8)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    evaluation_id: str = Field(pattern=COMPACT_ID_PATTERN[PREFIX_RULE_EVALUATION])
    session_id: str = Field(pattern=COMPACT_ID_PATTERN[PREFIX_SESSION])
    rule_id: str
    rule_version: str = Field(pattern=SEMVER_PATTERN)
    profile_id: str
    evaluated_at: AwareDatetime
    input_fact_ids: list[str]
    input_snapshot: dict[str, JsonValue]
    outcome: RuleOutcome
    reason_code: RuleReasonCode
    generated_finding_id: str | None = Field(pattern=COMPACT_ID_PATTERN[PREFIX_FINDING])


# ─────────────────────────────────────────────────────────────────────────────
#  §4.9 Finding
# ─────────────────────────────────────────────────────────────────────────────


class Finding(BaseModel):
    """A versioned policy output linked to evidence (spec §4.9)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    finding_id: str = Field(pattern=COMPACT_ID_PATTERN[PREFIX_FINDING])
    stable_finding_key: str = Field(pattern=SHA256_KEY_PATTERN)
    analysis_id: str = Field(pattern=COMPACT_ID_PATTERN[PREFIX_ANALYSIS])
    session_id: str = Field(pattern=COMPACT_ID_PATTERN[PREFIX_SESSION])
    rule_evaluation_id: str = Field(pattern=COMPACT_ID_PATTERN[PREFIX_RULE_EVALUATION])
    rule_id: str
    rule_version: str = Field(pattern=SEMVER_PATTERN)
    title: str
    category: FindingCategory
    severity: SeverityLevel
    policy_risk_contribution: int = Field(ge=0)
    evidence_confidence: ConfidenceLevel
    observability: ChainObservability
    fact_ids: list[str] = Field(min_length=1)
    evidence_ids: list[str] = Field(min_length=1)
    rationale: str
    impact: str
    recommendation_id: str = Field(pattern=RECOMMENDATION_PATTERN)
    standards_references: list[StandardsReference]
    limitations: list[AnalysisLimitation]
    created_at: AwareDatetime


# ─────────────────────────────────────────────────────────────────────────────
#  §4.10 AnomalyResult
# ─────────────────────────────────────────────────────────────────────────────


class AnomalyResult(BaseModel):
    """View of a model-dependent anomaly score, separate from policy risk."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    anomaly_result_id: str = Field(pattern=COMPACT_ID_PATTERN[PREFIX_ANOMALY])
    session_id: str = Field(pattern=COMPACT_ID_PATTERN[PREFIX_SESSION])
    model_id: str
    model_version: str = Field(pattern=SEMVER_PATTERN)
    feature_schema_version: str = Field(pattern=SEMVER_PATTERN)
    feature_snapshot: dict[str, JsonValue]
    raw_score: float = Field(allow_inf_nan=False)
    normalized_score: float = Field(ge=0.0, le=1.0, allow_inf_nan=False)
    threshold: float = Field(allow_inf_nan=False)
    band: AnomalyBand
    unusual_feature_indicators: list[str]
    linked_fact_ids: list[str] = Field(default_factory=list)
    linked_observation_ids: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    interpretation_note: Literal[ANOMALY_INTERPRETATION_NOTE]
    limitations: list[AnalysisLimitation]


# ─────────────────────────────────────────────────────────────────────────────
#  §4.11 Recommendation
# ─────────────────────────────────────────────────────────────────────────────


class Recommendation(BaseModel):
    """Remediation guidance for findings, advisory-only for submission (spec §4.11)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    recommendation_id: str = Field(pattern=RECOMMENDATION_PATTERN)
    title: str
    summary: str
    priority: RecommendationPriority
    affected_finding_ids: list[str]
    action_steps: list[str]
    verification_steps: list[str]
    standards_references: list[StandardsReference]
    scope: RecommendationScope
    automation_status: AutomationStatus


# ─────────────────────────────────────────────────────────────────────────────
#  §11 policy risk
# ─────────────────────────────────────────────────────────────────────────────


class PolicyRiskContribution(BaseModel):
    """One rule's declared contribution to capture-wide policy risk.

    Scoring rules belong to a later commit. This model stores the declared
    inputs: severity, confidence, contribution, factor, and adjusted points.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    contribution_id: str = Field(pattern=COMPACT_ID_PATTERN[PREFIX_POLICY_CONTRIBUTION])
    rule_id: str
    rule_version: str = Field(pattern=SEMVER_PATTERN)
    finding_id: str = Field(pattern=COMPACT_ID_PATTERN[PREFIX_FINDING])
    severity: SeverityLevel
    policy_risk_contribution: int = Field(ge=0)
    evidence_confidence: ConfidenceLevel
    confidence_factor: float = Field(gt=0.0)
    confidence_adjusted_points: int = Field(ge=0)


class PolicyRiskSummary(BaseModel):
    """Separate deterministic policy-risk summary (independent of ML anomaly)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    policy_risk_id: str = Field(pattern=COMPACT_ID_PATTERN[PREFIX_POLICY_RISK])
    analysis_id: str = Field(pattern=COMPACT_ID_PATTERN[PREFIX_ANALYSIS])
    profile_id: str
    uncapped_score: int = Field(ge=0)
    capped_score: int = Field(ge=0, le=POLICY_RISK_CAP)
    contributions: list[PolicyRiskContribution]
    limitations: list[AnalysisLimitation]


# ─────────────────────────────────────────────────────────────────────────────
#  §18 failure semantics / execution envelope
# ─────────────────────────────────────────────────────────────────────────────


class StageDiagnostic(BaseModel):
    """Typed runtime diagnostic for one analysis stage."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    stage: StageId
    status: StageStatus
    limitation: AnalysisLimitation | None = None
    runtime_seconds: float = Field(ge=0.0, allow_inf_nan=False, default=0.0)


class AnalysisExecution(BaseModel):
    """Volatile execution envelope, separate from reproducible chain content.

    This whole node is excluded from the canonical content hash. It records
    tool versions and stage diagnostics without claiming to be reproducible
    evidence.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    tool_versions: dict[str, str] = Field(default_factory=dict)
    stage_diagnostics: list[StageDiagnostic] = Field(default_factory=list)
    note: str = "Execution envelope; not part of reproducible chain content."


# ─────────────────────────────────────────────────────────────────────────────
#  §4.12 ArtifactManifest
# ─────────────────────────────────────────────────────────────────────────────


class ArtifactManifest(BaseModel):
    """Tamper-evident hashes and version metadata for produced artifacts."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    artifact_manifest_id: str = Field(pattern=COMPACT_ID_PATTERN[PREFIX_ARTIFACT])
    analysis_id: str = Field(pattern=COMPACT_ID_PATTERN[PREFIX_ANALYSIS])
    capture_sha256: str = Field(pattern=SHA256_DIGEST_PATTERN)
    canonical_json_sha256: str = Field(pattern=SHA256_DIGEST_PATTERN)
    html_report_sha256: str | None = Field(pattern=SHA256_DIGEST_PATTERN)
    pdf_report_sha256: str | None = Field(pattern=SHA256_DIGEST_PATTERN)
    rule_pack_sha256: str | None = Field(pattern=SHA256_DIGEST_PATTERN)
    model_artifact_sha256: str | None = Field(pattern=SHA256_DIGEST_PATTERN)
    generated_at: AwareDatetime
    signature_algorithm: str | None
    signature: str | None


# ─────────────────────────────────────────────────────────────────────────────
#  Root
# ─────────────────────────────────────────────────────────────────────────────


class ChainOfProof(BaseModel):
    """The versioned canonical chain-of-proof document (spec §1, §4)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_id: Literal[SCHEMA_ID]
    chain_schema_version: Literal[CHAIN_SCHEMA_VERSION]
    analysis: AnalysisManifest
    execution: AnalysisExecution
    captures: list[CaptureProvenance] = Field(min_length=1)
    sessions: list[Session]
    evidence: list[EvidenceReference]
    protocol_events: list[ProtocolEvent]
    crypto_observations: list[CryptoObservation]
    derived_facts: list[DerivedFact]
    rule_evaluations: list[RuleEvaluation]
    findings: list[Finding]
    policy_risk: PolicyRiskSummary | None
    anomaly_results: list[AnomalyResult]
    recommendations: list[Recommendation]
    artifacts: list[ArtifactManifest]
