"""Chain-of-Proof domain contract (Commit 1) and POC adapter (Commit 2).

This package defines the frozen, versioned contract for the Chain-of-Proof
engine (spec ``Chain-of-Proof-Specification.md`` schema 1.0.0): the stable
vocabulary, strict Pydantic models, deterministic identifiers, typed errors,
canonical serialization, and graph invariants.

Commit 2 adds :func:`build_chain_from_poc_analysis`, the pure, deterministic
adapter that maps verified E2/E3A analyzer output into the chain contract.

Commit 3 adds :func:`derive_smtp_transition_facts`, the deterministic fact
derivation that produces the SMTP STARTTLS transition facts from the ordered,
evidence-backed chain events.

Policy evaluation, anomaly scoring, and the later report artifacts are later
commits.
"""

from securemailscope.chain.canonical import (
    canonical_content_hash,
    canonical_content_json,
    canonical_json,
    datetime_canonical_str,
    extract_canonical_content,
    semantic_content_hash,
)
from securemailscope.chain.enums import (
    AnalysisStatus,
    AnomalyBand,
    AutomationStatus,
    ChainObservability,
    ConfidenceLevel,
    EdgeType,
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
from securemailscope.chain.errors import (
    ChainAdapterError,
    ChainError,
    ChainErrorCode,
    ChainValidationError,
)
from securemailscope.chain.ids import (
    stable_digest,
    stable_sha256_key,
)
from securemailscope.chain.invariants import (
    assert_chain_valid,
    index_chain,
    validate_chain,
)
from securemailscope.chain.models import (
    AnalysisExecution,
    AnalysisLimitation,
    AnalysisManifest,
    AnomalyResult,
    ArtifactManifest,
    CaptureProvenance,
    ChainOfProof,
    CryptoObservation,
    DerivedFact,
    Endpoint,
    EvidenceReference,
    Finding,
    PolicyRiskContribution,
    PolicyRiskSummary,
    ProtocolEvent,
    Recommendation,
    RuleEvaluation,
    Session,
    StageDiagnostic,
    StandardsReference,
)
from securemailscope.chain.poc_adapter import (
    CaptureMetadata,
    PocAdapterContext,
    build_chain_from_poc_analysis,
)
from securemailscope.chain.smtp_facts import derive_smtp_transition_facts

__all__ = [
    "AnalysisExecution",
    "AnalysisLimitation",
    "AnalysisManifest",
    "AnalysisStatus",
    "AnomalyBand",
    "AnomalyResult",
    "ArtifactManifest",
    "AutomationStatus",
    "CaptureMetadata",
    "CaptureProvenance",
    "ChainAdapterError",
    "ChainError",
    "ChainErrorCode",
    "ChainObservability",
    "ChainOfProof",
    "ChainValidationError",
    "ConfidenceLevel",
    "CryptoObservation",
    "DerivedFact",
    "EdgeType",
    "Endpoint",
    "EngineStatus",
    "EventStatus",
    "EvidenceRedaction",
    "EvidenceReference",
    "EvidenceSourceKind",
    "Finding",
    "FindingCategory",
    "LimitationCode",
    "ObservationKind",
    "PocAdapterContext",
    "PolicyRiskContribution",
    "PolicyRiskSummary",
    "ProtocolEvent",
    "ProtocolEventType",
    "ProtocolState",
    "Recommendation",
    "RecommendationPriority",
    "RecommendationScope",
    "RuleEvaluation",
    "RuleOutcome",
    "RuleReasonCode",
    "Session",
    "SeverityLevel",
    "StageDiagnostic",
    "StageId",
    "StageStatus",
    "StandardsReference",
    "Tls13SecretsStatus",
    "assert_chain_valid",
    "build_chain_from_poc_analysis",
    "canonical_content_hash",
    "canonical_content_json",
    "canonical_json",
    "datetime_canonical_str",
    "derive_smtp_transition_facts",
    "extract_canonical_content",
    "index_chain",
    "semantic_content_hash",
    "stable_digest",
    "stable_sha256_key",
    "validate_chain",
]
