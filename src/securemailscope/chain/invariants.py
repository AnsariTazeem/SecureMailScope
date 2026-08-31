"""Graph and business invariant checks for a Chain-of-Proof document.

Implements the spec §3 non-negotiable invariants, the §19 graph-invariant test
list, the TLS 1.3 certificate-visibility rule (§9, §18), the deterministic
policy-risk/anomaly separation (§11), reproducible deterministic identifiers
(§4, §12), schema/version/time ordering (§4, §16), evidence-backed graph
grounding (§3, §9) and engine failure semantics (§18). :func:`validate_chain`
returns an ``(ok, problems)`` pair; :func:`assert_chain_valid` raises a typed
:class:`ChainValidationError` instead. Values are never mutated: the checks are
pure and reproducible. No observability state can raise :class:`AttributeError`;
invariant validation always returns typed problems or raises a typed
:class:`ChainValidationError`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from securemailscope.chain.canonical import (
    canonical_content_hash,
    canonical_json,
)
from securemailscope.chain.enums import (
    ChainObservability,
    EngineStatus,
    EventStatus,
    EvidenceSourceKind,
    LimitationCode,
    ObservationKind,
    ProtocolEventType,
    RuleOutcome,
    Tls13SecretsStatus,
)
from securemailscope.chain.errors import ChainValidationError
from securemailscope.chain.ids import (
    COMPACT_ID_PATTERN,
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
    analysis_id,
    anomaly_result_id,
    artifact_manifest_id,
    capture_id_from_sha256,
    crypto_observation_id,
    evidence_id,
    fact_id_from_key,
    fact_stable_key,
    finding_id_from_key,
    finding_stable_key,
    is_recommendation_id,
    policy_contribution_id,
    policy_risk_id,
    protocol_event_id,
    rule_evaluation_id,
    session_id_from_key,
    session_stable_key,
)
from securemailscope.chain.models import (
    POLICY_RISK_CAP,
    AnomalyResult,
    ArtifactManifest,
    CaptureProvenance,
    ChainOfProof,
    CryptoObservation,
    DerivedFact,
    EvidenceReference,
    Finding,
    PolicyRiskContribution,
    ProtocolEvent,
    Recommendation,
    RuleEvaluation,
    Session,
)
from securemailscope.models import Protocol

_PORT_ONLY_FIELDS: frozenset[str] = frozenset(
    {
        "tcp.port",
        "tcp.srcport",
        "tcp.dstport",
        "udp.port",
        "udp.srcport",
        "udp.dstport",
        "ip.proto",
    }
)
_CONTENT_SOURCE_KINDS: frozenset[EvidenceSourceKind] = frozenset(
    {
        EvidenceSourceKind.TSHARK_FIELD,
        EvidenceSourceKind.TSHARK_FOLLOW_STREAM,
        EvidenceSourceKind.CRYPTOGRAPHY_LIBRARY,
        EvidenceSourceKind.DERIVED_STATE_MACHINE,
    }
)
_CERTIFICATE_KINDS: frozenset[ObservationKind] = frozenset(
    {
        ObservationKind.CERTIFICATE_SUBJECT,
        ObservationKind.CERTIFICATE_ISSUER,
        ObservationKind.CERTIFICATE_SAN,
        ObservationKind.CERTIFICATE_VALIDITY_WINDOW,
        ObservationKind.CERTIFICATE_FINGERPRINT,
        ObservationKind.CERTIFICATE_CHAIN_STRUCTURE,
        ObservationKind.CERTIFICATE_SERIAL_NUMBER,
        ObservationKind.CERTIFICATE_BASIC_CONSTRAINTS,
        ObservationKind.CERTIFICATE_KEY_USAGE,
        ObservationKind.CERTIFICATE_STRUCTURE_PARSED,
        ObservationKind.CERTIFICATE_SIGNATURE_CHAIN_CHECKED,
        ObservationKind.CERTIFICATE_TRUSTED_PATH_VALIDATED,
        ObservationKind.CERTIFICATE_SERVICE_IDENTITY_VALIDATED,
        ObservationKind.CERTIFICATE_REVOCATION_CHECKED,
        ObservationKind.TLS13_CERTIFICATE_UNAVAILABLE,
    }
)
_UNOBSERVABLE_STATE: frozenset[ChainObservability] = frozenset(
    {
        ChainObservability.NOT_OBSERVABLE,
        ChainObservability.INCOMPLETE_CAPTURE,
        ChainObservability.SESSION_SECRETS_REQUIRED,
    }
)
#: Observability states that assert real (non-unavailable) certificate content.
#: When authorized session secrets are absent, any certificate-field observation
#: in one of these states on a TLS 1.3 session fabricates certificate claims and
#: must fail. Unavailable states (e.g. session_secrets_required/not_observable)
#: are permitted only with the matching limitation.
_CERTIFICATE_CLAIMING_STATES: frozenset[ChainObservability] = frozenset(
    {
        ChainObservability.OBSERVED,
        ChainObservability.DERIVED,
        ChainObservability.POLICY_INFERRED,
    }
)
#: Deterministic neutral certificate-field representation for a TLS 1.3 session
#: without authorized session secrets, keyed by the only permitted observability
#: states. ``value`` must be null or this neutral string and ``normalized_value``
#: must equal it exactly, so an unavailable certificate-field observation never
#: carries actual certificate content.
_TLS13_NEUTRAL_CERT_VALUES: dict[ChainObservability, str] = {
    ChainObservability.SESSION_SECRETS_REQUIRED: "session_secrets_required",
    ChainObservability.NOT_OBSERVABLE: "not_observable",
}
#: Frozen neutral representation for the dedicated TLS 1.3 certificate-unavailable
#: sentinel. ``normalized_value`` must equal this exactly and ``value`` must be
#: null or this string, so the sentinel never carries certificate content.
_TLS13_UNAVAILABLE_NEUTRAL = "certificate_not_observable"
#: Material protocol events that must reference direct evidence when observed.
_MATERIAL_EVENTS: frozenset[ProtocolEventType] = frozenset(
    {
        ProtocolEventType.SERVER_GREETING,
        ProtocolEventType.CAPABILITY_REQUEST,
        ProtocolEventType.CAPABILITY_ADVERTISED,
        ProtocolEventType.TLS_UPGRADE_REQUESTED,
        ProtocolEventType.TLS_UPGRADE_ACCEPTED,
        ProtocolEventType.TLS_UPGRADE_REJECTED,
        ProtocolEventType.CLIENT_HELLO,
        ProtocolEventType.SERVER_HELLO,
        ProtocolEventType.CERTIFICATE_MESSAGE,
        ProtocolEventType.KEY_EXCHANGE_OBSERVED,
        ProtocolEventType.HANDSHAKE_FINISHED,
        ProtocolEventType.ENCRYPTED_APPLICATION_DATA,
        ProtocolEventType.PLAINTEXT_COMMAND_AFTER_TLS_OFFER,
    }
)


@dataclass
class ChainIndex:
    """Lightweight name-indexes over a chain for O(1) reference lookups."""

    analysis_id: str
    analysis_chain_schema_version: str
    captures: dict[str, CaptureProvenance]
    sessions: dict[str, Session]
    evidence: dict[str, EvidenceReference]
    events: dict[str, ProtocolEvent]
    observations: dict[str, CryptoObservation]
    facts: dict[str, DerivedFact]
    evaluations: dict[str, RuleEvaluation]
    findings: dict[str, Finding]
    anomalies: dict[str, AnomalyResult]
    recommendations: dict[str, Recommendation]
    artifacts: dict[str, ArtifactManifest]
    contributions: list[PolicyRiskContribution]


def index_chain(chain: ChainOfProof) -> ChainIndex:
    """Build name-indexes without mutating the chain."""
    return ChainIndex(
        analysis_id=chain.analysis.analysis_id,
        analysis_chain_schema_version=chain.analysis.chain_schema_version,
        captures={item.capture_id: item for item in chain.captures},
        sessions={item.session_id: item for item in chain.sessions},
        evidence={item.evidence_id: item for item in chain.evidence},
        events={item.event_id: item for item in chain.protocol_events},
        observations={item.observation_id: item for item in chain.crypto_observations},
        facts={item.fact_id: item for item in chain.derived_facts},
        evaluations={item.evaluation_id: item for item in chain.rule_evaluations},
        findings={item.finding_id: item for item in chain.findings},
        anomalies={item.anomaly_result_id: item for item in chain.anomaly_results},
        recommendations={item.recommendation_id: item for item in chain.recommendations},
        artifacts={item.artifact_manifest_id: item for item in chain.artifacts},
        contributions=list(chain.policy_risk.contributions) if chain.policy_risk else [],
    )


def _problem(problems: list[str], message: str) -> None:
    problems.append(message)


def _fits_pattern(problems: list[str], value: str, pattern: str, label: str) -> bool:
    if not re.fullmatch(pattern, value):
        _problem(problems, f"{label} has disallowed id shape: {value!r}")
        return False
    return True


def validate_chain(chain: ChainOfProof) -> tuple[bool, list[str]]:
    """Return ``(ok, problems)`` for a chain. Pure: not modified."""
    problems: list[str] = []
    index = index_chain(chain)

    _check_unique_ids(chain, index, problems)
    _check_id_shapes(chain, index, problems)
    _check_analysis_constraints(chain, index, problems)
    _check_reproducible_ids(chain, index, problems)
    _check_session_capture_links(chain, index, problems)
    _check_evidence_integrity(chain, index, problems)
    _check_node_session_references(chain, index, problems)
    _check_evidence_references(chain, index, problems)
    _check_evidence_backing(chain, index, problems)
    _check_event_ordering(chain, index, problems)
    _check_classification(chain, index, problems)
    _check_fact_sources(chain, index, problems)
    _check_fact_identities(chain, index, problems)
    _check_observability_reasons(chain, index, problems)
    _check_tls13_certificates(chain, index, problems)
    _check_rule_findings(chain, index, problems)
    _check_recommendations(chain, index, problems)
    _check_artifacts(chain, index, problems)
    _check_policy_risk(chain, index, problems)
    _check_anomaly_separation(chain, index, problems)
    _check_anomaly_links(chain, index, problems)
    return (not problems, problems)


def assert_chain_valid(chain: ChainOfProof) -> None:
    """Raise :class:`ChainValidationError` on invariant violation."""
    ok, problems = validate_chain(chain)
    if not ok:
        raise ChainValidationError(problems)


# ─────────────────────────────────────────────────────────────────────────────
#  Duplicate IDs
# ─────────────────────────────────────────────────────────────────────────────


def _raw_id_groups(chain: ChainOfProof) -> list[tuple[str, list[str]]]:
    """Raw (not dict-deduplicated) ID lists per top-level collection.

    Dictionaries erase duplicates, so uniqueness must be detected over the raw
    lists before any indexing.
    """
    groups: list[tuple[str, list[str]]] = [
        ("capture", [item.capture_id for item in chain.captures]),
        ("session", [item.session_id for item in chain.sessions]),
        ("evidence", [item.evidence_id for item in chain.evidence]),
        ("event", [item.event_id for item in chain.protocol_events]),
        ("observation", [item.observation_id for item in chain.crypto_observations]),
        ("fact", [item.fact_id for item in chain.derived_facts]),
        ("evaluation", [item.evaluation_id for item in chain.rule_evaluations]),
        ("finding", [item.finding_id for item in chain.findings]),
        ("anomaly", [item.anomaly_result_id for item in chain.anomaly_results]),
        ("recommendation", [item.recommendation_id for item in chain.recommendations]),
        ("artifact", [item.artifact_manifest_id for item in chain.artifacts]),
    ]
    if chain.policy_risk is not None:
        groups.append(
            (
                "policy_contribution",
                [item.contribution_id for item in chain.policy_risk.contributions],
            )
        )
    return groups


def _check_unique_ids(
    chain: ChainOfProof,
    index: ChainIndex,
    problems: list[str],
) -> None:
    seen_across: dict[str, str] = {}
    for group_name, node_ids in _raw_id_groups(chain):
        seen_within: set[str] = set()
        for node_id in node_ids:
            if node_id in seen_within:
                _problem(
                    problems,
                    f"duplicate {group_name} id within its collection: {node_id}",
                )
                continue
            seen_within.add(node_id)
            if node_id in seen_across:
                _problem(
                    problems,
                    f"duplicate id across collections: {node_id}",
                )
                continue
            seen_across[node_id] = group_name
    if chain.policy_risk is not None:
        pr_id = chain.policy_risk.policy_risk_id
        if pr_id in seen_across:
            _problem(problems, f"duplicate id across collections: {pr_id}")
        else:
            seen_across[pr_id] = "policy_risk"
    ana_id = chain.analysis.analysis_id
    if ana_id in seen_across:
        _problem(problems, f"duplicate id across collections: {ana_id}")


# ─────────────────────────────────────────────────────────────────────────────
#  ID shapes
# ─────────────────────────────────────────────────────────────────────────────


def _check_id_shapes(
    chain: ChainOfProof,
    index: ChainIndex,
    problems: list[str],
) -> None:
    shape_patterns = {
        "capture_id": (index.captures, PREFIX_CAPTURE),
        "session_id": (index.sessions, PREFIX_SESSION),
        "evidence_id": (index.evidence, PREFIX_EVIDENCE),
        "event_id": (index.events, PREFIX_PROTOCOL_EVENT),
        "observation_id": (index.observations, PREFIX_CRYPTO_OBSERVATION),
        "fact_id": (index.facts, PREFIX_FACT),
        "evaluation_id": (index.evaluations, PREFIX_RULE_EVALUATION),
        "finding_id": (index.findings, PREFIX_FINDING),
        "anomaly_result_id": (index.anomalies, PREFIX_ANOMALY),
        "artifact_manifest_id": (index.artifacts, PREFIX_ARTIFACT),
    }
    for label, (collection, prefix) in shape_patterns.items():
        for node_id in collection:
            _fits_pattern(problems, node_id, COMPACT_ID_PATTERN[prefix], label)
    if chain.policy_risk is not None:
        _fits_pattern(
            problems,
            chain.policy_risk.policy_risk_id,
            COMPACT_ID_PATTERN[PREFIX_POLICY_RISK],
            "policy_risk_id",
        )
        for contribution in index.contributions:
            _fits_pattern(
                problems,
                contribution.contribution_id,
                COMPACT_ID_PATTERN[PREFIX_POLICY_CONTRIBUTION],
                "contribution_id",
            )
    for recommendation in index.recommendations.values():
        if not is_recommendation_id(recommendation.recommendation_id):
            _problem(
                problems,
                f"recommendation has disallowed id shape: {recommendation.recommendation_id!r}",
            )


# ─────────────────────────────────────────────────────────────────────────────
#  Analysis / version / timeline (spec §4.1, §16)
# ─────────────────────────────────────────────────────────────────────────────


def _check_analysis_constraints(
    chain: ChainOfProof,
    index: ChainIndex,
    problems: list[str],
) -> None:
    if chain.chain_schema_version != chain.analysis.chain_schema_version:
        _problem(
            problems,
            "root chain_schema_version does not equal analysis.chain_schema_version",
        )
    created = chain.analysis.created_at
    started = chain.analysis.started_at
    completed = chain.analysis.completed_at
    if started < created:
        _problem(problems, "analysis.started_at is before analysis.created_at")
    if completed is not None:
        if completed < started:
            _problem(problems, "analysis.completed_at is before analysis.started_at")
        if completed < created:
            _problem(problems, "analysis.completed_at is before analysis.created_at")


# ─────────────────────────────────────────────────────────────────────────────
#  Reproducible deterministic IDs (spec §4, §12)
# ─────────────────────────────────────────────────────────────────────────────


def _check_reproducible_ids(
    chain: ChainOfProof,
    index: ChainIndex,
    problems: list[str],
) -> None:
    schema_version = chain.analysis.chain_schema_version
    if len(chain.captures) == 1:
        capture = chain.captures[0]
        expected_ana = analysis_id(
            schema_version,
            capture.sha256,
            chain.analysis.configuration_digest,
            chain.analysis.analyzer_version,
            chain.analysis.rule_pack_id,
            chain.analysis.rule_pack_version,
            chain.analysis.model_id,
            chain.analysis.model_version,
        )
        if chain.analysis.analysis_id != expected_ana:
            _problem(
                problems,
                "analysis_id is not reproducible from capture and versioned inputs "
                f"(expected {expected_ana})",
            )
            return

    for capture in chain.captures:
        expected = capture_id_from_sha256(capture.sha256)
        if capture.capture_id != expected:
            _problem(
                problems,
                f"capture {capture.capture_id}: capture_id not derived from its sha256",
            )

    for session in index.sessions.values():
        capture = index.captures.get(session.capture_id)
        if capture is None:
            continue
        expected_key = session_stable_key(
            schema_version,
            capture.sha256,
            session.tcp_stream_id,
            session.source_endpoint.ip,
            session.source_endpoint.port,
            session.destination_endpoint.ip,
            session.destination_endpoint.port,
        )
        if session.stable_session_key != expected_key:
            _problem(
                problems,
                f"session {session.session_id}: stable_session_key not reproducible "
                f"(expected {expected_key})",
            )
        if session.session_id != session_id_from_key(session.stable_session_key):
            _problem(
                problems,
                f"session {session.session_id}: session_id not derived from its stable key",
            )

    for evidence in index.evidence.values():
        expected = evidence_id(
            evidence.capture_id,
            evidence.session_id,
            evidence.source_kind.value,
            evidence.source_field,
            evidence.normalized_value,
            evidence.frame_numbers,
            evidence.direction.value,
            evidence.occurrence_index,
        )
        if evidence.evidence_id != expected:
            _problem(
                problems,
                f"evidence {evidence.evidence_id}: evidence_id not reproducible "
                f"(expected {expected})",
            )

    for event in index.events.values():
        expected = protocol_event_id(event.session_id, event.sequence_index, event.event_type.value)
        if event.event_id != expected:
            _problem(
                problems,
                f"event {event.event_id}: event_id not reproducible (expected {expected})",
            )

    for observation in index.observations.values():
        expected = crypto_observation_id(
            observation.session_id,
            observation.kind.value,
            observation.normalized_value,
        )
        if observation.observation_id != expected:
            _problem(
                problems,
                f"observation {observation.observation_id}: "
                f"observation_id not reproducible (expected {expected})",
            )

    for evaluation in index.evaluations.values():
        expected = rule_evaluation_id(
            evaluation.session_id,
            evaluation.rule_id,
            evaluation.rule_version,
            evaluation.profile_id,
        )
        if evaluation.evaluation_id != expected:
            _problem(
                problems,
                f"evaluation {evaluation.evaluation_id}: "
                f"evaluation_id not reproducible (expected {expected})",
            )

    for anomaly in index.anomalies.values():
        expected = anomaly_result_id(
            anomaly.session_id,
            anomaly.model_id,
            anomaly.model_version,
            anomaly.feature_schema_version,
        )
        if anomaly.anomaly_result_id != expected:
            _problem(
                problems,
                f"anomaly {anomaly.anomaly_result_id}: "
                f"anomaly_result_id not reproducible (expected {expected})",
            )

    if chain.policy_risk is not None:
        expected = policy_risk_id(index.analysis_id, chain.policy_risk.profile_id)
        if chain.policy_risk.policy_risk_id != expected:
            _problem(
                problems,
                f"policy_risk {chain.policy_risk.policy_risk_id}: "
                f"policy_risk_id not reproducible (expected {expected})",
            )
        for contribution in chain.policy_risk.contributions:
            expected_c = policy_contribution_id(
                contribution.finding_id,
                contribution.rule_id,
                contribution.rule_version,
            )
            if contribution.contribution_id != expected_c:
                _problem(
                    problems,
                    f"contribution {contribution.contribution_id}: "
                    f"contribution_id not reproducible (expected {expected_c})",
                )

    for artifact in index.artifacts.values():
        expected = artifact_manifest_id(index.analysis_id, artifact.canonical_json_sha256)
        if artifact.artifact_manifest_id != expected:
            _problem(
                problems,
                f"artifact {artifact.artifact_manifest_id}: "
                f"artifact_manifest_id not reproducible (expected {expected})",
            )


def _check_session_capture_links(
    chain: ChainOfProof,
    index: ChainIndex,
    problems: list[str],
) -> None:
    for session in index.sessions.values():
        capture = index.captures.get(session.capture_id)
        if capture is None:
            _problem(
                problems,
                f"session {session.session_id}: missing capture {session.capture_id}",
            )
            continue
        if session.started_at > session.ended_at:
            _problem(
                problems,
                f"session {session.session_id}: started_at after ended_at",
            )
        if capture.captured_at_start is not None and capture.captured_at_end is not None:
            if capture.captured_at_end < capture.captured_at_start:
                _problem(
                    problems,
                    f"capture {capture.capture_id}: captured_at_end before captured_at_start",
                )
            if capture.captured_at_start > session.started_at:
                _problem(
                    problems,
                    f"session {session.session_id}: starts before its capture",
                )
            if capture.captured_at_end < session.ended_at:
                _problem(
                    problems,
                    f"session {session.session_id}: ends after its capture",
                )


def _check_evidence_integrity(
    chain: ChainOfProof,
    index: ChainIndex,
    problems: list[str],
) -> None:
    for evidence in index.evidence.values():
        capture = index.captures.get(evidence.capture_id)
        if capture is None:
            _problem(
                problems,
                f"evidence {evidence.evidence_id}: missing capture {evidence.capture_id}",
            )
            continue
        if evidence.capture_sha256 != capture.sha256:
            _problem(
                problems,
                f"evidence {evidence.evidence_id}: capture_sha256 does not match its capture",
            )
        session = index.sessions.get(evidence.session_id)
        if session is None:
            _problem(
                problems,
                f"evidence {evidence.evidence_id}: missing session {evidence.session_id}",
            )
            continue
        if evidence.capture_id != session.capture_id:
            _problem(
                problems,
                f"evidence {evidence.evidence_id}: capture/session mismatch "
                f"(evidence capture {evidence.capture_id} != session capture "
                f"{session.capture_id})",
            )
        lowest = min(evidence.frame_numbers)
        highest = max(evidence.frame_numbers)
        if lowest < session.first_frame or highest > session.last_frame:
            _problem(
                problems,
                f"evidence {evidence.evidence_id}: frames outside session frame range",
            )
        if evidence.timestamp_start > evidence.timestamp_end:
            _problem(
                problems,
                f"evidence {evidence.evidence_id}: timestamp_start after timestamp_end",
            )
        if (
            session.started_at is not None
            and session.ended_at is not None
            and (
                evidence.timestamp_start < session.started_at
                or evidence.timestamp_end > session.ended_at
            )
        ):
            _problem(
                problems,
                f"evidence {evidence.evidence_id}: timestamps outside session window",
            )
        if capture.captured_at_start is not None and capture.captured_at_end is not None:
            if (
                evidence.timestamp_start < capture.captured_at_start
                or evidence.timestamp_end > capture.captured_at_end
            ):
                _problem(
                    problems,
                    f"evidence {evidence.evidence_id}: timestamps outside capture window",
                )


def _check_node_session_references(
    chain: ChainOfProof,
    index: ChainIndex,
    problems: list[str],
) -> None:
    def require_session(node_id: str, session_id: str, label: str) -> None:
        if session_id not in index.sessions:
            _problem(problems, f"{label} {node_id}: missing session {session_id}")

    for event in index.events.values():
        require_session(event.event_id, event.session_id, "event")
        session = index.sessions.get(event.session_id)
        if session is not None:
            if (
                session.started_at is not None
                and session.ended_at is not None
                and (event.timestamp < session.started_at or event.timestamp > session.ended_at)
            ):
                _problem(
                    problems,
                    f"event {event.event_id}: timestamp outside session window",
                )
    for observation in index.observations.values():
        require_session(observation.observation_id, observation.session_id, "observation")
    for fact in index.facts.values():
        require_session(fact.fact_id, fact.session_id, "fact")
    for evaluation in index.evaluations.values():
        require_session(evaluation.evaluation_id, evaluation.session_id, "evaluation")
    for finding in index.findings.values():
        require_session(finding.finding_id, finding.session_id, "finding")
        if finding.analysis_id != index.analysis_id:
            _problem(
                problems,
                f"finding {finding.finding_id}: analysis_id does not match manifest",
            )
    for anomaly in index.anomalies.values():
        require_session(anomaly.anomaly_result_id, anomaly.session_id, "anomaly")

    facts = index.facts
    for evaluation in index.evaluations.values():
        for fact_id in evaluation.input_fact_ids:
            fact = facts.get(fact_id)
            if fact is None:
                _problem(
                    problems,
                    f"evaluation {evaluation.evaluation_id}: missing input fact {fact_id}",
                )
            elif fact.session_id != evaluation.session_id:
                _problem(
                    problems,
                    f"evaluation {evaluation.evaluation_id}: input fact from another session",
                )
        if evaluation.outcome is RuleOutcome.MATCHED and evaluation.generated_finding_id is None:
            _problem(
                problems,
                f"evaluation {evaluation.evaluation_id}: matched outcome without a finding",
            )
        elif (
            evaluation.outcome is not RuleOutcome.MATCHED
            and evaluation.generated_finding_id is not None
        ):
            _problem(
                problems,
                f"evaluation {evaluation.evaluation_id}: finding generated for non-matched outcome",
            )

    for finding in index.findings.values():
        evaluation = index.evaluations.get(finding.rule_evaluation_id)
        if evaluation is None:
            _problem(
                problems,
                f"finding {finding.finding_id}: missing rule evaluation "
                f"{finding.rule_evaluation_id}",
            )
            continue
        if evaluation.outcome is not RuleOutcome.MATCHED:
            _problem(problems, f"finding {finding.finding_id}: evaluation did not match")
        if evaluation.generated_finding_id != finding.finding_id:
            _problem(
                problems,
                f"finding {finding.finding_id}: evaluation PRODUCED link is not bidirectional",
            )
        if evaluation.rule_id != finding.rule_id or evaluation.rule_version != finding.rule_version:
            _problem(
                problems,
                f"finding {finding.finding_id}: rule identity mismatch with evaluation",
            )
        if finding.session_id != evaluation.session_id:
            _problem(problems, f"finding {finding.finding_id}: session mismatch with evaluation")
        if not set(finding.fact_ids).issubset(set(evaluation.input_fact_ids)):
            _problem(problems, f"finding {finding.finding_id}: fact_ids exceed evaluation inputs")
        for fact_id in finding.fact_ids:
            fact = facts.get(fact_id)
            if fact is None:
                _problem(problems, f"finding {finding.finding_id}: missing fact {fact_id}")
            elif fact.session_id != finding.session_id:
                _problem(
                    problems,
                    f"finding {finding.finding_id}: fact from another session",
                )


def _check_evidence_references(
    chain: ChainOfProof,
    index: ChainIndex,
    problems: list[str],
) -> None:
    def inspect(owner: str, session_id: str, evidence_ids: list[str]) -> None:
        for evidence_id_value in evidence_ids:
            evidence = index.evidence.get(evidence_id_value)
            if evidence is None:
                _problem(problems, f"{owner}: missing evidence {evidence_id_value}")
            elif evidence.session_id != session_id:
                _problem(
                    problems,
                    f"{owner}: evidence from another session ({evidence_id_value})",
                )

    for event in index.events.values():
        inspect(f"event {event.event_id}", event.session_id, event.evidence_ids)
    for observation in index.observations.values():
        inspect(
            f"observation {observation.observation_id}",
            observation.session_id,
            observation.evidence_ids,
        )
    for finding in index.findings.values():
        inspect(f"finding {finding.finding_id}", finding.session_id, finding.evidence_ids)
    for anomaly in index.anomalies.values():
        inspect(
            f"anomaly {anomaly.anomaly_result_id}",
            anomaly.session_id,
            anomaly.evidence_ids,
        )


def _check_evidence_backing(
    chain: ChainOfProof,
    index: ChainIndex,
    problems: list[str],
) -> None:
    """Observed material events and observed crypto observations must be backed.

    Encodes spec §3 invariant 2 and §9: every observed material protocol event
    and every observed crypto observation must reference resolvable evidence,
    so derived-fact lineage terminates in evidence-backed nodes.
    """
    for event in index.events.values():
        if (
            event.event_type in _MATERIAL_EVENTS
            and event.observability is ChainObservability.OBSERVED
            and not event.evidence_ids
        ):
            _problem(
                problems,
                f"event {event.event_id}: observed material event "
                f"{event.event_type.value} without evidence",
            )
        if (
            event.event_status is EventStatus.OBSERVED
            and event.observability is not ChainObservability.OBSERVED
        ):
            _problem(
                problems,
                f"event {event.event_id}: observed event status conflicts with observability",
            )
        if (
            event.event_status is EventStatus.INFERRED
            and event.observability is ChainObservability.OBSERVED
        ):
            _problem(
                problems, f"event {event.event_id}: inferred event cannot be directly observed"
            )
        if (
            event.event_status is EventStatus.INCOMPLETE_CAPTURE
            and event.observability is not ChainObservability.INCOMPLETE_CAPTURE
        ):
            _problem(
                problems,
                f"event {event.event_id}: incomplete event status conflicts with observability",
            )
        if (
            event.event_status is EventStatus.NOT_OBSERVABLE
            and event.observability is ChainObservability.OBSERVED
        ):
            _problem(
                problems,
                f"event {event.event_id}: not-observable status conflicts with observability",
            )
    for observation in index.observations.values():
        if (
            observation.observability is ChainObservability.OBSERVED
            and not observation.evidence_ids
        ):
            _problem(
                problems,
                f"observation {observation.observation_id}: observed crypto observation "
                "without evidence",
            )


def _check_event_ordering(
    chain: ChainOfProof,
    index: ChainIndex,
    problems: list[str],
) -> None:
    by_session: dict[str, list[ProtocolEvent]] = {}
    for event in index.events.values():
        by_session.setdefault(event.session_id, []).append(event)
    for session_id, events in by_session.items():
        ordered = sorted(events, key=lambda e: e.sequence_index)
        for position, event in enumerate(ordered):
            if event.sequence_index != position:
                _problem(
                    problems,
                    f"session {session_id}: sequence_index not contiguous monotonic "
                    f"(expected {position}, got {event.sequence_index})",
                )
        if len(ordered) > 1:
            for previous, current in zip(ordered, ordered[1:], strict=False):
                if current.timestamp < previous.timestamp:
                    _problem(
                        problems,
                        f"session {session_id}: event timestamps not nondecreasing",
                    )


def _check_classification(
    chain: ChainOfProof,
    index: ChainIndex,
    problems: list[str],
) -> None:
    for session in index.sessions.values():
        if session.protocol is Protocol.UNKNOWN:
            for cls_id in session.classification_evidence_ids:
                evidence = index.evidence.get(cls_id)
                if evidence is None:
                    _problem(
                        problems,
                        f"session {session.session_id}: missing classification evidence {cls_id}",
                    )
                elif (
                    evidence.session_id != session.session_id
                    or evidence.capture_id != session.capture_id
                ):
                    _problem(
                        problems,
                        f"session {session.session_id}: classification evidence is outside "
                        "its session/capture",
                    )
            continue
        if not session.classification_evidence_ids:
            _problem(
                problems,
                f"session {session.session_id}: classified without evidence",
            )
            continue
        content_based = 0
        for cls_id in session.classification_evidence_ids:
            evidence = index.evidence.get(cls_id)
            if evidence is None:
                _problem(
                    problems,
                    f"session {session.session_id}: missing classification evidence {cls_id}",
                )
                continue
            if (
                evidence.session_id != session.session_id
                or evidence.capture_id != session.capture_id
            ):
                _problem(
                    problems,
                    f"session {session.session_id}: classification evidence is outside "
                    "its session/capture",
                )
                continue
            if evidence.source_field in _PORT_ONLY_FIELDS:
                continue
            if evidence.source_kind in _CONTENT_SOURCE_KINDS:
                content_based += 1
        if content_based == 0:
            _problem(
                problems,
                f"session {session.session_id}: classification relies only on port/service "
                "metadata",
            )


def _check_fact_sources(
    chain: ChainOfProof,
    index: ChainIndex,
    problems: list[str],
) -> None:
    facts = index.facts
    for fact in facts.values():
        source_count = (
            len(fact.source_event_ids)
            + len(fact.source_observation_ids)
            + len(fact.source_fact_ids)
        )
        if source_count == 0:
            _problem(problems, f"fact {fact.fact_id}: has no source events/observations/facts")
            continue
        for event_id in fact.source_event_ids:
            event = index.events.get(event_id)
            if event is None:
                _problem(problems, f"fact {fact.fact_id}: missing source event {event_id}")
            elif event.session_id != fact.session_id:
                _problem(problems, f"fact {fact.fact_id}: source event from another session")
        for observation_id in fact.source_observation_ids:
            observation = index.observations.get(observation_id)
            if observation is None:
                _problem(
                    problems,
                    f"fact {fact.fact_id}: missing source observation {observation_id}",
                )
            elif observation.session_id != fact.session_id:
                _problem(
                    problems,
                    f"fact {fact.fact_id}: source observation from another session",
                )
        for source_fact_id in fact.source_fact_ids:
            if source_fact_id not in facts:
                _problem(problems, f"fact {fact.fact_id}: missing source fact {source_fact_id}")
            elif facts[source_fact_id].session_id != fact.session_id:
                _problem(
                    problems,
                    f"fact {fact.fact_id}: source fact from another session",
                )

    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(fact_id: str, trail: set[str]) -> None:
        if fact_id in visiting:
            _problem(problems, f"fact derivation cycle detected involving {fact_id}")
            return
        if fact_id in visited:
            return
        visiting.add(fact_id)
        trail.add(fact_id)
        fact = facts.get(fact_id)
        if fact is not None:
            for source_fact_id in fact.source_fact_ids:
                if source_fact_id in trail:
                    _problem(
                        problems,
                        f"fact derivation cycle detected: {' -> '.join(trail)} -> {source_fact_id}",
                    )
                    continue
                visit(source_fact_id, set(trail))
        visiting.discard(fact_id)
        visited.add(fact_id)

    for fact_id in facts:
        visit(fact_id, set())


def _check_fact_identities(
    chain: ChainOfProof,
    index: ChainIndex,
    problems: list[str],
) -> None:
    schema_version = chain.analysis.chain_schema_version
    for fact in index.facts.values():
        session = index.sessions.get(fact.session_id)
        if session is None:
            continue
        normalized = canonical_json(fact.value)
        expected_key = fact_stable_key(
            schema_version,
            session.stable_session_key,
            fact.fact_type,
            normalized,
            fact.source_event_ids,
            fact.source_observation_ids,
            fact.source_fact_ids,
        )
        if fact.fact_id != fact_id_from_key(expected_key):
            _problem(
                problems,
                f"fact {fact.fact_id}: fact_id not reproducible from its content",
            )


def _check_observability_reasons(
    chain: ChainOfProof,
    index: ChainIndex,
    problems: list[str],
) -> None:
    for event in index.events.values():
        if event.observability in _UNOBSERVABLE_STATE and not _has_limitation(
            event.limitations, observability=event.observability
        ):
            _problem(
                problems,
                f"event {event.event_id}: {event.observability.value} without limitation",
            )
    for observation in index.observations.values():
        if observation.observability in _UNOBSERVABLE_STATE and not _has_limitation(
            observation.limitations, observability=observation.observability
        ):
            _problem(
                problems,
                f"observation {observation.observation_id}: "
                f"{observation.observability.value} without limitation",
            )
    for fact in index.facts.values():
        if fact.observability in _UNOBSERVABLE_STATE and not _has_limitation(
            fact.limitations, observability=fact.observability
        ):
            _problem(
                problems,
                f"fact {fact.fact_id}: {fact.observability.value} without limitation",
            )
        if not fact.confidence_basis:
            _problem(problems, f"fact {fact.fact_id}: confidence without a basis")
    for evidence in index.evidence.values():
        if evidence.observability is not ChainObservability.OBSERVED:
            _problem(
                problems,
                f"evidence {evidence.evidence_id}: must be directly observed "
                f"(got {evidence.observability.value})",
            )


def _has_limitation(limitations: list, observability: ChainObservability) -> bool:
    if not limitations:
        return False
    if observability is ChainObservability.SESSION_SECRETS_REQUIRED:
        return any(item.code is LimitationCode.SESSION_SECRETS_REQUIRED for item in limitations)
    return True


def _check_tls13_certificates(
    chain: ChainOfProof,
    index: ChainIndex,
    problems: list[str],
) -> None:
    secrets_status = chain.analysis.tls13_authorized_secrets
    tls13_sessions: set[str] = set()
    for observation in index.observations.values():
        if observation.kind is ObservationKind.TLS_NEGOTIATED_VERSION:
            if observation.normalized_value == "TLS_1_3":
                tls13_sessions.add(observation.session_id)
    secrets_supplied = secrets_status is Tls13SecretsStatus.AUTHORIZED_SUPPLIED
    unavailable_sessions = {
        observation.session_id
        for observation in index.observations.values()
        if observation.kind is ObservationKind.TLS13_CERTIFICATE_UNAVAILABLE
    }
    if tls13_sessions and not secrets_supplied:
        for session_id in tls13_sessions:
            if session_id not in unavailable_sessions:
                _problem(
                    problems,
                    f"TLS 1.3 session {session_id}: missing explicit "
                    "certificate-unavailable observation",
                )
    for observation in index.observations.values():
        if observation.kind not in _CERTIFICATE_KINDS:
            continue
        if observation.kind is ObservationKind.TLS13_CERTIFICATE_UNAVAILABLE:
            _check_tls13_unavailable(observation, tls13_sessions, problems)
            continue
        if observation.session_id not in tls13_sessions:
            continue
        if not secrets_supplied:
            _check_tls13_unavailable_cert_field(observation, problems)
        elif (
            observation.observability is ChainObservability.OBSERVED
            and not observation.evidence_ids
        ):
            _problem(
                problems,
                f"observation {observation.observation_id}: TLS 1.3 certificate observation "
                "requires actual evidence",
            )


def _check_tls13_unavailable_cert_field(
    observation: CryptoObservation,
    problems: list[str],
) -> None:
    """Validate an explicitly unavailable TLS 1.3 certificate-field observation
    when no authorized session secrets were supplied.

    Only ``session_secrets_required`` and ``not_observable`` are honest states
    here. Every other observability state (observed, derived, policy_inferred,
    incomplete_capture, not_applicable, ...) asserts or fabricates certificate
    content and must fail. An unavailable observation must carry the typed
    ``session_secrets_required`` limitation and a deterministic neutral value,
    never an actual certificate claim.
    """
    if observation.observability in _CERTIFICATE_CLAIMING_STATES:
        _problem(
            problems,
            f"observation {observation.observation_id}: certificate claim on "
            "TLS 1.3 session without authorized session secrets is fabricated",
        )
        return
    neutral = _TLS13_NEUTRAL_CERT_VALUES.get(observation.observability)
    if neutral is None:
        _problem(
            problems,
            f"observation {observation.observation_id}: disallowed state "
            f"{observation.observability.value} on a TLS 1.3 certificate field "
            "without authorized session secrets",
        )
        return
    if not _has_limitation(observation.limitations, ChainObservability.SESSION_SECRETS_REQUIRED):
        _problem(
            problems,
            f"observation {observation.observation_id}: unavailable TLS 1.3 "
            "certificate observation requires a session_secrets_required limitation",
        )
    if observation.normalized_value != neutral:
        _problem(
            problems,
            f"observation {observation.observation_id}: unavailable TLS 1.3 "
            "certificate observation must use deterministic neutral normalized "
            f"value {neutral!r}",
        )
    if observation.value is not None and observation.value != neutral:
        _problem(
            problems,
            f"observation {observation.observation_id}: unavailable TLS 1.3 "
            "certificate observation must not carry actual certificate content",
        )


def _check_tls13_unavailable(
    observation: CryptoObservation,
    tls13_sessions: set[str],
    problems: list[str],
) -> None:
    if observation.session_id not in tls13_sessions:
        _problem(
            problems,
            f"observation {observation.observation_id}: TLS 1.3 certificate-unavailable "
            "sentinel on a non-TLS 1.3 session",
        )
    if observation.observability not in {
        ChainObservability.SESSION_SECRETS_REQUIRED,
        ChainObservability.NOT_OBSERVABLE,
    }:
        _problem(
            problems,
            f"observation {observation.observation_id}: TLS 1.3 unobservable certificate "
            "must be session_secrets_required/not_observable",
        )
    if not any(
        item.code is LimitationCode.SESSION_SECRETS_REQUIRED for item in observation.limitations
    ):
        _problem(
            problems,
            f"observation {observation.observation_id}: missing session_secrets_required "
            "limitation",
        )
    if observation.normalized_value != _TLS13_UNAVAILABLE_NEUTRAL:
        _problem(
            problems,
            f"observation {observation.observation_id}: TLS 1.3 certificate-unavailable "
            "sentinel normalized_value must equal the frozen neutral "
            f"{_TLS13_UNAVAILABLE_NEUTRAL!r}",
        )
    if observation.value is not None and observation.value != _TLS13_UNAVAILABLE_NEUTRAL:
        _problem(
            problems,
            f"observation {observation.observation_id}: TLS 1.3 certificate-unavailable "
            "sentinel must not carry actual certificate content",
        )


def _check_rule_findings(
    chain: ChainOfProof,
    index: ChainIndex,
    problems: list[str],
) -> None:
    schema_version = chain.analysis.chain_schema_version
    findings = index.findings
    for finding in findings.values():
        if finding.observability is not ChainObservability.POLICY_INFERRED:
            _problem(
                problems,
                f"finding {finding.finding_id}: findings must be policy_inferred",
            )
        session = index.sessions.get(finding.session_id)
        evaluation = index.evaluations.get(finding.rule_evaluation_id)
        if session is None or evaluation is None:
            continue
        expected_key = finding_stable_key(
            schema_version,
            session.stable_session_key,
            finding.rule_id,
            finding.rule_version,
            sorted(finding.fact_ids),
        )
        if finding.stable_finding_key != expected_key:
            _problem(
                problems,
                f"finding {finding.finding_id}: stable_finding_key not reproducible "
                f"(expected {expected_key})",
            )
        if finding.finding_id != finding_id_from_key(finding.stable_finding_key):
            _problem(
                problems,
                f"finding {finding.finding_id}: finding_id not derived from its stable key",
            )


def _check_recommendations(
    chain: ChainOfProof,
    index: ChainIndex,
    problems: list[str],
) -> None:
    finding_reference_counts: dict[str, int] = {}
    for finding in index.findings.values():
        if finding.recommendation_id not in index.recommendations:
            _problem(
                problems,
                f"finding {finding.finding_id}: missing recommendation {finding.recommendation_id}",
            )
            continue
        finding_reference_counts[finding.recommendation_id] = (
            finding_reference_counts.get(finding.recommendation_id, 0) + 1
        )
    for recommendation in index.recommendations.values():
        if recommendation.recommendation_id not in finding_reference_counts:
            _problem(
                problems,
                f"recommendation {recommendation.recommendation_id}: orphan recommendation "
                "(not referenced by any finding)",
            )
        for finding_id in recommendation.affected_finding_ids:
            finding = index.findings.get(finding_id)
            if finding is None:
                _problem(
                    problems,
                    f"recommendation {recommendation.recommendation_id}: "
                    f"missing affected finding {finding_id}",
                )
            elif finding.recommendation_id != recommendation.recommendation_id:
                _problem(
                    problems,
                    f"recommendation {recommendation.recommendation_id}: "
                    "REMEDIATED_BY link is not bidirectional",
                )
    for finding in index.findings.values():
        recommendation = index.recommendations.get(finding.recommendation_id)
        if (
            recommendation is not None
            and finding.finding_id not in recommendation.affected_finding_ids
        ):
            _problem(
                problems,
                f"finding {finding.finding_id}: recommendation link is not bidirectional",
            )


def _check_artifacts(
    chain: ChainOfProof,
    index: ChainIndex,
    problems: list[str],
) -> None:
    capture_sha256s = {capture.sha256 for capture in index.captures.values()}
    expected_hash = canonical_content_hash(chain)
    for artifact in index.artifacts.values():
        if artifact.analysis_id != index.analysis_id:
            _problem(
                problems,
                f"artifact {artifact.artifact_manifest_id}: analysis_id does not match manifest",
            )
        if artifact.capture_sha256 not in capture_sha256s:
            _problem(
                problems,
                f"artifact {artifact.artifact_manifest_id}: capture_sha256 not present in chain",
            )
        if artifact.canonical_json_sha256 != expected_hash:
            _problem(
                problems,
                f"artifact {artifact.artifact_manifest_id}: canonical_json_sha256 does not "
                "match the reproducible canonical content",
            )


def _check_policy_risk(
    chain: ChainOfProof,
    index: ChainIndex,
    problems: list[str],
) -> None:
    rule_status = chain.analysis.rule_engine_status
    ml_status = chain.analysis.ml_engine_status
    if rule_status is EngineStatus.COMPLETE:
        if chain.policy_risk is None:
            _problem(problems, "policy risk missing although rule engine completed")
            return
        # 1. Every finding has exactly one contribution
        finding_to_contrib: dict[str, list[PolicyRiskContribution]] = {}
        for contrib in chain.policy_risk.contributions:
            finding_to_contrib.setdefault(contrib.finding_id, []).append(contrib)

        for finding in index.findings.values():
            contribs = finding_to_contrib.get(finding.finding_id, [])
            if len(contribs) != 1:
                _problem(
                    problems,
                    f"finding {finding.finding_id}: has {len(contribs)} contributions, "
                    "expected exactly 1",
                )
            else:
                contrib = contribs[0]
                # Contribution matches finding
                if (
                    contrib.rule_id != finding.rule_id
                    or contrib.rule_version != finding.rule_version
                    or finding.severity is not contrib.severity
                    or finding.evidence_confidence is not contrib.evidence_confidence
                    or finding.policy_risk_contribution != contrib.policy_risk_contribution
                ):
                    _problem(
                        problems,
                        f"contribution {contrib.contribution_id}: does not match its finding",
                    )
                # Evaluation matches
                evaluation = index.evaluations.get(finding.rule_evaluation_id)
                if evaluation is None or (
                    evaluation.rule_id != contrib.rule_id
                    or evaluation.rule_version != contrib.rule_version
                    or evaluation.session_id != finding.session_id
                ):
                    _problem(
                        problems,
                        f"contribution {contrib.contribution_id}: rule identity does not "
                        "match its evaluation",
                    )

        # 2. No contribution without finding
        for contrib in chain.policy_risk.contributions:
            if contrib.finding_id not in index.findings:
                _problem(
                    problems,
                    f"contribution {contrib.contribution_id}: missing finding {contrib.finding_id}",
                )

        # 3. Matched evaluation's generated_finding_id resolves
        for evaluation in index.evaluations.values():
            if evaluation.outcome is RuleOutcome.MATCHED:
                if not evaluation.generated_finding_id:
                    _problem(
                        problems,
                        f"evaluation {evaluation.evaluation_id}: matched outcome without "
                        "generated_finding_id",
                    )
                elif evaluation.generated_finding_id not in index.findings:
                    _problem(
                        problems,
                        f"evaluation {evaluation.evaluation_id}: generated_finding_id "
                        f"{evaluation.generated_finding_id} does not resolve",
                    )
                else:
                    finding = index.findings[evaluation.generated_finding_id]
                    if finding.rule_evaluation_id != evaluation.evaluation_id:
                        _problem(
                            problems,
                            f"evaluation {evaluation.evaluation_id}: finding link is not "
                            "bidirectional",
                        )

        # 4. All evaluations use policy_risk.profile_id
        expected_profile = chain.policy_risk.profile_id
        for evaluation in index.evaluations.values():
            if evaluation.profile_id != expected_profile:
                _problem(
                    problems,
                    f"evaluation {evaluation.evaluation_id}: profile_id "
                    f"{evaluation.profile_id} does not match policy_risk.profile_id "
                    f"{expected_profile}",
                )

        # 5. uncapped_score equals sum of adjusted points
        expected_uncapped = sum(
            contribution.confidence_adjusted_points
            for contribution in chain.policy_risk.contributions
        )
        if chain.policy_risk.uncapped_score != expected_uncapped:
            _problem(
                problems,
                f"policy_risk uncapped_score {chain.policy_risk.uncapped_score} != "
                f"sum of contributions {expected_uncapped}",
            )

        # 6. capped_score <= uncapped_score
        if chain.policy_risk.capped_score > chain.policy_risk.uncapped_score:
            _problem(
                problems,
                f"policy_risk capped_score {chain.policy_risk.capped_score} > "
                f"uncapped_score {chain.policy_risk.uncapped_score}",
            )

        # 7. capped_score <= POLICY_RISK_CAP
        if chain.policy_risk.capped_score > POLICY_RISK_CAP:
            _problem(
                problems,
                f"policy_risk capped_score {chain.policy_risk.capped_score} > "
                f"POLICY_RISK_CAP {POLICY_RISK_CAP}",
            )

        if chain.policy_risk.analysis_id != index.analysis_id:
            _problem(problems, "policy risk analysis_id does not match manifest")
    elif rule_status is EngineStatus.NOT_RUN:
        if chain.policy_risk is not None:
            _problem(problems, "policy risk present although rule engine did not run")
        if chain.rule_evaluations or chain.findings or chain.recommendations:
            _problem(problems, "rule-engine output present although rule engine did not run")
    # PARTIAL / FAILED / UNAVAILABLE: policy risk may be present or absent.

    if ml_status is EngineStatus.COMPLETE:
        if not chain.anomaly_results:
            _problem(problems, "anomaly results missing although ml engine completed")
    elif ml_status is EngineStatus.NOT_RUN:
        if chain.anomaly_results:
            _problem(problems, "anomaly results present although ml engine did not run")


def _check_anomaly_links(
    chain: ChainOfProof,
    index: ChainIndex,
    problems: list[str],
) -> None:
    """Anomaly results must resolve their linked facts/observations, keep them
    within the anomaly's own session, and cite at least one feature link.

    Kept separate from policy risk so the deterministic rule path never
    references the ML anomaly graph (§11 separation). Existing evidence-link
    requirements are enforced by :func:`_check_anomaly_separation` and
    :func:`_check_evidence_references`.
    """
    for anomaly in index.anomalies.values():
        anomaly_id = anomaly.anomaly_result_id
        session_id = anomaly.session_id
        for fact_id in anomaly.linked_fact_ids:
            fact = index.facts.get(fact_id)
            if fact is None:
                _problem(problems, f"anomaly {anomaly_id}: missing fact {fact_id}")
            elif fact.session_id != session_id:
                _problem(
                    problems,
                    f"anomaly {anomaly_id}: linked fact from another session ({fact_id})",
                )
        for observation_id in anomaly.linked_observation_ids:
            observation = index.observations.get(observation_id)
            if observation is None:
                _problem(
                    problems,
                    f"anomaly {anomaly_id}: missing linked observation {observation_id}",
                )
            elif observation.session_id != session_id:
                _problem(
                    problems,
                    f"anomaly {anomaly_id}: linked observation from another session "
                    f"({observation_id})",
                )
        if not anomaly.linked_fact_ids and not anomaly.linked_observation_ids:
            _problem(
                problems,
                f"anomaly {anomaly_id}: requires at least one linked fact or linked observation",
            )


def _check_anomaly_separation(
    chain: ChainOfProof,
    index: ChainIndex,
    problems: list[str],
) -> None:
    for anomaly in index.anomalies.values():
        if not anomaly.evidence_ids:
            _problem(
                problems,
                f"anomaly {anomaly.anomaly_result_id}: requires evidence linkage",
            )


def is_not_run(status: EngineStatus) -> bool:
    """True when the engine did not execute (typed, not magic-string)."""
    return status is EngineStatus.NOT_RUN
