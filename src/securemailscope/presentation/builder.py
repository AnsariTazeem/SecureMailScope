"""Lineage-safe projection from a validated Chain-of-Proof to one finding."""

from __future__ import annotations

from collections.abc import Iterable

from securemailscope.chain.errors import (
    ChainErrorCode,
    ChainValidationError,
    PresentationError,
)
from securemailscope.chain.invariants import assert_chain_valid, index_chain
from securemailscope.chain.models import AnalysisLimitation, ChainOfProof
from securemailscope.presentation.models import (
    AnomalyResultPresentation,
    EventPresentation,
    EvidencePresentation,
    FactPresentation,
    FindingPresentation,
    LimitationPresentation,
    MlAnomalyPresentation,
    ObservationPresentation,
    PolicyRiskPresentation,
    RecommendationPresentation,
    StandardPresentation,
)


def _reference_error() -> PresentationError:
    return PresentationError(
        ChainErrorCode.PRESENTATION_REFERENCE_INVALID,
        "selected finding contains an invalid lineage reference",
    )


def _limitation(item: AnalysisLimitation) -> LimitationPresentation:
    return LimitationPresentation.model_validate(item.model_dump(mode="python"))


def _limitations(items: Iterable[AnalysisLimitation]) -> list[LimitationPresentation]:
    unique = {(item.code.value, item.summary, item.detail): _limitation(item) for item in items}
    return [unique[key] for key in sorted(unique)]


def _standards(items) -> list[StandardPresentation]:  # noqa: ANN001
    return [
        StandardPresentation.model_validate(item.model_dump(mode="python"))
        for item in sorted(items, key=lambda value: (value.id, value.section or ""))
    ]


def _build_projection(chain: ChainOfProof, finding_id: str) -> FindingPresentation:
    index = index_chain(chain)
    finding = index.findings.get(finding_id)
    if finding is None:
        raise PresentationError(
            ChainErrorCode.PRESENTATION_FINDING_NOT_FOUND,
            "selected finding does not exist",
        )

    session = index.sessions.get(finding.session_id)
    evaluation = index.evaluations.get(finding.rule_evaluation_id)
    if session is None or evaluation is None:
        raise _reference_error()
    capture = index.captures.get(session.capture_id)
    recommendation = index.recommendations.get(finding.recommendation_id)
    if capture is None or recommendation is None:
        raise _reference_error()
    if (
        finding.analysis_id != chain.analysis.analysis_id
        or evaluation.session_id != finding.session_id
        or evaluation.generated_finding_id != finding.finding_id
        or evaluation.rule_id != finding.rule_id
        or evaluation.rule_version != finding.rule_version
        or finding.finding_id not in recommendation.affected_finding_ids
    ):
        raise _reference_error()

    for input_fact_id in evaluation.input_fact_ids:
        input_fact = index.facts.get(input_fact_id)
        if input_fact is None or input_fact.session_id != finding.session_id:
            raise _reference_error()

    selected_facts: dict[str, object] = {}
    selected_events: dict[str, object] = {}
    selected_observations: dict[str, object] = {}
    selected_evidence: dict[str, object] = {}
    visiting: set[str] = set()

    def add_evidence(evidence_id: str) -> None:
        evidence = index.evidence.get(evidence_id)
        if evidence is None or evidence.session_id != finding.session_id:
            raise _reference_error()
        selected_evidence[evidence_id] = evidence

    def add_fact(fact_id: str) -> None:
        if fact_id in visiting:
            raise _reference_error()
        if fact_id in selected_facts:
            return
        fact = index.facts.get(fact_id)
        if fact is None or fact.session_id != finding.session_id:
            raise _reference_error()
        visiting.add(fact_id)
        for source_fact_id in sorted(set(fact.source_fact_ids)):
            add_fact(source_fact_id)
        for event_id in sorted(set(fact.source_event_ids)):
            event = index.events.get(event_id)
            if event is None or event.session_id != finding.session_id:
                raise _reference_error()
            selected_events[event_id] = event
            for evidence_id in event.evidence_ids:
                add_evidence(evidence_id)
        for observation_id in sorted(set(fact.source_observation_ids)):
            observation = index.observations.get(observation_id)
            if observation is None or observation.session_id != finding.session_id:
                raise _reference_error()
            selected_observations[observation_id] = observation
            for evidence_id in observation.evidence_ids:
                add_evidence(evidence_id)
        visiting.remove(fact_id)
        selected_facts[fact_id] = fact

    for fact_id in sorted(set(finding.fact_ids)):
        add_fact(fact_id)
    for evidence_id in sorted(set(finding.evidence_ids)):
        add_evidence(evidence_id)

    anomalies = []
    for anomaly in sorted(chain.anomaly_results, key=lambda item: item.anomaly_result_id):
        if anomaly.session_id != finding.session_id:
            continue
        for fact_id in anomaly.linked_fact_ids:
            fact = index.facts.get(fact_id)
            if fact is None or fact.session_id != finding.session_id:
                raise _reference_error()
        for observation_id in anomaly.linked_observation_ids:
            observation = index.observations.get(observation_id)
            if observation is None or observation.session_id != finding.session_id:
                raise _reference_error()
        for evidence_id in anomaly.evidence_ids:
            evidence = index.evidence.get(evidence_id)
            if evidence is None or evidence.session_id != finding.session_id:
                raise _reference_error()
        anomaly_data = anomaly.model_dump(mode="python", exclude={"feature_snapshot"})
        anomaly_data["linked_fact_ids"] = sorted(set(anomaly.linked_fact_ids))
        anomaly_data["linked_observation_ids"] = sorted(set(anomaly.linked_observation_ids))
        anomaly_data["evidence_ids"] = sorted(set(anomaly.evidence_ids))
        anomaly_data["unusual_feature_indicators"] = sorted(set(anomaly.unusual_feature_indicators))
        anomaly_data["limitations"] = _limitations(anomaly.limitations)
        anomalies.append(AnomalyResultPresentation.model_validate(anomaly_data))

    facts = []
    for fact_id in sorted(selected_facts):
        fact = selected_facts[fact_id]
        fact_data = fact.model_dump(mode="python")
        fact_data["source_event_ids"] = sorted(set(fact.source_event_ids))
        fact_data["source_observation_ids"] = sorted(set(fact.source_observation_ids))
        fact_data["source_fact_ids"] = sorted(set(fact.source_fact_ids))
        fact_data["confidence_basis"] = sorted(set(fact.confidence_basis))
        fact_data["limitations"] = _limitations(fact.limitations)
        facts.append(FactPresentation.model_validate(fact_data))

    events = []
    for event in sorted(
        selected_events.values(),
        key=lambda item: (item.sequence_index, item.event_id),
    ):
        event_data = event.model_dump(
            mode="python", exclude={"protocol", "state_before", "state_after"}
        )
        event_data["evidence_ids"] = sorted(set(event.evidence_ids))
        event_data["limitations"] = _limitations(event.limitations)
        events.append(EventPresentation.model_validate(event_data))

    observations = []
    for observation_id in sorted(selected_observations):
        observation = selected_observations[observation_id]
        observation_data = observation.model_dump(
            mode="python", exclude={"value", "normalized_value"}
        )
        observation_data["evidence_ids"] = sorted(set(observation.evidence_ids))
        observation_data["limitations"] = _limitations(observation.limitations)
        observations.append(ObservationPresentation.model_validate(observation_data))

    evidence_items = []
    for evidence_id in sorted(selected_evidence):
        evidence = selected_evidence[evidence_id]
        evidence_data = evidence.model_dump(
            mode="python",
            exclude={
                "occurrence_index",
                "normalized_value",
                "safe_excerpt",
                "display_filter",
                "extractor_version",
            },
        )
        evidence_data["frame_numbers"] = sorted(set(evidence.frame_numbers))
        evidence_items.append(EvidencePresentation.model_validate(evidence_data))

    recommendation_data = recommendation.model_dump(mode="python")
    recommendation_data["affected_finding_ids"] = sorted(set(recommendation.affected_finding_ids))
    recommendation_data["standards_references"] = _standards(recommendation.standards_references)
    recommendation_presentation = RecommendationPresentation.model_validate(recommendation_data)

    policy_risk = None
    if chain.policy_risk is not None:
        risk_data = chain.policy_risk.model_dump(mode="python")
        risk_data["contributions"] = [
            item.model_dump(mode="python")
            for item in sorted(
                chain.policy_risk.contributions,
                key=lambda item: item.contribution_id,
            )
        ]
        risk_data["limitations"] = _limitations(chain.policy_risk.limitations)
        policy_risk = PolicyRiskPresentation.model_validate(risk_data)

    limitation_sources = [
        *chain.analysis.limitations,
        *session.limitations,
        *finding.limitations,
        *(item for fact in selected_facts.values() for item in fact.limitations),
        *(item for event in selected_events.values() for item in event.limitations),
        *(item for obs in selected_observations.values() for item in obs.limitations),
        *(chain.policy_risk.limitations if chain.policy_risk else []),
        *(
            item
            for anomaly in chain.anomaly_results
            if anomaly.session_id == finding.session_id
            for item in anomaly.limitations
        ),
    ]

    return FindingPresentation(
        chain_schema_version=chain.chain_schema_version,
        analysis_id=chain.analysis.analysis_id,
        capture_id=capture.capture_id,
        capture_sha256=capture.sha256,
        finding_id=finding.finding_id,
        stable_finding_key=finding.stable_finding_key,
        session_id=session.session_id,
        stable_session_key=session.stable_session_key,
        protocol=session.protocol,
        rule_evaluation_id=evaluation.evaluation_id,
        rule_id=finding.rule_id,
        rule_version=finding.rule_version,
        rule_outcome=evaluation.outcome,
        title=finding.title,
        category=finding.category,
        severity=finding.severity,
        evidence_confidence=finding.evidence_confidence,
        observability=finding.observability,
        policy_risk_contribution=finding.policy_risk_contribution,
        rationale=finding.rationale,
        impact=finding.impact,
        fact_ids=sorted(set(finding.fact_ids)),
        facts=facts,
        event_ids=[event.event_id for event in events],
        events=events,
        observation_ids=sorted(selected_observations),
        observations=observations,
        evidence_ids=sorted(selected_evidence),
        evidence=evidence_items,
        recommendation=recommendation_presentation,
        standards_references=_standards(finding.standards_references),
        limitations=_limitations(limitation_sources),
        policy_risk=policy_risk,
        ml_anomaly=MlAnomalyPresentation(
            engine_status=chain.analysis.ml_engine_status,
            results=anomalies,
        ),
        evaluated_at=evaluation.evaluated_at,
        created_at=finding.created_at,
    )


def build_finding_presentation(
    chain: ChainOfProof,
    finding_id: str,
) -> FindingPresentation:
    """Build a deterministic selected-finding view without mutating the Chain."""
    try:
        assert_chain_valid(chain)
    except ChainValidationError as exc:
        try:
            _build_projection(chain, finding_id)
        except PresentationError:
            raise
        except Exception as projection_exc:
            raise PresentationError(
                ChainErrorCode.PRESENTATION_INVALID_CHAIN,
                "chain failed presentation validation",
            ) from projection_exc
        raise PresentationError(
            ChainErrorCode.PRESENTATION_INVALID_CHAIN,
            "chain failed presentation validation",
        ) from exc
    try:
        return _build_projection(chain, finding_id)
    except PresentationError:
        raise
    except Exception as exc:
        raise PresentationError(
            ChainErrorCode.PRESENTATION_REFERENCE_INVALID,
            "selected finding could not be projected safely",
        ) from exc
