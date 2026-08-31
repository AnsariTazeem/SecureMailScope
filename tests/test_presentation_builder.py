"""End-to-end lineage projection tests for Commit 5A."""

from __future__ import annotations

import presentation_helpers
import pytest
from presentation_helpers import build_evaluated_chain, canonical_chain

from securemailscope.chain.enums import EngineStatus, RuleOutcome
from securemailscope.chain.errors import ChainErrorCode, PresentationError
from securemailscope.chain.ids import session_id_from_key, session_stable_key
from securemailscope.models import Protocol
from securemailscope.presentation import build_finding_presentation


def test_primary_insecure_smtp_finding_builds_chain_backed_presentation():
    chain = build_evaluated_chain()
    finding = chain.findings[0]
    presentation = build_finding_presentation(chain, finding.finding_id)

    assert presentation.analysis_id == chain.analysis.analysis_id
    assert presentation.finding_id == finding.finding_id
    assert presentation.stable_finding_key == finding.stable_finding_key
    assert presentation.protocol is Protocol.SMTP
    assert presentation.rule_id == "SMS-SMTP-STARTTLS-001"
    assert presentation.rule_version == "1.0.0"
    assert presentation.rule_outcome is RuleOutcome.MATCHED
    assert presentation.severity.value == "high"
    assert presentation.recommendation.recommendation_id == "REC-EMAIL-REQUIRE-TLS"
    assert presentation.policy_risk is not None
    assert presentation.policy_risk.capped_score == 25
    assert presentation.ml_anomaly.engine_status is EngineStatus.NOT_RUN
    assert presentation.ml_anomaly.results == []


def test_finding_fact_event_observation_and_evidence_lineage_resolves():
    chain = build_evaluated_chain()
    finding = chain.findings[0]
    presentation = build_finding_presentation(chain, finding.finding_id)
    fact_index = {item.fact_id: item for item in chain.derived_facts}
    event_index = {item.event_id: item for item in chain.protocol_events}
    observation_index = {item.observation_id: item for item in chain.crypto_observations}
    evidence_index = {item.evidence_id: item for item in chain.evidence}

    assert presentation.fact_ids == sorted(finding.fact_ids)
    assert set(presentation.fact_ids) <= {item.fact_id for item in presentation.facts}
    for fact in presentation.facts:
        source = fact_index[fact.fact_id]
        assert fact.source_event_ids == sorted(set(source.source_event_ids))
        assert all(event_id in event_index for event_id in fact.source_event_ids)
        assert all(obs_id in observation_index for obs_id in fact.source_observation_ids)
    assert [item.sequence_index for item in presentation.events] == sorted(
        item.sequence_index for item in presentation.events
    )
    assert presentation.event_ids == [item.event_id for item in presentation.events]
    assert all(item.session_id == finding.session_id for item in presentation.events)
    presentation_evidence_ids = {item.evidence_id for item in presentation.evidence}
    assert all(
        evidence_id in presentation_evidence_ids
        for event in presentation.events
        for evidence_id in event.evidence_ids
    )
    assert set(finding.evidence_ids) <= set(presentation.evidence_ids)
    assert presentation.evidence_ids == sorted(item.evidence_id for item in presentation.evidence)
    assert all(evidence_id in evidence_index for evidence_id in presentation.evidence_ids)


def test_event_projection_uses_protocol_sequence_not_hashed_id(monkeypatch):
    monkeypatch.setattr(presentation_helpers, "CAPTURE_SHA256", "b" * 64)
    chain = build_evaluated_chain()
    presentation = build_finding_presentation(chain, chain.findings[0].finding_id)
    selected_event_ids = {
        event_id for fact in presentation.facts for event_id in fact.source_event_ids
    }
    expected_events = sorted(
        (event for event in chain.protocol_events if event.event_id in selected_event_ids),
        key=lambda event: (event.sequence_index, event.event_id),
    )
    expected_ids = [event.event_id for event in expected_events]

    assert expected_ids != sorted(expected_ids)
    assert presentation.event_ids == expected_ids
    assert [event.sequence_index for event in presentation.events] == [3, 4, 5, 6]


def test_evidence_frames_and_timestamps_match_chain_exactly():
    chain = build_evaluated_chain()
    presentation = build_finding_presentation(chain, chain.findings[0].finding_id)
    evidence_index = {item.evidence_id: item for item in chain.evidence}

    for item in presentation.evidence:
        source = evidence_index[item.evidence_id]
        assert item.frame_numbers == sorted(source.frame_numbers)
        assert item.timestamp_start == source.timestamp_start
        assert item.timestamp_end == source.timestamp_end
        assert item.capture_sha256 == source.capture_sha256


def test_missing_finding_raises_stable_typed_error():
    chain = build_evaluated_chain()

    with pytest.raises(PresentationError) as exc:
        build_finding_presentation(chain, "fnd_00000000000000000000000000")

    assert exc.value.code is ChainErrorCode.PRESENTATION_FINDING_NOT_FOUND
    assert exc.value.detail == ""


def test_cross_session_selected_lineage_raises_reference_error():
    chain = build_evaluated_chain()
    first = chain.sessions[0]
    stable_key = session_stable_key(
        chain.chain_schema_version,
        chain.captures[0].sha256,
        1,
        first.source_endpoint.ip,
        first.source_endpoint.port + 1,
        first.destination_endpoint.ip,
        first.destination_endpoint.port,
    )
    second = first.model_copy(
        update={
            "session_id": session_id_from_key(stable_key),
            "stable_session_key": stable_key,
            "tcp_stream_id": 1,
            "source_endpoint": first.source_endpoint.model_copy(
                update={"port": first.source_endpoint.port + 1}
            ),
            "protocol": Protocol.UNKNOWN,
            "classification_evidence_ids": [],
        }
    )
    selected_event_id = chain.derived_facts[0].source_event_ids[0]
    events = [
        event.model_copy(update={"session_id": second.session_id})
        if event.event_id == selected_event_id
        else event
        for event in chain.protocol_events
    ]
    invalid = chain.model_copy(update={"sessions": [first, second], "protocol_events": events})

    with pytest.raises(PresentationError) as exc:
        build_finding_presentation(invalid, chain.findings[0].finding_id)

    assert exc.value.code is ChainErrorCode.PRESENTATION_REFERENCE_INVALID


def test_unrelated_invalid_chain_raises_invalid_chain_error():
    chain = build_evaluated_chain()
    analysis = chain.analysis.model_copy(update={"chain_schema_version": "2.0.0"})
    invalid = chain.model_copy(update={"analysis": analysis})

    with pytest.raises(PresentationError) as exc:
        build_finding_presentation(invalid, chain.findings[0].finding_id)

    assert exc.value.code is ChainErrorCode.PRESENTATION_INVALID_CHAIN


def test_builder_is_non_mutating_and_stable_for_reordered_source_collections():
    chain = build_evaluated_chain()
    before = canonical_chain(chain)
    reordered = chain.model_copy(
        update={
            "evidence": list(reversed(chain.evidence)),
            "protocol_events": list(reversed(chain.protocol_events)),
            "derived_facts": list(reversed(chain.derived_facts)),
            "rule_evaluations": list(reversed(chain.rule_evaluations)),
            "findings": list(reversed(chain.findings)),
            "recommendations": list(reversed(chain.recommendations)),
        }
    )
    reordered_before = canonical_chain(reordered)

    first = build_finding_presentation(chain, chain.findings[0].finding_id)
    second = build_finding_presentation(reordered, chain.findings[0].finding_id)

    assert canonical_chain(chain) == before
    assert canonical_chain(reordered) == reordered_before
    assert first == second


def test_optional_anomaly_summary_remains_independent_of_policy_risk():
    chain = build_evaluated_chain(with_anomaly=True)
    presentation = build_finding_presentation(chain, chain.findings[0].finding_id)

    assert presentation.policy_risk is not None
    assert presentation.policy_risk.capped_score == 25
    assert presentation.ml_anomaly.engine_status is EngineStatus.COMPLETE
    assert len(presentation.ml_anomaly.results) == 1
    assert presentation.ml_anomaly.results[0].normalized_score == 0.75
