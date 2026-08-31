"""Real analyzer-to-policy flow shared by Commit 5A presentation tests."""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal

from _e3a_helpers import frame, stream

from securemailscope.chain.canonical import canonical_json
from securemailscope.chain.enums import AnomalyBand, EngineStatus
from securemailscope.chain.ids import analysis_id, anomaly_result_id
from securemailscope.chain.invariants import assert_chain_valid
from securemailscope.chain.models import (
    ANOMALY_INTERPRETATION_NOTE,
    AnomalyResult,
    ChainOfProof,
)
from securemailscope.chain.poc_adapter import (
    CaptureMetadata,
    PocAdapterContext,
    build_chain_from_poc_analysis,
)
from securemailscope.chain.policy.engine import evaluate_default_policy
from securemailscope.chain.policy.models import PolicyEvaluationContext
from securemailscope.chain.smtp_facts import derive_smtp_transition_facts
from securemailscope.models import (
    AnalyzeResult,
    CaptureFormat,
    CaptureProvenance,
    Direction,
    Protocol,
    ProvenanceStatus,
)
from securemailscope.protocols import classify_stream
from securemailscope.sessions import build_transition

C = Direction.CLIENT_TO_SERVER
S = Direction.SERVER_TO_CLIENT
CAPTURE_SHA256 = "a" * 64
BASE_CONFIGURATION_DIGEST = "c" * 64
EVALUATED_AT = datetime(2026, 8, 27, 11, 0, 0, tzinfo=UTC)


def _plaintext_continuation_frames():
    return [
        frame(1, b"", direction=C, syn=True),
        frame(2, b"", direction=S, syn=True, ack=True),
        frame(3, b"", direction=C, ack=True),
        frame(4, b"220 secure.example ESMTP\r\n", direction=S),
        frame(5, b"EHLO client.example\r\n", direction=C),
        frame(6, b"250-STARTTLS\r\n", direction=S),
        frame(7, b"MAIL FROM:<secret-sender@example.test>\r\n", direction=C),
        frame(8, b"RCPT TO:<secret-recipient@example.test>\r\n", direction=C),
        frame(9, b"QUIT\r\n", direction=C),
    ]


def build_derived_chain() -> ChainOfProof:
    tcp_stream = stream(_plaintext_continuation_frames())
    classification = classify_stream(tcp_stream)
    assert classification.protocol is Protocol.SMTP
    transition = build_transition(tcp_stream, capture_truncation=False)
    result = AnalyzeResult(
        provenance=CaptureProvenance(
            input_path="/private/work/capture.pcapng",
            sha256=CAPTURE_SHA256,
            size_bytes=4096,
            capture_format=CaptureFormat.PCAPNG,
            packet_count=len(tcp_stream.frames),
            first_epoch_seconds=Decimal("1800000000.100000000"),
            last_epoch_seconds=Decimal("1800000002.300000000"),
            tshark_version="4.2.5",
            capinfos_version="4.2.5",
            status=ProvenanceStatus.OK,
            warnings=[],
        ),
        tool_records=[],
        streams=[tcp_stream],
        classifications=[classification],
        smtp_transitions=[transition],
        warnings=[],
    )
    chain = build_chain_from_poc_analysis(
        result,
        context=PocAdapterContext(
            capture_metadata=CaptureMetadata(
                link_layer_types=["ethernet"],
                snaplen=262144,
                truncated_packet_count=0,
            ),
            source_configuration_digest=BASE_CONFIGURATION_DIGEST,
            analyzer_version="securemailscope/0.5.0",
            created_at=datetime(2026, 8, 27, 9, 59, 0, tzinfo=UTC),
            started_at=datetime(2026, 8, 27, 10, 0, 0, tzinfo=UTC),
            completed_at=datetime(2026, 8, 27, 10, 1, 0, tzinfo=UTC),
        ),
    )
    derived = derive_smtp_transition_facts(chain)
    assert_chain_valid(derived)
    return derived


def _add_anomaly(chain: ChainOfProof) -> ChainOfProof:
    model_id = "test-isolation-model"
    model_version = "1.0.0"
    feature_schema_version = "1.0.0"
    session = chain.sessions[0]
    fact = chain.derived_facts[0]
    evidence_ids = sorted(
        {
            evidence_id
            for event_id in fact.source_event_ids
            for event in chain.protocol_events
            if event.event_id == event_id
            for evidence_id in event.evidence_ids
        }
    )
    updated_analysis_id = analysis_id(
        chain.analysis.chain_schema_version,
        chain.captures[0].sha256,
        chain.analysis.configuration_digest,
        chain.analysis.analyzer_version,
        None,
        None,
        model_id,
        model_version,
    )
    analysis = chain.analysis.model_copy(
        update={
            "analysis_id": updated_analysis_id,
            "ml_engine_status": EngineStatus.COMPLETE,
            "model_id": model_id,
            "model_version": model_version,
        }
    )
    anomaly = AnomalyResult(
        anomaly_result_id=anomaly_result_id(
            session.session_id,
            model_id,
            model_version,
            feature_schema_version,
        ),
        session_id=session.session_id,
        model_id=model_id,
        model_version=model_version,
        feature_schema_version=feature_schema_version,
        feature_snapshot={"event_count": 3},
        raw_score=-0.25,
        normalized_score=0.75,
        threshold=0.5,
        band=AnomalyBand.ELEVATED,
        unusual_feature_indicators=["event_count"],
        linked_fact_ids=[fact.fact_id],
        linked_observation_ids=[],
        evidence_ids=evidence_ids,
        interpretation_note=ANOMALY_INTERPRETATION_NOTE,
        limitations=[],
    )
    updated = chain.model_copy(update={"analysis": analysis, "anomaly_results": [anomaly]})
    assert_chain_valid(updated)
    return updated


def build_evaluated_chain(*, with_anomaly: bool = False) -> ChainOfProof:
    chain = build_derived_chain()
    if with_anomaly:
        chain = _add_anomaly(chain)
    evaluated = evaluate_default_policy(
        chain,
        context=PolicyEvaluationContext(
            profile_id="sms-liberal",
            evaluated_at=EVALUATED_AT,
            base_configuration_digest=chain.analysis.configuration_digest,
        ),
    )
    assert_chain_valid(evaluated)
    assert len(evaluated.findings) == 1
    return evaluated


def canonical_chain(chain: ChainOfProof) -> str:
    return canonical_json(chain.model_dump(mode="python"))
