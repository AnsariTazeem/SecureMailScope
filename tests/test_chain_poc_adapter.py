"""Commit 2 tests: the existing-POC -> Chain-of-Proof adapter.

The adapter is the pure mapping boundary between the verified E2/E3A analyzer
path and the frozen Chain contract. These tests therefore build analysis
results with the *real* analyzer components (``classify_stream`` /
``build_transition``), or with exact typed analyzer values where a failure path
must be constructed, and then check the mapped chain against independently
stated expectations. No analyzer behavior is mocked.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

import pytest
from _e3a_helpers import frame, stream
from pydantic import ValidationError

from securemailscope.analyze import analyze_capture
from securemailscope.chain.canonical import canonical_content_hash
from securemailscope.chain.enums import (
    AnalysisStatus,
    ChainObservability,
    ConfidenceLevel,
    EngineStatus,
    EventStatus,
    EvidenceRedaction,
    EvidenceSourceKind,
    LimitationCode,
    ProtocolEventType,
    ProtocolState,
    StageId,
    StageStatus,
    Tls13SecretsStatus,
)
from securemailscope.chain.errors import ChainAdapterError, ChainErrorCode
from securemailscope.chain.ids import stable_digest
from securemailscope.chain.invariants import validate_chain
from securemailscope.chain.models import EvidenceReference
from securemailscope.chain.poc_adapter import (
    CaptureMetadata,
    PocAdapterContext,
    build_chain_from_poc_analysis,
)
from securemailscope.models import (
    AnalyzeResult,
    CaptureFormat,
    CaptureProvenance,
    ClassificationStatus,
    CompleteStatus,
    Direction,
    Protocol,
    ProvenanceStatus,
    RawFrameObservation,
    SmtpEvent,
    SmtpEventCategory,
    SmtpTransition,
    TcpStream,
    ToolExecutionRecord,
    TransitionOutcome,
)
from securemailscope.protocols import classify_stream
from securemailscope.sessions import build_transition

REPO = Path(__file__).resolve().parents[1]
PCAP = REPO / "fixtures" / "pcaps" / "smtp_tls12_valid.pcapng"
PCAP_SHA256 = "772d166b5e2b32516c76833357ff309af0d99d7bc962cf4c685279fc662ab086"
FROZEN_STARTTLS_COMMAND_FRAMES = [9, 11]
FROZEN_ACCEPTANCE_FRAME = 13
FROZEN_CLIENT_HELLO_FRAME = 15

SYN_STARTTLS_COMMAND_FRAMES = [11, 13]
SYN_ACCEPTANCE_FRAME = 15
SYN_CLIENT_HELLO_FRAME = 17

CFG_DIGEST = "c" * 64
CAPTURE_SHA256 = "a" * 64
ANALYZER_VERSION = "securemailscope/0.4.0"

C = Direction.CLIENT_TO_SERVER
S = Direction.SERVER_TO_CLIENT

_HANDshake_EVENT_BY_TYPE: dict[int, ProtocolEventType] = {
    1: ProtocolEventType.CLIENT_HELLO,
    2: ProtocolEventType.SERVER_HELLO,
    11: ProtocolEventType.CERTIFICATE_MESSAGE,
    12: ProtocolEventType.KEY_EXCHANGE_OBSERVED,
    16: ProtocolEventType.KEY_EXCHANGE_OBSERVED,
    20: ProtocolEventType.HANDSHAKE_FINISHED,
}

_NUMERIC_FILTER = re.compile(
    r"^tcp\.stream eq \d+ && frame\.number (?:== \d+|in \{\d+(?:, \d+)*\})$"
)


def _provenance(**overrides) -> CaptureProvenance:
    values = {
        "input_path": "capture.pcapng",
        "sha256": CAPTURE_SHA256,
        "size_bytes": 4096,
        "capture_format": CaptureFormat.PCAPNG,
        "packet_count": 28,
        "first_epoch_seconds": Decimal("1800000000.100000000"),
        "last_epoch_seconds": Decimal("1800000002.300000000"),
        "tshark_version": "4.2.5",
        "capinfos_version": "4.2.5",
        "status": ProvenanceStatus.OK,
        "warnings": [],
    }
    values.update(overrides)
    return CaptureProvenance(**values)


def _context(**overrides) -> PocAdapterContext:
    values = {
        "capture_metadata": CaptureMetadata(
            link_layer_types=["ethernet"], snaplen=262144, truncated_packet_count=0
        ),
        "source_configuration_digest": CFG_DIGEST,
        "analyzer_version": ANALYZER_VERSION,
        "created_at": datetime(2026, 8, 27, 9, 59, 0, tzinfo=UTC),
        "started_at": datetime(2026, 8, 27, 10, 0, 0, tzinfo=UTC),
        "completed_at": datetime(2026, 8, 27, 10, 1, 0, tzinfo=UTC),
    }
    values.update(overrides)
    return PocAdapterContext(**values)


def _result(
    streams: list[TcpStream],
    classifications,
    transitions: list[SmtpTransition] | None = None,
    *,
    tool_records=None,
    warnings=None,
) -> AnalyzeResult:
    return AnalyzeResult(
        provenance=_provenance(),
        tool_records=tool_records or [],
        streams=streams,
        classifications=classifications,
        smtp_transitions=transitions or [],
        warnings=warnings or [],
    )


def _tool_record(
    stage: str,
    *,
    tool: str = "tshark",
    succeeded: bool = True,
    runtime_seconds: float = 1.0,
    stage_diagnostic: str = "bounded diagnostic",
) -> ToolExecutionRecord:
    return ToolExecutionRecord(
        tool=tool,
        argument_summary="bounded arguments",
        stage=stage,
        timeout_seconds=20.0,
        runtime_seconds=runtime_seconds,
        exit_code=0 if succeeded else 1,
        succeeded=succeeded,
        stderr_diagnostic=stage_diagnostic,
        output_char_count=0,
    )


def _analyze(frames: list[RawFrameObservation], *, capture_truncation: bool = False):
    tcp_stream = stream(frames)
    classification = classify_stream(tcp_stream)
    transition = None
    if classification.protocol is Protocol.SMTP:
        transition = build_transition(tcp_stream, capture_truncation=capture_truncation)
    return (
        _result([tcp_stream], [classification], [transition] if transition is not None else []),
        classification,
        transition,
    )


def _handshake_frames() -> list[RawFrameObservation]:
    """The ordered three-way handshake: client SYN, server SYN+ACK, client ACK."""
    return [
        frame(1, b"", direction=C, syn=True),
        frame(2, b"", direction=S, syn=True, ack=True),
        frame(3, b"", direction=C, ack=True),
    ]


def _accepted_tls_frames() -> list[RawFrameObservation]:
    """The frozen T01-style profile: split STARTTLS + accepted TLS handshake.

    The leading frames carry the genuine three-way handshake so the adapter may
    prove the ordered connection; the SMTP dialog then begins on frame 4.
    """
    return [
        *_handshake_frames(),
        frame(4, b"220 secure.example ESMTP\r\n", direction=S),
        frame(5, b"", direction=C),
        frame(6, b"EHLO client.example\r\n", direction=C),
        frame(7, b"250-server.example\r\n", direction=S),
        frame(8, b"250-STARTTLS\r\n", direction=S),
        frame(9, b"", direction=C),
        frame(10, b"250 AUTH LOGIN PLAIN\r\n", direction=S),
        frame(11, b"START", direction=C),
        frame(12, b"", direction=S),
        frame(13, b"TLS\r\n", direction=C),
        frame(14, b"", direction=S),
        frame(15, b"220 2.0.0 Ready to start TLS\r\n", direction=S),
        frame(16, b"", direction=C),
        frame(17, b"\x16\x03\x01\x00\x05", direction=C, tls_handshake_types=(1,)),
        frame(18, b"\x16\x03\x03\x00\x05", direction=S, tls_handshake_types=(2,)),
        frame(19, b"\x16\x03\x03\x00\x05", direction=S, tls_handshake_types=(11,)),
        frame(20, b"\x16\x03\x03\x00\x05", direction=S, tls_handshake_types=(12,)),
        frame(21, b"\x16\x03\x03\x00\x05", direction=S, tls_handshake_types=(16,)),
        frame(22, b"\x16\x03\x03\x00\x05", direction=C, tls_handshake_types=(20,)),
    ]


# ─────────────────────────────────────────────────────────────────────────────
#  Happy path: the accepted-TLS transition
# ─────────────────────────────────────────────────────────────────────────────


def test_adapter_maps_accepted_tls_session_facts() -> None:
    result, classification, transition = _analyze(_accepted_tls_frames())
    assert classification.status is ClassificationStatus.CONFIRMED
    assert transition.outcome is TransitionOutcome.ACCEPTED_TLS
    assert transition.completeness is CompleteStatus.COMPLETE

    chain = build_chain_from_poc_analysis(result, context=_context())

    ok, problems = validate_chain(chain)
    assert ok, problems

    assert len(chain.sessions) == 1
    session = chain.sessions[0]
    assert session.protocol is Protocol.SMTP
    assert session.protocol_confidence is ConfidenceLevel.HIGH
    assert session.capture_completeness is CompleteStatus.COMPLETE
    assert session.limitations == []
    assert session.first_frame == 1
    assert session.last_frame == 22
    assert session.packet_count == 22
    assert session.source_endpoint.ip == "10.0.0.1"
    assert session.source_endpoint.port == 49100
    assert session.destination_endpoint.ip == "10.0.0.2"
    assert session.destination_endpoint.port == 2525

    event_types = [event.event_type for event in chain.protocol_events]
    assert event_types == [
        ProtocolEventType.TCP_CONNECTED,
        ProtocolEventType.SERVER_GREETING,
        ProtocolEventType.CAPABILITY_REQUEST,
        ProtocolEventType.CAPABILITY_ADVERTISED,
        ProtocolEventType.TLS_UPGRADE_REQUESTED,
        ProtocolEventType.TLS_UPGRADE_ACCEPTED,
        ProtocolEventType.CLIENT_HELLO,
        ProtocolEventType.SERVER_HELLO,
        ProtocolEventType.CERTIFICATE_MESSAGE,
        ProtocolEventType.KEY_EXCHANGE_OBSERVED,
        ProtocolEventType.KEY_EXCHANGE_OBSERVED,
        ProtocolEventType.HANDSHAKE_FINISHED,
    ]
    for position, event in enumerate(chain.protocol_events):
        assert event.sequence_index == position
        assert event.session_id == session.session_id
        assert event.event_status is EventStatus.OBSERVED
        assert event.observability is ChainObservability.OBSERVED
        assert event.limitations == []


def test_adapter_state_machine_matches_starttls_semantics() -> None:
    chain = build_chain_from_poc_analysis(_analyze(_accepted_tls_frames())[0], context=_context())
    states = [
        (event.event_type, event.state_before, event.state_after) for event in chain.protocol_events
    ]
    assert states == [
        (ProtocolEventType.TCP_CONNECTED, ProtocolState.UNKNOWN, ProtocolState.CONNECTION_OPEN),
        (ProtocolEventType.SERVER_GREETING, ProtocolState.CONNECTION_OPEN, ProtocolState.GREETING),
        (ProtocolEventType.CAPABILITY_REQUEST, ProtocolState.GREETING, ProtocolState.READY),
        (ProtocolEventType.CAPABILITY_ADVERTISED, ProtocolState.READY, ProtocolState.TLS_OFFERED),
        (
            ProtocolEventType.TLS_UPGRADE_REQUESTED,
            ProtocolState.TLS_OFFERED,
            ProtocolState.TLS_REQUESTED,
        ),
        (
            ProtocolEventType.TLS_UPGRADE_ACCEPTED,
            ProtocolState.TLS_REQUESTED,
            ProtocolState.TLS_NEGOTIATING,
        ),
        (
            ProtocolEventType.CLIENT_HELLO,
            ProtocolState.TLS_NEGOTIATING,
            ProtocolState.TLS_NEGOTIATING,
        ),
        (
            ProtocolEventType.SERVER_HELLO,
            ProtocolState.TLS_NEGOTIATING,
            ProtocolState.TLS_NEGOTIATING,
        ),
        (
            ProtocolEventType.CERTIFICATE_MESSAGE,
            ProtocolState.TLS_NEGOTIATING,
            ProtocolState.TLS_NEGOTIATING,
        ),
        (
            ProtocolEventType.KEY_EXCHANGE_OBSERVED,
            ProtocolState.TLS_NEGOTIATING,
            ProtocolState.TLS_NEGOTIATING,
        ),
        (
            ProtocolEventType.KEY_EXCHANGE_OBSERVED,
            ProtocolState.TLS_NEGOTIATING,
            ProtocolState.TLS_NEGOTIATING,
        ),
        (
            ProtocolEventType.HANDSHAKE_FINISHED,
            ProtocolState.TLS_NEGOTIATING,
            ProtocolState.TLS_ACTIVE,
        ),
    ]


def test_adapter_split_starttls_command_referenced_via_native_reassembly() -> None:
    chain = build_chain_from_poc_analysis(_analyze(_accepted_tls_frames())[0], context=_context())
    requested = [
        event
        for event in chain.protocol_events
        if event.event_type is ProtocolEventType.TLS_UPGRADE_REQUESTED
    ]
    assert len(requested) == 1
    evidence = [node for node in chain.evidence if node.evidence_id in requested[0].evidence_ids]
    assert len(evidence) == 1
    assert evidence[0].source_kind is EvidenceSourceKind.TSHARK_FOLLOW_STREAM
    assert evidence[0].source_field == "follow,tcp,raw"
    assert evidence[0].normalized_value == "smtp:starttls_command"
    assert evidence[0].frame_numbers == SYN_STARTTLS_COMMAND_FRAMES
    assert evidence[0].direction is Direction.CLIENT_TO_SERVER


def test_adapter_acceptance_evidence_frames_match_frozen_facts() -> None:
    chain = build_chain_from_poc_analysis(_analyze(_accepted_tls_frames())[0], context=_context())
    accepted = [
        event
        for event in chain.protocol_events
        if event.event_type is ProtocolEventType.TLS_UPGRADE_ACCEPTED
    ]
    assert len(accepted) == 1
    accept_evidence = [
        node for node in chain.evidence if node.evidence_id in accepted[0].evidence_ids
    ]
    assert accept_evidence[0].frame_numbers == [SYN_ACCEPTANCE_FRAME]
    assert accept_evidence[0].normalized_value == "smtp:starttls_accept"
    assert accept_evidence[0].direction is Direction.SERVER_TO_CLIENT

    client_hello = [
        event
        for event in chain.protocol_events
        if event.event_type is ProtocolEventType.CLIENT_HELLO
    ]
    hello_evidence = [
        node for node in chain.evidence if node.evidence_id in client_hello[0].evidence_ids
    ]
    assert hello_evidence[0].frame_numbers == [SYN_CLIENT_HELLO_FRAME]
    assert hello_evidence[0].normalized_value == "tls:handshake_type:1"


def test_adapter_emits_exactly_the_observed_handshake_types() -> None:
    result, _classification, _transition = _analyze(_accepted_tls_frames())
    observed = {
        handshake
        for tcp_stream in result.streams
        for observed_frame in tcp_stream.frames
        for handshake in observed_frame.tls_handshake_types
    }
    expected_types = {
        _HANDshake_EVENT_BY_TYPE[t] for t in observed if t in _HANDshake_EVENT_BY_TYPE
    }
    assert expected_types

    chain = build_chain_from_poc_analysis(result, context=_context())
    handshake_events = {
        event.event_type
        for event in chain.protocol_events
        if event.event_type
        in {
            ProtocolEventType.CLIENT_HELLO,
            ProtocolEventType.SERVER_HELLO,
            ProtocolEventType.CERTIFICATE_MESSAGE,
            ProtocolEventType.KEY_EXCHANGE_OBSERVED,
            ProtocolEventType.HANDSHAKE_FINISHED,
        }
    }
    assert handshake_events == expected_types


def test_adapter_single_frame_command_uses_frame_payload_evidence() -> None:
    frames = [
        *_handshake_frames(),
        frame(4, b"220 secure.example ESMTP\r\n", direction=S),
        frame(5, b"EHLO client.example\r\n", direction=C),
        frame(6, b"250-STARTTLS\r\n", direction=S),
        frame(7, b"STARTTLS\r\n", direction=C),
        frame(8, b"220 2.0.0 Ready to start TLS\r\n", direction=S),
        frame(9, b"\x16\x03\x01\x00\x05", direction=C, tls_handshake_types=(1,)),
    ]
    result, classification, transition = _analyze(frames)
    assert transition.outcome is TransitionOutcome.ACCEPTED_TLS
    assert transition.starttls_command_frames == [7]

    chain = build_chain_from_poc_analysis(result, context=_context())
    requested = [
        event
        for event in chain.protocol_events
        if event.event_type is ProtocolEventType.TLS_UPGRADE_REQUESTED
    ]
    command_evidence = [
        node for node in chain.evidence if node.evidence_id in requested[0].evidence_ids
    ]
    assert command_evidence[0].source_kind is EvidenceSourceKind.TSHARK_FIELD
    assert command_evidence[0].source_field == "tcp.payload"
    assert command_evidence[0].frame_numbers == [7]


# ─────────────────────────────────────────────────────────────────────────────
#  Other transition outcomes
# ─────────────────────────────────────────────────────────────────────────────


def test_adapter_rejected_transition_emits_rejection_event() -> None:
    frames = [
        *_handshake_frames(),
        frame(4, b"220 secure.example ESMTP\r\n", direction=S),
        frame(5, b"EHLO client.example\r\n", direction=C),
        frame(6, b"250-STARTTLS\r\n", direction=S),
        frame(7, b"STARTTLS\r\n", direction=C),
        frame(8, b"454 TLS not available\r\n", direction=S),
    ]
    result, _classification, transition = _analyze(frames)
    assert transition.outcome is TransitionOutcome.REJECTED

    chain = build_chain_from_poc_analysis(result, context=_context())
    rejected = [
        event
        for event in chain.protocol_events
        if event.event_type is ProtocolEventType.TLS_UPGRADE_REJECTED
    ]
    assert len(rejected) == 1
    assert rejected[0].state_after is ProtocolState.TLS_FAILED
    assert rejected[0].state_before is ProtocolState.TLS_REQUESTED
    reject_evidence = [
        node for node in chain.evidence if node.evidence_id in rejected[0].evidence_ids
    ]
    assert reject_evidence[0].frame_numbers == [8]
    assert reject_evidence[0].normalized_value == "smtp:starttls_reject"


def test_adapter_accepted_without_tls_emits_acceptance_only() -> None:
    frames = [
        *_handshake_frames(),
        frame(4, b"220 secure.example ESMTP\r\n", direction=S),
        frame(5, b"EHLO client.example\r\n", direction=C),
        frame(6, b"250-STARTTLS\r\n", direction=S),
        frame(7, b"STARTTLS\r\n", direction=C),
        frame(8, b"220 OK\r\n", direction=S),
        frame(9, b"QUIT\r\n", direction=C),
        frame(10, b"221 Bye\r\n", direction=S),
    ]
    result, _classification, transition = _analyze(frames)
    assert transition.outcome is TransitionOutcome.ACCEPTED_WITHOUT_TLS

    chain = build_chain_from_poc_analysis(result, context=_context())
    types = [event.event_type for event in chain.protocol_events]
    assert types[-1] is ProtocolEventType.TLS_UPGRADE_ACCEPTED
    assert ProtocolEventType.CLIENT_HELLO not in types


def test_adapter_truncated_capture_reports_limit_and_no_fabricated_outcome() -> None:
    frames = [
        *_handshake_frames(),
        frame(4, b"220 secure.example ESMTP\r\n", direction=S),
        frame(5, b"EHLO client.example\r\n", direction=C),
        frame(6, b"250-STARTTLS\r\n", direction=S),
        frame(7, b"START", direction=C),
    ]
    result, _classification, transition = _analyze(frames, capture_truncation=True)
    assert transition.outcome is TransitionOutcome.TRUNCATED
    assert transition.completeness is CompleteStatus.CAPTURE_INCOMPLETE

    chain = build_chain_from_poc_analysis(result, context=_context())
    assert chain.analysis.analysis_status is AnalysisStatus.PARTIAL
    assert [limit.code for limit in chain.analysis.limitations] == [
        LimitationCode.CAPTURE_INCOMPLETE
    ]
    assert [limit.code for limit in chain.sessions[0].limitations] == [
        LimitationCode.CAPTURE_INCOMPLETE
    ]
    assert chain.captures[0].capture_warnings
    assert any(
        "capture" in warning and "STARTTLS" in warning
        for warning in chain.captures[0].capture_warnings
    )
    assert chain.sessions[0].capture_completeness is CompleteStatus.CAPTURE_INCOMPLETE
    types = [event.event_type for event in chain.protocol_events]
    assert ProtocolEventType.TLS_UPGRADE_ACCEPTED not in types
    assert ProtocolEventType.TLS_UPGRADE_REJECTED not in types


def test_adapter_partial_command_never_produces_complete_request_evidence() -> None:
    frames = [
        *_handshake_frames(),
        frame(4, b"220 secure.example ESMTP\r\n", direction=S),
        frame(5, b"EHLO client.example\r\n", direction=C),
        frame(6, b"250-STARTTLS\r\n", direction=S),
        frame(7, b"START", direction=C),
    ]
    result, _classification, transition = _analyze(frames, capture_truncation=True)
    assert transition.outcome is TransitionOutcome.TRUNCATED
    assert transition.completeness is CompleteStatus.CAPTURE_INCOMPLETE
    assert transition.starttls_command != "STARTTLS\r\n"
    assert transition.starttls_command_frames

    chain = build_chain_from_poc_analysis(result, context=_context())
    requested = [
        event
        for event in chain.protocol_events
        if event.event_type is ProtocolEventType.TLS_UPGRADE_REQUESTED
    ]
    assert requested == []
    command_evidence = [
        node for node in chain.evidence if node.normalized_value == "smtp:starttls_command"
    ]
    assert command_evidence == []
    assert not any(
        node.source_kind is EvidenceSourceKind.TSHARK_FOLLOW_STREAM for node in chain.evidence
    )


def test_adapter_incomplete_transition_has_no_synthetic_outcome_event() -> None:
    frames = [
        *_handshake_frames(),
        frame(4, b"220 secure.example ESMTP\r\n", direction=S),
        frame(5, b"EHLO client.example\r\n", direction=C),
        frame(6, b"250-STARTTLS\r\n", direction=S),
        frame(7, b"STARTTLS\r\n", direction=C),
    ]
    result, _classification, transition = _analyze(frames)
    assert transition.outcome is TransitionOutcome.INCOMPLETE

    chain = build_chain_from_poc_analysis(result, context=_context())
    types = [event.event_type for event in chain.protocol_events]
    assert ProtocolEventType.TLS_UPGRADE_ACCEPTED not in types
    assert ProtocolEventType.TLS_UPGRADE_REJECTED not in types
    assert types == [
        ProtocolEventType.TCP_CONNECTED,
        ProtocolEventType.SERVER_GREETING,
        ProtocolEventType.CAPABILITY_REQUEST,
        ProtocolEventType.CAPABILITY_ADVERTISED,
        ProtocolEventType.TLS_UPGRADE_REQUESTED,
    ]
    assert chain.sessions[0].capture_completeness is CompleteStatus.COMPLETE
    assert [limit.code for limit in chain.sessions[0].limitations] == [
        LimitationCode.UNKNOWN_INSUFFICIENT_EVIDENCE
    ]
    assert LimitationCode.CAPTURE_INCOMPLETE not in [
        limit.code for limit in chain.sessions[0].limitations
    ]


def test_adapter_unknown_stream_is_honestly_unclassified() -> None:
    frames = [
        *_handshake_frames(),
        frame(4, b"\x16\x03\x01\x00\x05", direction=C, tls_handshake_types=(1,)),
    ]
    result, classification, _transition = _analyze(frames)
    assert classification.protocol is Protocol.UNKNOWN

    chain = build_chain_from_poc_analysis(result, context=_context())
    session = chain.sessions[0]
    assert session.protocol is Protocol.UNKNOWN
    assert session.protocol_confidence is ConfidenceLevel.NOT_SCORED
    assert session.capture_completeness is CompleteStatus.INSUFFICIENT
    assert [limit.code for limit in session.limitations] == [
        LimitationCode.UNKNOWN_INSUFFICIENT_EVIDENCE
    ]
    event_types = [event.event_type for event in chain.protocol_events]
    assert ProtocolEventType.TCP_CONNECTED in event_types


def _chain_for_frames(frames: list[RawFrameObservation]):
    result, _classification, _transition = _analyze(frames)
    return build_chain_from_poc_analysis(result, context=_context())


def _handshake_evidence(chain) -> list[EvidenceReference]:
    connected = [
        event
        for event in chain.protocol_events
        if event.event_type is ProtocolEventType.TCP_CONNECTED
    ]
    assert len(connected) == 1
    ids = set(connected[0].evidence_ids)
    return [node for node in chain.evidence if node.evidence_id in ids]


def test_adapter_ordered_handshake_proves_connection() -> None:
    chain = _chain_for_frames(
        [
            *_handshake_frames(),
            frame(4, b"220 secure.example ESMTP\r\n", direction=S),
        ]
    )
    legs = {node.normalized_value: node for node in _handshake_evidence(chain)}
    assert set(legs) == {"tcp:syn", "tcp:syn_ack", "tcp:ack"}
    assert legs["tcp:syn"].frame_numbers == [1]
    assert legs["tcp:syn"].direction is Direction.CLIENT_TO_SERVER
    assert legs["tcp:syn_ack"].frame_numbers == [2]
    assert legs["tcp:syn_ack"].direction is Direction.SERVER_TO_CLIENT
    assert legs["tcp:ack"].frame_numbers == [3]
    assert legs["tcp:ack"].direction is Direction.CLIENT_TO_SERVER


def test_adapter_single_lone_syn_proves_attempt_only() -> None:
    chain = _chain_for_frames(
        [
            frame(1, b"", direction=C, syn=True),
            frame(2, b"220 secure.example ESMTP\r\n", direction=S),
        ]
    )
    assert not any(
        event.event_type is ProtocolEventType.TCP_CONNECTED for event in chain.protocol_events
    )


def test_adapter_syn_and_syn_ack_without_final_ack_has_no_connection() -> None:
    chain = _chain_for_frames(
        [
            frame(1, b"", direction=C, syn=True),
            frame(2, b"", direction=S, syn=True, ack=True),
            frame(3, b"220 secure.example ESMTP\r\n", direction=S),
        ]
    )
    assert not any(
        event.event_type is ProtocolEventType.TCP_CONNECTED for event in chain.protocol_events
    )


def test_adapter_out_of_order_handshake_has_no_connection() -> None:
    chain = _chain_for_frames(
        [
            frame(1, b"", direction=C, ack=True),
            frame(2, b"", direction=S, syn=True, ack=True),
            frame(3, b"", direction=C, syn=True),
            frame(4, b"220 secure.example ESMTP\r\n", direction=S),
        ]
    )
    assert not any(
        event.event_type is ProtocolEventType.TCP_CONNECTED for event in chain.protocol_events
    )


def test_adapter_repeated_syn_after_handshake_is_ignored_for_connection() -> None:
    chain = _chain_for_frames(
        [
            *_handshake_frames(),
            frame(4, b"", direction=C, syn=True),
            frame(5, b"220 secure.example ESMTP\r\n", direction=S),
        ]
    )
    legs = {node.normalized_value for node in _handshake_evidence(chain)}
    assert legs == {"tcp:syn", "tcp:syn_ack", "tcp:ack"}
    assert not any(
        node.frame_numbers == [4]
        for node in _handshake_evidence(chain)
        if node.normalized_value == "tcp:syn"
    )


def test_adapter_handshake_evidence_is_observed_and_exactly_scoped() -> None:
    chain = _chain_for_frames(
        [
            *_handshake_frames(),
            frame(4, b"220 secure.example ESMTP\r\n", direction=S),
        ]
    )
    for node in _handshake_evidence(chain):
        assert node.observability is ChainObservability.OBSERVED
        assert node.safe_excerpt == ""
        assert node.display_filter == f"tcp.stream eq 0 && frame.number == {node.frame_numbers[0]}"


# ─────────────────────────────────────────────────────────────────────────────
#  Evidence hygiene
# ─────────────────────────────────────────────────────────────────────────────


def test_adapter_evidence_is_observed_and_safe() -> None:
    chain = build_chain_from_poc_analysis(_analyze(_accepted_tls_frames())[0], context=_context())
    assert chain.evidence
    for node in chain.evidence:
        assert node.observability is ChainObservability.OBSERVED
        assert node.redaction is EvidenceRedaction.NONE
        assert node.safe_excerpt == ""
        assert _NUMERIC_FILTER.fullmatch(node.display_filter), node.display_filter
        assert node.timestamp_start <= node.timestamp_end
        assert node.extractor_version == "poc-adapter/1.0.0"


def test_adapter_evidence_session_consistency_holds() -> None:
    chain = build_chain_from_poc_analysis(_analyze(_accepted_tls_frames())[0], context=_context())
    session = chain.sessions[0]
    for node in chain.evidence:
        assert node.capture_id == session.capture_id
        assert node.session_id == session.session_id
        assert node.capture_sha256 == CAPTURE_SHA256


# ─────────────────────────────────────────────────────────────────────────────
#  Capture / manifest / execution nodes
# ─────────────────────────────────────────────────────────────────────────────


def test_adapter_manifest_matches_engine_inputs() -> None:
    chain = build_chain_from_poc_analysis(_analyze(_accepted_tls_frames())[0], context=_context())
    analysis = chain.analysis
    assert analysis.analysis_status is AnalysisStatus.COMPLETE
    assert analysis.analyzer_version == ANALYZER_VERSION
    assert analysis.tshark_version == "4.2.5"
    assert analysis.configuration_digest == stable_digest(CFG_DIGEST, "1.0.0", "1.0.0")
    assert analysis.tls13_authorized_secrets is Tls13SecretsStatus.NOT_SUPPLIED
    assert analysis.rule_engine_status is EngineStatus.NOT_RUN
    assert analysis.rule_pack_id is None
    assert analysis.rule_pack_version is None
    assert analysis.ml_engine_status is EngineStatus.NOT_RUN
    assert analysis.model_id is None
    assert analysis.model_version is None
    assert analysis.completed_at is not None


def test_adapter_execution_envelope_is_not_run() -> None:
    chain = build_chain_from_poc_analysis(_analyze(_accepted_tls_frames())[0], context=_context())
    assert chain.execution.tool_versions == {"tshark": "4.2.5", "capinfos": "4.2.5"}
    assert chain.execution.stage_diagnostics == []
    assert chain.analysis.rule_engine_status is EngineStatus.NOT_RUN
    assert chain.analysis.ml_engine_status is EngineStatus.NOT_RUN


def test_adapter_capture_node_reproduces_provenance_and_metadata() -> None:
    chain = build_chain_from_poc_analysis(_analyze(_accepted_tls_frames())[0], context=_context())
    capture = chain.captures[0]
    assert capture.format is CaptureFormat.PCAPNG
    assert capture.sha256 == CAPTURE_SHA256
    assert capture.size_bytes == 4096
    assert capture.packet_count == 28
    assert capture.original_filename_sanitized == "capture.pcapng"
    assert capture.link_layer_types == ["ethernet"]
    assert capture.snaplen == 262144
    assert capture.truncated_packet_count == 0
    assert capture.captured_at_start is not None
    assert capture.captured_at_end is not None
    assert capture.captured_at_start <= chain.sessions[0].started_at
    assert capture.captured_at_end >= chain.sessions[0].ended_at


def test_adapter_commits_2_collections_are_empty() -> None:
    chain = build_chain_from_poc_analysis(_analyze(_accepted_tls_frames())[0], context=_context())
    assert chain.crypto_observations == []
    assert chain.derived_facts == []
    assert chain.rule_evaluations == []
    assert chain.findings == []
    assert chain.policy_risk is None
    assert chain.anomaly_results == []
    assert chain.recommendations == []
    assert chain.artifacts == []


# ─────────────────────────────────────────────────────────────────────────────
#  Reproducibility
# ─────────────────────────────────────────────────────────────────────────────


def test_adapter_is_deterministic_across_runs() -> None:
    first = build_chain_from_poc_analysis(_analyze(_accepted_tls_frames())[0], context=_context())
    second = build_chain_from_poc_analysis(_analyze(_accepted_tls_frames())[0], context=_context())
    assert canonical_content_hash(first) == canonical_content_hash(second)
    assert [e.event_id for e in first.protocol_events] == [
        e.event_id for e in second.protocol_events
    ]
    assert [e.evidence_id for e in first.evidence] == [e.evidence_id for e in second.evidence]
    assert first.sessions[0].stable_session_key == second.sessions[0].stable_session_key


def test_adapter_output_is_independent_of_analyzer_list_order() -> None:
    stream_a = stream(_accepted_tls_frames())
    classification_a = classify_stream(stream_a)
    transition_a = build_transition(stream_a)
    assert transition_a.outcome is TransitionOutcome.ACCEPTED_TLS

    rejected_frames = [
        *_handshake_frames(),
        frame(4, b"220 secure.example ESMTP\r\n", direction=S),
        frame(5, b"EHLO client.example\r\n", direction=C),
        frame(6, b"250-STARTTLS\r\n", direction=S),
        frame(7, b"STARTTLS\r\n", direction=C),
        frame(8, b"454 TLS not available\r\n", direction=S),
    ]
    rejected_frames = [f.model_copy(update={"tcp_stream": 1}) for f in rejected_frames]
    stream_b = stream(rejected_frames).model_copy(update={"stream_id": 1})
    classification_b = classify_stream(stream_b).model_copy(update={"tcp_stream": 1})
    transition_b = build_transition(stream_b).model_copy(update={"tcp_stream": 1})
    assert transition_b.outcome is TransitionOutcome.REJECTED

    forward = _result(
        [stream_a, stream_b],
        [classification_a, classification_b],
        [transition_a, transition_b],
    )
    reversed_input = forward.model_copy(deep=True)
    reversed_input.streams = list(reversed(reversed_input.streams))
    reversed_input.classifications = list(reversed(reversed_input.classifications))
    reversed_input.smtp_transitions = list(reversed(reversed_input.smtp_transitions))

    chain_forward = build_chain_from_poc_analysis(forward, context=_context())
    chain_reversed = build_chain_from_poc_analysis(reversed_input, context=_context())
    assert canonical_content_hash(chain_forward) == canonical_content_hash(chain_reversed)
    assert [session.session_id for session in chain_forward.sessions] == [
        session.session_id for session in chain_reversed.sessions
    ]
    assert len(chain_forward.sessions) == 2
    assert {event.session_id for event in chain_reversed.protocol_events} == {
        event.session_id for event in chain_forward.protocol_events
    }


def test_adapter_reproducible_analysis_id_is_listed() -> None:
    chain = build_chain_from_poc_analysis(_analyze(_accepted_tls_frames())[0], context=_context())
    ok, problems = validate_chain(chain)
    assert ok, problems
    assert chain.analysis.analysis_id


# ─────────────────────────────────────────────────────────────────────────────
#  Adapter-input validation errors
# ─────────────────────────────────────────────────────────────────────────────


def test_adapter_rejects_authorized_tls13_secrets() -> None:
    result, _classification, _transition = _analyze(_accepted_tls_frames())
    context = _context(tls13_authorized_secrets=Tls13SecretsStatus.AUTHORIZED_SUPPLIED)
    with pytest.raises(ChainAdapterError) as exc:
        build_chain_from_poc_analysis(result, context=context)
    assert exc.value.code is ChainErrorCode.ADAPTER_INPUT_INVALID
    assert "secret" in exc.value.message.lower()


def test_adapter_rejects_blank_analyzer_version() -> None:
    result, _classification, _transition = _analyze(_accepted_tls_frames())
    with pytest.raises(ChainAdapterError) as exc:
        build_chain_from_poc_analysis(result, context=_context(analyzer_version="  "))
    assert exc.value.code is ChainErrorCode.ADAPTER_INPUT_INVALID


def test_adapter_rejects_bad_source_configuration_digest() -> None:
    result, _classification, _transition = _analyze(_accepted_tls_frames())
    with pytest.raises(ChainAdapterError) as exc:
        build_chain_from_poc_analysis(
            result, context=_context(source_configuration_digest="x" * 63)
        )
    assert exc.value.code is ChainErrorCode.ADAPTER_INPUT_INVALID


def test_adapter_rejects_inverted_analysis_timestamps() -> None:
    result, _classification, _transition = _analyze(_accepted_tls_frames())
    started = datetime(2026, 8, 27, 9, 58, 0, tzinfo=UTC)
    created = datetime(2026, 8, 27, 9, 59, 0, tzinfo=UTC)
    with pytest.raises(ChainAdapterError) as exc:
        build_chain_from_poc_analysis(
            result, context=_context(created_at=created, started_at=started)
        )
    assert exc.value.code is ChainErrorCode.ADAPTER_INPUT_INVALID


def test_adapter_rejects_completed_before_started() -> None:
    result, _classification, _transition = _analyze(_accepted_tls_frames())
    completed = datetime(2026, 8, 27, 9, 58, 0, tzinfo=UTC)
    with pytest.raises(ChainAdapterError) as exc:
        build_chain_from_poc_analysis(result, context=_context(completed_at=completed))
    assert exc.value.code is ChainErrorCode.ADAPTER_INPUT_INVALID


# ─────────────────────────────────────────────────────────────────────────────
#  Provenance validation errors
# ─────────────────────────────────────────────────────────────────────────────


def test_adapter_requires_usable_provenance_status() -> None:
    result, _classification, _transition = _analyze(
        _accepted_tls_frames(),
    )
    result.provenance = _provenance(status=ProvenanceStatus.FAILED)
    with pytest.raises(ChainAdapterError) as exc:
        build_chain_from_poc_analysis(result, context=_context())
    assert exc.value.code is ChainErrorCode.ADAPTER_METADATA_REQUIRED


def test_adapter_requires_valid_capture_sha256() -> None:
    result, _classification, _transition = _analyze(
        _accepted_tls_frames(),
    )
    result.provenance = _provenance(sha256="not-a-digest")
    with pytest.raises(ChainAdapterError) as exc:
        build_chain_from_poc_analysis(result, context=_context())
    assert exc.value.code is ChainErrorCode.ADAPTER_METADATA_REQUIRED


# ─────────────────────────────────────────────────────────────────────────────
#  Analyzer-shape mapping failures
# ─────────────────────────────────────────────────────────────────────────────


def test_adapter_rejects_duplicate_stream_ids() -> None:
    tcp_stream = stream(_accepted_tls_frames())
    classification = classify_stream(tcp_stream)
    result = _result([tcp_stream, tcp_stream], [classification])
    with pytest.raises(ChainAdapterError) as exc:
        build_chain_from_poc_analysis(result, context=_context())
    assert exc.value.code is ChainErrorCode.ADAPTER_MAPPING_FAILED
    assert "duplicate" in exc.value.message


def test_adapter_rejects_classification_for_unknown_stream() -> None:
    result, _classification, _transition = _analyze(_accepted_tls_frames())
    result.classifications[0] = result.classifications[0].model_copy(update={"tcp_stream": 999})
    with pytest.raises(ChainAdapterError) as exc:
        build_chain_from_poc_analysis(result, context=_context())
    assert exc.value.code is ChainErrorCode.ADAPTER_MAPPING_FAILED
    assert "unknown tcp.stream" in exc.value.message


def test_adapter_rejects_duplicate_classification() -> None:
    result, _classification, _transition = _analyze(_accepted_tls_frames())
    dup = result.classifications[0].model_copy()
    result.classifications.append(dup)
    with pytest.raises(ChainAdapterError) as exc:
        build_chain_from_poc_analysis(result, context=_context())
    assert exc.value.code is ChainErrorCode.ADAPTER_MAPPING_FAILED
    assert "duplicate classification" in exc.value.message


def test_adapter_rejects_smtp_without_transition() -> None:
    result, classification, _transition = _analyze(_accepted_tls_frames())
    assert classification.protocol is Protocol.SMTP
    result.smtp_transitions = []
    with pytest.raises(ChainAdapterError) as exc:
        build_chain_from_poc_analysis(result, context=_context())
    assert exc.value.code is ChainErrorCode.ADAPTER_MAPPING_FAILED
    assert "no STARTTLS transition" in exc.value.message


def test_adapter_rejects_transition_for_non_smtp_stream() -> None:
    frames = [
        *_handshake_frames(),
        frame(4, b"\x16\x03\x01\x00\x05", direction=C, tls_handshake_types=(1,)),
    ]
    result, classification, _transition = _analyze(frames)
    assert classification.protocol is Protocol.UNKNOWN
    result.smtp_transitions = [SmtpTransition(tcp_stream=0, outcome=TransitionOutcome.INCOMPLETE)]
    with pytest.raises(ChainAdapterError) as exc:
        build_chain_from_poc_analysis(result, context=_context())
    assert exc.value.code is ChainErrorCode.ADAPTER_MAPPING_FAILED
    assert "non-SMTP" in exc.value.message


def test_adapter_rejects_smtp_classification_that_is_not_confirmed() -> None:
    result, classification, transition = _analyze(_accepted_tls_frames())
    assert classification.status is ClassificationStatus.CONFIRMED
    result.classifications[0] = classification.model_copy(
        update={"status": ClassificationStatus.INSUFFICIENT}
    )
    with pytest.raises(ChainAdapterError) as exc:
        build_chain_from_poc_analysis(result, context=_context())
    assert exc.value.code is ChainErrorCode.ADAPTER_MAPPING_FAILED


def test_adapter_rejects_stream_with_no_frames() -> None:
    empty = TcpStream(
        stream_id=0,
        client_ip="10.0.0.1",
        client_port=49100,
        server_ip="10.0.0.2",
        server_port=2525,
        frames=[],
    )
    from securemailscope.models import ProtocolClassification

    classification = ProtocolClassification(
        tcp_stream=0,
        protocol=Protocol.SMTP,
        status=ClassificationStatus.CONFIRMED,
        reason="manual",
    )
    result = _result([empty], [classification])
    with pytest.raises(ChainAdapterError) as exc:
        build_chain_from_poc_analysis(result, context=_context())
    assert exc.value.code is ChainErrorCode.ADAPTER_MAPPING_FAILED
    assert "no frame observations" in exc.value.message


def test_adapter_rejects_accepted_outcome_without_response_frame() -> None:
    result, classification, transition = _analyze(_accepted_tls_frames())
    assert transition.outcome is TransitionOutcome.ACCEPTED_TLS
    result.smtp_transitions[0] = transition.model_copy(
        update={
            "outcome": TransitionOutcome.ACCEPTED_TLS,
            "starttls_response_frames": [],
        }
    )
    with pytest.raises(ChainAdapterError) as exc:
        build_chain_from_poc_analysis(result, context=_context())
    assert exc.value.code is ChainErrorCode.ADAPTER_MAPPING_FAILED
    assert "without a server response frame" in exc.value.message


def test_adapter_rejects_evidence_referencing_a_foreign_frame() -> None:
    result, classification, transition = _analyze(_accepted_tls_frames())
    assert transition.outcome is TransitionOutcome.ACCEPTED_TLS
    result.smtp_transitions[0] = transition.model_copy(update={"starttls_command_frames": [999]})
    with pytest.raises(ChainAdapterError) as exc:
        build_chain_from_poc_analysis(result, context=_context())
    assert exc.value.code is ChainErrorCode.ADAPTER_MAPPING_FAILED
    assert "unknown frame" in exc.value.message


def test_adapter_rejects_duplicate_frame_numbers_in_a_stream() -> None:
    result, _classification, _transition = _analyze(_accepted_tls_frames())
    duplicated = result.streams[0].frames + [result.streams[0].frames[10]]
    result.streams[0] = result.streams[0].model_copy(update={"frames": duplicated})
    with pytest.raises(ChainAdapterError) as exc:
        build_chain_from_poc_analysis(result, context=_context())
    assert exc.value.code is ChainErrorCode.ADAPTER_MAPPING_FAILED
    assert "duplicate frame" in exc.value.message


def test_adapter_rejects_foreign_tcp_stream_on_a_frame() -> None:
    result, _classification, _transition = _analyze(_accepted_tls_frames())
    foreign = result.streams[0].frames[10].model_copy(update={"tcp_stream": 7})
    result.streams[0].frames[10] = foreign
    with pytest.raises(ChainAdapterError) as exc:
        build_chain_from_poc_analysis(result, context=_context())
    assert exc.value.code is ChainErrorCode.ADAPTER_MAPPING_FAILED
    assert "belongs to" in exc.value.message
    assert "not its containing stream" in exc.value.message


def test_adapter_rejects_analyzer_event_referencing_an_unknown_frame() -> None:
    result, _classification, transition = _analyze(_accepted_tls_frames())
    ghost = SmtpEvent(
        category=SmtpEventCategory.EHLO,
        direction=Direction.CLIENT_TO_SERVER,
        frame=999,
        occurrence=0,
        text="EHLO ghost",
    )
    result.smtp_transitions[0] = transition.model_copy(
        update={"events": transition.events + [ghost]}
    )
    with pytest.raises(ChainAdapterError) as exc:
        build_chain_from_poc_analysis(result, context=_context())
    assert exc.value.code is ChainErrorCode.ADAPTER_MAPPING_FAILED
    assert "unknown frame" in exc.value.message
    assert "not silently skipped" in exc.value.message


# ─────────────────────────────────────────────────────────────────────────────
#  Metadata model constraints
# ─────────────────────────────────────────────────────────────────────────────


def test_capture_metadata_rejects_all_empty_link_layers() -> None:
    with pytest.raises(ValidationError):
        CaptureMetadata(
            link_layer_types=["  ", ""],
            snaplen=262144,
            truncated_packet_count=0,
        )


def test_capture_metadata_rejects_zero_snaplen() -> None:
    with pytest.raises(ValidationError):
        CaptureMetadata(
            link_layer_types=["ethernet"],
            snaplen=0,
            truncated_packet_count=0,
        )


def test_capture_metadata_rejects_negative_truncated_packets() -> None:
    with pytest.raises(ValidationError):
        CaptureMetadata(
            link_layer_types=["ethernet"],
            snaplen=262144,
            truncated_packet_count=-1,
        )


def test_context_rejects_unknown_extra_fields() -> None:
    with pytest.raises(ValidationError):
        PocAdapterContext(
            capture_metadata=CaptureMetadata(
                link_layer_types=["ethernet"], snaplen=262144, truncated_packet_count=0
            ),
            source_configuration_digest=CFG_DIGEST,
            analyzer_version=ANALYZER_VERSION,
            created_at=datetime(2026, 8, 27, 9, 59, 0, tzinfo=UTC),
            started_at=datetime(2026, 8, 27, 10, 0, 0, tzinfo=UTC),
            completed_at=datetime(2026, 8, 27, 10, 1, 0, tzinfo=UTC),
            surprise=True,
        )


# ─────────────────────────────────────────────────────────────────────────────
#  Response-driven events (observed server responses, correction 2)
# ─────────────────────────────────────────────────────────────────────────────


def _acceptance_only_frames() -> list[RawFrameObservation]:
    return [
        *_handshake_frames(),
        frame(4, b"220 secure.example ESMTP\r\n", direction=S),
        frame(5, b"EHLO client.example\r\n", direction=C),
        frame(6, b"250-STARTTLS\r\n", direction=S),
        frame(7, b"STARTTLS\r\n", direction=C),
        frame(8, b"220 2.0.0 Ready to start TLS\r\n", direction=S),
    ]


def test_adapter_acceptance_is_preserved_without_later_proof() -> None:
    result, _classification, transition = _analyze(_acceptance_only_frames())
    assert transition.outcome is TransitionOutcome.INCOMPLETE
    assert transition.completeness is CompleteStatus.COMPLETE
    assert transition.starttls_response_frames == [8]

    chain = build_chain_from_poc_analysis(result, context=_context())
    accepted = [
        event
        for event in chain.protocol_events
        if event.event_type is ProtocolEventType.TLS_UPGRADE_ACCEPTED
    ]
    assert len(accepted) == 1
    accept_evidence = [
        node for node in chain.evidence if node.evidence_id in accepted[0].evidence_ids
    ]
    assert accept_evidence[0].frame_numbers == [8]
    assert accept_evidence[0].normalized_value == "smtp:starttls_accept"
    assert ProtocolEventType.CLIENT_HELLO not in [
        event.event_type for event in chain.protocol_events
    ]


def test_adapter_acceptance_preserved_when_capture_truncated_after_response() -> None:
    result, _classification, transition = _analyze(
        _acceptance_only_frames(), capture_truncation=True
    )
    assert transition.outcome is TransitionOutcome.TRUNCATED
    assert transition.completeness is CompleteStatus.CAPTURE_INCOMPLETE

    chain = build_chain_from_poc_analysis(result, context=_context())
    types = [event.event_type for event in chain.protocol_events]
    assert ProtocolEventType.TLS_UPGRADE_ACCEPTED in types
    assert ProtocolEventType.CLIENT_HELLO not in types
    assert [limit.code for limit in chain.sessions[0].limitations] == [
        LimitationCode.CAPTURE_INCOMPLETE
    ]
    assert chain.analysis.analysis_status is AnalysisStatus.PARTIAL


def test_adapter_rejection_is_observed_response_driven() -> None:
    frames = [
        *_handshake_frames(),
        frame(4, b"220 secure.example ESMTP\r\n", direction=S),
        frame(5, b"EHLO client.example\r\n", direction=C),
        frame(6, b"250-STARTTLS\r\n", direction=S),
        frame(7, b"STARTTLS\r\n", direction=C),
        frame(8, b"454 TLS not available\r\n", direction=S),
    ]
    result, _classification, transition = _analyze(frames)
    assert transition.outcome is TransitionOutcome.REJECTED
    chain = build_chain_from_poc_analysis(result, context=_context())
    rejected = [
        event
        for event in chain.protocol_events
        if event.event_type is ProtocolEventType.TLS_UPGRADE_REJECTED
    ]
    assert len(rejected) == 1
    reject_evidence = [
        node for node in chain.evidence if node.evidence_id in rejected[0].evidence_ids
    ]
    assert reject_evidence[0].frame_numbers == [8]
    assert reject_evidence[0].normalized_value == "smtp:starttls_reject"
    assert ProtocolEventType.TLS_UPGRADE_ACCEPTED not in [
        event.event_type for event in chain.protocol_events
    ]


def test_adapter_unrecognized_response_emits_no_synthetic_event() -> None:
    frames = [
        *_handshake_frames(),
        frame(4, b"220 secure.example ESMTP\r\n", direction=S),
        frame(5, b"EHLO client.example\r\n", direction=C),
        frame(6, b"250-STARTTLS\r\n", direction=S),
        frame(7, b"STARTTLS\r\n", direction=C),
        frame(8, b"250 2.0.0 unrecognized\r\n", direction=S),
    ]
    result, _classification, transition = _analyze(frames)
    assert transition.outcome is TransitionOutcome.INCOMPLETE
    chain = build_chain_from_poc_analysis(result, context=_context())
    types = [event.event_type for event in chain.protocol_events]
    assert ProtocolEventType.TLS_UPGRADE_ACCEPTED not in types
    assert ProtocolEventType.TLS_UPGRADE_REJECTED not in types
    assert not any(
        node.normalized_value in ("smtp:starttls_accept", "smtp:starttls_reject")
        for node in chain.evidence
    )
    assert ProtocolEventType.TLS_UPGRADE_REQUESTED in types


def test_adapter_response_without_proven_command_raises() -> None:
    result, _classification, transition = _analyze(_acceptance_only_frames())
    assert transition.outcome is TransitionOutcome.INCOMPLETE
    result.smtp_transitions[0] = transition.model_copy(update={"starttls_command": "STARTTLS"})
    with pytest.raises(ChainAdapterError) as exc:
        build_chain_from_poc_analysis(result, context=_context())
    assert exc.value.code is ChainErrorCode.ADAPTER_MAPPING_FAILED
    assert "complete STARTTLS command" in exc.value.message


def test_adapter_inconsistent_outcome_with_response_raises() -> None:
    result, _classification, transition = _analyze(_acceptance_only_frames())
    result.smtp_transitions[0] = transition.model_copy(
        update={"outcome": TransitionOutcome.REJECTED}
    )
    with pytest.raises(ChainAdapterError) as exc:
        build_chain_from_poc_analysis(result, context=_context())
    assert exc.value.code is ChainErrorCode.ADAPTER_MAPPING_FAILED
    assert "inconsistent with the observed server response" in exc.value.message


def test_adapter_complete_command_without_attribute_frames_raises() -> None:
    result, _classification, transition = _analyze(_acceptance_only_frames())
    result.smtp_transitions[0] = transition.model_copy(update={"starttls_command_frames": []})
    with pytest.raises(ChainAdapterError) as exc:
        build_chain_from_poc_analysis(result, context=_context())
    assert exc.value.code is ChainErrorCode.ADAPTER_MAPPING_FAILED
    assert "frame evidence" in exc.value.message


def _mutate_frame_direction(result, frame_number: int, direction: Direction) -> None:
    stream_node = result.streams[0]
    stream_node.frames = [
        (f.model_copy(update={"direction": direction}) if f.frame == frame_number else f)
        for f in stream_node.frames
    ]


def test_adapter_rejects_server_response_frame_flagged_client_to_server() -> None:
    result, _classification, _transition = _analyze(_acceptance_only_frames())
    _mutate_frame_direction(result, 8, Direction.CLIENT_TO_SERVER)
    with pytest.raises(ChainAdapterError) as exc:
        build_chain_from_poc_analysis(result, context=_context())
    assert exc.value.code is ChainErrorCode.ADAPTER_MAPPING_FAILED
    assert "disagrees" in exc.value.message


def test_adapter_rejects_command_frame_flagged_server_to_client() -> None:
    result, _classification, _transition = _analyze(_acceptance_only_frames())
    _mutate_frame_direction(result, 7, Direction.SERVER_TO_CLIENT)
    with pytest.raises(ChainAdapterError) as exc:
        build_chain_from_poc_analysis(result, context=_context())
    assert exc.value.code is ChainErrorCode.ADAPTER_MAPPING_FAILED
    assert "disagrees" in exc.value.message


def test_adapter_rejects_event_direction_disagreeing_with_its_frame() -> None:
    result, _classification, transition = _analyze(_acceptance_only_frames())
    mutated = [
        (
            event.model_copy(update={"direction": Direction.CLIENT_TO_SERVER})
            if event.category is SmtpEventCategory.BANNER
            else event
        )
        for event in transition.events
    ]
    result.smtp_transitions[0] = transition.model_copy(update={"events": mutated})
    with pytest.raises(ChainAdapterError) as exc:
        build_chain_from_poc_analysis(result, context=_context())
    assert exc.value.code is ChainErrorCode.ADAPTER_MAPPING_FAILED
    assert "disagrees" in exc.value.message


def test_adapter_rejects_multi_frame_evidence_with_mixed_directions() -> None:
    result, _classification, transition = _analyze(_accepted_tls_frames())
    assert transition.starttls_command_frames == SYN_STARTTLS_COMMAND_FRAMES
    _mutate_frame_direction(result, SYN_STARTTLS_COMMAND_FRAMES[1], Direction.SERVER_TO_CLIENT)
    with pytest.raises(ChainAdapterError) as exc:
        build_chain_from_poc_analysis(result, context=_context())
    assert exc.value.code is ChainErrorCode.ADAPTER_MAPPING_FAILED
    assert "disagrees" in exc.value.message


def test_adapter_rejects_response_before_or_at_command_frame() -> None:
    result, _classification, transition = _analyze(_acceptance_only_frames())
    result.smtp_transitions[0] = transition.model_copy(update={"starttls_response_frames": [4]})
    with pytest.raises(ChainAdapterError) as exc:
        build_chain_from_poc_analysis(result, context=_context())
    assert exc.value.code is ChainErrorCode.ADAPTER_MAPPING_FAILED
    assert "not strictly after" in exc.value.message


def test_adapter_rejects_ambiguous_multiple_response_frames() -> None:
    result, _classification, transition = _analyze(_acceptance_only_frames())
    result.smtp_transitions[0] = transition.model_copy(update={"starttls_response_frames": [7, 8]})
    with pytest.raises(ChainAdapterError) as exc:
        build_chain_from_poc_analysis(result, context=_context())
    assert exc.value.code is ChainErrorCode.ADAPTER_MAPPING_FAILED
    assert "multiple STARTTLS response frames" in exc.value.message


def test_adapter_acceptance_event_ordering_and_no_accept_before_request() -> None:
    chain = build_chain_from_poc_analysis(
        _analyze(_acceptance_only_frames())[0], context=_context()
    )
    event_types = [event.event_type for event in chain.protocol_events]
    requested = event_types.index(ProtocolEventType.TLS_UPGRADE_REQUESTED)
    accepted = event_types.index(ProtocolEventType.TLS_UPGRADE_ACCEPTED)
    assert requested < accepted
    assert ProtocolEventType.TLS_UPGRADE_REJECTED not in event_types


# ─────────────────────────────────────────────────────────────────────────────
#  Truncated-packet / stage-partial analysis status (correction 3, part 2)
# ─────────────────────────────────────────────────────────────────────────────


def test_adapter_truncated_packet_count_marks_analysis_partial_without_session_blame() -> None:
    result, _classification, _transition = _analyze(_accepted_tls_frames())
    chain = build_chain_from_poc_analysis(
        result,
        context=_context(
            capture_metadata=CaptureMetadata(
                link_layer_types=["ethernet"],
                snaplen=262144,
                truncated_packet_count=3,
            )
        ),
    )
    assert chain.analysis.analysis_status is AnalysisStatus.PARTIAL
    assert [limit.code for limit in chain.analysis.limitations] == [
        LimitationCode.CAPTURE_INCOMPLETE
    ]
    assert chain.captures[0].truncated_packet_count == 3
    assert chain.sessions[0].capture_completeness is CompleteStatus.COMPLETE
    assert [limit.code for limit in chain.sessions[0].limitations] == []


# ─────────────────────────────────────────────────────────────────────────────
#  Stage diagnostics (correction 4)
# ─────────────────────────────────────────────────────────────────────────────


def test_adapter_maps_successful_tool_records_into_stage_diagnostics() -> None:
    result, _classification, _transition = _analyze(_accepted_tls_frames())
    result.tool_records = [
        _tool_record("intake", tool="sha256sum", runtime_seconds=1.5),
        _tool_record("intake", tool="capinfos", runtime_seconds=2.5),
        _tool_record("tshark_observe", runtime_seconds=3.0),
        _tool_record("tshark_epochs", runtime_seconds=0.5),
        _tool_record("tshark_follow", runtime_seconds=1.0),
    ]
    chain = build_chain_from_poc_analysis(result, context=_context())
    diagnostics = chain.execution.stage_diagnostics
    assert [(d.stage, d.status) for d in diagnostics] == [
        (StageId.CAPTURE_PROVENANCE, StageStatus.COMPLETE),
        (StageId.EVENT_RECONSTRUCTION, StageStatus.COMPLETE),
        (StageId.INTAKE, StageStatus.COMPLETE),
        (StageId.STREAM_RECONSTRUCTION, StageStatus.COMPLETE),
    ]
    assert all(d.limitation is None for d in diagnostics)
    assert {d.stage: d.runtime_seconds for d in diagnostics}[StageId.INTAKE] == 4.0
    assert {d.stage: d.runtime_seconds for d in diagnostics}[StageId.EVENT_RECONSTRUCTION] == 3.0
    assert chain.analysis.analysis_status is AnalysisStatus.COMPLETE


def test_adapter_aggregates_multiple_records_per_stage_deterministically() -> None:
    result, _classification, _transition = _analyze(_accepted_tls_frames())
    result.tool_records = [
        _tool_record("tshark_follow", runtime_seconds=1.0),
        _tool_record("tshark_follow", runtime_seconds=2.0),
        _tool_record("tshark_follow", runtime_seconds=3.0),
    ]
    chain = build_chain_from_poc_analysis(result, context=_context())
    diagnostics = chain.execution.stage_diagnostics
    assert len(diagnostics) == 1
    assert diagnostics[0].stage is StageId.STREAM_RECONSTRUCTION
    assert diagnostics[0].status is StageStatus.COMPLETE
    assert diagnostics[0].runtime_seconds == 6.0


def test_adapter_partial_and_failed_stages_get_limitation_and_partial_analysis() -> None:
    result, _classification, _transition = _analyze(_accepted_tls_frames())
    result.tool_records = [
        _tool_record("intake", succeeded=True),
        _tool_record("intake", succeeded=False),
        _tool_record("tshark_follow", succeeded=False),
    ]
    chain = build_chain_from_poc_analysis(result, context=_context())
    diagnostics = chain.execution.stage_diagnostics
    by_stage = {d.stage: d for d in diagnostics}
    assert by_stage[StageId.INTAKE].status is StageStatus.PARTIAL
    assert by_stage[StageId.STREAM_RECONSTRUCTION].status is StageStatus.FAILED
    for diagnostic in diagnostics:
        assert diagnostic.limitation is not None
        assert diagnostic.limitation.code is LimitationCode.FIELD_UNAVAILABLE
    assert chain.analysis.analysis_status is AnalysisStatus.PARTIAL


def test_adapter_rejects_unknown_tool_stage() -> None:
    result, _classification, _transition = _analyze(_accepted_tls_frames())
    result.tool_records = [_tool_record("mystery_stage")]
    with pytest.raises(ChainAdapterError) as exc:
        build_chain_from_poc_analysis(result, context=_context())
    assert exc.value.code is ChainErrorCode.ADAPTER_MAPPING_FAILED
    assert "stage" in exc.value.message


def test_adapter_stage_ordering_is_independent_of_record_order() -> None:
    result_a, _classification, _transition = _analyze(_accepted_tls_frames())
    result_b, _classification, _transition = _analyze(_accepted_tls_frames())
    records = [
        _tool_record("tshark_follow"),
        _tool_record("intake"),
        _tool_record("tshark_observe"),
        _tool_record("tshark_epochs"),
    ]
    result_a.tool_records = list(records)
    result_b.tool_records = list(reversed(records))
    chain_a = build_chain_from_poc_analysis(result_a, context=_context())
    chain_b = build_chain_from_poc_analysis(result_b, context=_context())
    assert [
        (d.stage, d.status, d.runtime_seconds) for d in chain_a.execution.stage_diagnostics
    ] == [(d.stage, d.status, d.runtime_seconds) for d in chain_b.execution.stage_diagnostics]


def test_adapter_stage_diagnostics_never_serialize_args_paths_or_stderr() -> None:
    result, _classification, _transition = _analyze(_accepted_tls_frames())
    result.tool_records = [
        _tool_record(
            "intake",
            succeeded=False,
            stage_diagnostic="failed to open /root/private/secret-capture.pcapng\x00boom",
        )
    ]
    chain = build_chain_from_poc_analysis(result, context=_context())
    text = chain.model_dump_json()
    assert "/root/" not in text
    assert "secret-capture" not in text
    assert "boom" not in text
    assert "bounded arguments" not in text
    assert chain.execution.stage_diagnostics[0].limitation.detail.startswith("tools:")


def test_adapter_tool_names_are_sanitized_to_parent_free_basenames() -> None:
    result, _classification, _transition = _analyze(_accepted_tls_frames())
    result.tool_records = [
        _tool_record("intake", succeeded=False, tool="/home/dell/private/bin/tshark"),
        _tool_record("intake", succeeded=False, tool="C:\\private\\bin\\tshark.exe"),
        _tool_record("intake", succeeded=False, tool="\\\\server\\share\\opencrypto\\cryptography"),
        _tool_record("intake", succeeded=False, tool="/home/dell/My Projects/private/bin/grep"),
    ]
    chain = build_chain_from_poc_analysis(result, context=_context())
    detail = chain.execution.stage_diagnostics[0].limitation.detail
    assert detail == "tools: cryptography,grep,tshark,tshark.exe"
    serialized = chain.model_dump_json()
    for leaked in (
        "/home/dell/My Projects/private/bin/grep",
        "C:\\private\\bin\\tshark.exe",
        "\\\\server\\share\\opencrypto",
        "private/bin",
        "My Projects",
        "opencrypto",
    ):
        assert leaked not in serialized
    for kept in ("tshark", "tshark.exe", "grep", "cryptography"):
        assert kept in serialized


def test_adapter_tool_name_fallback_is_stable_neutral_and_control_free() -> None:
    result, _classification, _transition = _analyze(_accepted_tls_frames())
    result.tool_records = [
        _tool_record("intake", succeeded=False, tool=""),
        _tool_record("intake", succeeded=False, tool="..."),
        _tool_record("intake", succeeded=False, tool="\x01\x02mkfifo"),
    ]
    chain = build_chain_from_poc_analysis(result, context=_context())
    detail = chain.execution.stage_diagnostics[0].limitation.detail
    assert detail == "tools: mkfifo,tool"
    serialized = chain.model_dump_json()
    assert "\x01" not in serialized
    assert "\x02" not in serialized


def test_adapter_tool_names_are_bounded_in_length() -> None:
    result, _classification, _transition = _analyze(_accepted_tls_frames())
    result.tool_records = [_tool_record("intake", succeeded=False, tool="dir/" + "t" * 60)]
    chain = build_chain_from_poc_analysis(result, context=_context())
    detail = chain.execution.stage_diagnostics[0].limitation.detail
    assert "t" * 50 in detail
    assert "t" * 51 not in detail


# ─────────────────────────────────────────────────────────────────────────────
#  Warning sanitization (correction 5)
# ─────────────────────────────────────────────────────────────────────────────


def test_adapter_merges_and_sanitizes_analysis_and_provenance_warnings() -> None:
    result, _classification, _transition = _analyze(_accepted_tls_frames())
    result.warnings = [
        "tcp.reassembly failed on /home/user/private/capture.pcapng",
        "line one\nline two\x00 embedded",
        "duplicate warning",
        "duplicate warning",
    ]
    result.provenance = _provenance(
        warnings=[
            "windows path C:\\Users\\dell\\private\\capture.pcapng opened",
            "unc \\\\server\\share\\file.pcap missing",
        ]
    )
    chain = build_chain_from_poc_analysis(result, context=_context())
    warnings = chain.captures[0].capture_warnings
    assert "tcp.reassembly failed on" in warnings
    assert "home" not in "".join(warnings)
    assert "Users" not in "".join(warnings)
    assert "server" not in "".join(warnings)
    assert "line one line two embedded" in warnings
    assert warnings.count("duplicate warning") == 1
    assert "windows path" in "".join(warnings)
    assert "capture.pcapng" not in "".join(warnings)


def test_adapter_warns_are_bounded_in_length_and_count() -> None:
    result, _classification, _transition = _analyze(_accepted_tls_frames())
    long_warning = "x" * 500
    result.warnings = [f"prefix {long_warning}" for _ in range(15)]
    chain = build_chain_from_poc_analysis(result, context=_context())
    warnings = chain.captures[0].capture_warnings
    assert len(warnings) <= 10
    assert all(len(w) <= 200 for w in warnings)
    assert all(w.endswith(" ...") for w in warnings)


def test_adapter_warnings_remove_paths_with_spaces_in_directories() -> None:
    result, _classification, _transition = _analyze(_accepted_tls_frames())
    result.warnings = [
        "/home/dell/My Projects/private/capture.pcapng opened",
        "windows C:\\Users\\dell\\My Projects\\private\\capture.pcapng opened",
        "unc \\\\server\\My Share\\private\\capture.pcapng missing",
    ]
    chain = build_chain_from_poc_analysis(result, context=_context())
    warnings = chain.captures[0].capture_warnings
    joined = "? ".join(warnings)
    for piece in (
        "home",
        "dell",
        "My Projects",
        "My Share",
        "Users",
        "private",
        "capture.pcapng",
        "\\\\server",
    ):
        assert piece not in joined
    assert "opened" not in joined
    assert "missing" not in joined
    assert all("??" not in w for w in warnings)
    for w in warnings:
        assert "  " not in w


def test_adapter_warnings_remove_posix_paths_with_spaces_in_filename() -> None:
    result, _classification, _transition = _analyze(_accepted_tls_frames())
    result.warnings = [
        "/home/dell/My Projects/private/my capture.pcapng opened",
    ]
    chain = build_chain_from_poc_analysis(result, context=_context())
    warnings = chain.captures[0].capture_warnings
    joined = "? ".join(warnings)
    for piece in (
        "home",
        "dell",
        "My Projects",
        "private",
        "my capture.pcapng",
        "capture.pcapng",
    ):
        assert piece not in joined
    assert "/" not in joined
    assert "opened" not in joined


def test_adapter_warnings_remove_windows_paths_with_spaces_in_filename() -> None:
    result, _classification, _transition = _analyze(_accepted_tls_frames())
    result.warnings = [
        "C:\\Users\\dell\\My Projects\\private\\my capture.pcapng opened",
    ]
    chain = build_chain_from_poc_analysis(result, context=_context())
    warnings = chain.captures[0].capture_warnings
    joined = "? ".join(warnings)
    for piece in (
        "Users",
        "dell",
        "My Projects",
        "private",
        "my capture.pcapng",
        "capture.pcapng",
    ):
        assert piece not in joined
    assert "\\" not in joined
    assert "opened" not in joined


def test_adapter_warnings_remove_unc_paths_with_spaces_in_filename() -> None:
    result, _classification, _transition = _analyze(_accepted_tls_frames())
    result.warnings = [
        "\\\\server\\My Share\\private\\my capture.pcapng missing",
    ]
    chain = build_chain_from_poc_analysis(result, context=_context())
    warnings = chain.captures[0].capture_warnings
    joined = "? ".join(warnings)
    for piece in (
        "server",
        "My Share",
        "private",
        "my capture.pcapng",
        "capture.pcapng",
    ):
        assert piece not in joined
    assert "\\" not in joined
    assert "missing" not in joined


def test_adapter_capture_incomplete_summary_holds_reserved_first_slot() -> None:
    result, _classification, _transition = _analyze(
        _acceptance_only_frames(), capture_truncation=True
    )
    result.warnings = [f"warning-{i:02d}" for i in range(10)]
    chain = build_chain_from_poc_analysis(result, context=_context())
    warnings = chain.captures[0].capture_warnings
    summary = "capture ended before one or more SMTP STARTTLS transitions completed"
    assert len(warnings) == 10
    assert warnings[0] == summary
    assert summary not in warnings[1:]
    assert any(w.startswith("warning-") for w in warnings[1:])
    assert len(set(warnings)) == 10


def test_adapter_warning_maximum_length_is_exact_including_suffix() -> None:
    result, _classification, _transition = _analyze(_accepted_tls_frames())
    result.warnings = ["text-" + "y" * 300]
    chain = build_chain_from_poc_analysis(result, context=_context())
    warnings = chain.captures[0].capture_warnings
    assert warnings
    assert len(warnings[-1]) == 200
    assert warnings[-1].endswith(" ...")
    assert all(len(w) <= 200 for w in warnings)


def test_adapter_warning_single_component_posix_path_is_truncated() -> None:
    result, _classification, _transition = _analyze(_accepted_tls_frames())
    result.warnings = [
        "/secret",
        "failed /secret opened",
        "first /secret then /home/user/file",
    ]
    chain = build_chain_from_poc_analysis(result, context=_context())
    warnings = chain.captures[0].capture_warnings
    joined = "? ".join(warnings)
    assert "secret" not in joined
    assert "/" not in joined
    assert "opened" not in joined
    assert "failed" in "".join(warnings)
    assert "first" in "".join(warnings)
    assert "then" not in joined


def test_adapter_warning_windows_single_component_path_is_truncated() -> None:
    result, _classification, _transition = _analyze(_accepted_tls_frames())
    result.warnings = [
        "failed C:\\secret opened",
        "C:/secret",
    ]
    chain = build_chain_from_poc_analysis(result, context=_context())
    warnings = chain.captures[0].capture_warnings
    joined = "? ".join(warnings)
    assert "secret" not in joined
    assert "\\" not in joined
    assert "opened" not in joined
    assert "failed" in "".join(warnings)


def test_adapter_warning_unc_single_component_path_is_truncated() -> None:
    result, _classification, _transition = _analyze(_accepted_tls_frames())
    result.warnings = [
        "failed \\\\server\\share opened",
        "\\\\server\\share",
    ]
    chain = build_chain_from_poc_analysis(result, context=_context())
    warnings = chain.captures[0].capture_warnings
    joined = "? ".join(warnings)
    assert "server" not in joined
    assert "\\" not in joined
    assert "opened" not in joined
    assert "failed" in "".join(warnings)


def test_adapter_warning_without_path_is_unchanged() -> None:
    result, _classification, _transition = _analyze(_accepted_tls_frames())
    plain = "ordinary warning no absolute path"
    result.warnings = [plain]
    chain = build_chain_from_poc_analysis(result, context=_context())
    warnings = chain.captures[0].capture_warnings
    assert plain in warnings


def test_adapter_warning_truncates_at_earliest_path_start() -> None:
    result, _classification, _transition = _analyze(_accepted_tls_frames())
    result.warnings = [
        "start /secret then C:\\secret and /home/user/file",
        "head C:\\secret tail \\\\server\\share end",
    ]
    chain = build_chain_from_poc_analysis(result, context=_context())
    warnings = chain.captures[0].capture_warnings
    joined = "? ".join(warnings)
    assert "secret" not in joined
    assert "home" not in joined
    assert "server" not in joined
    assert "tail" not in joined
    assert "start" in "".join(warnings)
    assert "head" in "".join(warnings)


def test_adapter_warning_posix_path_after_equals_is_truncated() -> None:
    result, _classification, _transition = _analyze(_accepted_tls_frames())
    result.warnings = ["path=/secret opened"]
    chain = build_chain_from_poc_analysis(result, context=_context())
    warnings = chain.captures[0].capture_warnings
    assert warnings == ["path="]
    joined = "? ".join(warnings)
    assert "secret" not in joined
    assert "opened" not in joined


def test_adapter_warning_posix_path_after_opening_parenthesis_is_truncated() -> None:
    result, _classification, _transition = _analyze(_accepted_tls_frames())
    result.warnings = ["failed (/secret) opened"]
    chain = build_chain_from_poc_analysis(result, context=_context())
    warnings = chain.captures[0].capture_warnings
    assert warnings == ["failed ("]
    joined = "? ".join(warnings)
    assert "secret" not in joined
    assert "opened" not in joined


def test_adapter_warning_posix_path_after_opening_bracket_is_truncated() -> None:
    result, _classification, _transition = _analyze(_accepted_tls_frames())
    result.warnings = ["failed [/secret] opened"]
    chain = build_chain_from_poc_analysis(result, context=_context())
    warnings = chain.captures[0].capture_warnings
    assert warnings == ["failed ["]
    joined = "? ".join(warnings)
    assert "secret" not in joined
    assert "opened" not in joined


def test_adapter_warning_posix_path_after_opening_brace_is_truncated() -> None:
    result, _classification, _transition = _analyze(_accepted_tls_frames())
    result.warnings = ["failed {/secret} opened"]
    chain = build_chain_from_poc_analysis(result, context=_context())
    warnings = chain.captures[0].capture_warnings
    assert warnings == ["failed {"]
    joined = "? ".join(warnings)
    assert "secret" not in joined
    assert "opened" not in joined


def test_adapter_warning_tab_before_path_is_normalized_not_deleted() -> None:
    result, _classification, _transition = _analyze(_accepted_tls_frames())
    result.warnings = ["failed\t/secret opened"]
    chain = build_chain_from_poc_analysis(result, context=_context())
    warnings = chain.captures[0].capture_warnings
    assert warnings == ["failed"]
    joined = "? ".join(warnings)
    assert "secret" not in joined
    assert "opened" not in joined


def test_adapter_warning_windows_path_after_equals_is_truncated() -> None:
    result, _classification, _transition = _analyze(_accepted_tls_frames())
    result.warnings = ["field=C:\\secret opened"]
    chain = build_chain_from_poc_analysis(result, context=_context())
    warnings = chain.captures[0].capture_warnings
    assert warnings == ["field="]
    joined = "? ".join(warnings)
    assert "secret" not in joined
    assert "opened" not in joined


def test_adapter_warning_unc_path_after_equals_is_truncated() -> None:
    result, _classification, _transition = _analyze(_accepted_tls_frames())
    result.warnings = ["field=\\\\server\\share opened"]
    chain = build_chain_from_poc_analysis(result, context=_context())
    warnings = chain.captures[0].capture_warnings
    assert warnings == ["field="]
    joined = "? ".join(warnings)
    assert "server" not in joined
    assert "share" not in joined
    assert "opened" not in joined


def test_adapter_warning_embedded_separator_is_preserved() -> None:
    result, _classification, _transition = _analyze(_accepted_tls_frames())
    result.warnings = ["ordinary a/b warning"]
    chain = build_chain_from_poc_analysis(result, context=_context())
    assert chain.captures[0].capture_warnings == ["ordinary a/b warning"]


def test_adapter_warning_scheme_url_is_not_an_absolute_path() -> None:
    result, _classification, _transition = _analyze(_accepted_tls_frames())
    result.warnings = ["URL https://example.test/path failed"]
    chain = build_chain_from_poc_analysis(result, context=_context())
    assert chain.captures[0].capture_warnings == ["URL https://example.test/path failed"]


def test_adapter_warning_colon_delimited_posix_path_is_truncated() -> None:
    result, _classification, _transition = _analyze(_accepted_tls_frames())
    result.warnings = ["path:/secret opened"]
    chain = build_chain_from_poc_analysis(result, context=_context())
    assert chain.captures[0].capture_warnings == ["path:"]


def test_adapter_warning_colon_delimited_windows_path_is_truncated() -> None:
    result, _classification, _transition = _analyze(_accepted_tls_frames())
    result.warnings = [r"path:C:\secret opened"]
    chain = build_chain_from_poc_analysis(result, context=_context())
    assert chain.captures[0].capture_warnings == ["path:"]


def test_adapter_warning_colon_delimited_unc_path_is_truncated() -> None:
    result, _classification, _transition = _analyze(_accepted_tls_frames())
    result.warnings = [r"path:\\server\share opened"]
    chain = build_chain_from_poc_analysis(result, context=_context())
    assert chain.captures[0].capture_warnings == ["path:"]


def test_adapter_warning_repeated_slashes_at_start_are_removed() -> None:
    result, _classification, _transition = _analyze(_accepted_tls_frames())
    result.warnings = ["//server/share opened"]
    chain = build_chain_from_poc_analysis(result, context=_context())
    assert chain.captures[0].capture_warnings == []


def test_adapter_warning_repeated_slashes_after_equals_are_removed() -> None:
    result, _classification, _transition = _analyze(_accepted_tls_frames())
    result.warnings = ["path=//server/share opened"]
    chain = build_chain_from_poc_analysis(result, context=_context())
    assert chain.captures[0].capture_warnings == ["path="]


def test_adapter_warning_triple_leading_slashes_are_removed() -> None:
    result, _classification, _transition = _analyze(_accepted_tls_frames())
    result.warnings = ["///private/file opened"]
    chain = build_chain_from_poc_analysis(result, context=_context())
    assert chain.captures[0].capture_warnings == []


def test_adapter_warning_mixed_paths_truncate_at_earliest_start() -> None:
    result, _classification, _transition = _analyze(_accepted_tls_frames())
    result.warnings = [
        "start path:/secret then C:\\secret and //server/share",
        "second path:\\\\server\\share tail and /home/user/file",
    ]
    chain = build_chain_from_poc_analysis(result, context=_context())
    warnings = chain.captures[0].capture_warnings
    assert warnings == ["start path:", "second path:"]
    joined = "? ".join(warnings)
    assert "secret" not in joined
    assert "server" not in joined
    assert "share" not in joined
    assert "then" not in joined
    assert "tail" not in joined
    assert "home" not in joined
    assert "file" not in joined


# ─────────────────────────────────────────────────────────────────────────────
#  Filename sanitization (correction 6)
# ─────────────────────────────────────────────────────────────────────────────


def test_adapter_filename_is_display_basename_across_separators() -> None:
    posix = "/home/user/private/capture.pcapng"
    windows = "C:\\Users\\dell\\private\\capture.pcapng"
    for path in (posix, windows):
        result, _classification, _transition = _analyze(_accepted_tls_frames())
        result.provenance = _provenance(input_path=path)
        chain = build_chain_from_poc_analysis(result, context=_context())
        assert chain.captures[0].original_filename_sanitized == "capture.pcapng"
        assert "/" not in chain.captures[0].original_filename_sanitized
        assert "\\" not in chain.captures[0].original_filename_sanitized


def test_adapter_filename_fallback_is_stable_neutral_name() -> None:
    result, _classification, _transition = _analyze(_accepted_tls_frames())
    for bad in ("", "   ", "...", "..", "/"):
        result.provenance = _provenance(input_path=bad)
        chain = build_chain_from_poc_analysis(result, context=_context())
        assert chain.captures[0].original_filename_sanitized == "capture"


def test_adapter_filename_drops_control_characters_without_switching_name() -> None:
    result, _classification, _transition = _analyze(_accepted_tls_frames())
    result.provenance = _provenance(input_path="capture\x00.pcapng")
    chain = build_chain_from_poc_analysis(result, context=_context())
    assert chain.captures[0].original_filename_sanitized == "capture.pcapng"
    assert "\x00" not in chain.captures[0].original_filename_sanitized


# ─────────────────────────────────────────────────────────────────────────────
#  byte_count fidelity (correction 7)
# ─────────────────────────────────────────────────────────────────────────────


def test_adapter_byte_count_uses_reassembled_streams_not_frame_payloads() -> None:
    result, _classification, _transition = _analyze(_accepted_tls_frames())
    original_stream = result.streams[0]
    payload_total = sum(len(f.payload) for f in original_stream.frames)
    diverged = original_stream.model_copy(
        update={"client_reassembled": original_stream.client_reassembled + b"EXTRA"}
    )
    result.streams = [diverged]
    chain = build_chain_from_poc_analysis(result, context=_context())
    expected = len(diverged.client_reassembled) + len(diverged.server_reassembled)
    assert chain.sessions[0].byte_count == expected
    assert expected != payload_total


# ─────────────────────────────────────────────────────────────────────────────
#  Exact display filters (correction 8)
# ─────────────────────────────────────────────────────────────────────────────


def test_adapter_non_contiguous_evidence_uses_exact_set_filter() -> None:
    chain = build_chain_from_poc_analysis(_analyze(_accepted_tls_frames())[0], context=_context())
    requested = [
        event
        for event in chain.protocol_events
        if event.event_type is ProtocolEventType.TLS_UPGRADE_REQUESTED
    ]
    command_evidence = [
        node for node in chain.evidence if node.evidence_id in requested[0].evidence_ids
    ]
    assert command_evidence[0].frame_numbers == SYN_STARTTLS_COMMAND_FRAMES
    assert command_evidence[0].display_filter == "tcp.stream eq 0 && frame.number in {11, 13}"
    assert "12" not in command_evidence[0].display_filter
    assert ">= " not in command_evidence[0].display_filter


def test_adapter_rejects_shaped_empty_evidence_route_without_index_error() -> None:
    result, _classification, transition = _analyze(_acceptance_only_frames())
    result.smtp_transitions[0] = transition.model_copy(update={"starttls_command_frames": []})
    with pytest.raises(ChainAdapterError):
        build_chain_from_poc_analysis(result, context=_context())


# ─────────────────────────────────────────────────────────────────────────────
#  CaptureMetadata immutability (correction 9)
# ─────────────────────────────────────────────────────────────────────────────


def test_capture_metadata_normalizes_and_freezes_link_layer_types() -> None:
    metadata = CaptureMetadata(
        link_layer_types=[" ethernet ", "radio", "ethernet", "  "],
        snaplen=262144,
        truncated_packet_count=0,
    )
    assert metadata.link_layer_types == ("ethernet", "radio")
    assert isinstance(metadata.link_layer_types, tuple)
    with pytest.raises(AttributeError):
        metadata.link_layer_types.append("wifi")
    with pytest.raises(ValidationError):
        metadata.link_layer_types = ("wifi",)
    with pytest.raises(ValidationError):
        CaptureMetadata(link_layer_types=(), snaplen=262144, truncated_packet_count=0)


# ─────────────────────────────────────────────────────────────────────────────
#  T01 integration
# ─────────────────────────────────────────────────────────────────────────────


def _capinfos_metadata() -> dict:
    """Derive capture metadata from capinfos (read-only), like the intake path."""
    capinfos = shutil.which("capinfos") or "/usr/bin/capinfos"
    completed = subprocess.run(
        [capinfos, str(PCAP)],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    output = completed.stdout
    link_layer = None
    snaplen = None
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if line.startswith("File encapsulation:"):
            link_layer = line.split(":", 1)[1].strip().lower()
        if line.startswith("Capture length ="):
            snaplen = int(line.split("=", 1)[1].strip())
    return {"link_layer": link_layer, "snaplen": snaplen}


@staticmethod
def _t01_skipif() -> bool:
    return not PCAP.is_file() or shutil.which("capinfos") is None or shutil.which("tshark") is None


def test_t01_analyzer_output_maps_to_valid_chain() -> None:
    if _t01_skipif():
        pytest.skip("frozen T01 PCAP or capinfos not present in this working tree")

    result = analyze_capture(PCAP)
    provenance = result.provenance
    assert provenance.sha256 == PCAP_SHA256
    metadata = _capinfos_metadata()
    assert metadata["link_layer"] == "ethernet"
    assert isinstance(metadata["snaplen"], int)

    context = _context(
        capture_metadata=CaptureMetadata(
            link_layer_types=[metadata["link_layer"]],
            snaplen=metadata["snaplen"],
            truncated_packet_count=0,
        )
    )
    chain = build_chain_from_poc_analysis(result, context=context)

    ok, problems = validate_chain(chain)
    assert ok, problems

    assert len(chain.sessions) == 1
    session = chain.sessions[0]
    assert session.protocol is Protocol.SMTP
    assert session.protocol_confidence is ConfidenceLevel.HIGH
    assert session.capture_completeness is CompleteStatus.COMPLETE
    assert session.destination_endpoint.port == 2525

    requested = [
        event
        for event in chain.protocol_events
        if event.event_type is ProtocolEventType.TLS_UPGRADE_REQUESTED
    ]
    command_evidence = [
        node for node in chain.evidence if node.evidence_id in requested[0].evidence_ids
    ]
    assert command_evidence[0].source_kind is EvidenceSourceKind.TSHARK_FOLLOW_STREAM
    assert command_evidence[0].frame_numbers == FROZEN_STARTTLS_COMMAND_FRAMES
    assert command_evidence[0].display_filter == "tcp.stream eq 0 && frame.number in {9, 11}"
    assert command_evidence[0].direction is Direction.CLIENT_TO_SERVER

    syn_evidence = [
        node
        for node in chain.evidence
        if node.normalized_value == "tcp:syn"
        and any(
            event.event_type is ProtocolEventType.TCP_CONNECTED
            for event in chain.protocol_events
            if node.evidence_id in event.evidence_ids
        )
    ]
    assert syn_evidence and syn_evidence[0].direction is Direction.CLIENT_TO_SERVER

    tshark = shutil.which("tshark")
    completed = subprocess.run(
        [
            tshark,
            "-r",
            str(PCAP),
            "-Y",
            command_evidence[0].display_filter,
            "-T",
            "fields",
            "-e",
            "frame.number",
            "-E",
            "separator=,",
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    selected_frames = {int(token) for token in completed.stdout.split() if token.strip()}
    assert selected_frames == set(FROZEN_STARTTLS_COMMAND_FRAMES)
    assert 10 not in selected_frames

    accepted = [
        event
        for event in chain.protocol_events
        if event.event_type is ProtocolEventType.TLS_UPGRADE_ACCEPTED
    ]
    accept_evidence = [
        node for node in chain.evidence if node.evidence_id in accepted[0].evidence_ids
    ]
    assert accept_evidence[0].frame_numbers == [FROZEN_ACCEPTANCE_FRAME]
    assert accept_evidence[0].direction is Direction.SERVER_TO_CLIENT

    connected = [
        event
        for event in chain.protocol_events
        if event.event_type is ProtocolEventType.TCP_CONNECTED
    ]
    assert len(connected) == 1
    assert len(connected[0].evidence_ids) == 3
    connected_evidence_ids = set(connected[0].evidence_ids)
    assert any(
        node.normalized_value == "tcp:syn_ack"
        for node in chain.evidence
        if node.evidence_id in connected_evidence_ids
    )
    assert any(
        node.normalized_value == "tcp:ack"
        for node in chain.evidence
        if node.evidence_id in connected_evidence_ids
    )

    hello_events = [
        event
        for event in chain.protocol_events
        if event.event_type is ProtocolEventType.CLIENT_HELLO
    ]
    hello_evidence = [
        node for node in chain.evidence if node.evidence_id in hello_events[0].evidence_ids
    ]
    assert hello_evidence[0].frame_numbers == [FROZEN_CLIENT_HELLO_FRAME]

    observed_frame_types = {
        handshake
        for tcp_stream in result.streams
        for observed_frame in tcp_stream.frames
        for handshake in observed_frame.tls_handshake_types
    }
    expected_handshake_types = {
        _HANDshake_EVENT_BY_TYPE[t] for t in observed_frame_types if t in _HANDshake_EVENT_BY_TYPE
    }
    handshake_event_types = {
        event.event_type
        for event in chain.protocol_events
        if event.event_type
        in {
            ProtocolEventType.CLIENT_HELLO,
            ProtocolEventType.SERVER_HELLO,
            ProtocolEventType.CERTIFICATE_MESSAGE,
            ProtocolEventType.KEY_EXCHANGE_OBSERVED,
            ProtocolEventType.HANDSHAKE_FINISHED,
        }
    }
    assert handshake_event_types == expected_handshake_types

    assert chain.captures[0].sha256 == PCAP_SHA256
    assert chain.captures[0].original_filename_sanitized == PCAP.name
    assert chain.analysis.limitations == []

    assert chain.execution.stage_diagnostics
    assert {diagnostic.stage for diagnostic in chain.execution.stage_diagnostics} == {
        StageId.CAPTURE_PROVENANCE,
        StageId.EVENT_RECONSTRUCTION,
        StageId.INTAKE,
        StageId.STREAM_RECONSTRUCTION,
    }
    assert all(
        diagnostic.status is StageStatus.COMPLETE
        for diagnostic in chain.execution.stage_diagnostics
    )
