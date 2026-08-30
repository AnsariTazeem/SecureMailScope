"""Commit 3 tests: deterministic SMTP transition-fact derivation.

The derivation function ``derive_smtp_transition_facts`` is a pure mapping from
evidence-backed chain events to ``DerivedFact`` nodes. No analyzer or packet
data is consumed; every expected outcome is asserted against independently
stated expectations built from synthetic adapter output.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from decimal import Decimal

import pytest
from _e3a_helpers import frame, stream
from chain_helpers import load_checked_in_schema
from jsonschema import Draft202012Validator

from securemailscope.chain.canonical import canonical_json
from securemailscope.chain.enums import (
    ChainObservability,
    ConfidenceLevel,
    EventStatus,
    LimitationCode,
    ProtocolEventType,
)
from securemailscope.chain.errors import ChainValidationError
from securemailscope.chain.ids import fact_id_from_key, fact_stable_key, protocol_event_id
from securemailscope.chain.invariants import validate_chain
from securemailscope.chain.models import (
    ChainOfProof,
    DerivedFact,
    EvidenceReference,
    ProtocolEvent,
)
from securemailscope.chain.poc_adapter import (
    CaptureMetadata,
    PocAdapterContext,
    build_chain_from_poc_analysis,
)
from securemailscope.chain.smtp_facts import (
    DERIVATION_PLAINTEXT_COMMANDS_AFTER_OFFER,
    DERIVATION_STARTTLS_ADVERTISED,
    DERIVATION_TLS_UPGRADE_COMPLETED,
    DERIVATION_VERSION,
    FACT_TYPE_PLAINTEXT_COMMANDS_AFTER_OFFER,
    FACT_TYPE_STARTTLS_ADVERTISED,
    FACT_TYPE_TLS_UPGRADE_COMPLETED,
    derive_smtp_transition_facts,
)
from securemailscope.models import (
    AnalyzeResult,
    CaptureFormat,
    CaptureProvenance,
    CompleteStatus,
    Direction,
    Protocol,
    ProvenanceStatus,
    RawFrameObservation,
    SmtpTransition,
    TcpStream,
)
from securemailscope.protocols import classify_stream
from securemailscope.sessions import build_transition

C = Direction.CLIENT_TO_SERVER
S = Direction.SERVER_TO_CLIENT
CFG_DIGEST = "c" * 64
CAPTURE_SHA256 = "a" * 64

SMTP_CAPABILITY_EVENT = ProtocolEventType.CAPABILITY_ADVERTISED
SMTP_PLAINTEXT_EVENT = ProtocolEventType.PLAINTEXT_COMMAND_AFTER_TLS_OFFER
SMTP_REQUESTED_EVENT = ProtocolEventType.TLS_UPGRADE_REQUESTED
SMTP_ACCEPTED_EVENT = ProtocolEventType.TLS_UPGRADE_ACCEPTED
SMTP_REJECTED_EVENT = ProtocolEventType.TLS_UPGRADE_REJECTED
SMTP_FINISHED_EVENT = ProtocolEventType.HANDSHAKE_FINISHED


# ─────────────────────────────────────────────────────────────────────────────
#  Shared helpers (mirror adapter-test conventions)
# ─────────────────────────────────────────────────────────────────────────────


def _provenance(**overrides) -> CaptureProvenance:
    values = dict(
        input_path="capture.pcapng",
        sha256=CAPTURE_SHA256,
        size_bytes=4096,
        capture_format=CaptureFormat.PCAPNG,
        packet_count=28,
        first_epoch_seconds=Decimal("1800000000.100000000"),
        last_epoch_seconds=Decimal("1800000002.300000000"),
        tshark_version="4.2.5",
        capinfos_version="4.2.5",
        status=ProvenanceStatus.OK,
        warnings=[],
    )
    values.update(overrides)
    return CaptureProvenance(**values)


def _context(**overrides) -> PocAdapterContext:
    values = dict(
        capture_metadata=CaptureMetadata(
            link_layer_types=["ethernet"], snaplen=262144, truncated_packet_count=0
        ),
        source_configuration_digest=CFG_DIGEST,
        analyzer_version="securemailscope/0.4.0",
        created_at=datetime(2026, 8, 27, 9, 59, 0, tzinfo=UTC),
        started_at=datetime(2026, 8, 27, 10, 0, 0, tzinfo=UTC),
        completed_at=datetime(2026, 8, 27, 10, 1, 0, tzinfo=UTC),
    )
    values.update(overrides)
    return PocAdapterContext(**values)


def _result(
    streams: list[TcpStream],
    classifications,
    transitions: list[SmtpTransition] | None = None,
) -> AnalyzeResult:
    return AnalyzeResult(
        provenance=_provenance(),
        tool_records=[],
        streams=streams,
        classifications=classifications,
        smtp_transitions=transitions or [],
        warnings=[],
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


def _build_chain(
    frames: list[RawFrameObservation], *, capture_truncation: bool = False
) -> ChainOfProof:
    result, _classification, _transition = _analyze(frames, capture_truncation=capture_truncation)
    return build_chain_from_poc_analysis(result, context=_context())


def _derived(
    frames: list[RawFrameObservation], *, capture_truncation: bool = False
) -> ChainOfProof:
    """Build the adapter chain and immediately derive its SMTP facts."""
    chain = _build_chain(frames, capture_truncation=capture_truncation)
    return derive_smtp_transition_facts(chain)


def _handshake(start: int = 1) -> list[RawFrameObservation]:
    return [
        frame(start, b"", direction=C, syn=True),
        frame(start + 1, b"", direction=S, syn=True, ack=True),
        frame(start + 2, b"", direction=C, ack=True),
    ]


def _accepted_tls_frames() -> list[RawFrameObservation]:
    return [
        *_handshake(),
        frame(4, b"220 secure.example ESMTP\r\n", direction=S),
        frame(5, b"EHLO client.example\r\n", direction=C),
        frame(6, b"250-server.example\r\n", direction=S),
        frame(7, b"250-STARTTLS\r\n", direction=S),
        frame(8, b"250 AUTH LOGIN PLAIN\r\n", direction=S),
        frame(9, b"START", direction=C),
        frame(10, b"", direction=S),
        frame(11, b"TLS\r\n", direction=C),
        frame(12, b"", direction=S),
        frame(13, b"220 2.0.0 Ready to start TLS\r\n", direction=S),
        frame(14, b"", direction=C),
        frame(15, b"\x16\x03\x01\x00\x05", direction=C, tls_handshake_types=(1,)),
        frame(16, b"\x16\x03\x03\x00\x05", direction=S, tls_handshake_types=(2,)),
        frame(17, b"\x16\x03\x03\x00\x05", direction=S, tls_handshake_types=(11,)),
        frame(18, b"\x16\x03\x03\x00\x05", direction=S, tls_handshake_types=(12,)),
        frame(19, b"\x16\x03\x03\x00\x05", direction=S, tls_handshake_types=(16,)),
        frame(20, b"\x16\x03\x03\x00\x05", direction=C, tls_handshake_types=(20,)),
    ]


def _accepted_without_tls_frames() -> list[RawFrameObservation]:
    """Accepted STARTTLS handshake but client continues in plaintext (QUIT)."""
    return [
        *_handshake(),
        frame(4, b"220 secure.example ESMTP\r\n", direction=S),
        frame(5, b"EHLO client.example\r\n", direction=C),
        frame(6, b"250-STARTTLS\r\n", direction=S),
        frame(7, b"STARTTLS\r\n", direction=C),
        frame(8, b"220 OK\r\n", direction=S),
        frame(9, b"QUIT\r\n", direction=C),
        frame(10, b"221 Bye\r\n", direction=S),
    ]


def _accepted_no_finished_no_plaintext_frames() -> list[RawFrameObservation]:
    """Accepted STARTTLS handshake then clean stream close (no QUIT)."""
    return [
        *_handshake(),
        frame(4, b"220 secure.example ESMTP\r\n", direction=S),
        frame(5, b"EHLO client.example\r\n", direction=C),
        frame(6, b"250-STARTTLS\r\n", direction=S),
        frame(7, b"STARTTLS\r\n", direction=C),
        frame(8, b"220 OK\r\n", direction=S),
        frame(9, b"", direction=C, fin=True),
    ]


def _rejected_frames() -> list[RawFrameObservation]:
    return [
        *_handshake(),
        frame(4, b"220 secure.example ESMTP\r\n", direction=S),
        frame(5, b"EHLO client.example\r\n", direction=C),
        frame(6, b"250-STARTTLS\r\n", direction=S),
        frame(7, b"STARTTLS\r\n", direction=C),
        frame(8, b"454 TLS not available\r\n", direction=S),
    ]


def _advertised_only_frames() -> list[RawFrameObservation]:
    """Server advertises STARTTLS; client sends nothing after the capability."""
    return [
        *_handshake(),
        frame(4, b"220 secure.example ESMTP\r\n", direction=S),
        frame(5, b"EHLO client.example\r\n", direction=C),
        frame(6, b"250-STARTTLS\r\n", direction=S),
    ]


def _no_capability_frames() -> list[RawFrameObservation]:
    """Server never advertises STARTTLS; complete capture, no transition."""
    return [
        *_handshake(),
        frame(4, b"220 secure.example ESMTP\r\n", direction=S),
        frame(5, b"EHLO client.example\r\n", direction=C),
        frame(6, b"250 AUTH LOGIN PLAIN\r\n", direction=S),
        frame(7, b"QUIT\r\n", direction=C),
        frame(8, b"221 Bye\r\n", direction=S),
    ]


def _section22_frames() -> list[RawFrameObservation]:
    """Section-22 path: server advertises; client sends plaintext immediately."""
    return [
        *_handshake(),
        frame(4, b"220 secure.example ESMTP\r\n", direction=S),
        frame(5, b"EHLO client.example\r\n", direction=C),
        frame(6, b"250-STARTTLS\r\n", direction=S),
        frame(7, b"MAIL FROM:<alice@example.test>\r\n", direction=C),
        frame(8, b"RCPT TO:<bob@example.test>\r\n", direction=C),
        frame(9, b"QUIT\r\n", direction=C),
    ]


def _events_of(chain: ChainOfProof, event_type: ProtocolEventType):
    return [e for e in chain.protocol_events if e.event_type is event_type]


def _facts_of(chain: ChainOfProof, fact_type: str):
    return [f for f in chain.derived_facts if f.fact_type == fact_type]


def _fact_for(chain: ChainOfProof, fact_type: str) -> DerivedFact:
    results = _facts_of(chain, fact_type)
    assert len(results) == 1
    return results[0]


def _evidence_of(event, chain: ChainOfProof) -> EvidenceReference:
    matches = [node for node in chain.evidence if node.evidence_id in event.evidence_ids]
    assert len(matches) == 1
    return matches[0]


def _external_fact(
    chain: ChainOfProof,
    *,
    fact_type: str = "test.external.fact",
    value: str = "example_value",
    source_event_ids: list[str] | None = None,
) -> DerivedFact:
    session = chain.sessions[0]
    source_ids = (
        source_event_ids
        or [e.event_id for e in chain.protocol_events if e.session_id == session.session_id][:1]
    )
    normalized = canonical_json(value)
    stable_key = fact_stable_key(
        chain.analysis.chain_schema_version,
        session.stable_session_key,
        fact_type,
        normalized,
        source_ids,
        [],
        [],
    )
    return DerivedFact(
        fact_id=fact_id_from_key(stable_key),
        session_id=session.session_id,
        fact_type=fact_type,
        value=value,
        derivation_id="chain.example.external.derivation",
        derivation_version="0.1.0",
        source_event_ids=source_ids,
        source_observation_ids=[],
        source_fact_ids=[],
        observability=ChainObservability.DERIVED,
        confidence_level=ConfidenceLevel.HIGH,
        confidence_basis=["test_external_basis"],
        limitations=[],
    )


def _assert_valid(chain: ChainOfProof) -> None:
    ok, problems = validate_chain(chain)
    assert ok, problems


def _restamp_events(
    chain: ChainOfProof,
    *,
    event_types: frozenset[ProtocolEventType] | None = None,
    protocol: Protocol | None = None,
    event_status: EventStatus = EventStatus.INFERRED,
    observability: ChainObservability = ChainObservability.DERIVED,
    evidence_ids: list[str] | None = None,
) -> ChainOfProof:
    """Copy the chain with select events re-stamped (invariant-valid).

    Used to build adversarial chains in which material evidence is no longer
    directly observed, or carries a non-SMTP protocol label, while still
    satisfying the graph invariants. ``evidence_ids`` is only replaced when
    explicitly given; ``None`` keeps the original evidence references.
    """
    session_id = chain.sessions[0].session_id
    updated: list[ProtocolEvent] = []
    for event in chain.protocol_events:
        if event.session_id == session_id and (
            event_types is None or event.event_type in event_types
        ):
            fields: dict[str, object] = {
                "event_status": event_status,
                "observability": observability,
            }
            if evidence_ids is not None:
                fields["evidence_ids"] = evidence_ids
            if protocol is not None:
                fields["protocol"] = protocol
            updated.append(event.model_copy(update=fields))
        else:
            updated.append(event)
    return chain.model_copy(update={"protocol_events": updated})


def _synthetic_chain(chain: ChainOfProof, *ordered_types: ProtocolEventType) -> ChainOfProof:
    """Rebuild the session's protocol events as the given ordered observed SMTP
    event types, with recomputed sequence indexes/ids and timestamps inside the
    session window."""
    session = chain.sessions[0]
    template = chain.protocol_events[0]
    evidence_id = session.classification_evidence_ids[0]
    events: list[ProtocolEvent] = []
    for index, event_type in enumerate(ordered_types):
        events.append(
            template.model_copy(
                update={
                    "event_id": protocol_event_id(session.session_id, index, event_type.value),
                    "sequence_index": index,
                    "event_type": event_type,
                    "protocol": Protocol.SMTP,
                    "timestamp": session.started_at,
                    "direction": C,
                    "evidence_ids": [evidence_id],
                    "event_status": EventStatus.OBSERVED,
                    "observability": ChainObservability.OBSERVED,
                    "limitations": [],
                }
            )
        )
    return chain.model_copy(update={"protocol_events": events})


def _append_transition(
    chain: ChainOfProof,
    *specs: ProtocolEventType,
) -> tuple[ChainOfProof, list[ProtocolEvent]]:
    """Append observed SMTP transition events after the session's last event."""
    session = chain.sessions[0]
    events = list(chain.protocol_events)
    next_seq = max(event.sequence_index for event in events) + 1
    last_ts = max(event.timestamp for event in events)
    template = events[0]
    evidence_id = session.classification_evidence_ids[0]
    added: list[ProtocolEvent] = []
    for offset, event_type in enumerate(specs):
        added.append(
            template.model_copy(
                update={
                    "event_id": protocol_event_id(
                        session.session_id, next_seq + offset, event_type.value
                    ),
                    "sequence_index": next_seq + offset,
                    "event_type": event_type,
                    "protocol": Protocol.SMTP,
                    "timestamp": last_ts,
                    "direction": C,
                    "evidence_ids": [evidence_id],
                    "event_status": EventStatus.OBSERVED,
                    "observability": ChainObservability.OBSERVED,
                    "limitations": [],
                }
            )
        )
    return chain.model_copy(update={"protocol_events": events + added}), added


# ─────────────────────────────────────────────────────────────────────────────
#  §1 Advertised fact
# ─────────────────────────────────────────────────────────────────────────────

# 1. starttls_advertised emitted with correct properties when capability present


def test_advertised_fact_emitted_with_capability_event() -> None:
    chain = _derived(_section22_frames())
    _assert_valid(chain)

    advertised_events = _events_of(chain, SMTP_CAPABILITY_EVENT)
    assert len(advertised_events) == 1

    fact = _fact_for(chain, FACT_TYPE_STARTTLS_ADVERTISED)
    assert fact.value is True
    assert fact.session_id == chain.sessions[0].session_id
    assert fact.observability is ChainObservability.DERIVED
    assert fact.confidence_level is ConfidenceLevel.HIGH
    assert fact.confidence_basis == ["ordered_starttls_capability_advertisement"]
    assert fact.derivation_id == DERIVATION_STARTTLS_ADVERTISED
    assert fact.derivation_version == DERIVATION_VERSION
    assert fact.limitations == []
    assert len(fact.source_event_ids) == 1
    assert fact.source_event_ids[0] == advertised_events[0].event_id


# 2. advertised fact_id matches independent recomputation


def test_advertised_fact_id_matches_formula() -> None:
    chain = _derived(_section22_frames())
    fact = _fact_for(chain, FACT_TYPE_STARTTLS_ADVERTISED)
    session = chain.sessions[0]
    normalized = canonical_json(fact.value)
    expected_key = fact_stable_key(
        chain.analysis.chain_schema_version,
        session.stable_session_key,
        FACT_TYPE_STARTTLS_ADVERTISED,
        normalized,
        fact.source_event_ids,
        [],
        [],
    )
    assert fact.fact_id == fact_id_from_key(expected_key)


# 3. no fact from absence when server never advertises STARTTLS


def test_no_fact_from_absence_when_no_capability() -> None:
    chain = _derived(_no_capability_frames())
    _assert_valid(chain)

    assert _events_of(chain, SMTP_CAPABILITY_EVENT) == []
    assert chain.derived_facts == []


# ─────────────────────────────────────────────────────────────────────────────
#  §2 Plaintext count
# ─────────────────────────────────────────────────────────────────────────────

# 4. plaintext count == 1 for accepted-without-TLS + QUIT


def test_plaintext_count_one_accepted_without_tls() -> None:
    chain = _derived(_accepted_without_tls_frames())
    _assert_valid(chain)

    plaintext = _events_of(chain, SMTP_PLAINTEXT_EVENT)
    assert len(plaintext) == 1
    assert _evidence_of(plaintext[0], chain).frame_numbers[0] == 9

    fact = _fact_for(chain, FACT_TYPE_PLAINTEXT_COMMANDS_AFTER_OFFER)
    assert fact.value == 1
    assert fact.observability is ChainObservability.DERIVED
    assert fact.confidence_level is ConfidenceLevel.HIGH
    assert fact.confidence_basis == ["ordered_plaintext_command_after_offer"]
    assert fact.derivation_id == DERIVATION_PLAINTEXT_COMMANDS_AFTER_OFFER
    assert fact.limitations == []


# 5. plaintext count == 3 for section-22 frames


def test_plaintext_count_three_section_22_no_request() -> None:
    chain = _derived(_section22_frames())
    _assert_valid(chain)

    plaintext = _events_of(chain, SMTP_PLAINTEXT_EVENT)
    assert [_evidence_of(e, chain).frame_numbers[0] for e in plaintext] == [7, 8, 9]

    fact = _fact_for(chain, FACT_TYPE_PLAINTEXT_COMMANDS_AFTER_OFFER)
    assert fact.value == 3


# 6. body/bdat lines excluded; only command lines counted


def test_plaintext_count_excludes_body_and_bdat_lines() -> None:
    frames = [
        *_handshake(),
        frame(4, b"220 secure.example ESMTP\r\n", direction=S),
        frame(5, b"EHLO client.example\r\n", direction=C),
        frame(6, b"250-STARTTLS\r\n", direction=S),
        frame(7, b"DATA\r\n", direction=C),
        frame(8, b"Subject: hello\r\n", direction=C),
        frame(9, b"body line\r\n", direction=C),
        frame(10, b".\r\n", direction=C),
        frame(11, b"BDAT 5\r\n", direction=C),
        frame(12, b"MAIL FROM:<chunk@example.test>\r\n", direction=C),
        frame(13, b"QUIT\r\n", direction=C),
    ]
    chain = _derived(frames)
    _assert_valid(chain)

    # DATA counts once; the message body and terminator do not; BDAT counts
    # once and its chunk payload is absorbed, so the chunk-hook MAIL/QUIT are
    # never counted.
    plaintext = _events_of(chain, SMTP_PLAINTEXT_EVENT)
    assert [_evidence_of(e, chain).frame_numbers[0] for e in plaintext] == [7, 11]

    fact = _fact_for(chain, FACT_TYPE_PLAINTEXT_COMMANDS_AFTER_OFFER)
    assert fact.value == 2


# 7. no plaintext fact before offer or for non-command verbs


def test_no_plaintext_fact_before_offer_or_non_commands() -> None:
    frames = [
        *_handshake(),
        frame(4, b"220 secure.example ESMTP\r\n", direction=S),
        frame(5, b"MAIL FROM:<early@example.test>\r\n", direction=C),
        frame(6, b"EHLO client.example\r\n", direction=C),
        frame(7, b"250-STARTTLS\r\n", direction=S),
        frame(8, b"MAILBOX invalid\r\n", direction=C),
        frame(9, b"XABC extension\r\n", direction=C),
    ]
    chain = _derived(frames)
    _assert_valid(chain)

    assert _events_of(chain, SMTP_PLAINTEXT_EVENT) == []
    # advertised fact IS present (capability observed); no plaintext fact
    assert _facts_of(chain, FACT_TYPE_PLAINTEXT_COMMANDS_AFTER_OFFER) == []
    assert len(_facts_of(chain, FACT_TYPE_STARTTLS_ADVERTISED)) == 1


# ─────────────────────────────────────────────────────────────────────────────
#  EHLO/HELO after the STARTTLS offer (plaintext continuation)
# ─────────────────────────────────────────────────────────────────────────────


def _post_offer(verb: str) -> list[RawFrameObservation]:
    """Advertisement followed by a post-offer EHLO/HELO (no request/accept/reject)."""
    return [
        *_handshake(),
        frame(4, b"220 secure.example ESMTP\r\n", direction=S),
        frame(5, b"EHLO client.example\r\n", direction=C),
        frame(6, b"250-STARTTLS\r\n", direction=S),
        frame(7, f"{verb} client.example\r\n".encode(), direction=C),
    ]


def test_post_offer_ehlo_counts_one_and_false_completion() -> None:
    chain = _derived(_post_offer("EHLO"))
    _assert_valid(chain)

    plaintext = _events_of(chain, SMTP_PLAINTEXT_EVENT)
    assert [_evidence_of(e, chain).frame_numbers[0] for e in plaintext] == [7]

    count = _fact_for(chain, FACT_TYPE_PLAINTEXT_COMMANDS_AFTER_OFFER)
    assert count.value == 1
    assert count.confidence_basis == ["ordered_plaintext_command_after_offer"]

    completed = _fact_for(chain, FACT_TYPE_TLS_UPGRADE_COMPLETED)
    assert completed.value is False
    assert completed.confidence_basis == [
        "ordered_plaintext_continuation_before_tls_completion",
    ]
    advertised = _events_of(chain, SMTP_CAPABILITY_EVENT)
    assert completed.source_event_ids == [
        e.event_id for e in sorted(advertised + plaintext, key=lambda e: e.sequence_index)
    ]


def test_post_offer_helo_counts_one_and_false_completion() -> None:
    chain = _derived(_post_offer("HELO"))
    _assert_valid(chain)

    plaintext = _events_of(chain, SMTP_PLAINTEXT_EVENT)
    assert [_evidence_of(e, chain).frame_numbers[0] for e in plaintext] == [7]

    count = _fact_for(chain, FACT_TYPE_PLAINTEXT_COMMANDS_AFTER_OFFER)
    assert count.value == 1

    completed = _fact_for(chain, FACT_TYPE_TLS_UPGRADE_COMPLETED)
    assert completed.value is False
    assert completed.confidence_basis == [
        "ordered_plaintext_continuation_before_tls_completion",
    ]


def test_ehlo_before_advertisement_is_not_counted() -> None:
    frames = [
        *_handshake(),
        frame(4, b"220 secure.example ESMTP\r\n", direction=S),
        frame(5, b"EHLO client.example\r\n", direction=C),
        frame(6, b"250-STARTTLS\r\n", direction=S),
        frame(7, b"250 AUTH LOGIN PLAIN\r\n", direction=S),
    ]
    chain = _derived(frames)
    _assert_valid(chain)

    # The only EHLO precedes the advertisement, so it stays a CAPABILITY_REQUEST
    assert _events_of(chain, SMTP_PLAINTEXT_EVENT) == []
    capability_requests = _events_of(chain, ProtocolEventType.CAPABILITY_REQUEST)
    assert len(capability_requests) == 1
    assert _facts_of(chain, FACT_TYPE_PLAINTEXT_COMMANDS_AFTER_OFFER) == []


def test_ehlo_before_offer_and_ehlo_after_offer_only_after_counts() -> None:
    frames = [
        *_handshake(),
        frame(4, b"220 secure.example ESMTP\r\n", direction=S),
        frame(5, b"EHLO client.example\r\n", direction=C),
        frame(6, b"250-STARTTLS\r\n", direction=S),
        frame(7, b"EHLO client.example\r\n", direction=C),
    ]
    chain = _derived(frames)
    _assert_valid(chain)

    requests = _events_of(chain, ProtocolEventType.CAPABILITY_REQUEST)
    assert len(requests) == 1
    assert _evidence_of(requests[0], chain).frame_numbers[0] == 5

    plaintext = _events_of(chain, SMTP_PLAINTEXT_EVENT)
    assert [_evidence_of(e, chain).frame_numbers[0] for e in plaintext] == [7]

    count = _fact_for(chain, FACT_TYPE_PLAINTEXT_COMMANDS_AFTER_OFFER)
    assert count.value == 1


def test_multiple_post_offer_commands_in_one_frame_are_deterministic() -> None:
    frames = [
        *_handshake(),
        frame(4, b"220 secure.example ESMTP\r\n", direction=S),
        frame(5, b"EHLO client.example\r\n", direction=C),
        frame(6, b"250-STARTTLS\r\n", direction=S),
        frame(7, b"EHLO client.example\r\nMAIL FROM:<a@example.test>\r\n", direction=C),
    ]
    chain = _derived(frames)
    _assert_valid(chain)

    plaintext = _events_of(chain, SMTP_PLAINTEXT_EVENT)
    assert [_evidence_of(e, chain).frame_numbers[0] for e in plaintext] == [7, 7]
    evidence_indexes = [_evidence_of(e, chain).occurrence_index for e in plaintext]
    assert evidence_indexes == [0, 1]

    count = _fact_for(chain, FACT_TYPE_PLAINTEXT_COMMANDS_AFTER_OFFER)
    assert count.value == 2

    completed = _fact_for(chain, FACT_TYPE_TLS_UPGRADE_COMPLETED)
    assert completed.value is False
    assert completed.confidence_basis == [
        "ordered_plaintext_continuation_before_tls_completion",
    ]
    advertised = _events_of(chain, SMTP_CAPABILITY_EVENT)
    assert completed.source_event_ids == [
        e.event_id for e in sorted(advertised + plaintext, key=lambda e: e.sequence_index)
    ]


# ─────────────────────────────────────────────────────────────────────────────
#  §3 Completed == True
# ─────────────────────────────────────────────────────────────────────────────

# 8. true when requested < accepted < finished (ordered triple)


def test_completed_true_ordered_triple() -> None:
    chain = _derived(_accepted_tls_frames())
    _assert_valid(chain)

    requested = _events_of(chain, SMTP_REQUESTED_EVENT)
    accepted = _events_of(chain, SMTP_ACCEPTED_EVENT)
    finished = _events_of(chain, SMTP_FINISHED_EVENT)
    assert len(requested) == 1
    assert len(accepted) == 1
    assert len(finished) == 1

    fact = _fact_for(chain, FACT_TYPE_TLS_UPGRADE_COMPLETED)
    assert fact.value is True
    assert fact.observability is ChainObservability.DERIVED
    assert fact.confidence_level is ConfidenceLevel.HIGH
    assert fact.confidence_basis == ["ordered_starttls_acceptance_and_handshake_finished"]
    assert fact.derivation_id == DERIVATION_TLS_UPGRADE_COMPLETED
    assert fact.limitations == []


# 9. completed true fact_id matches independent formula


def test_completed_true_id_matches_formula() -> None:
    chain = _derived(_accepted_tls_frames())
    fact = _fact_for(chain, FACT_TYPE_TLS_UPGRADE_COMPLETED)
    session = chain.sessions[0]
    normalized = canonical_json(fact.value)
    expected_key = fact_stable_key(
        chain.analysis.chain_schema_version,
        session.stable_session_key,
        FACT_TYPE_TLS_UPGRADE_COMPLETED,
        normalized,
        fact.source_event_ids,
        [],
        [],
    )
    assert fact.fact_id == fact_id_from_key(expected_key)


# 10. completed true sources are exactly [requested, accepted, finished]


def test_completed_true_sources_three_events() -> None:
    chain = _derived(_accepted_tls_frames())
    fact = _fact_for(chain, FACT_TYPE_TLS_UPGRADE_COMPLETED)
    expected_ids = [
        e.event_id
        for e in sorted(chain.protocol_events, key=lambda e: e.sequence_index)
        if e.event_type in (SMTP_REQUESTED_EVENT, SMTP_ACCEPTED_EVENT, SMTP_FINISHED_EVENT)
    ]
    assert fact.source_event_ids == expected_ids
    assert len(fact.source_event_ids) == 3


# ─────────────────────────────────────────────────────────────────────────────
#  §4 Completed == False
# ─────────────────────────────────────────────────────────────────────────────

# 11. false basis (1): rejection after request


def test_completed_false_rejection() -> None:
    chain = _derived(_rejected_frames())
    _assert_valid(chain)

    fact = _fact_for(chain, FACT_TYPE_TLS_UPGRADE_COMPLETED)
    assert fact.value is False
    assert fact.observability is ChainObservability.DERIVED
    assert fact.confidence_level is ConfidenceLevel.HIGH
    assert fact.confidence_basis == ["ordered_starttls_rejection"]
    assert fact.limitations == []

    requested = _events_of(chain, SMTP_REQUESTED_EVENT)
    rejected = _events_of(chain, SMTP_REJECTED_EVENT)
    assert fact.source_event_ids == [
        e.event_id for e in sorted(requested + rejected, key=lambda e: e.sequence_index)
    ]


# 12. false basis (3): accepted followed by plaintext, no finished, capture complete


def test_completed_false_accepted_with_plaintext() -> None:
    chain = _derived(_accepted_without_tls_frames())
    _assert_valid(chain)

    assert chain.sessions[0].capture_completeness is CompleteStatus.COMPLETE

    fact = _fact_for(chain, FACT_TYPE_TLS_UPGRADE_COMPLETED)
    assert fact.value is False
    assert fact.confidence_basis == ["accepted_upgrade_followed_by_observed_plaintext"]

    # sources are exactly the accepted attempt's request + acceptance and the
    # qualifying plaintext command after the acceptance
    requested = _events_of(chain, SMTP_REQUESTED_EVENT)
    accepted = _events_of(chain, SMTP_ACCEPTED_EVENT)
    plaintext = _events_of(chain, SMTP_PLAINTEXT_EVENT)
    assert fact.source_event_ids == [
        e.event_id for e in sorted(requested + accepted + plaintext, key=lambda e: e.sequence_index)
    ]


# 13. false basis (2): advertised + plaintext, no request/reject/accept, capture complete


def test_completed_false_advertised_with_plaintext() -> None:
    chain = _derived(_section22_frames())
    _assert_valid(chain)

    assert chain.sessions[0].capture_completeness is CompleteStatus.INSUFFICIENT
    # Gate is "not capture-incomplete"; INSUFFICIENT satisfies this gate
    fact = _fact_for(chain, FACT_TYPE_TLS_UPGRADE_COMPLETED)
    assert fact.value is False
    assert fact.confidence_basis == [
        "ordered_plaintext_continuation_before_tls_completion",
    ]

    advertised = _events_of(chain, SMTP_CAPABILITY_EVENT)
    plaintext = _events_of(chain, SMTP_PLAINTEXT_EVENT)
    assert fact.source_event_ids == [
        e.event_id for e in sorted(advertised + plaintext, key=lambda e: e.sequence_index)
    ]


# 14. incomplete capture blocks false basis (3)


def test_completed_incomplete_capture_gate_blocks_false_basis_3() -> None:
    frames = [
        *_handshake(),
        frame(4, b"220 secure.example ESMTP\r\n", direction=S),
        frame(5, b"EHLO client.example\r\n", direction=C),
        frame(6, b"250-STARTTLS\r\n", direction=S),
        frame(7, b"STARTTLS\r\n", direction=C),
        frame(8, b"220 OK\r\n", direction=S),
        frame(9, b"QUIT\r\n", direction=C),
    ]
    chain = _derived(frames, capture_truncation=True)
    _assert_valid(chain)

    assert chain.sessions[0].capture_completeness is CompleteStatus.CAPTURE_INCOMPLETE

    fact = _fact_for(chain, FACT_TYPE_TLS_UPGRADE_COMPLETED)
    assert fact.value == "incomplete_capture"
    assert fact.observability is ChainObservability.INCOMPLETE_CAPTURE
    assert fact.confidence_level is ConfidenceLevel.NOT_SCORED
    assert fact.confidence_basis == ["capture_ended_before_tls_transition_completion"]
    assert len(fact.limitations) == 1
    assert fact.limitations[0].code is LimitationCode.CAPTURE_INCOMPLETE


# 15. incomplete capture blocks false basis (2)


def test_completed_incomplete_capture_gate_blocks_false_basis_2() -> None:
    frames = [
        *_handshake(),
        frame(4, b"220 secure.example ESMTP\r\n", direction=S),
        frame(5, b"EHLO client.example\r\n", direction=C),
        frame(6, b"250-STARTTLS\r\n", direction=S),
        frame(7, b"MAIL FROM:<alice@example.test>\r\n", direction=C),
        frame(8, b"STA", direction=C),  # truncated mid-STARTTLS
    ]
    chain = _derived(frames, capture_truncation=True)
    _assert_valid(chain)

    assert chain.sessions[0].capture_completeness is CompleteStatus.CAPTURE_INCOMPLETE

    fact = _fact_for(chain, FACT_TYPE_TLS_UPGRADE_COMPLETED)
    assert fact.value == "incomplete_capture"
    assert fact.limitations[0].code is LimitationCode.CAPTURE_INCOMPLETE


# 16. advertised-only with capture truncated: only advertised fact, no completed fact


def test_only_advertised_no_positive_evidence_never_fabricates() -> None:
    frames = [
        *_handshake(),
        frame(4, b"220 secure.example ESMTP\r\n", direction=S),
        frame(5, b"EHLO client.example\r\n", direction=C),
        frame(6, b"250-STARTTLS\r\n", direction=S),
    ]
    chain = _derived(frames, capture_truncation=True)
    _assert_valid(chain)

    # The analyzer cannot mark a session capture_incomplete without a STARTTLS
    # command; the point is that no positive evidence ever fabricates a fact.
    assert chain.sessions[0].capture_completeness is CompleteStatus.INSUFFICIENT
    positive = [
        e
        for e in chain.protocol_events
        if e.event_type
        in (
            SMTP_REQUESTED_EVENT,
            SMTP_ACCEPTED_EVENT,
            SMTP_REJECTED_EVENT,
            SMTP_PLAINTEXT_EVENT,
        )
    ]
    assert positive == []

    # advertised present; no completed fact emitted at all
    assert len(_facts_of(chain, FACT_TYPE_STARTTLS_ADVERTISED)) == 1
    assert _facts_of(chain, FACT_TYPE_TLS_UPGRADE_COMPLETED) == []


# ─────────────────────────────────────────────────────────────────────────────
#  §5 Completed == unknown / incomplete
# ─────────────────────────────────────────────────────────────────────────────

# 17. accepted no finished no plaintext (complete capture) → unknown


def test_completed_unknown_accepted_no_finished_no_plaintext() -> None:
    chain = _derived(_accepted_no_finished_no_plaintext_frames())
    _assert_valid(chain)

    assert chain.sessions[0].capture_completeness is CompleteStatus.COMPLETE
    assert _events_of(chain, SMTP_PLAINTEXT_EVENT) == []

    fact = _fact_for(chain, FACT_TYPE_TLS_UPGRADE_COMPLETED)
    assert fact.value == "unknown_insufficient_evidence"
    assert fact.observability is ChainObservability.NOT_OBSERVABLE
    assert fact.confidence_level is ConfidenceLevel.NOT_SCORED
    assert fact.confidence_basis == ["insufficient_ordered_evidence_for_tls_completion"]
    assert len(fact.limitations) == 1
    assert fact.limitations[0].code is LimitationCode.UNKNOWN_INSUFFICIENT_EVIDENCE

    requested = _events_of(chain, SMTP_REQUESTED_EVENT)
    accepted = _events_of(chain, SMTP_ACCEPTED_EVENT)
    assert fact.source_event_ids == [
        e.event_id for e in sorted(requested + accepted, key=lambda e: e.sequence_index)
    ]


# 18. accepted no finished no plaintext (capture truncated) → incomplete_capture


def test_completed_incomplete_accepted_no_finished_no_plaintext() -> None:
    frames = [
        *_handshake(),
        frame(4, b"220 secure.example ESMTP\r\n", direction=S),
        frame(5, b"EHLO client.example\r\n", direction=C),
        frame(6, b"250-STARTTLS\r\n", direction=S),
        frame(7, b"STARTTLS\r\n", direction=C),
        frame(8, b"220 OK\r\n", direction=S),
    ]
    chain = _derived(frames, capture_truncation=True)
    _assert_valid(chain)

    assert chain.sessions[0].capture_completeness is CompleteStatus.CAPTURE_INCOMPLETE
    assert _events_of(chain, SMTP_PLAINTEXT_EVENT) == []

    fact = _fact_for(chain, FACT_TYPE_TLS_UPGRADE_COMPLETED)
    assert fact.value == "incomplete_capture"
    assert fact.observability is ChainObservability.INCOMPLETE_CAPTURE
    assert fact.limitations[0].code is LimitationCode.CAPTURE_INCOMPLETE


# 19. rejection is unconditional under truncation → false, not incomplete


def test_completed_false_rejection_unconditional_under_truncation() -> None:
    frames = [
        *_handshake(),
        frame(4, b"220 secure.example ESMTP\r\n", direction=S),
        frame(5, b"EHLO client.example\r\n", direction=C),
        frame(6, b"250-STARTTLS\r\n", direction=S),
        frame(7, b"STARTTLS\r\n", direction=C),
        frame(8, b"454 TLS not available\r\n", direction=S),
    ]
    chain = _derived(frames, capture_truncation=True)
    _assert_valid(chain)

    assert chain.sessions[0].capture_completeness is CompleteStatus.CAPTURE_INCOMPLETE

    fact = _fact_for(chain, FACT_TYPE_TLS_UPGRADE_COMPLETED)
    assert fact.value is False
    assert fact.observability is ChainObservability.DERIVED
    assert fact.confidence_level is ConfidenceLevel.HIGH
    assert fact.confidence_basis == ["ordered_starttls_rejection"]
    assert fact.limitations == []


# ─────────────────────────────────────────────────────────────────────────────
#  §6 No C-fact at all (silent session)
# ─────────────────────────────────────────────────────────────────────────────

# 20. advertised-only silent session → only advertised, no completed fact


def test_no_completed_fact_advertised_only_silent() -> None:
    chain = _derived(_advertised_only_frames())
    _assert_valid(chain)

    assert len(_facts_of(chain, FACT_TYPE_STARTTLS_ADVERTISED)) == 1
    assert _facts_of(chain, FACT_TYPE_TLS_UPGRADE_COMPLETED) == []

    positive = [
        e
        for e in chain.protocol_events
        if e.event_type
        in (
            SMTP_REQUESTED_EVENT,
            SMTP_ACCEPTED_EVENT,
            SMTP_REJECTED_EVENT,
            SMTP_PLAINTEXT_EVENT,
        )
    ]
    assert positive == []


# ─────────────────────────────────────────────────────────────────────────────
#  §7 Non-SMTP session skipped
# ─────────────────────────────────────────────────────────────────────────────

# 21. non-SMTP stream produces UNKNOWN session; no facts derived


def test_non_smtp_session_skipped() -> None:
    frames = [
        *_handshake(),
        frame(4, b"\x16\x03\x01\x00\x05", direction=C, tls_handshake_types=(1,)),
    ]
    chain = _derived(frames)
    _assert_valid(chain)

    assert chain.sessions[0].protocol is Protocol.UNKNOWN
    assert chain.derived_facts == []

    derived = derive_smtp_transition_facts(chain)
    assert derived.derived_facts == []


# ─────────────────────────────────────────────────────────────────────────────
#  §8 Idempotence
# ─────────────────────────────────────────────────────────────────────────────

# 22. derive(derive(chain)) == derive(chain) for representative frames


def _content_hash(chain: ChainOfProof) -> str:
    from securemailscope.chain.canonical import canonical_content_hash

    return canonical_content_hash(chain)


@pytest.mark.parametrize(
    "label,frames,capture_truncation",
    [
        ("accepted", _accepted_tls_frames(), False),
        ("section22", _section22_frames(), False),
        ("truncated", _accepted_without_tls_frames(), True),
        ("no_finished", _accepted_no_finished_no_plaintext_frames(), False),
    ],
)
def test_idempotence(
    label: str,
    frames: list[RawFrameObservation],
    capture_truncation: bool,
) -> None:
    chain = _build_chain(frames, capture_truncation=capture_truncation)
    once = derive_smtp_transition_facts(chain)
    twice = derive_smtp_transition_facts(once)

    _assert_valid(once)
    _assert_valid(twice)
    assert _content_hash(once) == _content_hash(twice)
    assert len(once.derived_facts) == len(twice.derived_facts)
    for f1, f2 in zip(once.derived_facts, twice.derived_facts, strict=True):
        assert f1.model_dump() == f2.model_dump()


# ─────────────────────────────────────────────────────────────────────────────
#  §9 Unrelated (non-owned) fact preserved
# ─────────────────────────────────────────────────────────────────────────────

# 23. external fact preserved byte-for-byte; owned facts added; chain valid


def test_unrelated_fact_preserved() -> None:
    chain = _derived(_accepted_tls_frames())
    external = _external_fact(chain)
    chain_with_external = chain.model_copy(
        update={"derived_facts": list(chain.derived_facts) + [external]}
    )
    _assert_valid(chain_with_external)

    derived = derive_smtp_transition_facts(chain_with_external)
    _assert_valid(derived)

    external_ids = [f.fact_id for f in derived.derived_facts if f.fact_type == "test.external.fact"]
    assert len(external_ids) == 1
    ext = [f for f in derived.derived_facts if f.fact_id == external_ids[0]][0]
    assert ext.model_dump() == external.model_dump()

    owned_ids = [f.derivation_id for f in derived.derived_facts]
    assert DERIVATION_STARTTLS_ADVERTISED in owned_ids
    assert DERIVATION_TLS_UPGRADE_COMPLETED in owned_ids


# ─────────────────────────────────────────────────────────────────────────────
#  §10 Deterministic ordering
# ─────────────────────────────────────────────────────────────────────────────

# 24. within one session, facts sort by (fact_type, value, id)


def test_deterministic_ordering_within_session() -> None:
    chain = _derived(_section22_frames())
    derived = derive_smtp_transition_facts(chain)
    _assert_valid(derived)

    types = [f.fact_type for f in derived.derived_facts]
    assert types == sorted(types)

    # plaintext < starttls_advertised < tls_upgrade_completed alphabetically
    assert types == [
        FACT_TYPE_PLAINTEXT_COMMANDS_AFTER_OFFER,
        FACT_TYPE_STARTTLS_ADVERTISED,
        FACT_TYPE_TLS_UPGRADE_COMPLETED,
    ]


# 25. multi-session ordering: session 0 facts precede session 1 facts


def test_multi_session_ordering() -> None:
    fr1 = _handshake() + [
        frame(4, b"220 one ESMTP\r\n", direction=S),
        frame(5, b"EHLO c\r\n", direction=C),
        frame(6, b"250-STARTTLS\r\n", direction=S),
    ]
    raw2 = _handshake(start=101) + [
        frame(104, b"220 two ESMTP\r\n", direction=S),
        frame(105, b"EHLO c\r\n", direction=C),
        frame(106, b"250-STARTTLS\r\n", direction=S),
        frame(107, b"QUIT\r\n", direction=C),
    ]
    fr2 = [f.model_copy(update={"tcp_stream": 1}) for f in raw2]

    s1 = stream(fr1).model_copy(update={"stream_id": 0})
    s2 = stream(fr2).model_copy(update={"stream_id": 1, "server_port": 2526})
    cl1, cl2 = classify_stream(s1), classify_stream(s2)
    tr1, tr2 = build_transition(s1), build_transition(s2)
    r = AnalyzeResult(
        provenance=_provenance(),
        tool_records=[],
        streams=[s1, s2],
        classifications=[
            cl1.model_copy(update={"tcp_stream": 0}),
            cl2.model_copy(update={"tcp_stream": 1}),
        ],
        smtp_transitions=[
            tr1.model_copy(update={"tcp_stream": 0}),
            tr2.model_copy(update={"tcp_stream": 1}),
        ],
        warnings=[],
    )
    chain = build_chain_from_poc_analysis(r, context=_context())
    _assert_valid(chain)

    assert len(chain.sessions) == 2
    sid0 = chain.sessions[0].session_id
    sid1 = chain.sessions[1].session_id

    derived = derive_smtp_transition_facts(chain)
    _assert_valid(derived)

    # session 0 is advertised-only → one fact; session 1 is section-22 → three facts
    assert len(derived.derived_facts) == 4

    fact_session_ids = [f.session_id for f in derived.derived_facts]
    assert fact_session_ids[:1] == [sid0]
    assert fact_session_ids[1:] == [sid1] * 3

    # within session 1, fact_type ordering is alphabetical
    s1_types = [f.fact_type for f in derived.derived_facts if f.session_id == sid1]
    assert s1_types == sorted(s1_types)
    assert s1_types == [
        FACT_TYPE_PLAINTEXT_COMMANDS_AFTER_OFFER,
        FACT_TYPE_STARTTLS_ADVERTISED,
        FACT_TYPE_TLS_UPGRADE_COMPLETED,
    ]


# ─────────────────────────────────────────────────────────────────────────────
#  §11 Invalid input fail-closed
# ─────────────────────────────────────────────────────────────────────────────

# 26. invalid non-owned fact (corrupted identity) → ChainValidationError


def test_invalid_input_fail_closed() -> None:
    chain = _derived(_accepted_tls_frames())
    external = _external_fact(chain)
    corrupted = external.model_copy(update={"value": "corrupted_value"})
    corrupted_chain = chain.model_copy(
        update={"derived_facts": list(chain.derived_facts) + [corrupted]}
    )
    with pytest.raises(ChainValidationError):
        derive_smtp_transition_facts(corrupted_chain)


# ─────────────────────────────────────────────────────────────────────────────
#  §12 Full invariant validity
# ─────────────────────────────────────────────────────────────────────────────

# 27. derived output satisfies invariants across representative scenarios


@pytest.mark.parametrize(
    "label,frames,capture_truncation",
    [
        ("accepted", _accepted_tls_frames(), False),
        ("rejected", _rejected_frames(), False),
        ("accepted_without_tls", _accepted_without_tls_frames(), False),
        ("section22", _section22_frames(), False),
        ("no_finished", _accepted_no_finished_no_plaintext_frames(), False),
        ("truncated_accepted", _accepted_without_tls_frames(), True),
        ("truncated_section22", _section22_frames(), True),
    ],
)
def test_full_invariant_validity(
    label: str,
    frames: list[RawFrameObservation],
    capture_truncation: bool,
) -> None:
    chain = _build_chain(frames, capture_truncation=capture_truncation)
    derived = derive_smtp_transition_facts(chain)
    ok, problems = validate_chain(derived)
    assert ok, f"invariant violations for {label}: {problems}"


# ─────────────────────────────────────────────────────────────────────────────
#  §13 Observed-only eligibility (adversarial)
# ─────────────────────────────────────────────────────────────────────────────

# 28. an inferred capability never supports advertised/count/completed facts


def test_inferred_capability_suppresses_all_facts() -> None:
    base = _build_chain(_section22_frames())
    chain = _restamp_events(
        base,
        event_types=frozenset({SMTP_CAPABILITY_EVENT}),
        evidence_ids=[],
    )
    _assert_valid(chain)

    derived = derive_smtp_transition_facts(chain)
    _assert_valid(derived)
    assert derived.derived_facts == []


# 29. inferred plaintext never counted and never supports a false conclusion


def test_inferred_plaintext_not_counted_no_high_confidence() -> None:
    base = _build_chain(_section22_frames())
    chain = _restamp_events(
        base,
        event_types=frozenset({SMTP_PLAINTEXT_EVENT}),
        evidence_ids=[],
    )
    _assert_valid(chain)

    derived = derive_smtp_transition_facts(chain)
    _assert_valid(derived)

    assert len(_facts_of(derived, FACT_TYPE_STARTTLS_ADVERTISED)) == 1
    assert _facts_of(derived, FACT_TYPE_PLAINTEXT_COMMANDS_AFTER_OFFER) == []
    assert _facts_of(derived, FACT_TYPE_TLS_UPGRADE_COMPLETED) == []


# 30. inferred accept/finish never produces a high-confidence true fact


def test_inferred_accept_and_finish_never_true() -> None:
    base = _build_chain(_accepted_tls_frames())
    chain = _restamp_events(
        base,
        event_types=frozenset({SMTP_ACCEPTED_EVENT, SMTP_FINISHED_EVENT}),
        evidence_ids=[],
    )
    _assert_valid(chain)

    derived = derive_smtp_transition_facts(chain)
    _assert_valid(derived)

    facts = _facts_of(derived, FACT_TYPE_TLS_UPGRADE_COMPLETED)
    assert len(facts) == 1
    assert facts[0].value == "unknown_insufficient_evidence"
    assert facts[0].observability is ChainObservability.NOT_OBSERVABLE
    assert facts[0].confidence_level is ConfidenceLevel.NOT_SCORED

    requested = _events_of(derived, SMTP_REQUESTED_EVENT)
    assert len(requested) == 1
    assert requested[0].event_status is EventStatus.OBSERVED
    assert facts[0].source_event_ids == [requested[0].event_id]


# ─────────────────────────────────────────────────────────────────────────────
#  §14 Protocol isolation (adversarial)
# ─────────────────────────────────────────────────────────────────────────────

# 31. non-SMTP events inside an SMTP session are ignored entirely


def test_non_smtp_events_ignored_inside_smtp_session() -> None:
    base = _build_chain(_section22_frames())
    chain = _restamp_events(
        base,
        protocol=Protocol.IMAP,
        event_status=EventStatus.OBSERVED,
        observability=ChainObservability.OBSERVED,
    )
    _assert_valid(chain)

    derived = derive_smtp_transition_facts(chain)
    _assert_valid(derived)
    assert derived.derived_facts == []


# ─────────────────────────────────────────────────────────────────────────────
#  §15 Handshake-only evidence never decides completion (ClientHello)
# ─────────────────────────────────────────────────────────────────────────────

# 32. an observed ClientHello without request/accept/plaintext emits nothing


def test_client_hello_only_no_completed_fact() -> None:
    frames = [
        *_handshake(),
        frame(4, b"220 secure.example ESMTP\r\n", direction=S),
        frame(5, b"EHLO client.example\r\n", direction=C),
        frame(6, b"250-STARTTLS\r\n", direction=S),
        frame(7, b"\x16\x03\x01\x00\x05", direction=C, tls_handshake_types=(1,)),
    ]
    chain = _build_chain(frames)
    _assert_valid(chain)

    assert chain.sessions[0].protocol is Protocol.SMTP
    assert len(_events_of(chain, ProtocolEventType.CLIENT_HELLO)) == 1

    derived = derive_smtp_transition_facts(chain)
    _assert_valid(derived)

    assert len(_facts_of(derived, FACT_TYPE_STARTTLS_ADVERTISED)) == 1
    assert _facts_of(derived, FACT_TYPE_PLAINTEXT_COMMANDS_AFTER_OFFER) == []
    assert _facts_of(derived, FACT_TYPE_TLS_UPGRADE_COMPLETED) == []


# ─────────────────────────────────────────────────────────────────────────────
#  §16 Ordered attempt scan (adversarial)
# ─────────────────────────────────────────────────────────────────────────────

# 33. a completed second attempt is a true fact sourced only to that attempt


def test_completed_true_from_second_attempt_exact_sources() -> None:
    base = _build_chain(_rejected_frames())
    chain, (r2, a2, f2) = _append_transition(
        base, SMTP_REQUESTED_EVENT, SMTP_ACCEPTED_EVENT, SMTP_FINISHED_EVENT
    )
    _assert_valid(chain)

    derived = derive_smtp_transition_facts(chain)
    _assert_valid(derived)

    fact = _fact_for(derived, FACT_TYPE_TLS_UPGRADE_COMPLETED)
    assert fact.value is True
    assert fact.source_event_ids == [r2.event_id, a2.event_id, f2.event_id]


# 34. a request after a rejection is never retroactively paired with it


def test_later_request_after_rejection_not_retroactively_paired() -> None:
    base = _build_chain(_rejected_frames())
    chain, (r2,) = _append_transition(base, SMTP_REQUESTED_EVENT)
    _assert_valid(chain)

    derived = derive_smtp_transition_facts(chain)
    _assert_valid(derived)

    fact = _fact_for(derived, FACT_TYPE_TLS_UPGRADE_COMPLETED)
    assert fact.value is False

    original_request = min(
        _events_of(derived, SMTP_REQUESTED_EVENT), key=lambda e: e.sequence_index
    )
    (rejected,) = _events_of(derived, SMTP_REJECTED_EVENT)
    assert sorted(fact.source_event_ids) == sorted([original_request.event_id, rejected.event_id])
    assert r2.event_id not in fact.source_event_ids


# 35. a completed early attempt wins; later attempts are not mixed into sources


def test_completed_true_picks_earliest_triple_only() -> None:
    base = _build_chain(_accepted_tls_frames())
    chain, added = _append_transition(
        base, SMTP_REQUESTED_EVENT, SMTP_ACCEPTED_EVENT, SMTP_FINISHED_EVENT
    )
    _assert_valid(chain)

    derived = derive_smtp_transition_facts(chain)
    _assert_valid(derived)

    fact = _fact_for(derived, FACT_TYPE_TLS_UPGRADE_COMPLETED)
    assert fact.value is True
    assert len(fact.source_event_ids) == 3
    assert {e.event_id for e in added}.isdisjoint(fact.source_event_ids)


# ─────────────────────────────────────────────────────────────────────────────
#  §17 Plaintext ordering (adversarial)
# ─────────────────────────────────────────────────────────────────────────────

# 36. plaintext before every advertisement is never counted and never a fact


def test_plaintext_before_offer_not_counted_no_false() -> None:
    base = _build_chain(_section22_frames())
    chain = _synthetic_chain(base, SMTP_PLAINTEXT_EVENT, SMTP_CAPABILITY_EVENT)
    _assert_valid(chain)

    derived = derive_smtp_transition_facts(chain)
    _assert_valid(derived)

    assert len(_facts_of(derived, FACT_TYPE_STARTTLS_ADVERTISED)) == 1
    assert _facts_of(derived, FACT_TYPE_PLAINTEXT_COMMANDS_AFTER_OFFER) == []
    assert _facts_of(derived, FACT_TYPE_TLS_UPGRADE_COMPLETED) == []


# 37. acceptance after plaintext never uses the accepted-plaintext basis


def test_reordered_acceptance_never_pairs_with_plaintext() -> None:
    base = _build_chain(_accepted_without_tls_frames())
    chain = _synthetic_chain(
        base,
        SMTP_CAPABILITY_EVENT,
        SMTP_REQUESTED_EVENT,
        SMTP_PLAINTEXT_EVENT,
        SMTP_ACCEPTED_EVENT,
    )
    _assert_valid(chain)

    derived = derive_smtp_transition_facts(chain)
    _assert_valid(derived)

    fact = _fact_for(derived, FACT_TYPE_TLS_UPGRADE_COMPLETED)
    assert fact.value is False
    # the acceptance sits after the plaintext, so only the offer-driven
    # continuation basis applies and the acceptance is not among the sources
    assert fact.confidence_basis == ["ordered_plaintext_continuation_before_tls_completion"]

    ordered = sorted(chain.protocol_events, key=lambda e: e.sequence_index)
    assert fact.source_event_ids == [ordered[0].event_id, ordered[2].event_id]
    accepted_ids = [e.event_id for e in ordered if e.event_type is SMTP_ACCEPTED_EVENT]
    assert accepted_ids and accepted_ids[0] not in fact.source_event_ids


# ─────────────────────────────────────────────────────────────────────────────
#  §18 Acceptance (schema, immutability, determinism, sensitive data)
# ─────────────────────────────────────────────────────────────────────────────

# 38. derived chains validate against the frozen schema


def test_derived_chain_validates_against_schema() -> None:
    chain = _derived(_section22_frames())
    data = json.loads(chain.model_dump_json())
    errors = sorted(
        Draft202012Validator(load_checked_in_schema()).iter_errors(data),
        key=lambda e: list(e.path),
    )
    assert errors == []


# 39. derivation never mutates its input


def test_derivation_does_not_mutate_input() -> None:
    base = _build_chain(_accepted_tls_frames())
    before = base.model_dump()
    derived = derive_smtp_transition_facts(base)
    _assert_valid(derived)
    assert base.model_dump() == before


# 40. multiple recognized commands in one frame are distinct counted events


def test_plaintext_count_multiple_commands_one_frame_deterministic() -> None:
    frames = [
        *_handshake(),
        frame(4, b"220 secure.example ESMTP\r\n", direction=S),
        frame(5, b"EHLO client.example\r\n", direction=C),
        frame(6, b"250-STARTTLS\r\n", direction=S),
        frame(
            7,
            b"MAIL FROM:<alice@example.test>\r\nMAIL FROM:<bob@example.test>\r\n",
            direction=C,
        ),
        frame(8, b"QUIT\r\n", direction=C),
    ]
    chain = _derived(frames)
    _assert_valid(chain)

    plaintext = _events_of(chain, SMTP_PLAINTEXT_EVENT)
    assert len(plaintext) == 3
    assert len({e.event_id for e in plaintext}) == 3
    located = sorted(
        (_evidence_of(e, chain).frame_numbers[0], _evidence_of(e, chain).occurrence_index)
        for e in plaintext
    )
    assert located == [(7, 0), (7, 1), (8, 0)]

    fact = _fact_for(chain, FACT_TYPE_PLAINTEXT_COMMANDS_AFTER_OFFER)
    assert fact.value == 3

    again = _derived(frames)
    assert [f.model_dump() for f in chain.derived_facts] == [
        f.model_dump() for f in again.derived_facts
    ]


# 41. partial STARTTLS verbs are neither counted nor start a transition


def test_partial_start_verbs_neither_counted_nor_starttls() -> None:
    frames = [
        *_handshake(),
        frame(4, b"220 secure.example ESMTP\r\n", direction=S),
        frame(5, b"EHLO client.example\r\n", direction=C),
        frame(6, b"250-STARTTLS\r\n", direction=S),
        frame(7, b"START\r\n", direction=C),
        frame(8, b"STARTT\r\n", direction=C),
        frame(9, b"STARTTL\r\n", direction=C),
    ]
    chain = _derived(frames)
    _assert_valid(chain)

    assert _events_of(chain, SMTP_PLAINTEXT_EVENT) == []
    assert _events_of(chain, SMTP_REQUESTED_EVENT) == []
    assert _facts_of(chain, FACT_TYPE_PLAINTEXT_COMMANDS_AFTER_OFFER) == []
    assert _facts_of(chain, FACT_TYPE_TLS_UPGRADE_COMPLETED) == []


# 42. sensitive payload values are never serialized into the chain


def test_sensitive_values_not_serialized_into_chain() -> None:
    secret = "hunter2-super-duper-secret"
    auth_plain = "AUTH PLAIN " + "AGFsaWNlAGh1bnRlcjItc3VwZXItZHVwZXItc2VjcmV0\r\n"
    frames = [
        *_handshake(),
        frame(4, b"220 secure.example ESMTP\r\n", direction=S),
        frame(5, b"EHLO client.example\r\n", direction=C),
        frame(6, b"250 STARTTLS\r\n", direction=S),
        frame(7, auth_plain.encode(), direction=C),
        frame(8, b"MAIL FROM:<alice@example.test>\r\n", direction=C),
        frame(9, b"RCPT TO:<bob@example.test>\r\n", direction=C),
        frame(10, b"DATA\r\n", direction=C),
        frame(11, b"Subject: topsecret-candidate\r\n", direction=C),
        frame(12, b"body line with pii\r\n", direction=C),
        frame(13, b".\r\n", direction=C),
        frame(14, b"QUIT\r\n", direction=C),
    ]
    chain = _derived(frames)
    _assert_valid(chain)

    serialized = chain.model_dump_json()
    for sensitive in (
        secret,
        "alice@example.test",
        "bob@example.test",
        "topsecret-candidate",
        "body line with pii",
    ):
        assert sensitive not in serialized


# 43. Commit 3 derives facts without touching any later output collection


def test_later_outputs_untouched_by_derivation() -> None:
    chain = _derived(_accepted_tls_frames())
    derived = derive_smtp_transition_facts(chain)
    _assert_valid(derived)

    assert derived.rule_evaluations == []
    assert derived.findings == []
    assert derived.policy_risk is None
    assert derived.anomaly_results == []
    assert derived.recommendations == []
    assert derived.artifacts == []


# 44. the Commit 2 adapter chain itself carries no derived facts


def test_adapter_chain_has_no_derived_facts_before_derivation() -> None:
    chain = _build_chain(_accepted_tls_frames())
    _assert_valid(chain)
    assert chain.derived_facts == []
