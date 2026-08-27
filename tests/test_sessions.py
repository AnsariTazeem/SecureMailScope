"""SMTP STARTTLS transition state-machine tests (pure, offline)."""

from __future__ import annotations

from _e3a_helpers import frame, stream

from securemailscope.models import (
    CompleteStatus,
    Direction,
    SmtpEventCategory,
    TransitionOutcome,
)
from securemailscope.sessions import build_transition


def _accepted_tls_frames() -> list:
    return [
        frame(1, b"220 mail.test ESMTP\r\n", direction=Direction.SERVER_TO_CLIENT, seq=1000),
        frame(2, b"EHLO client.test\r\n", direction=Direction.CLIENT_TO_SERVER, seq=1000),
        frame(
            3, b"250-mail.test\r\n250 STARTTLS\r\n", direction=Direction.SERVER_TO_CLIENT, seq=2000
        ),
        frame(4, b"START", direction=Direction.CLIENT_TO_SERVER, seq=3000),
        frame(5, b"TLS\r\n", direction=Direction.CLIENT_TO_SERVER, seq=3005),
        frame(6, b"220 Ready to start TLS\r\n", direction=Direction.SERVER_TO_CLIENT, seq=4000),
        frame(7, b"", direction=Direction.CLIENT_TO_SERVER, seq=6000, has_client_hello=True),
    ]


def test_accepted_tls_reconstructs_split_command() -> None:
    s = stream(_accepted_tls_frames())
    t = build_transition(s)
    assert t.starttls_command == "STARTTLS\r\n"
    assert t.starttls_command_frames == [4, 5]
    assert t.client_hello_frame == 7
    assert t.outcome is TransitionOutcome.ACCEPTED_TLS
    assert t.completeness is CompleteStatus.COMPLETE
    assert t.starttls_response_frames == [6]


def test_overlapping_retransmission_reconstructs_exactly_once() -> None:
    frames = [
        frame(1, b"220 banner\r\n", direction=Direction.SERVER_TO_CLIENT, seq=1000),
        frame(2, b"EHLO c\r\n", direction=Direction.CLIENT_TO_SERVER, seq=1000),
        frame(3, b"250 STARTTLS\r\n", direction=Direction.SERVER_TO_CLIENT, seq=2000),
        # STARTTLS sent, then retransmitted with an overlapping prefix
        frame(4, b"START", direction=Direction.CLIENT_TO_SERVER, seq=3000),
        frame(5, b"STARTTLS\r\n", direction=Direction.CLIENT_TO_SERVER, seq=3000),
        frame(6, b"220 Ready\r\n", direction=Direction.SERVER_TO_CLIENT, seq=4000),
        frame(7, b"", direction=Direction.CLIENT_TO_SERVER, seq=5000, has_client_hello=True),
    ]
    t = build_transition(stream(frames))
    assert t.starttls_command == "STARTTLS\r\n"
    assert t.outcome is TransitionOutcome.ACCEPTED_TLS


def test_rejected_transition() -> None:
    frames = [
        frame(1, b"220 banner\r\n", direction=Direction.SERVER_TO_CLIENT, seq=1000),
        frame(2, b"EHLO c\r\n", direction=Direction.CLIENT_TO_SERVER, seq=2000),
        frame(3, b"STARTTLS\r\n", direction=Direction.CLIENT_TO_SERVER, seq=3000),
        frame(4, b"454 TLS not available\r\n", direction=Direction.SERVER_TO_CLIENT, seq=4000),
    ]
    t = build_transition(stream(frames))
    assert t.outcome is TransitionOutcome.REJECTED
    assert t.starttls_response_frames == [4]


def test_accepted_without_tls_requires_positive_proof() -> None:
    frames = [
        frame(1, b"220 banner\r\n", direction=Direction.SERVER_TO_CLIENT, seq=1000),
        frame(2, b"EHLO c\r\n", direction=Direction.CLIENT_TO_SERVER, seq=2000),
        frame(3, b"STARTTLS\r\n", direction=Direction.CLIENT_TO_SERVER, seq=3000),
        frame(4, b"220 Ready to start TLS\r\n", direction=Direction.SERVER_TO_CLIENT, seq=4000),
        frame(5, b"QUIT\r\n", direction=Direction.CLIENT_TO_SERVER, seq=5000),
    ]
    t = build_transition(stream(frames))
    assert t.outcome is TransitionOutcome.ACCEPTED_WITHOUT_TLS
    assert t.completeness is CompleteStatus.COMPLETE
    assert t.client_hello_same_stream is False


def test_absence_of_hello_without_proof_is_incomplete() -> None:
    frames = [
        frame(1, b"220 banner\r\n", direction=Direction.SERVER_TO_CLIENT, seq=1000),
        frame(2, b"EHLO c\r\n", direction=Direction.CLIENT_TO_SERVER, seq=2000),
        frame(3, b"STARTTLS\r\n", direction=Direction.CLIENT_TO_SERVER, seq=3000),
        frame(4, b"220 Ready to start TLS\r\n", direction=Direction.SERVER_TO_CLIENT, seq=4000),
    ]
    t = build_transition(stream(frames))
    assert t.outcome is TransitionOutcome.INCOMPLETE
    assert t.client_hello_same_stream is False


def test_client_hello_before_acceptance_is_not_accepted_tls() -> None:
    frames = [
        frame(1, b"220 banner\r\n", direction=Direction.SERVER_TO_CLIENT, seq=1000),
        frame(2, b"EHLO c\r\n", direction=Direction.CLIENT_TO_SERVER, seq=2000),
        frame(3, b"STARTTLS\r\n", direction=Direction.CLIENT_TO_SERVER, seq=3000),
        frame(4, b"", direction=Direction.CLIENT_TO_SERVER, seq=4000, has_client_hello=True),
        frame(5, b"220 Ready to start TLS\r\n", direction=Direction.SERVER_TO_CLIENT, seq=5000),
    ]
    t = build_transition(stream(frames))
    assert t.outcome is not TransitionOutcome.ACCEPTED_TLS
    assert t.client_hello_frame is None


def test_capability_recorded_in_events() -> None:
    t = build_transition(stream(_accepted_tls_frames()))
    assert t.starttls_capability_evidence == [3]
    capabilities = [e for e in t.events if e.category is SmtpEventCategory.STARTTLS_CAPABILITY]
    assert capabilities
    assert capabilities[0].frame == 3


def test_event_occurrence_is_per_frame_not_global_index() -> None:
    t = build_transition(stream(_accepted_tls_frames()))
    frame_3_events = [e for e in t.events if e.frame == 3]
    # Frame 3 has two response lines then the capability; occurrences 0,1,2
    # prove per-frame indexing independent of global order.
    assert [e.occurrence for e in frame_3_events] == [0, 1, 2]
    assert frame_3_events[2].category is SmtpEventCategory.STARTTLS_CAPABILITY
    # ordering is (frame, occurrence)
    ordered_keys = [(e.frame, e.occurrence) for e in t.events]
    assert ordered_keys == sorted(ordered_keys)


def test_truncated_after_acceptance_on_capture_incomplete() -> None:
    frames = [
        frame(1, b"220 banner\r\n", direction=Direction.SERVER_TO_CLIENT, seq=1000),
        frame(2, b"EHLO c\r\n", direction=Direction.CLIENT_TO_SERVER, seq=2000),
        frame(3, b"STARTTLS\r\n", direction=Direction.CLIENT_TO_SERVER, seq=3000),
        frame(4, b"220 Ready\r\n", direction=Direction.SERVER_TO_CLIENT, seq=4000),
    ]
    t = build_transition(stream(frames), reassembly_error_streams={0})
    assert t.outcome is TransitionOutcome.TRUNCATED
    assert t.completeness is CompleteStatus.CAPTURE_INCOMPLETE


def test_truncated_before_response_on_capture_incomplete() -> None:
    frames = [
        frame(1, b"220 banner\r\n", direction=Direction.SERVER_TO_CLIENT, seq=1000),
        frame(2, b"EHLO c\r\n", direction=Direction.CLIENT_TO_SERVER, seq=2000),
        frame(3, b"STARTTLS\r\n", direction=Direction.CLIENT_TO_SERVER, seq=3000),
    ]
    t = build_transition(stream(frames), capture_truncation=True)
    assert t.outcome is TransitionOutcome.TRUNCATED


def test_incomplete_no_command() -> None:
    frames = [
        frame(1, b"220 banner\r\n", direction=Direction.SERVER_TO_CLIENT, seq=1000),
        frame(2, b"EHLO c\r\n", direction=Direction.CLIENT_TO_SERVER, seq=2000),
    ]
    t = build_transition(stream(frames))
    assert t.outcome is TransitionOutcome.INCOMPLETE
    assert t.starttls_command == ""


def test_incomplete_command_no_response() -> None:
    frames = [
        frame(1, b"220 banner\r\n", direction=Direction.SERVER_TO_CLIENT, seq=1000),
        frame(2, b"EHLO c\r\n", direction=Direction.CLIENT_TO_SERVER, seq=2000),
        frame(3, b"STARTTLS\r\n", direction=Direction.CLIENT_TO_SERVER, seq=3000),
    ]
    t = build_transition(stream(frames))
    assert t.outcome is TransitionOutcome.INCOMPLETE


def test_rejected_takes_precedence_over_later_acceptance() -> None:
    frames = [
        frame(1, b"220 banner\r\n", direction=Direction.SERVER_TO_CLIENT, seq=1000),
        frame(2, b"STARTTLS\r\n", direction=Direction.CLIENT_TO_SERVER, seq=2000),
        frame(3, b"454 rejected\r\n", direction=Direction.SERVER_TO_CLIENT, seq=3000),
        frame(4, b"220 unexpected\r\n", direction=Direction.SERVER_TO_CLIENT, seq=4000),
    ]
    t = build_transition(stream(frames))
    assert t.outcome is TransitionOutcome.REJECTED


def test_banner_and_ehlo_evidence_frames() -> None:
    t = build_transition(stream(_accepted_tls_frames()))
    assert t.banner_evidence == [1]
    assert t.ehlo_evidence == [2]


def _accepted_no_tls_frames(extra: list) -> list:
    return [
        frame(1, b"220 banner\r\n", direction=Direction.SERVER_TO_CLIENT, seq=1000),
        frame(2, b"EHLO c\r\n", direction=Direction.CLIENT_TO_SERVER, seq=2000),
        frame(3, b"STARTTLS\r\n", direction=Direction.CLIENT_TO_SERVER, seq=3000),
        frame(4, b"220 Ready to start TLS\r\n", direction=Direction.SERVER_TO_CLIENT, seq=4000),
        *extra,
    ]


def test_one_sided_fin_is_incomplete() -> None:
    frames = _accepted_no_tls_frames(
        [frame(5, b"", direction=Direction.CLIENT_TO_SERVER, seq=5000, fin=True)]
    )
    t = build_transition(stream(frames))
    assert t.outcome is TransitionOutcome.INCOMPLETE
    assert t.client_hello_same_stream is False


def test_bidirectional_fin_after_acceptance_is_accepted_without_tls() -> None:
    frames = _accepted_no_tls_frames(
        [
            frame(5, b"", direction=Direction.CLIENT_TO_SERVER, seq=5000, fin=True),
            frame(6, b"", direction=Direction.SERVER_TO_CLIENT, seq=6000, fin=True),
        ]
    )
    t = build_transition(stream(frames))
    assert t.outcome is TransitionOutcome.ACCEPTED_WITHOUT_TLS
    assert t.completeness is CompleteStatus.COMPLETE


def test_strict_plaintext_command_after_acceptance_is_accepted_without_tls() -> None:
    frames = _accepted_no_tls_frames(
        [frame(5, b"QUIT\r\n", direction=Direction.CLIENT_TO_SERVER, seq=5000)]
    )
    t = build_transition(stream(frames))
    assert t.outcome is TransitionOutcome.ACCEPTED_WITHOUT_TLS
    assert t.completeness is CompleteStatus.COMPLETE


def test_binary_payload_after_acceptance_is_incomplete() -> None:
    frames = _accepted_no_tls_frames(
        [frame(5, b"\x16\x03\x01\x00\x05hello", direction=Direction.CLIENT_TO_SERVER, seq=5000)]
    )
    t = build_transition(stream(frames))
    assert t.outcome is TransitionOutcome.INCOMPLETE


def test_rst_alone_is_incomplete() -> None:
    frames = _accepted_no_tls_frames(
        [frame(5, b"", direction=Direction.CLIENT_TO_SERVER, seq=5000, rst=True)]
    )
    t = build_transition(stream(frames))
    assert t.outcome is TransitionOutcome.INCOMPLETE


def test_partial_command_with_capture_incomplete_is_truncated() -> None:
    frames = [
        frame(1, b"220 banner\r\n", direction=Direction.SERVER_TO_CLIENT, seq=1000),
        frame(2, b"EHLO c\r\n", direction=Direction.CLIENT_TO_SERVER, seq=2000),
        frame(3, b"START", direction=Direction.CLIENT_TO_SERVER, seq=3000),
        frame(4, b"T", direction=Direction.CLIENT_TO_SERVER, seq=3004),
    ]
    t = build_transition(stream(frames), capture_truncation=True)
    assert t.outcome is TransitionOutcome.TRUNCATED
    assert t.completeness is CompleteStatus.CAPTURE_INCOMPLETE
    assert t.starttls_command_frames == [3, 4]
    assert any("interrupted" in r for r in t.reasons)


def test_partial_command_without_capture_incomplete_is_incomplete() -> None:
    frames = [
        frame(1, b"220 banner\r\n", direction=Direction.SERVER_TO_CLIENT, seq=1000),
        frame(2, b"EHLO c\r\n", direction=Direction.CLIENT_TO_SERVER, seq=2000),
        frame(3, b"START", direction=Direction.CLIENT_TO_SERVER, seq=3000),
        frame(4, b"T", direction=Direction.CLIENT_TO_SERVER, seq=3004),
    ]
    t = build_transition(stream(frames))
    assert t.outcome is TransitionOutcome.INCOMPLETE
    assert t.completeness is CompleteStatus.INSUFFICIENT


def test_capture_incomplete_after_ehlo_not_truncated() -> None:
    frames = [
        frame(1, b"220 banner\r\n", direction=Direction.SERVER_TO_CLIENT, seq=1000),
        frame(2, b"EHLO c\r\n", direction=Direction.CLIENT_TO_SERVER, seq=2000),
    ]
    t = build_transition(stream(frames), capture_truncation=True)
    assert t.outcome is TransitionOutcome.INCOMPLETE
    assert t.completeness is not CompleteStatus.CAPTURE_INCOMPLETE


def test_absent_native_reassembly_cannot_produce_accepted_tls() -> None:
    s = stream(_accepted_tls_frames())
    t = build_transition(s.model_copy(update={"client_reassembled": b""}))
    assert t.outcome is not TransitionOutcome.ACCEPTED_TLS
    assert t.client_hello_same_stream is False


def test_client_hello_from_frame_blocks_later_plaintext_without_summary_field() -> None:
    frames = [
        frame(1, b"220 banner\r\n", direction=Direction.SERVER_TO_CLIENT, seq=1000),
        frame(2, b"EHLO c\r\n", direction=Direction.CLIENT_TO_SERVER, seq=2000),
        frame(3, b"STARTTLS\r\n", direction=Direction.CLIENT_TO_SERVER, seq=3000),
        frame(4, b"", direction=Direction.CLIENT_TO_SERVER, seq=4000, has_client_hello=True),
        frame(5, b"220 Ready\r\n", direction=Direction.SERVER_TO_CLIENT, seq=5000),
        frame(6, b"QUIT\r\n", direction=Direction.CLIENT_TO_SERVER, seq=6000),
    ]
    s = stream(frames)
    assert s.client_hello_frame is None
    t = build_transition(s)
    assert t.outcome is not TransitionOutcome.ACCEPTED_WITHOUT_TLS
    assert t.outcome is TransitionOutcome.INCOMPLETE
    # The ClientHello in frame 4 must be derived from the frame observations,
    # so the later QUIT payload in frame 6 is never plaintext-continuation proof
    # and never emitted as an SMTP event.
    assert not any(e.frame == 6 for e in t.events)
