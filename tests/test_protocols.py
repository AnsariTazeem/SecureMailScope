"""Content-based SMTP classification tests (pure, offline)."""

from __future__ import annotations

from _e3a_helpers import SERVER_PORT, frame, stream

from securemailscope.models import ClassificationStatus, Direction, Protocol
from securemailscope.protocols import classify_stream


def _smtp_flow() -> list:
    return [
        frame(1, b"220 mail.test ESMTP secure\r\n", direction=Direction.SERVER_TO_CLIENT),
        frame(2, b"EHLO client.test\r\n", direction=Direction.CLIENT_TO_SERVER),
        frame(3, b"250-mail.test\r\n250 STARTTLS\r\n", direction=Direction.SERVER_TO_CLIENT),
        frame(4, b"START\r\n", direction=Direction.CLIENT_TO_SERVER),
    ]


def test_confirmed_smtp_both_directions() -> None:
    result = classify_stream(stream(_smtp_flow()))
    assert result.protocol is Protocol.SMTP
    assert result.status is ClassificationStatus.CONFIRMED
    categories = {(e.category, e.direction) for e in result.positive_evidence}
    assert ("ehlo", Direction.CLIENT_TO_SERVER) in categories
    assert ("banner", Direction.SERVER_TO_CLIENT) in categories


def test_banner_only_captured_once_not_every_220() -> None:
    frames = [
        frame(1, b"220 banner\r\n", direction=Direction.SERVER_TO_CLIENT),
        frame(2, b"EHLO c\r\n", direction=Direction.CLIENT_TO_SERVER),
        frame(3, b"220 starttls-ok\r\n", direction=Direction.SERVER_TO_CLIENT),
    ]
    result = classify_stream(stream(frames))
    banner = next(e for e in result.positive_evidence if e.category == "banner")
    assert banner.frames == [1]


def test_server_evidence_records_frames() -> None:
    frames = [
        frame(1, b"220 banner\r\n", direction=Direction.SERVER_TO_CLIENT),
        frame(2, b"EHLO c\r\n", direction=Direction.CLIENT_TO_SERVER),
        frame(3, b"250-SIZE 100\r\n250 STARTTLS\r\n", direction=Direction.SERVER_TO_CLIENT),
        frame(4, b"250 ok\r\n", direction=Direction.SERVER_TO_CLIENT),
    ]
    result = classify_stream(stream(frames))
    banner = next(e for e in result.positive_evidence if e.category == "banner")
    assert banner.frames == [1]
    resp = next(e for e in result.positive_evidence if e.category == "esmtp_response")
    assert 3 in resp.frames and 4 in resp.frames


def test_one_direction_only_is_unknown() -> None:
    frames = [
        frame(1, b"220 banner\r\n", direction=Direction.SERVER_TO_CLIENT),
        frame(2, b"250-SIZE\r\n", direction=Direction.SERVER_TO_CLIENT),
    ]
    result = classify_stream(stream(frames))
    assert result.protocol is Protocol.UNKNOWN
    assert result.status is ClassificationStatus.INSUFFICIENT


def test_no_evidence_is_unknown() -> None:
    frames = [frame(1, b"garbage-bytes", direction=Direction.CLIENT_TO_SERVER)]
    result = classify_stream(stream(frames))
    assert result.protocol is Protocol.UNKNOWN
    assert result.status is ClassificationStatus.INSUFFICIENT


def test_unmatched_payload_is_unknown_not_false_smtp() -> None:
    frames = [
        frame(1, b"* OK IMAP4rev1 ready\r\n", direction=Direction.SERVER_TO_CLIENT),
    ]
    result = classify_stream(stream(frames))
    assert result.protocol is Protocol.UNKNOWN
    assert result.status is ClassificationStatus.INSUFFICIENT


def test_port_hints_recorded_as_hint() -> None:
    result = classify_stream(stream(_smtp_flow()))
    assert SERVER_PORT in result.port_hints


def test_starttls_line_records_both_response_and_capability() -> None:
    frames = [
        frame(1, b"220 banner\r\n", direction=Direction.SERVER_TO_CLIENT),
        frame(2, b"EHLO c\r\n", direction=Direction.CLIENT_TO_SERVER),
        frame(3, b"250-mail\r\n250 STARTTLS\r\n", direction=Direction.SERVER_TO_CLIENT),
    ]
    result = classify_stream(stream(frames))
    assert result.protocol is Protocol.SMTP
    assert result.status is ClassificationStatus.CONFIRMED
    cats = {(e.category, e.direction) for e in result.positive_evidence}
    assert ("esmtp_response", Direction.SERVER_TO_CLIENT) in cats
    assert ("starttls_capability", Direction.SERVER_TO_CLIENT) in cats


def test_starttls_command_only_is_unknown() -> None:
    frames = [
        frame(1, b"STARTTLS\r\n", direction=Direction.CLIENT_TO_SERVER),
    ]
    result = classify_stream(stream(frames))
    assert result.protocol is Protocol.UNKNOWN
    assert result.status is ClassificationStatus.INSUFFICIENT


def test_standard_port_with_unrelated_content_is_unknown() -> None:
    frames = [
        frame(1, b"GET / HTTP/1.1\r\nHost: x\r\n", direction=Direction.CLIENT_TO_SERVER),
        frame(2, b"HTTP/1.1 200 OK\r\n", direction=Direction.SERVER_TO_CLIENT),
    ]
    result = classify_stream(stream(frames))
    assert result.protocol is Protocol.UNKNOWN
    assert result.status is ClassificationStatus.INSUFFICIENT


def test_smtp_plus_imap_is_contradictory() -> None:
    frames = [
        frame(1, b"* OK IMAP4rev1 ready\r\n", direction=Direction.SERVER_TO_CLIENT),
        frame(2, b"EHLO client\r\n", direction=Direction.CLIENT_TO_SERVER),
    ]
    result = classify_stream(stream(frames))
    assert result.protocol is Protocol.UNKNOWN
    assert result.status is ClassificationStatus.CONTRADICTORY
    assert result.contradictory_evidence


def test_client_hello_first_ignores_all_later_smtp_as_unknown() -> None:
    frames = [
        frame(1, b"", direction=Direction.CLIENT_TO_SERVER, has_client_hello=True),
        frame(2, b"220 mail.test ESMTP secure\r\n", direction=Direction.SERVER_TO_CLIENT),
        frame(3, b"EHLO client.test\r\n", direction=Direction.CLIENT_TO_SERVER),
    ]
    result = classify_stream(stream(frames))
    assert result.protocol is Protocol.UNKNOWN
    assert result.status is ClassificationStatus.INSUFFICIENT
    assert result.positive_evidence == []
