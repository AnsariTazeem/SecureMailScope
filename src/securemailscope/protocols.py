"""Content-based (protocol-byte) mail-transport classification.

Classification uses observable plaintext from each frame on a stream, grouped
by the direction inferred from the TCP handshake (SYN = client). A positive
``CONFIRMED`` decision requires **both** directions, at least two distinct SMTP
evidence categories, direction consistency, and strict plaintext lines read
before any TLS upgrade. Port numbers are a hint only, never sufficient.
"""

from __future__ import annotations

import re

from securemailscope.models import (
    ClassificationBasis,
    ClassificationStatus,
    Direction,
    Protocol,
    ProtocolClassification,
    RawFrameObservation,
    TcpStream,
)

_CRLF_RE = re.compile(r"\r\n|\n")

_SERVER_BANNER_RE = re.compile(r"^220\b", re.MULTILINE)
_SERVER_ESMTP_RESPONSE_RE = re.compile(r"^2\d\d[ -]", re.MULTILINE)
_ESMTP_RESPONSE_OR_CAPABILITY_RE = re.compile(r"^(220|250)[ -]", re.MULTILINE)
_ADVERTISED_STARTTLS_RE = re.compile(r"(?i)\bSTARTTLS\b")
_STARTTLS_COMMAND_RE = re.compile(r"(?i)^[ -]*STARTTLS\r?$")
_EHLO_HELO_RE = re.compile(r"(?i)^(EHLO|HELO)[ \t]")
_FOREIGN_PROTOCOL_RE = re.compile(r"^\* OK\b|^\* BYE\b|^\+OK\b|^-ERR\b", re.MULTILINE)


def classify_stream(stream: TcpStream) -> ProtocolClassification:
    """Classify one stream by observable plaintext content from both directions."""
    positive: list[ClassificationBasis] = []
    contradictory: list[ClassificationBasis] = []
    port_hints = _port_hints(stream)
    seen: dict[tuple[str, Direction], ClassificationBasis] = {}

    def _record(category: str, direction: Direction, frame_idx: int, text: str) -> None:
        key = (category, direction)
        entry = seen.get(key)
        if entry is None:
            entry = ClassificationBasis(
                category=category,
                direction=direction,
                frames=[],
                text=text,
            )
            seen[key] = entry
            (positive if _is_positive(category) else contradictory).append(entry)
        if frame_idx not in entry.frames:
            entry.frames.append(frame_idx)

    banner_emitted = False
    for frame in stream.frames:
        if frame.has_client_hello:
            # TLS upgrade begins here: never classify SMTP evidence from the
            # ClientHello frame or any later frame.
            break
        if not frame.has_payload:
            continue
        for category, direction, text in _analyze_frame(frame, banner_emitted=banner_emitted):
            _record(category, direction, frame.frame, text)
            if category == "banner":
                banner_emitted = True

    positive.sort(key=lambda e: (e.direction.value, -len(e.frames), e.category))
    contradictory.sort(key=lambda e: (e.direction.value, -len(e.frames), e.category))

    protocol, status, reason = _decide(stream.stream_id, positive, contradictory, port_hints)
    return ProtocolClassification(
        tcp_stream=stream.stream_id,
        protocol=protocol,
        status=status,
        positive_evidence=positive,
        contradictory_evidence=contradictory,
        port_hints=port_hints,
        reason=reason,
    )


def _port_hints(stream: TcpStream) -> list[int]:
    hints: list[int] = []
    for frame in stream.frames:
        client_sent = frame.direction is Direction.CLIENT_TO_SERVER
        hint = frame.destination_port if client_sent else frame.source_port
        if hint not in hints:
            hints.append(hint)
    return hints


def _is_positive(category: str) -> bool:
    return category in (
        "banner",
        "esmtp_response",
        "ehlo",
        "helo",
        "starttls_command",
        "starttls_capability",
    )


def _analyze_frame(
    frame: RawFrameObservation, *, banner_emitted: bool
) -> list[tuple[str, Direction, str]]:
    """Return ``(category, direction, snippet)`` tuples from one frame's payload."""
    results: list[tuple[str, Direction, str]] = []
    is_server = frame.direction is Direction.SERVER_TO_CLIENT
    is_client = frame.direction is Direction.CLIENT_TO_SERVER
    for line in _payload_lines(frame.payload):
        trimmed = line.strip()
        if not trimmed:
            continue
        if is_server:
            results.extend(_classify_server_line(trimmed, frame.direction, banner=banner_emitted))
        elif is_client:
            category = _classify_client_line(trimmed)
            if category is not None:
                results.append((category, frame.direction, trimmed[:120]))
    return results


def _classify_server_line(
    line: str, direction: Direction, *, banner: bool
) -> list[tuple[str, Direction, str]]:
    results: list[tuple[str, Direction, str]] = []
    if _SERVER_BANNER_RE.match(line):
        if not banner:
            results.append(("banner", direction, line[:120]))
        else:
            results.append(("esmtp_response", direction, line[:120]))
    elif _ESMTP_RESPONSE_OR_CAPABILITY_RE.match(line):
        results.append(("esmtp_response", direction, line[:120]))
        if _ADVERTISED_STARTTLS_RE.search(line):
            results.append(("starttls_capability", direction, line[:120]))
    elif _FOREIGN_PROTOCOL_RE.search(line):
        results.append(("foreign_protocol", direction, line[:120]))
    return results


def _classify_client_line(line: str) -> str | None:
    if _STARTTLS_COMMAND_RE.match(line):
        return "starttls_command"
    ehlo_match = _EHLO_HELO_RE.match(line)
    if ehlo_match:
        return "ehlo" if ehlo_match.group(1).upper() == "EHLO" else "helo"
    if _FOREIGN_PROTOCOL_RE.search(line):
        return "foreign_protocol"
    return None


def _decide(
    stream_id: int,
    positive: list[ClassificationBasis],
    contradictory: list[ClassificationBasis],
    port_hints: list[int],
) -> tuple[Protocol, ClassificationStatus, str]:
    if contradictory:
        if positive:
            return (
                Protocol.UNKNOWN,
                ClassificationStatus.CONTRADICTORY,
                "conflicting non-SMTP protocol evidence; no decisive classification",
            )
        return (
            Protocol.UNKNOWN,
            ClassificationStatus.INSUFFICIENT,
            "non-SMTP protocol evidence only; no decisive classification",
        )

    client_categories = {e.category for e in positive if e.direction is Direction.CLIENT_TO_SERVER}
    server_categories = {e.category for e in positive if e.direction is Direction.SERVER_TO_CLIENT}

    if client_categories and server_categories and len(client_categories | server_categories) >= 2:
        return (
            Protocol.SMTP,
            ClassificationStatus.CONFIRMED,
            f"both-direction multi-category SMTP evidence on stream {stream_id}",
        )
    return (
        Protocol.UNKNOWN,
        ClassificationStatus.INSUFFICIENT,
        f"insufficient SMTP evidence on stream {stream_id}"
        + (f" (ports: {port_hints})" if port_hints else ""),
    )


def _payload_lines(payload: bytes) -> list[str]:
    text = payload.decode("utf-8", errors="replace")
    return _CRLF_RE.split(text)
