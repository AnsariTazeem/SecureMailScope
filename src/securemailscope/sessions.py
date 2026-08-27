"""Reconstruct the SMTP STARTTLS transition from observable evidence.

The builder reconstructs the command from the TShark-native reassembled client
byte-stream (``stream.client_reassembled``), then attributes the command bytes
to the exact contributing frames using the per-frame ``tcp.payload``. Ordering
is enforced by ascending frame number: the STARTTLS command must precede the
server acceptance response, which must precede any TLS ClientHello on the same
stream.

Outcomes
--------
``accepted_tls``
    STARTTLS observed in a complete capture, accepted (``220``), and a TLS
    ClientHello observed strictly after the acceptance on the same stream.
``rejected``
    STARTTLS observed and the first server response after it rejected it
    (``454``/``500``/...).
``accepted_without_tls``
    Server accepted STARTTLS but no ClientHello follows, with positive proof
    the session continued or closed cleanly in plaintext (later plaintext or a
    clean close). Absence of a ClientHello alone is never enough.
``truncated``
    STARTTLS left incomplete and an explicit capture-incomplete signal was
    observed (reassembly error or capture truncation warning).
``incomplete``
    STARTTLS not reconstructed, or no decisive server response, or an
    acceptance without positive plaintext/close proof within a complete capture.
"""

from __future__ import annotations

import re

from securemailscope.models import (
    CompleteStatus,
    Direction,
    RawFrameObservation,
    SmtpEvent,
    SmtpEventCategory,
    SmtpTransition,
    TcpStream,
    TransitionOutcome,
)

_STARTTLS_COMMAND_BYTES = b"STARTTLS\r\n"
_STARTTLS_ACCEPT_RE = re.compile(rb"^220\b", re.MULTILINE)
_STARTTLS_REJECT_RE = re.compile(rb"^(4[0-9][0-9]|5[0-9][0-9])[ -]", re.MULTILINE)
_LINE_RE = re.compile(rb"[^\r\n]+(?:\r?\n|$)")
# Proper non-empty prefixes of STARTTLS\r\n, longest first, used to detect a
# command interrupted mid-flow by an incomplete capture.
_STARTTLS_PREFIXES = tuple(
    sorted(
        (_STARTTLS_COMMAND_BYTES[:i] for i in range(1, len(_STARTTLS_COMMAND_BYTES))),
        key=len,
        reverse=True,
    )
)

_CLIENT_EVENT_TOKEN = {
    "EHLO": SmtpEventCategory.EHLO,
    "HELO": SmtpEventCategory.HELO,
}


def build_transition(
    stream: TcpStream,
    *,
    reassembly_error_streams: set[int] | None = None,
    capture_truncation: bool = False,
) -> SmtpTransition:
    """Build an :class:`SmtpTransition` for one classified SMTP stream."""
    reassembly_errors = reassembly_error_streams or set()
    ordered = sorted(stream.frames, key=lambda f: (f.frame,))

    events, banner_evidence = _build_events(ordered)

    reassembly_incomplete = stream.stream_id in reassembly_errors or capture_truncation
    client_reassembled = stream.client_reassembled
    command_match = _find_command(client_reassembled)
    command_frames: list[int] = []
    if command_match is not None:
        command_frames = _attributing_frames(stream, command_match[0], len(command_match[1]))

    if not command_frames and _starttls_partial_suffix(client_reassembled):
        partial = _starttls_partial_suffix(client_reassembled)
        if not reassembly_incomplete:
            return SmtpTransition(
                tcp_stream=stream.stream_id,
                events=events,
                banner_evidence=banner_evidence,
                starttls_command_frames=[],
                outcome=TransitionOutcome.INCOMPLETE,
                completeness=CompleteStatus.INSUFFICIENT,
                reasons=["partial STARTTLS command without capture-incomplete evidence"],
            )
        partial_frames = _attributing_partial(stream, client_reassembled, partial)
        return SmtpTransition(
            tcp_stream=stream.stream_id,
            events=events,
            banner_evidence=banner_evidence,
            starttls_command_frames=partial_frames,
            outcome=TransitionOutcome.TRUNCATED,
            completeness=CompleteStatus.CAPTURE_INCOMPLETE,
            reasons=["STARTTLS reconstruction interrupted mid-command by an incomplete capture"],
        )

    if not command_frames:
        return SmtpTransition(
            tcp_stream=stream.stream_id,
            events=events,
            banner_evidence=banner_evidence,
            starttls_command_frames=[],
            outcome=TransitionOutcome.INCOMPLETE,
            completeness=CompleteStatus.INSUFFICIENT,
            reasons=["no STARTTLS command reconstructable on stream"],
        )

    reasons: list[str] = []
    completeness = CompleteStatus.COMPLETE
    if reassembly_incomplete:
        completeness = CompleteStatus.CAPTURE_INCOMPLETE
        reasons.append("capture-incomplete signal present on stream")

    response = _first_server_response_after(stream, command_frames)
    client_hello_frame = None
    response_frame = response.frame if response is not None else -1
    if stream.client_hello_frame is not None and stream.client_hello_frame > response_frame:
        client_hello_frame = stream.client_hello_frame
    else:
        for frame in ordered:
            if (
                frame.has_client_hello
                and frame.direction is Direction.CLIENT_TO_SERVER
                and frame.frame > response_frame
            ):
                client_hello_frame = frame.frame
                break

    if response is None:
        if completeness is CompleteStatus.CAPTURE_INCOMPLETE:
            outcome = TransitionOutcome.TRUNCATED
            reasons.append("STARTTLS sent but capture incomplete before server response")
        else:
            outcome = TransitionOutcome.INCOMPLETE
            reasons.append("STARTTLS sent but no server response in complete capture")
    elif _STARTTLS_REJECT_RE.search(response.payload):
        outcome = TransitionOutcome.REJECTED
        reasons.append(f"STARTTLS rejected (frame {response.frame})")
    elif _STARTTLS_ACCEPT_RE.search(response.payload):
        if client_hello_frame is not None:
            outcome = TransitionOutcome.ACCEPTED_TLS
            reasons.append(
                f"STARTTLS accepted (frame {response.frame}) and "
                f"TLS ClientHello seen strictly after (frame {client_hello_frame})"
            )
        elif completeness is CompleteStatus.CAPTURE_INCOMPLETE:
            outcome = TransitionOutcome.TRUNCATED
            reasons.append(
                f"STARTTLS accepted (frame {response.frame}) but "
                "capture incomplete before ClientHello"
            )
        elif _has_plaintext_continuation(stream, response.frame):
            outcome = TransitionOutcome.ACCEPTED_WITHOUT_TLS
            reasons.append(
                f"STARTTLS accepted (frame {response.frame}) with no TLS "
                "ClientHello but observable plaintext continuation"
            )
        else:
            outcome = TransitionOutcome.INCOMPLETE
            reasons.append(
                f"STARTTLS accepted (frame {response.frame}) but no TLS "
                "ClientHello and no positive plaintext/close proof"
            )
    else:
        outcome = TransitionOutcome.INCOMPLETE
        reasons.append(
            f"STARTTLS followed by an unrecognized server response (frame {response.frame})"
        )

    starttls_response_frames = [response.frame] if response is not None else []

    return SmtpTransition(
        tcp_stream=stream.stream_id,
        events=events,
        banner_evidence=banner_evidence,
        ehlo_evidence=_frames_for_category(events, SmtpEventCategory.EHLO),
        starttls_capability_evidence=_frames_for_category(
            events, SmtpEventCategory.STARTTLS_CAPABILITY
        ),
        starttls_command=command_match[1].decode("ascii", errors="replace"),
        starttls_command_frames=command_frames,
        starttls_response_frames=starttls_response_frames,
        client_hello_frame=client_hello_frame,
        client_hello_same_stream=client_hello_frame is not None,
        outcome=outcome,
        completeness=completeness,
        reasons=reasons,
    )


def _build_events(ordered: list[RawFrameObservation]) -> tuple[list[SmtpEvent], list[int]]:
    """Emit ordered plaintext-SMTP/TLS events with per-frame occurrence indices.

    The canonical ordering is ``(frame, occurrence)``; ``occurrence`` is the
    0-based event index within a single frame.
    """
    events: list[SmtpEvent] = []
    banner_emitted = False
    banner_frames: list[int] = []
    for frame in ordered:
        if frame.has_client_hello:
            break
        if not frame.has_payload:
            continue
        if not _is_plaintext(frame.payload):
            continue
        occurrence = 0
        for category in _categories_for_frame(frame, banner=not banner_emitted):
            if category is SmtpEventCategory.BANNER:
                banner_emitted = True
                banner_frames.append(frame.frame)
            events.append(
                SmtpEvent(
                    category=category,
                    direction=frame.direction,
                    frame=frame.frame,
                    occurrence=occurrence,
                    text=frame.payload.decode("utf-8", errors="replace")[:200],
                )
            )
            occurrence += 1
    return events, sorted(set(banner_frames))


def _categories_for_frame(frame: RawFrameObservation, *, banner: bool) -> list[SmtpEventCategory]:
    """Return the ordered event categories produced by one frame's payload lines."""
    categories: list[SmtpEventCategory] = []
    if frame.direction is Direction.CLIENT_TO_SERVER:
        for line in _lines(frame.payload):
            stripped = line.decode("utf-8", errors="replace").strip()
            upper = stripped.upper()
            if upper in ("STARTTLS", "STARTTLS\r", "STARTTLS\n", "STARTTLS\r\n"):
                categories.append(SmtpEventCategory.STARTTLS_COMMAND)
            elif upper.startswith("EHLO"):
                categories.append(SmtpEventCategory.EHLO)
            elif upper.startswith("HELO"):
                categories.append(SmtpEventCategory.HELO)
            else:
                categories.append(SmtpEventCategory.OTHER)
        return categories
    if frame.direction is Direction.SERVER_TO_CLIENT:
        local_banner = banner
        for line in _lines(frame.payload):
            stripped = line.decode("utf-8", errors="replace").strip()
            if local_banner and stripped.startswith("220"):
                categories.append(SmtpEventCategory.BANNER)
                local_banner = False
            elif stripped.startswith(("220", "250")):
                categories.append(SmtpEventCategory.ESMTP_RESPONSE)
                if _advertises_starttls(stripped):
                    categories.append(SmtpEventCategory.STARTTLS_CAPABILITY)
            else:
                categories.append(SmtpEventCategory.OTHER)
    return categories


def _lines(payload: bytes) -> list[bytes]:
    return [m.group(0) for m in _LINE_RE.finditer(payload)]


def _is_plaintext(payload: bytes) -> bool:
    """True when a payload decodes cleanly as UTF-8 text (not TLS binary)."""
    try:
        payload.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True


def _advertises_starttls(line: str) -> bool:
    marker = "STARTTLS"
    return marker in line.upper()


def _find_command(reassembled: bytes) -> tuple[int, bytes] | None:
    index = reassembled.find(_STARTTLS_COMMAND_BYTES)
    if index < 0:
        return None
    return index, _STARTTLS_COMMAND_BYTES


def _attributing_frames(stream: TcpStream, start: int, length: int) -> list[int]:
    """Map a byte range of the client byte-stream to its contributing frames."""
    contributing: list[int] = []
    offset = 0
    end = start + length
    for frame in sorted(stream.frames, key=lambda f: f.frame):
        if frame.direction is not Direction.CLIENT_TO_SERVER or not frame.has_payload:
            continue
        seg_end = offset + len(frame.payload)
        if seg_end > start and offset < end:
            contributing.append(frame.frame)
        offset = seg_end
    if contributing:
        return sorted(contributing)
    return _attributing_frames_brute(stream, start, length)


def _attributing_frames_brute(stream: TcpStream, start: int, length: int) -> list[int]:
    """Fallback attribution scanning consecutive client frames for the command."""
    client_frames = [
        f
        for f in sorted(stream.frames, key=lambda f: f.frame)
        if f.direction is Direction.CLIENT_TO_SERVER and f.has_payload
    ]
    for idx in range(len(client_frames)):
        for j in range(idx, len(client_frames)):
            chunk = b"".join(f.payload for f in client_frames[idx : j + 1])
            if _STARTTLS_COMMAND_BYTES in chunk:
                return [f.frame for f in client_frames[idx : j + 1]]
            if len(chunk) > len(_STARTTLS_COMMAND_BYTES) + 4:
                break
    return []


def _first_server_response_after(
    stream: TcpStream, command_frames: list[int]
) -> RawFrameObservation | None:
    if not command_frames:
        return None
    max_cmd_frame = max(command_frames)
    for frame in sorted(stream.frames, key=lambda f: f.frame):
        if (
            frame.direction is Direction.SERVER_TO_CLIENT
            and frame.has_payload
            and frame.frame > max_cmd_frame
        ):
            return frame
    return None


def _has_plaintext_continuation(stream: TcpStream, after_frame: int) -> bool:
    """Positive proof the session continued or closed cleanly in plaintext.

    A single FIN from one direction is never sufficient. A clean close requires
    FIN observed from *both* directions after the acceptance response, or a
    strict observable plaintext continuation after the acceptance. Binary /
    TLS-looking / control-character payloads never count as plaintext, and a
    RST alone never counts as a clean close. Nothing after an observed TLS
    ClientHello is treated as plaintext-continuation proof.
    """
    tls_boundary = _client_hello_boundary(stream)
    fin_client = False
    fin_server = False
    for frame in sorted(stream.frames, key=lambda f: f.frame):
        if frame.frame <= after_frame:
            continue
        if tls_boundary is not None and frame.frame >= tls_boundary:
            break
        if frame.flags_rst:
            continue
        if frame.flags_fin:
            if frame.direction is Direction.CLIENT_TO_SERVER:
                fin_client = True
            elif frame.direction is Direction.SERVER_TO_CLIENT:
                fin_server = True
            continue
        if frame.has_payload and _is_plaintext_strict(frame.payload):
            return True
    return fin_client and fin_server


def _client_hello_boundary(stream: TcpStream) -> int | None:
    """Return the earliest client-side TLS ClientHello frame on the stream.

    The boundary is the minimum of the summarized ``client_hello_frame`` (when
    present) and every raw observation with ``has_client_hello=True`` in the
    client-to-server direction. Deriving it from raw frame observations also
    ensures that a ClientHello is never missed when the summarized field is
    unset.
    """
    candidates: list[int] = []
    if stream.client_hello_frame is not None:
        candidates.append(stream.client_hello_frame)
    for frame in stream.frames:
        if frame.has_client_hello and frame.direction is Direction.CLIENT_TO_SERVER:
            candidates.append(frame.frame)
    if not candidates:
        return None
    return min(candidates)


_TLS_RECORD_CONTENT_TYPES = b"\x14\x15\x16\x17"


def _is_plaintext_strict(payload: bytes) -> bool:
    """True only for clean ASCII/UTF-8 text, never TLS or control bytes."""
    if not payload:
        return False
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        return False
    if not text:
        return False
    if payload[0] in _TLS_RECORD_CONTENT_TYPES:
        return False
    for ch in text:
        code = ord(ch)
        if code < 0x20 and code not in (0x09, 0x0A, 0x0D):
            return False
    return True


def _starttls_partial_suffix(reassembled: bytes) -> bytes:
    """Return a non-empty proper prefix of STARTTLS\\r\\n ending the stream.

    Returns ``b""`` when the native client reassembly does not end with an
    interrupted prefix of the STARTTLS command.
    """
    for prefix in _STARTTLS_PREFIXES:
        if reassembled.endswith(prefix):
            return prefix
    return b""


def _attributing_partial(stream: TcpStream, reassembled: bytes, suffix: bytes) -> list[int]:
    """Attribute a partial command suffix to its contributing client frames."""
    if not suffix:
        return []
    start = max(0, len(reassembled) - len(suffix))
    return _attributing_frames(stream, start, len(suffix))


def _frames_for_category(events: list[SmtpEvent], category: SmtpEventCategory) -> list[int]:
    return [event.frame for event in events if event.category is category]
