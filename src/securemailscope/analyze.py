"""Orchestrate the E2/E3A offline capture analysis path.

The analysis is read-only: provenance intake, stream discovery, raw observable
frame collection, content-based SMTP classification, and SMTP STARTTLS
transition reconstruction. No capture, manifest, or evidence file is written,
rewritten, or repaired.

Reassembly is TShark-native: the authoritative per-direction byte stream of
each stream comes from ``follow,tcp,raw``, and per-frame ``tcp.payload`` is used
only to attribute a reconstructed command to its contributing frames. No custom
TCP sequence-number buffer is synthesized.
"""

from __future__ import annotations

from decimal import Decimal
from pathlib import Path

from securemailscope.errors import AnalysisError, ErrorCode
from securemailscope.intake import (
    DEFAULT_MAX_INPUT_BYTES,
    build_capture_provenance,
    validate_input_path,
)
from securemailscope.models import (
    AnalyzeResult,
    CaptureProvenance,
    Direction,
    DirectionBasis,
    Protocol,
    RawFrameObservation,
    TcpStream,
    ToolExecutionRecord,
)
from securemailscope.protocols import classify_stream
from securemailscope.sessions import build_transition
from securemailscope.tshark import (
    build_epochs_argv,
    build_follow_argv,
    build_tshark_argv,
    parse_capture_frame_metadata,
    parse_follow_output,
    run_tool,
)

OBSERVATION_FIELDS = (
    "frame.number",
    "frame.time_epoch",
    "ip.src",
    "ip.dst",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.stream",
    "tcp.seq",
    "tcp.flags.syn",
    "tcp.flags.ack",
    "tcp.flags.fin",
    "tcp.flags.reset",
    "tcp.payload",
    "tls.handshake.type",
    "_ws.malformed",
)


def analyze_capture(
    path: Path,
    *,
    max_input_bytes: int = DEFAULT_MAX_INPUT_BYTES,
    timeout_seconds: float = 20.0,
) -> AnalyzeResult:
    """Analyze one capture fully offline and return typed results."""
    validated = validate_input_path(path, max_input_bytes=max_input_bytes)
    tool_records: list[ToolExecutionRecord] = []

    provenance = build_capture_provenance(
        validated,
        max_input_bytes=max_input_bytes,
        timeout_seconds=timeout_seconds,
        tool_records=tool_records,
    )

    argv = build_tshark_argv(validated, display_filter="tcp", fields=OBSERVATION_FIELDS)
    record, observation_output = run_tool(
        argv, stage="tshark_observe", timeout_seconds=timeout_seconds
    )
    tool_records.append(record)

    frames_by_stream, reassembly_error_streams, malformed_capture = _parse_observations(
        observation_output
    )

    epochs_record, epochs_output = run_tool(
        build_epochs_argv(validated), stage="tshark_epochs", timeout_seconds=timeout_seconds
    )
    tool_records.append(epochs_record)
    first_epoch, last_epoch, truncated_packet_count = parse_capture_frame_metadata(
        epochs_output,
        expected_packet_count=provenance.packet_count,
    )
    provenance = _set_capture_frame_metadata(
        provenance,
        first_epoch,
        last_epoch,
        truncated_packet_count,
    )
    capture_incomplete = malformed_capture or truncated_packet_count > 0

    streams: list[TcpStream] = []
    classifications = []
    smtp_transitions = []

    for stream_id in sorted(frames_by_stream):
        stream = _assemble_stream(stream_id, frames_by_stream[stream_id])
        follow_record, follow_output = run_tool(
            build_follow_argv(validated, stream_id),
            stage="tshark_follow",
            timeout_seconds=timeout_seconds,
        )
        tool_records.append(follow_record)
        node0, node1, ep0, ep1, follow_incomplete = parse_follow_output(follow_output)
        stream = _attach_reassembled(stream, node0, node1, ep0, ep1)
        streams.append(stream)
        if follow_incomplete:
            capture_incomplete = True
        classification = classify_stream(stream)
        classifications.append(classification)
        if classification.protocol is Protocol.SMTP:
            transition = build_transition(
                stream,
                reassembly_error_streams=reassembly_error_streams,
                capture_truncation=capture_incomplete,
            )
            smtp_transitions.append(transition)

    return AnalyzeResult(
        provenance=provenance,
        tool_records=tool_records,
        streams=streams,
        classifications=classifications,
        smtp_transitions=smtp_transitions,
    )


def _set_capture_frame_metadata(
    provenance: CaptureProvenance,
    first_epoch: Decimal | None,
    last_epoch: Decimal | None,
    truncated_packet_count: int,
) -> CaptureProvenance:
    updates: dict[str, object] = {"truncated_packet_count": truncated_packet_count}
    if first_epoch is not None and last_epoch is not None:
        updates["first_epoch_seconds"] = first_epoch
        updates["last_epoch_seconds"] = last_epoch
    return provenance.model_copy(update=updates)


def _attach_reassembled(
    stream: TcpStream, node0: bytes, node1: bytes, ep0: str, ep1: str
) -> TcpStream:
    """Attach native reassembly byte-streams by matching follow nodes to endpoints.

    Follow nodes are mapped to the analyzer's client/server by their
    ``ip:port`` endpoints (never by assuming node order).
    """
    client_endpoint = f"{stream.client_ip}:{stream.client_port}" if stream.client_ip else ""
    if ep0 == client_endpoint:
        client_reassembled, server_reassembled = node0, node1
    elif ep1 == client_endpoint:
        client_reassembled, server_reassembled = node1, node0
    else:
        # Endpoints cannot be mapped safely: never guess node direction and
        # never substitute raw per-frame plaintext for native reassembly.
        # Leave the reassembled streams empty so the outcome is conservative.
        return stream
    return stream.model_copy(
        update={
            "client_reassembled": client_reassembled,
            "server_reassembled": server_reassembled,
        }
    )


def _parse_observations(
    tool_output: str,
) -> tuple[dict[int, list[RawFrameObservation]], set[int], bool]:
    """Parse tab-separated field rows and group raw observations by stream.

    Returns ``(frames_by_stream, reassembly_error_streams, malformed_capture)``.
    Malformation remains an incompleteness signal but is not counted as packet
    truncation; authoritative truncation uses all-frame captured/original lengths.
    """
    frames_by_stream: dict[int, list[RawFrameObservation]] = {}
    reassembly_streams: set[int] = set()
    truncation = False
    for line in tool_output.splitlines():
        if not line.strip():
            continue
        columns = line.split("\t")
        if len(columns) < 12:
            raise AnalysisError(
                ErrorCode.MALFORMED_TOOL_OUTPUT,
                "tshark_observe",
                "observation row does not have the expected number of fields",
            )
        frame_number = _parse_int(columns[0], "frame.number")
        epoch = _parse_decimal(columns[1], "frame.time_epoch")
        src_ip = columns[2]
        dst_ip = columns[3]
        src_port = _parse_int(columns[4], "tcp.srcport")
        dst_port = _parse_int(columns[5], "tcp.dstport")
        stream_id = _parse_int(columns[6], "tcp.stream")
        seq_value = _parse_decimal(columns[7], "tcp.seq")
        syn = _parse_bool(columns[8])
        ack = _parse_bool(columns[9])
        fin = _parse_bool(columns[10])
        rst = _parse_bool(columns[11])
        payload_hex = columns[12] if len(columns) > 12 and columns[12] else ""
        handshake_types = _parse_handshake_types(columns[13]) if len(columns) > 13 else ()
        malformed = _parse_bool(columns[14]) if len(columns) > 14 else False

        payload = _hex_to_bytes(payload_hex)
        direction, basis = _infer_direction(syn, ack)

        observation = RawFrameObservation(
            frame=frame_number,
            epoch_seconds=epoch,
            source_ip=src_ip,
            destination_ip=dst_ip,
            source_port=src_port,
            destination_port=dst_port,
            direction=direction,
            direction_basis=basis,
            tcp_stream=stream_id,
            payload=payload,
            seq=seq_value,
            has_payload=bool(payload),
            has_client_hello=(1 in handshake_types),
            tls_handshake_types=handshake_types,
            flags_syn=syn,
            flags_ack=ack,
            flags_fin=fin,
            flags_rst=rst,
        )
        frames_by_stream.setdefault(stream_id, []).append(observation)
        if malformed:
            reassembly_streams.add(stream_id)
            truncation = True
    return frames_by_stream, reassembly_streams, truncation


def _parse_handshake_types(text: str) -> tuple[int, ...]:
    """Parse repeated ``tls.handshake.type`` values preserving their order.

    Multiple occurrences in one frame are kept as an ordered tuple (e.g.
    ``(1, 11, 2)``); an observed value is never collapsed. An empty/missing
    field yields ``()``, which is distinct from an observed set of values.
    """
    tokens = text.split(",")
    if not any(t.strip() for t in tokens):
        return ()
    result: list[int] = []
    for token in tokens:
        if not token.strip():
            continue
        result.append(_parse_int(token, "tls.handshake.type"))
    return tuple(result)


def _assemble_stream(stream_id: int, frames: list[RawFrameObservation]) -> TcpStream:
    ordered = sorted(frames, key=lambda f: (f.frame,))

    client_ip = client_port = server_ip = server_port = ""
    syn_seen = False
    syn_ack_seen = False
    reset_count = 0
    fin_client = fin_server = False
    client_hello_frame: int | None = None

    # Infer endpoints from the TCP handshake only (SYN => client). Without a
    # SYN the endpoints are left unresolved rather than guessed from the first
    # payload sender, which would risk reversing the roles.
    for frame in ordered:
        if frame.flags_syn and not frame.flags_ack and not syn_seen:
            client_ip, client_port = frame.source_ip, frame.source_port
            server_ip, server_port = frame.destination_ip, frame.destination_port
            syn_seen = True
        if frame.flags_syn and frame.flags_ack:
            syn_ack_seen = True

    direction_basis = DirectionBasis.TCP_SYN if syn_seen else DirectionBasis.NOT_DETERMINED

    def effective_direction(frame: RawFrameObservation) -> Direction:
        if client_ip and frame.source_ip == client_ip and frame.source_port == client_port:
            return Direction.CLIENT_TO_SERVER
        if server_ip and frame.source_ip == server_ip and frame.source_port == server_port:
            return Direction.SERVER_TO_CLIENT
        return frame.direction

    corrected: list[RawFrameObservation] = []
    client_chunks: list[bytes] = []
    server_chunks: list[bytes] = []
    frame_epochs: list[tuple[int, Decimal]] = []
    for frame in ordered:
        direction = effective_direction(frame)
        corrected_frame = frame.model_copy(update={"direction": direction})
        corrected.append(corrected_frame)
        frame_epochs.append((frame.frame, frame.epoch_seconds))
        if frame.flags_rst and direction is Direction.CLIENT_TO_SERVER:
            reset_count += 1
        if frame.flags_fin:
            if direction is Direction.CLIENT_TO_SERVER:
                fin_client = True
            else:
                fin_server = True
        if frame.has_client_hello:
            if direction is Direction.CLIENT_TO_SERVER and client_hello_frame is None:
                client_hello_frame = frame.frame
        if frame.has_payload:
            if direction is Direction.CLIENT_TO_SERVER:
                client_chunks.append(frame.payload)
            elif direction is Direction.SERVER_TO_CLIENT:
                server_chunks.append(frame.payload)

    return TcpStream(
        stream_id=stream_id,
        client_ip=client_ip,
        client_port=int(client_port) if client_port else 0,
        server_ip=server_ip,
        server_port=int(server_port) if server_port else 0,
        direction_basis=direction_basis,
        client_syn=syn_seen,
        server_syn_ack=syn_ack_seen,
        fin_from_client=fin_client,
        fin_from_server=fin_server,
        reset_count=reset_count,
        client_plaintext=b"".join(client_chunks),
        server_plaintext=b"".join(server_chunks),
        client_hello_frame=client_hello_frame,
        frame_epochs=frame_epochs,
        frames=corrected,
    )


def _infer_direction(syn: bool, ack: bool) -> tuple[Direction, DirectionBasis]:
    if syn and not ack:
        return Direction.CLIENT_TO_SERVER, DirectionBasis.TCP_SYN
    if syn and ack:
        return Direction.SERVER_TO_CLIENT, DirectionBasis.TCP_SYN
    return Direction.UNKNOWN, DirectionBasis.NOT_DETERMINED


def _parse_int(text: str, field: str) -> int:
    try:
        return int(text.strip())
    except (TypeError, ValueError):
        raise AnalysisError(
            ErrorCode.MALFORMED_TOOL_OUTPUT, "tshark_observe", f"malformed {field} '{text[:20]}'"
        ) from None


def _parse_decimal(text: str, field: str) -> Decimal:
    stripped = text.strip()
    try:
        return Decimal(stripped)
    except (ValueError, ArithmeticError):
        raise AnalysisError(
            ErrorCode.MALFORMED_TOOL_OUTPUT, "tshark_observe", f"malformed {field} '{text[:20]}'"
        ) from None


def _parse_bool(text: str) -> bool:
    return text.strip().lower() in ("1", "true", "yes")


def _hex_to_bytes(hex_string: str) -> bytes:
    if not hex_string:
        return b""
    compact = hex_string.replace(":", "")
    try:
        return bytes.fromhex(compact)
    except ValueError:
        raise AnalysisError(
            ErrorCode.MALFORMED_TOOL_OUTPUT,
            "tshark_observe",
            "malformed tcp.payload hex value",
        ) from None
