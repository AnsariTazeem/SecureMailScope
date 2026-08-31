"""Offline tests for observation parsing and stream assembly.

These drive the private parsing/assembly functions with synthetic TShark
field rows; no real tool is executed and no capture is read.
"""

from __future__ import annotations

import pytest

from securemailscope.analyze import (
    _assemble_stream,
    _attach_reassembled,
    _hex_to_bytes,
    _parse_observations,
)
from securemailscope.errors import AnalysisError, ErrorCode
from securemailscope.models import Direction, DirectionBasis
from securemailscope.tshark import parse_capture_frame_metadata


def _row(
    number: str,
    epoch: str,
    src: str,
    dst: str,
    sport: str,
    dport: str,
    stream: str,
    seq: str,
    *,
    syn: bool = False,
    ack: bool = False,
    fin: bool = False,
    reset: bool = False,
    payload: str = "",
    tls_types: str = "",
    malformed: str = "0",
) -> str:
    def b(flag: bool) -> str:
        return "True" if flag else "False"

    return "\t".join(
        [
            number,
            epoch,
            src,
            dst,
            sport,
            dport,
            stream,
            seq,
            b(syn),
            b(ack),
            b(fin),
            b(reset),
            payload,
            tls_types,
            malformed,
        ]
    )


def test_parse_and_assemble_direction_routing() -> None:
    hex_payload = lambda s: s.encode("utf-8").hex()  # noqa: E731
    lines = "\n".join(
        [
            _row(
                "1",
                "1800000000.100000000",
                "10.0.0.1",
                "10.0.0.2",
                "49100",
                "2525",
                "0",
                "1000",
                syn=True,
            ),
            _row(
                "2",
                "1800000000.110000000",
                "10.0.0.2",
                "10.0.0.1",
                "2525",
                "49100",
                "0",
                "2000",
                syn=True,
                ack=True,
            ),
            _row(
                "3",
                "1800000000.120000000",
                "10.0.0.2",
                "10.0.0.1",
                "2525",
                "49100",
                "0",
                "3000",
                ack=True,
                payload=hex_payload("220 banner\r\n"),
            ),
            _row(
                "4",
                "1800000000.130000000",
                "10.0.0.1",
                "10.0.0.2",
                "49100",
                "2525",
                "0",
                "4000",
                ack=True,
                payload=hex_payload("EHLO client\r\n"),
            ),
        ]
    )
    frames_by_stream, reassembly, _truncation = _parse_observations(lines)
    assert set(frames_by_stream) == {0}
    assert reassembly == set()

    stream = _assemble_stream(0, frames_by_stream[0])
    assert stream.direction_basis is DirectionBasis.TCP_SYN
    assert stream.client_port == 49100 and stream.server_port == 2525
    assert stream.client_syn is True and stream.server_syn_ack is True
    assert b"EHLO" in stream.client_plaintext
    assert b"220 banner" in stream.server_plaintext
    directions = {f.direction for f in stream.frames}
    assert Direction.CLIENT_TO_SERVER in directions
    assert Direction.SERVER_TO_CLIENT in directions


def test_assemble_no_syn_leaves_endpoints_and_hello_unresolved() -> None:
    hex_payload = lambda s: s.encode("utf-8").hex()  # noqa: E731
    lines = "\n".join(
        [
            _row(
                "1",
                "1800000000.100000000",
                "10.0.0.1",
                "10.0.0.2",
                "49100",
                "2525",
                "0",
                "1000",
                ack=True,
                payload=hex_payload("EHLO client\r\n"),
            ),
            _row(
                "2",
                "1800000000.110000000",
                "10.0.0.1",
                "10.0.0.2",
                "49100",
                "2525",
                "0",
                "2000",
                ack=True,
                payload="160301",
                tls_types="1",
            ),
        ]
    )
    frames_by_stream, _, _ = _parse_observations(lines)
    stream = _assemble_stream(0, frames_by_stream[0])
    assert stream.direction_basis is DirectionBasis.NOT_DETERMINED
    assert stream.client_ip == "" and stream.server_ip == ""
    assert stream.client_port == 0 and stream.server_port == 0
    assert stream.client_hello_frame is None
    assert stream.client_plaintext == b""
    assert not any(f.direction is not Direction.UNKNOWN for f in stream.frames)


def test_parse_requires_all_columns() -> None:
    with pytest.raises(AnalysisError) as exc:
        _parse_observations("1\t2\t3\t4\t5")
    assert exc.value.code is ErrorCode.MALFORMED_TOOL_OUTPUT


def test_hex_to_bytes_preserves_exact_bytes() -> None:
    assert _hex_to_bytes("48:45:4c:4f") == b"HELO"
    assert _hex_to_bytes("") == b""


def test_hex_to_bytes_rejects_malformed() -> None:
    with pytest.raises(AnalysisError):
        _hex_to_bytes("zz:zz:gg")


def test_malformed_flag_marks_stream_reassembly_error() -> None:
    lines = _row(
        "1",
        "1800000000.100000000",
        "10.0.0.1",
        "10.0.0.2",
        "49100",
        "2525",
        "0",
        "1000",
        payload="00",
        malformed="1",
    )
    frames, reassembly, _ = _parse_observations(lines)
    assert reassembly == {0}


def test_malformed_packet_does_not_imply_captured_frame_truncation() -> None:
    malformed_line = _row(
        "1",
        "1800000000.100000000",
        "10.0.0.1",
        "10.0.0.2",
        "49100",
        "2525",
        "0",
        "1000",
        malformed="1",
    )
    _, reassembly, malformed_capture = _parse_observations(malformed_line)
    _, _, truncated_count = parse_capture_frame_metadata(
        "1\t1800000000.100000000\t100\t100\n",
        expected_packet_count=1,
    )
    assert reassembly == {0}
    assert malformed_capture is True
    assert truncated_count == 0


def test_attach_reassembled_endpoint_mismatch_does_not_copy_plaintext() -> None:
    hex_payload = lambda s: s.encode("utf-8").hex()  # noqa: E731
    lines = "\n".join(
        [
            _row(
                "1",
                "1800000000.100000000",
                "10.0.0.1",
                "10.0.0.2",
                "49100",
                "2525",
                "0",
                "1000",
                syn=True,
            ),
            _row(
                "2",
                "1800000000.110000000",
                "10.0.0.2",
                "10.0.0.1",
                "2525",
                "49100",
                "0",
                "2000",
                syn=True,
                ack=True,
            ),
            _row(
                "3",
                "1800000000.120000000",
                "10.0.0.1",
                "10.0.0.2",
                "49100",
                "2525",
                "0",
                "3000",
                ack=True,
                payload=hex_payload("EHLO client\r\n"),
            ),
        ]
    )
    frames_by_stream, _, _ = _parse_observations(lines)
    stream = _assemble_stream(0, frames_by_stream[0])
    assert stream.client_port == 49100
    assert b"EHLO" in stream.client_plaintext

    node0 = b"garbage-from-node0"
    node1 = b"garbage-from-node1"
    attached = _attach_reassembled(stream, node0, node1, "9.9.9.9:1", "8.8.8.8:2")
    # Endpoints do not match the client endpoint: raw per-frame plaintext must
    # never be substituted into the authoritative reassembled fields.
    assert attached.client_reassembled == b""
    assert attached.server_reassembled == b""
    assert attached.client_plaintext != b""


def test_parse_preserves_ordered_multiple_handshake_types() -> None:
    lines = _row(
        "1",
        "1800000000.100000000",
        "10.0.0.1",
        "10.0.0.2",
        "49100",
        "2525",
        "0",
        "1000",
        tls_types="1,11,2",
    )
    frames, _, _ = _parse_observations(lines)
    obs = frames[0][0]
    assert obs.tls_handshake_types == (1, 11, 2)
    assert obs.has_client_hello is True


def test_parse_empty_handshake_types_distinct_from_observed() -> None:
    lines = _row(
        "1",
        "1800000000.100000000",
        "10.0.0.1",
        "10.0.0.2",
        "49100",
        "2525",
        "0",
        "1000",
    )
    frames, _, _ = _parse_observations(lines)
    obs = frames[0][0]
    assert obs.tls_handshake_types == ()
    assert obs.has_client_hello is False
