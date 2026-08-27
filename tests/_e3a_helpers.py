"""Shared helpers for building synthetic streams/frames in unit tests."""

from __future__ import annotations

from decimal import Decimal

from securemailscope.models import (
    Direction,
    DirectionBasis,
    RawFrameObservation,
    TcpStream,
)

CLIENT_IP = "10.0.0.1"
SERVER_IP = "10.0.0.2"
CLIENT_PORT = 49100
SERVER_PORT = 2525


def frame(
    number: int,
    payload: bytes,
    *,
    direction: Direction,
    seq: int = 1000,
    epoch: str = "1800000000.100000000",
    syn: bool = False,
    ack: bool = False,
    fin: bool = False,
    rst: bool = False,
    has_client_hello: bool = False,
    tls_handshake_types: tuple[int, ...] | None = None,
) -> RawFrameObservation:
    is_client = direction is Direction.CLIENT_TO_SERVER
    src_port = CLIENT_PORT if is_client else SERVER_PORT
    dst_port = SERVER_PORT if is_client else CLIENT_PORT
    handshake = (1,) if has_client_hello and tls_handshake_types is None else tls_handshake_types
    if handshake is None:
        handshake = ()
    return RawFrameObservation(
        frame=number,
        epoch_seconds=Decimal(epoch),
        source_ip=CLIENT_IP if is_client else SERVER_IP,
        destination_ip=SERVER_IP if is_client else CLIENT_IP,
        source_port=src_port,
        destination_port=dst_port,
        direction=direction,
        direction_basis=DirectionBasis.TCP_SYN,
        tcp_stream=0,
        payload=payload,
        seq=Decimal(seq),
        has_payload=bool(payload),
        has_client_hello=(1 in handshake),
        tls_handshake_types=handshake,
        flags_syn=syn,
        flags_ack=ack,
        flags_fin=fin,
        flags_rst=rst,
    )


def stream(frames: list[RawFrameObservation]) -> TcpStream:
    client_reassembled = b"".join(
        f.payload
        for f in sorted(frames, key=lambda x: x.frame)
        if f.direction is Direction.CLIENT_TO_SERVER and f.has_payload
    )
    server_reassembled = b"".join(
        f.payload
        for f in sorted(frames, key=lambda x: x.frame)
        if f.direction is Direction.SERVER_TO_CLIENT and f.has_payload
    )
    return TcpStream(
        stream_id=0,
        client_ip=CLIENT_IP,
        client_port=CLIENT_PORT,
        server_ip=SERVER_IP,
        server_port=SERVER_PORT,
        direction_basis=DirectionBasis.TCP_SYN,
        client_reassembled=client_reassembled,
        server_reassembled=server_reassembled,
        frames=frames,
    )
