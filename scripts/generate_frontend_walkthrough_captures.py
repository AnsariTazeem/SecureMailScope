"""Generate deterministic, non-sensitive PCAPNG files for the frontend walkthrough.

This generator is independent of the analyzer. It constructs two controlled
SMTP byte streams from explicit fixture configuration and records their hashes
and expected observable facts in a manifest. Existing artifacts are never
overwritten unless --force is explicitly supplied.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import struct
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIR = REPO_ROOT / "web" / "public" / "captures"
MANIFEST_PATH = OUTPUT_DIR / "securemailscope-walkthrough-manifest.json"
GENERATOR_VERSION = "frontend-walkthrough-fixture/1.0.0"
PCAPNG_SIZE_BYTES = 4096
CLIENT_IP = "192.0.2.10"
SERVER_IP = "192.0.2.20"
CLIENT_PORT = 35210
SERVER_PORT = 2525
CLIENT_MAC = bytes.fromhex("020000000010")
SERVER_MAC = bytes.fromhex("020000000020")


@dataclass(frozen=True)
class PacketSpec:
    timestamp: str
    direction: str
    payload: bytes = b""
    flags: int = 0x18


@dataclass(frozen=True)
class CaptureSpec:
    filename: str
    capture_id: str
    frame_bytes: int
    packets: tuple[PacketSpec, ...]
    expected: dict[str, object]


SECURE_SPEC = CaptureSpec(
    filename="secure-chain.pcapng",
    capture_id="cap_d25934ad4f2ad02e",
    frame_bytes=2048,
    packets=(
        PacketSpec("2026-08-27T10:00:02.100000Z", "server", b"220 example.test ESMTP ready\r\n"),
        PacketSpec("2026-08-27T10:00:02.300000Z", "client", b"EHLO client.example\r\n"),
        PacketSpec(
            "2026-08-27T10:00:02.400000Z",
            "server",
            b"250-example.test\r\n250-STARTTLS\r\n250 SIZE 1048576\r\n",
        ),
        PacketSpec("2026-08-27T10:00:02.600000Z", "client", b"STARTTLS\r\n"),
        PacketSpec(
            "2026-08-27T10:00:02.800000Z",
            "server",
            b"220 2.0.0 Ready to start TLS\r\n",
        ),
        PacketSpec("2026-08-27T10:00:02.900000Z", "client", b"__CLIENT_HELLO__"),
        PacketSpec("2026-08-27T10:00:03.000000Z", "server", b"__SERVER_HELLO__"),
        PacketSpec("2026-08-27T10:00:03.300000Z", "server", b"__TLS_APPLICATION__"),
        PacketSpec("2026-08-27T10:00:03.350000Z", "client", b"__TLS_APPLICATION__"),
        PacketSpec("2026-08-27T10:00:03.400000Z", "server", b"__TLS_APPLICATION__"),
        PacketSpec("2026-08-27T10:00:03.450000Z", "client", b"__TLS_APPLICATION__"),
        PacketSpec("2026-08-27T10:00:03.500000Z", "server", flags=0x11),
    ),
    expected={
        "protocol": "smtp",
        "smtp_commands": ["EHLO", "STARTTLS"],
        "starttls_advertised": True,
        "starttls_requested": True,
        "plaintext_mail_after_offer": False,
        "tls_handshake_types": [1, 2],
        "tls_supported_version": "0x0304",
        "tls_cipher_suite": "0x1301",
        "tls_key_share_group": 23,
    },
)

INSECURE_SPEC = CaptureSpec(
    filename="insecure-chain.pcapng",
    capture_id="cap_57936ac41b3d6c4b",
    frame_bytes=1024,
    packets=(
        PacketSpec("2026-08-27T11:00:02.100000Z", "server", b"220 example.test ESMTP ready\r\n"),
        PacketSpec("2026-08-27T11:00:02.300000Z", "client", b"EHLO client.example\r\n"),
        PacketSpec(
            "2026-08-27T11:00:02.400000Z",
            "server",
            b"250-example.test\r\n250-STARTTLS\r\n250 SIZE 1048576\r\n",
        ),
        PacketSpec(
            "2026-08-27T11:00:02.700000Z",
            "client",
            b"MAIL FROM:<sender@example.test>\r\n",
        ),
        PacketSpec("2026-08-27T11:00:02.750000Z", "server", b"250 2.1.0 Sender OK\r\n"),
        PacketSpec("2026-08-27T11:00:02.800000Z", "client", b"QUIT\r\n"),
    ),
    expected={
        "protocol": "smtp",
        "smtp_commands": ["EHLO", "MAIL", "QUIT"],
        "starttls_advertised": True,
        "starttls_requested": False,
        "plaintext_mail_after_offer": True,
        "tls_handshake_types": [],
    },
)

CAPTURE_SPECS = (SECURE_SPEC, INSECURE_SPEC)


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    words = struct.unpack(f"!{len(data) // 2}H", data)
    total = sum(words)
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _ipv4_bytes(address: str) -> bytes:
    return ipaddress.IPv4Address(address).packed


def _tls_extension(extension_type: int, body: bytes) -> bytes:
    return struct.pack("!HH", extension_type, len(body)) + body


def _handshake(message_type: int, body: bytes) -> bytes:
    return bytes([message_type]) + len(body).to_bytes(3, "big") + body


def _tls_record(content_type: int, body: bytes) -> bytes:
    return bytes([content_type]) + b"\x03\x03" + struct.pack("!H", len(body)) + body


def _client_hello() -> bytes:
    point = b"\x04" + bytes(range(1, 65))
    supported_versions = _tls_extension(0x002B, b"\x02\x03\x04")
    supported_groups = _tls_extension(0x000A, b"\x00\x02\x00\x17")
    share = struct.pack("!HH", 0x0017, len(point)) + point
    key_share = _tls_extension(0x0033, struct.pack("!H", len(share)) + share)
    extensions = supported_versions + supported_groups + key_share
    body = (
        b"\x03\x03"
        + bytes(range(32))
        + b"\x00"
        + b"\x00\x02\x13\x01"
        + b"\x01\x00"
        + struct.pack("!H", len(extensions))
        + extensions
    )
    return _tls_record(22, _handshake(1, body))


def _server_hello() -> bytes:
    point = b"\x04" + bytes(range(65, 129))
    supported_version = _tls_extension(0x002B, b"\x03\x04")
    key_share = _tls_extension(
        0x0033,
        struct.pack("!HH", 0x0017, len(point)) + point,
    )
    extensions = supported_version + key_share
    body = (
        b"\x03\x03"
        + bytes(range(32, 64))
        + b"\x00"
        + b"\x13\x01"
        + b"\x00"
        + struct.pack("!H", len(extensions))
        + extensions
    )
    return _tls_record(22, _handshake(2, body))


def _tls_application(direction: str) -> bytes:
    marker = b"server-record" if direction == "server" else b"client-record"
    return _tls_record(23, hashlib.sha256(marker).digest()[:24])


def _resolve_payload(spec: PacketSpec) -> bytes:
    if spec.payload == b"__CLIENT_HELLO__":
        return _client_hello()
    if spec.payload == b"__SERVER_HELLO__":
        return _server_hello()
    if spec.payload == b"__TLS_APPLICATION__":
        return _tls_application(spec.direction)
    return spec.payload


def _tcp_frame(
    *,
    direction: str,
    payload: bytes,
    flags: int,
    sequence: int,
    acknowledgment: int,
    ip_identification: int,
) -> bytes:
    client_to_server = direction == "client"
    source_ip = CLIENT_IP if client_to_server else SERVER_IP
    destination_ip = SERVER_IP if client_to_server else CLIENT_IP
    source_port = CLIENT_PORT if client_to_server else SERVER_PORT
    destination_port = SERVER_PORT if client_to_server else CLIENT_PORT
    source_mac = CLIENT_MAC if client_to_server else SERVER_MAC
    destination_mac = SERVER_MAC if client_to_server else CLIENT_MAC

    tcp_header = struct.pack(
        "!HHIIBBHHH",
        source_port,
        destination_port,
        sequence,
        acknowledgment,
        5 << 4,
        flags,
        65535,
        0,
        0,
    )
    pseudo_header = (
        _ipv4_bytes(source_ip)
        + _ipv4_bytes(destination_ip)
        + b"\x00\x06"
        + struct.pack("!H", len(tcp_header) + len(payload))
    )
    tcp_checksum = _checksum(pseudo_header + tcp_header + payload)
    tcp_header = tcp_header[:16] + struct.pack("!H", tcp_checksum) + tcp_header[18:]

    total_length = 20 + len(tcp_header) + len(payload)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        ip_identification,
        0x4000,
        64,
        6,
        0,
        _ipv4_bytes(source_ip),
        _ipv4_bytes(destination_ip),
    )
    ip_checksum = _checksum(ip_header)
    ip_header = ip_header[:10] + struct.pack("!H", ip_checksum) + ip_header[12:]
    ethernet = destination_mac + source_mac + b"\x08\x00"
    return ethernet + ip_header + tcp_header + payload


def _build_frames(spec: CaptureSpec) -> list[bytes]:
    client_sequence = 100_000
    server_sequence = 200_000
    frames: list[bytes] = []
    for index, packet in enumerate(spec.packets, start=1):
        payload = _resolve_payload(packet)
        if packet.direction == "client":
            sequence = client_sequence
            acknowledgment = server_sequence
            client_sequence += len(payload) + (1 if packet.flags & 0x01 else 0)
        else:
            sequence = server_sequence
            acknowledgment = client_sequence
            server_sequence += len(payload) + (1 if packet.flags & 0x01 else 0)
        frames.append(
            _tcp_frame(
                direction=packet.direction,
                payload=payload,
                flags=packet.flags,
                sequence=sequence,
                acknowledgment=acknowledgment,
                ip_identification=index,
            )
        )

    extra = spec.frame_bytes - sum(len(frame) for frame in frames)
    if extra < 0:
        raise ValueError(f"{spec.filename}: frame byte budget is too small")
    for index in range(extra):
        frame_index = index % len(frames)
        frames[frame_index] += b"\x00"
    if sum(len(frame) for frame in frames) != spec.frame_bytes:
        raise AssertionError("frame padding did not reach the configured byte count")
    return frames


def _pcapng_block(block_type: int, body: bytes) -> bytes:
    padding = b"\x00" * ((-len(body)) % 4)
    total_length = 12 + len(body) + len(padding)
    return (
        struct.pack("<II", block_type, total_length)
        + body
        + padding
        + struct.pack("<I", total_length)
    )


def _timestamp_microseconds(value: str) -> int:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)
    return int(parsed.timestamp() * 1_000_000)


def _build_pcapng(spec: CaptureSpec) -> bytes:
    frames = _build_frames(spec)
    section = _pcapng_block(
        0x0A0D0D0A,
        struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1),
    )
    interface = _pcapng_block(1, struct.pack("<HHI", 1, 0, 65535))
    packet_bodies: list[bytes] = []
    for packet, frame in zip(spec.packets, frames, strict=True):
        timestamp = _timestamp_microseconds(packet.timestamp)
        body = (
            struct.pack(
                "<IIIII",
                0,
                timestamp >> 32,
                timestamp & 0xFFFFFFFF,
                len(frame),
                len(frame),
            )
            + frame
            + b"\x00" * ((-len(frame)) % 4)
        )
        packet_bodies.append(body)

    packet_blocks = [_pcapng_block(6, body) for body in packet_bodies]
    base_size = len(section) + len(interface) + sum(map(len, packet_blocks))
    remaining = PCAPNG_SIZE_BYTES - base_size
    if remaining < 8 or remaining % 4:
        raise ValueError(
            f"{spec.filename}: cannot pad {base_size} bytes to "
            f"{PCAPNG_SIZE_BYTES} with a valid packet option"
        )
    comment_length = remaining - 8
    packet_bodies[-1] += (
        struct.pack("<HH", 1, comment_length) + b"\x00" * comment_length + struct.pack("<HH", 0, 0)
    )
    packet_blocks[-1] = _pcapng_block(6, packet_bodies[-1])
    capture = section + interface + b"".join(packet_blocks)
    if len(capture) != PCAPNG_SIZE_BYTES:
        raise AssertionError("PCAPNG padding did not reach the configured size")
    return capture


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _manifest_entry(spec: CaptureSpec, capture: bytes) -> dict[str, object]:
    return {
        "filename": spec.filename,
        "capture_id": spec.capture_id,
        "sha256": _sha256(capture),
        "size_bytes": len(capture),
        "packet_count": len(spec.packets),
        "frame_bytes": spec.frame_bytes,
        "captured_at_start": spec.packets[0].timestamp,
        "captured_at_end": spec.packets[-1].timestamp,
        "expected": spec.expected,
    }


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--force",
        action="store_true",
        help="replace the exact walkthrough artifacts if they already exist",
    )
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    artifact_paths = [
        *(OUTPUT_DIR / spec.filename for spec in CAPTURE_SPECS),
        MANIFEST_PATH,
    ]
    existing = [path for path in artifact_paths if path.exists()]
    if existing and not args.force:
        listing = "\n".join(f"  {path}" for path in existing)
        raise SystemExit(f"Refusing to overwrite existing artifacts:\n{listing}")

    captures = [(spec, _build_pcapng(spec)) for spec in CAPTURE_SPECS]
    manifest = {
        "schema_version": "1.0.0",
        "generator_version": GENERATOR_VERSION,
        "synthetic": True,
        "non_sensitive": True,
        "purpose": "Recognized offline frontend walkthrough capture bundle",
        "files": [_manifest_entry(spec, capture) for spec, capture in captures],
    }

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    for spec, capture in captures:
        (OUTPUT_DIR / spec.filename).write_bytes(capture)
    MANIFEST_PATH.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    print("Generated controlled frontend capture bundle:")
    for entry in manifest["files"]:
        assert isinstance(entry, dict)
        print(
            f"  {entry['filename']}: sha256={entry['sha256']} "
            f"packets={entry['packet_count']} bytes={entry['size_bytes']}"
        )
    print(f"  manifest: {MANIFEST_PATH.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
