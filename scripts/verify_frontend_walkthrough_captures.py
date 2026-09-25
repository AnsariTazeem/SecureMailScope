"""Independently verify the controlled frontend walkthrough PCAPNG bundle."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
CAPTURE_DIR = REPO_ROOT / "web" / "public" / "captures"
MANIFEST_PATH = CAPTURE_DIR / "securemailscope-walkthrough-manifest.json"
MAX_TOOL_OUTPUT_BYTES = 1_000_000
TSHARK_TIMEOUT_SECONDS = 20


class VerificationError(RuntimeError):
    """The controlled capture bundle disagrees with independent observation."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65_536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _run_tshark(path: Path) -> list[dict[str, str]]:
    executable = shutil.which("tshark")
    if executable is None:
        raise VerificationError("tshark is not installed")
    fields = (
        "frame.number",
        "frame.time_epoch",
        "frame.len",
        "ip.src",
        "tcp.srcport",
        "tcp.payload",
        "tls.handshake.type",
        "tls.handshake.extensions.supported_version",
        "tls.handshake.ciphersuite",
        "tls.handshake.extensions_key_share_group",
        "tls.record.opaque_type",
    )
    argv = [
        executable,
        "-2",
        "-r",
        str(path),
        "-d",
        "tcp.port==2525,smtp",
        "-T",
        "fields",
        "-E",
        "separator=|",
    ]
    for field in fields:
        argv.extend(("-e", field))
    completed = subprocess.run(  # noqa: S603
        argv,
        capture_output=True,
        check=False,
        timeout=TSHARK_TIMEOUT_SECONDS,
    )
    if len(completed.stdout) > MAX_TOOL_OUTPUT_BYTES:
        raise VerificationError(f"{path.name}: TShark output exceeded the bound")
    if completed.returncode != 0:
        stderr = completed.stderr.decode("utf-8", errors="replace")[:500]
        raise VerificationError(f"{path.name}: TShark failed with {completed.returncode}: {stderr}")

    rows: list[dict[str, str]] = []
    text = completed.stdout.decode("utf-8", errors="strict")
    for line in text.splitlines():
        values = line.split("|")
        if len(values) != len(fields):
            raise VerificationError(f"{path.name}: malformed TShark row")
        rows.append(dict(zip(fields, values, strict=True)))
    return rows


def _payloads(rows: list[dict[str, str]], source_ip: str) -> bytes:
    joined = bytearray()
    for row in rows:
        if row["ip.src"] != source_ip or not row["tcp.payload"]:
            continue
        try:
            joined.extend(bytes.fromhex(row["tcp.payload"].replace(":", "")))
        except ValueError as exc:
            raise VerificationError("TShark returned malformed TCP payload hex") from exc
    return bytes(joined)


def _values(rows: list[dict[str, str]], field: str) -> set[str]:
    values: set[str] = set()
    for row in rows:
        values.update(value for value in row[field].split(",") if value)
    return values


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def _verify_entry(entry: dict[str, Any]) -> None:
    filename = entry.get("filename")
    _require(
        isinstance(filename, str) and Path(filename).name == filename,
        "manifest contains an unsafe filename",
    )
    path = CAPTURE_DIR / filename
    _require(path.is_file(), f"{filename}: capture is missing")
    _require(path.stat().st_size == entry["size_bytes"], f"{filename}: size mismatch")
    _require(_sha256(path) == entry["sha256"], f"{filename}: SHA-256 mismatch")

    rows = _run_tshark(path)
    expected = entry["expected"]
    _require(len(rows) == entry["packet_count"], f"{filename}: packet count mismatch")
    _require(
        sum(int(row["frame.len"]) for row in rows) == entry["frame_bytes"],
        f"{filename}: frame-byte count mismatch",
    )
    _require(
        rows[0]["frame.time_epoch"].startswith("1787824802.1")
        if filename.startswith("secure-")
        else rows[0]["frame.time_epoch"].startswith("1787828402.1"),
        f"{filename}: first packet timestamp mismatch",
    )

    client_payload = _payloads(rows, "192.0.2.10")
    server_payload = _payloads(rows, "192.0.2.20")
    _require(
        b"220 example.test ESMTP ready\r\n" in server_payload, f"{filename}: SMTP greeting missing"
    )
    _require(b"250-STARTTLS\r\n" in server_payload, f"{filename}: STARTTLS advertisement missing")

    requested = b"STARTTLS\r\n" in client_payload
    plaintext_mail = b"MAIL FROM:<sender@example.test>\r\n" in client_payload
    _require(requested is expected["starttls_requested"], f"{filename}: STARTTLS request mismatch")
    _require(
        plaintext_mail is expected["plaintext_mail_after_offer"],
        f"{filename}: plaintext MAIL state mismatch",
    )

    handshake_types = {int(value) for value in _values(rows, "tls.handshake.type")}
    _require(
        handshake_types == set(expected["tls_handshake_types"]),
        f"{filename}: TLS handshake types mismatch",
    )
    if expected["tls_handshake_types"]:
        _require(
            expected["tls_supported_version"]
            in _values(rows, "tls.handshake.extensions.supported_version"),
            f"{filename}: TLS supported version mismatch",
        )
        _require(
            expected["tls_cipher_suite"] in _values(rows, "tls.handshake.ciphersuite"),
            f"{filename}: TLS cipher mismatch",
        )
        _require(
            str(expected["tls_key_share_group"])
            in _values(rows, "tls.handshake.extensions_key_share_group"),
            f"{filename}: TLS key-share group mismatch",
        )
        _require(
            "23" in _values(rows, "tls.record.opaque_type"),
            f"{filename}: TLS 1.3 opaque application record missing",
        )
    else:
        _require(
            not _values(rows, "tls.record.opaque_type"),
            f"{filename}: unexpected TLS application record",
        )

    sensitive_markers = (b"AUTH ", b"PASSWORD", b"PRIVATE KEY", b"BEGIN CERTIFICATE")
    combined = client_payload.upper() + server_payload.upper()
    _require(
        not any(marker in combined for marker in sensitive_markers),
        f"{filename}: sensitive marker present",
    )


def main() -> int:
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    _require(manifest["schema_version"] == "1.0.0", "unexpected manifest schema")
    _require(manifest["synthetic"] is True, "bundle is not labelled synthetic")
    _require(manifest["non_sensitive"] is True, "bundle is not labelled non-sensitive")
    files = manifest["files"]
    _require(isinstance(files, list) and len(files) == 2, "expected exactly two captures")
    _require(
        {entry["filename"] for entry in files} == {"secure-chain.pcapng", "insecure-chain.pcapng"},
        "capture bundle filenames differ",
    )
    for entry in files:
        _verify_entry(entry)
    print(
        "PASS: 2 deterministic non-sensitive PCAPNG files; hashes, sizes, "
        "12/6 packet counts, 2048/1024 frame bytes, SMTP STARTTLS states, "
        "TLS 1.3 version/cipher/key-share, and plaintext continuation verified."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
