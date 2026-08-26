"""Shared bounded-execution, hashing, and wire-row helpers for fixture tooling.

Fixture scripts intentionally live outside the `securemailscope` package:
ground-truth generation and manual verification must never depend on analyzer
code. Everything here is generic infrastructure with no protocol semantics
beyond byte-level TCP payload rows.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_TIMEOUT_SECONDS = 20.0
DETAIL_TEXT_LIMIT = 240
HASH_READ_CHUNK_BYTES = 65536
LOG_TEXT_LIMIT_CHARS = 4000

_PACKET_COUNT_LINE = re.compile(r"^\s*Number of packets\s*[:=]\s*(\d+)\s*$")
_EPOCH_ROW_MIN_COLUMNS = 2
EPOCH_TEXT_PATTERN = re.compile(r"^\d+\.\d{1,9}$")


class FixtureError(RuntimeError):
    """Base class for typed fixture-generation and verification failures."""


class FixtureToolError(FixtureError):
    """An external tool invocation could not produce a usable result."""


@dataclass(frozen=True)
class PayloadFrame:
    """One TCP payload row as reported by TShark for a single frame."""

    frame_number: int
    source_ip: str
    source_port: int
    destination_port: int
    payload: bytes


@dataclass(frozen=True)
class BoundedRun:
    """Bounded outcome of one external command executed without a shell."""

    argv_head: str
    returncode: int
    stdout_text: str
    stderr_text: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0


@dataclass(frozen=True)
class FileIntegrity:
    """Streaming SHA-256 digest and byte size of one file."""

    sha256_hex: str
    size_bytes: int


@dataclass(frozen=True)
class CommandWindow:
    """Frames whose payloads jointly carry one located command byte range."""

    frames: tuple[PayloadFrame, ...]
    start_offset: int
    end_offset: int


@dataclass(frozen=True)
class FrameEpoch:
    """One frame number with its absolute epoch timestamp."""

    frame_number: int
    epoch_seconds: str


def parse_packet_count(tool_output: str) -> int | None:
    """Parse `Number of packets:` or `= N` lines; None when absent/malformed."""
    for line in tool_output.splitlines():
        match = _PACKET_COUNT_LINE.match(line)
        if match:
            return int(match.group(1))
    return None


def parse_frame_epoch_rows(stdout_text: str) -> tuple[FrameEpoch, ...]:
    """Parse `-T fields -e frame.number -e frame.time_epoch` rows."""
    rows: list[FrameEpoch] = []
    for line in stdout_text.splitlines():
        columns = line.split("\t")
        if len(columns) < _EPOCH_ROW_MIN_COLUMNS:
            continue
        try:
            frame_number = int(columns[0])
            Decimal(columns[1])
        except (ValueError, InvalidOperation):
            continue
        rows.append(FrameEpoch(frame_number=frame_number, epoch_seconds=columns[1]))
    return tuple(rows)


def parse_validated_epoch(text: str) -> Decimal | None:
    """Strict forensic epoch: `sec.frac` with 1-9 fractional digits.

    Returns None for malformed, negative, or non-finite values. Equality and
    ordering must use the returned Decimal, never float.
    """
    if not EPOCH_TEXT_PATTERN.match(text.strip()):
        return None
    try:
        value = Decimal(text.strip())
    except InvalidOperation:
        return None
    if not value.is_finite() or value < 0:
        return None
    return value


def decimal_epoch_to_utc_iso(epoch: Decimal) -> str:
    """Canonical UTC rendering with fixed nine fractional digits (no float)."""
    total_nanoseconds = int((epoch * Decimal(1_000_000_000)).to_integral_value())
    seconds, nanoseconds = divmod(total_nanoseconds, 1_000_000_000)
    moment = datetime.fromtimestamp(seconds, tz=UTC)
    return (
        f"{moment.year:04d}-{moment.month:02d}-{moment.day:02d}"
        f"T{moment.hour:02d}:{moment.minute:02d}:{moment.second:02d}."
        f"{nanoseconds:09d}Z"
    )


def capture_interval(
    rows: Sequence[FrameEpoch],
) -> tuple[str, str] | None:
    """First (by frame order) and last packet epochs; None without rows."""
    if not rows:
        return None
    ordered = sorted(rows, key=lambda row: row.frame_number)
    return ordered[0].epoch_seconds, ordered[-1].epoch_seconds


def truncate_log_text(text: str, limit: int = LOG_TEXT_LIMIT_CHARS) -> str:
    """Bounded log content that preserves line structure."""
    if len(text) <= limit:
        return text
    return text[:limit].rstrip() + "\n... [truncated]"


def normalize_argv(argv: Sequence[str]) -> list[str]:
    """Reject shell strings and malformed argument lists before execution."""
    if isinstance(argv, str):
        raise FixtureToolError("commands must be argument lists, never shell strings")
    parts = list(argv)
    if not parts or not all(isinstance(part, str) and part for part in parts):
        raise FixtureToolError("command arguments must be non-empty strings")
    return parts


def run_bounded(
    argv: Sequence[str],
    *,
    error_stage: str,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
) -> BoundedRun:
    """Execute an argument-list command with shell=False and a hard timeout."""
    parts = normalize_argv(argv)
    try:
        completed = subprocess.run(  # noqa: S603
            parts,
            capture_output=True,
            check=False,
            shell=False,
            timeout=timeout_seconds,
        )
    except FileNotFoundError as exc:
        raise FixtureToolError(
            f"{error_stage}: executable '{parts[0]}' was not found on PATH"
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise FixtureToolError(
            f"{error_stage}: '{parts[0]}' timed out after {timeout_seconds:g} seconds"
        ) from exc
    return BoundedRun(
        argv_head=parts[0],
        returncode=completed.returncode,
        stdout_text=decode_bytes(completed.stdout),
        stderr_text=decode_bytes(completed.stderr),
    )


def decode_bytes(raw: bytes | None) -> str:
    if not raw:
        return ""
    return raw.decode(encoding="utf-8", errors="replace")


def bound_text(text: str, limit: int = DETAIL_TEXT_LIMIT) -> str:
    collapsed = " ".join(text.split())
    if len(collapsed) <= limit:
        return collapsed
    return collapsed[: limit - 3].rstrip() + "..."


def sha256_file(path: Path) -> FileIntegrity:
    """Hash a file by streaming so large captures never enter memory."""
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        while chunk := handle.read(HASH_READ_CHUNK_BYTES):
            digest.update(chunk)
            size += len(chunk)
    return FileIntegrity(sha256_hex=digest.hexdigest(), size_bytes=size)


def iso_utc(moment: datetime) -> str:
    return moment.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def utc_now() -> datetime:
    return datetime.now(UTC)


def parse_utc_iso(value: str) -> datetime:
    return datetime.fromisoformat(value.strip().replace("Z", "+00:00"))


def write_json_file(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(payload, indent=2, ensure_ascii=True) + "\n"
    path.write_text(text, encoding="utf-8")


def parse_payload_rows(stdout_text: str) -> tuple[PayloadFrame, ...]:
    """Parse `tshark -T fields` rows of frame/ip/ports/payload into frames."""
    frames: list[PayloadFrame] = []
    for line in stdout_text.splitlines():
        columns = line.split("\t")
        if len(columns) < 5 or not columns[4]:
            continue
        try:
            frame_number = int(columns[0])
            source_port = int(columns[2])
            destination_port = int(columns[3])
            payload = bytes.fromhex(columns[4].replace(":", ""))
        except ValueError:
            continue
        frames.append(
            PayloadFrame(
                frame_number=frame_number,
                source_ip=columns[1],
                source_port=source_port,
                destination_port=destination_port,
                payload=payload,
            )
        )
    return tuple(frames)


def locate_command_window(
    ordered_frames: Sequence[PayloadFrame], command: bytes, minimum_frames: int
) -> CommandWindow | None:
    """Find the contiguous frames carrying `command`; require >= minimum_frames."""
    buffer = b"".join(frame.payload for frame in ordered_frames)
    start = buffer.find(command)
    if start < 0:
        return None
    end = start + len(command)
    offset = 0
    covering: list[PayloadFrame] = []
    for frame in ordered_frames:
        frame_start = offset
        frame_end = offset + len(frame.payload)
        offset = frame_end
        if frame_start < end and frame_end > start:
            covering.append(frame)
    if len(covering) < minimum_frames or buffer[start:end] != command:
        return None
    return CommandWindow(frames=tuple(covering), start_offset=start, end_offset=end)
