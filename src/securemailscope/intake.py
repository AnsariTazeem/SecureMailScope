"""Generic capture intake and immutable provenance.

The intake stage validates the input path (typed errors), fingerprints the
capture with a streamed SHA-256 (never loading the whole file), enforces a
configurable maximum size, and obtains capture format and packet count from
actual tool inspection (never the file extension), and records the relevant
tool versions. Exact first/last packet epochs are populated later by the
analysis stage from observed frame timestamps.

The supplied capture is never mutated, normalized, copied, rewritten, or
repaired.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from securemailscope.errors import AnalysisError, ErrorCode
from securemailscope.models import (
    CaptureFormat,
    CaptureProvenance,
    ProvenanceStatus,
    ToolExecutionRecord,
)
from securemailscope.tshark import (
    capinfos_argv,
    capinfos_stats_argv,
    capinfos_version_argv,
    parse_capture_format,
    parse_packet_count,
    run_tool,
    tshark_version_argv,
)

HASH_READ_CHUNK_BYTES = 65536
DEFAULT_MAX_INPUT_BYTES = 512 * 1024 * 1024


def _stream_sha256(path: Path) -> tuple[str, int]:
    """Hash by streaming fixed-size chunks so large captures never enter memory."""
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        while chunk := handle.read(HASH_READ_CHUNK_BYTES):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def validate_input_path(path: Path, *, max_input_bytes: int = DEFAULT_MAX_INPUT_BYTES) -> Path:
    """Resolve and validate the capture path with typed errors."""
    if not path.exists():
        raise AnalysisError(
            ErrorCode.PATH_NOT_FOUND,
            "intake",
            f"input path not found: {path}",
        )
    if not path.is_file():
        raise AnalysisError(
            ErrorCode.NOT_A_REGULAR_FILE,
            "intake",
            f"input is not a regular file: {path}",
        )
    if path.stat().st_size == 0:
        raise AnalysisError(
            ErrorCode.EMPTY_INPUT,
            "intake",
            f"input capture is empty: {path}",
        )
    if path.stat().st_size > max_input_bytes:
        raise AnalysisError(
            ErrorCode.INPUT_TOO_LARGE,
            "intake",
            f"input exceeds configured maximum of {max_input_bytes} bytes",
        )
    return path


def _execute(
    argv: list[str],
    *,
    stage: str,
    timeout_seconds: float,
    tool_records: list[ToolExecutionRecord],
) -> str:
    record, stdout_text = run_tool(argv, stage=stage, timeout_seconds=timeout_seconds)
    tool_records.append(record)
    return stdout_text


def build_capture_provenance(
    path: Path,
    *,
    max_input_bytes: int = DEFAULT_MAX_INPUT_BYTES,
    timeout_seconds: float,
    tool_records: list[ToolExecutionRecord] | None = None,
) -> CaptureProvenance:
    """Compute immutable capture provenance from an already-validated path.

    ``tool_records`` is an optional caller-owned list to which execution records
    are appended; when omitted, records are discarded.
    """
    records = tool_records if tool_records is not None else []
    warnings: list[str] = []

    sha256_hex, size_bytes = _stream_sha256(path)

    try:
        tshark_version = _tool_first_line(
            _execute(
                tshark_version_argv(),
                stage="intake",
                timeout_seconds=timeout_seconds,
                tool_records=records,
            )
        )
    except AnalysisError as exc:
        tshark_version = ""
        warnings.append(f"tshark version unavailable: {exc.message}")

    try:
        capinfos_version = (
            _execute(
                capinfos_version_argv(),
                stage="intake",
                timeout_seconds=timeout_seconds,
                tool_records=records,
            )
            .splitlines()[0]
            .strip()
        )
    except (AnalysisError, IndexError):
        capinfos_version = ""

    capinfos_out = _execute(
        capinfos_argv(path),
        stage="intake",
        timeout_seconds=timeout_seconds,
        tool_records=records,
    )
    capture_format = parse_capture_format(capinfos_out)
    if capture_format is CaptureFormat.UNKNOWN:
        raise AnalysisError(
            ErrorCode.UNSUPPORTED_CAPTURE,
            "intake",
            f"capture format could not be identified for {path}",
        )

    stats_out = _execute(
        capinfos_stats_argv(path),
        stage="intake",
        timeout_seconds=timeout_seconds,
        tool_records=records,
    )
    packet_count = parse_packet_count(stats_out)

    if packet_count == 0:
        raise AnalysisError(
            ErrorCode.NO_PACKETS,
            "intake",
            f"capture contains no packets (capinfos reported {packet_count})",
        )

    return CaptureProvenance(
        input_path=str(path.resolve()),
        sha256=sha256_hex,
        size_bytes=size_bytes,
        capture_format=capture_format,
        packet_count=packet_count,
        tshark_version=tshark_version,
        capinfos_version=capinfos_version,
        status=ProvenanceStatus.OK,
        warnings=warnings,
    )


def _tool_first_line(text: str) -> str:
    for line in text.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped
    return ""
