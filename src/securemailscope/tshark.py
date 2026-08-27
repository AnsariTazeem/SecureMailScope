"""Safe, deterministic TShark execution and raw observation normalization.

This module owns the only subprocess boundary for the E2/E3A analysis path.
Every command is an explicit argument list (never a shell string, never
``shell=True``), runs with a timeout, bounded input/output limits, checked
return codes, and bounded/sanitized stderr. Results are returned as typed
:class:`ToolExecutionRecord` objects or surfaced as typed
:class:`~securemailscope.errors.AnalysisError` failures.

TShark field rows are parsed here; multiple occurrences of a repeated field in
one frame are preserved as distinct ordered values, never flattened into an
ambiguous comma string by the caller.
"""

from __future__ import annotations

import re
import subprocess
import threading
import time
from collections.abc import Sequence
from decimal import Decimal
from pathlib import Path

from securemailscope.errors import AnalysisError, ErrorCode
from securemailscope.models import CaptureFormat, ToolExecutionRecord

DEFAULT_TIMEOUT_SECONDS = 20.0
DEFAULT_MAX_OUTPUT_CHARS = 4_000_000
_DEFAULT_STDERR_LIMIT = 2000
_READ_CHUNK_BYTES = 65536

_REASSEMBLY_PREFERENCES = ("tcp.desegment_tcp_streams:TRUE",)

_VALID_INT = re.compile(r"^\d+$")
_HEX_LINE_RE = re.compile(r"^[0-9a-fA-F]+$")


def sanitize_argv(argv: Sequence[str]) -> list[str]:
    """Validate that a command is an explicit non-shell argument list."""
    if isinstance(argv, str):
        raise AnalysisError(
            ErrorCode.TOOL_UNAVAILABLE,
            "tool",
            "commands must be argument lists, never shell strings",
        )
    parts = list(argv)
    if not parts or not all(isinstance(part, str) and part for part in parts):
        raise AnalysisError(
            ErrorCode.TOOL_UNAVAILABLE,
            "tool",
            "command arguments must be non-empty strings",
        )
    return parts


def validate_port(value: int) -> int:
    """Validate a dynamic port before it is used in a decode-as or filter."""
    if not isinstance(value, int) or not 0 <= value <= 65535:
        raise AnalysisError(
            ErrorCode.MALFORMED_TOOL_OUTPUT,
            "tshark",
            f"invalid port value for dynamic filter: {value!r}",
        )
    return value


def _bound_stderr(raw: bytes | None, limit: int = 2000) -> str:
    if not raw:
        return ""
    text = raw.decode("utf-8", errors="replace").strip()
    collapsed = " ".join(text.split())
    if len(collapsed) <= limit:
        return collapsed
    return collapsed[: limit - 3].rstrip() + "..."


def _bound_text(text: str, limit: int) -> str:
    collapsed = " ".join(text.split())
    if len(collapsed) <= limit:
        return collapsed
    return collapsed[: limit - 3].rstrip() + "..."


def _summary_part(part: str) -> str:
    """Sanitize one argument so tool records never expose full local paths."""
    if part in ("",):
        return part
    if part.startswith("/") or "/" in part:
        return Path(part).name or part
    return part


def _stop_child(proc: subprocess.Popen) -> None:
    """Terminate, then kill, then reap a child process that must go away."""
    if proc is None or proc.poll() is not None:
        return
    try:
        proc.terminate()
    except OSError:
        pass
    try:
        proc.wait(timeout=1.0)
    except subprocess.TimeoutExpired:
        try:
            proc.kill()
        except OSError:
            pass
        try:
            proc.wait(timeout=5.0)
        except subprocess.TimeoutExpired:
            pass
    except OSError:
        pass


def _bounded_read(
    handle,
    buffer: bytearray,
    limit: int,
    overflow: list[bool],
) -> None:
    """Drain one pipe into a capped buffer until EOF, marking overflow.

    The reader keeps draining (discarding excess bytes) so a slow writer is
    never blocked on a full pipe, while never accumulating more than ``limit``
    bytes. The overflow flag is set the moment a single chunk is larger than the
    remaining capacity so a fast writer that slightly exceeds the bound is not
    silently truncated. The caller is responsible for terminating an overflowed
    or timed-out child.
    """
    while True:
        try:
            chunk = handle.read(_READ_CHUNK_BYTES)
        except Exception:  # noqa: BLE001
            return
        if not chunk:
            return
        room = limit - len(buffer)
        if room <= 0:
            overflow[0] = True
            continue
        buffer.extend(chunk[:room])
        if len(chunk) > room:
            overflow[0] = True


def run_tool(
    argv: Sequence[str],
    *,
    stage: str,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    max_output_chars: int = DEFAULT_MAX_OUTPUT_CHARS,
) -> tuple[ToolExecutionRecord, str]:
    """Execute one tool as a validated argument list and return bounded output.

    Output is consumed incrementally from both pipes with per-stream byte caps
    enforced *while the process runs*; a process that overruns the bound (or
    times out) is terminated, killed, and reaped. Returns ``(record, text)`` on
    success and raises a typed :class:`AnalysisError` otherwise.
    """
    parts = sanitize_argv(argv)
    tool = parts[0]
    argument_summary = " ".join(_summary_part(part) for part in parts[1:])
    started = time.perf_counter()
    try:
        proc = subprocess.Popen(  # noqa: S603
            parts,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
        )
    except FileNotFoundError as exc:
        raise AnalysisError(
            ErrorCode.TOOL_UNAVAILABLE,
            stage,
            f"executable '{tool}' not found on PATH",
        ) from exc

    stdout_buf = bytearray()
    stderr_buf = bytearray()
    stdout_overflow: list[bool] = [False]
    stderr_overflow: list[bool] = [False]
    stdout_thread = threading.Thread(
        target=_bounded_read,
        args=(proc.stdout, stdout_buf, max_output_chars, stdout_overflow),
    )
    stderr_thread = threading.Thread(
        target=_bounded_read,
        args=(proc.stderr, stderr_buf, _DEFAULT_STDERR_LIMIT, stderr_overflow),
    )
    stdout_thread.start()
    stderr_thread.start()

    timed_out = False
    overflowed = False
    deadline = time.monotonic() + timeout_seconds
    while True:
        try:
            proc.wait(timeout=0.1)
            break
        except subprocess.TimeoutExpired:
            if stdout_overflow[0] or stderr_overflow[0]:
                overflowed = True
                _stop_child(proc)
                break
            if time.monotonic() >= deadline:
                timed_out = True
                _stop_child(proc)
                break
    # Reader threads drain to EOF of their own accord; joining never short-
    # circuits a normally exited child. Overflow must be re-checked after both
    # threads finish because a fast writer can exceed the bound and exit before
    # the polling loop ever observes the flag.
    stdout_thread.join(timeout=5.0)
    stderr_thread.join(timeout=5.0)

    runtime = time.perf_counter() - started
    if overflowed or stdout_overflow[0] or stderr_overflow[0]:
        raise AnalysisError(
            ErrorCode.TOOL_OUTPUT_TOO_LARGE,
            stage,
            f"'{tool}' output exceeded configured limits",
        )
    if timed_out:
        raise AnalysisError(
            ErrorCode.TOOL_TIMEOUT,
            stage,
            f"'{tool}' timed out after {timeout_seconds:g} seconds",
        )

    stdout_text = bytes(stdout_buf).decode("utf-8", errors="replace")
    stderr_diagnostic = _bound_stderr(bytes(stderr_buf))
    record = ToolExecutionRecord(
        tool=tool,
        argument_summary=argument_summary,
        stage=stage,
        timeout_seconds=timeout_seconds,
        runtime_seconds=runtime,
        exit_code=proc.returncode,
        succeeded=proc.returncode == 0,
        stderr_diagnostic=stderr_diagnostic,
        output_char_count=len(stdout_text),
    )
    if proc.returncode != 0:
        detail = stderr_diagnostic or _bound_text(stdout_text, 200)
        raise AnalysisError(
            ErrorCode.TOOL_NONZERO_EXIT,
            stage,
            f"'{tool}' exited with code {proc.returncode}",
            detail=detail,
        )
    return record, stdout_text


# ─────────────────────────────────────────────────────────────────────────────
#  Command builders
# ─────────────────────────────────────────────────────────────────────────────


def build_tshark_argv(
    pcap_path: Path,
    *,
    display_filter: str,
    fields: Sequence[str],
    decode_as: str | None = None,
) -> list[str]:
    """Deterministic two-pass TShark command (list, never a shell string)."""
    argv = ["tshark", "-2", "-r", str(pcap_path)]
    for preference in _REASSEMBLY_PREFERENCES:
        argv.extend(["-o", preference])
    if decode_as is not None:
        argv.extend(["-d", decode_as])
    argv.extend(["-Y", display_filter, "-T", "fields"])
    for field_name in fields:
        argv.extend(["-e", field_name])
    return argv


def build_follow_argv(pcap_path: Path, stream_id: int) -> list[str]:
    """TShark-native raw byte-stream follow command for one TCP stream."""
    if not isinstance(stream_id, int) or stream_id < 0:
        raise AnalysisError(
            ErrorCode.MALFORMED_TOOL_OUTPUT,
            "tshark",
            f"invalid tcp.stream for follow: {stream_id!r}",
        )
    return ["tshark", "-q", "-r", str(pcap_path), "-z", f"follow,tcp,raw,{stream_id}"]


def build_epochs_argv(pcap_path: Path) -> list[str]:
    """TShark command returning ``frame.time_epoch`` for *every* packet."""
    return ["tshark", "-r", str(pcap_path), "-T", "fields", "-e", "frame.time_epoch"]


def decode_as_arg(port: int, dissector: str) -> str:
    """Build a ``tcp.port==PORT,dissector`` decode-as from a validated int port."""
    validate_port(port)
    return f"tcp.port=={port},{dissector}"


def capinfos_argv(pcap_path: Path) -> list[str]:
    """capinfos command as an argument list."""
    return ["capinfos", str(pcap_path)]


def capinfos_stats_argv(pcap_path: Path) -> list[str]:
    """capinfos with explicit options for packet count and epochs."""
    return ["capinfos", "-c", "-u", str(pcap_path)]


def tshark_version_argv() -> list[str]:
    return ["tshark", "--version"]


def capinfos_version_argv() -> list[str]:
    return ["capinfos", "--version"]


# ─────────────────────────────────────────────────────────────────────────────
#  TShark output parsing
# ─────────────────────────────────────────────────────────────────────────────


def parse_packet_count(tool_output: str) -> int:
    """Parse ``Number of packets:``/``= N`` from capinfos output."""
    _PACKET_COUNT = re.compile(r"^\s*Number of packets\s*[:=]\s*(\d+)\s*$")
    for line in tool_output.splitlines():
        match = _PACKET_COUNT.match(line)
        if match:
            return int(match.group(1))
    raise AnalysisError(
        ErrorCode.MALFORMED_TOOL_OUTPUT,
        "intake",
        "packet count not present in tool output",
    )


def parse_capture_format(tool_output: str) -> CaptureFormat:
    """Infer pcap vs pcapng from actual tool output (never the extension)."""
    lowered = tool_output.lower()
    if "pcapng" in lowered:
        return CaptureFormat.PCAPNG
    if "pcap" in lowered:
        return CaptureFormat.PCAP
    return CaptureFormat.UNKNOWN


def parse_stream_ids(tool_output: str) -> list[int]:
    """Parse a single-column list of TCP stream ids."""
    stream_ids: list[int] = []
    for line in tool_output.splitlines():
        token = line.strip()
        if not token:
            continue
        if not _VALID_INT.match(token):
            raise AnalysisError(
                ErrorCode.MALFORMED_TOOL_OUTPUT,
                "tshark",
                f"malformed tcp.stream value '{token[:20]}'",
            )
        stream_ids.append(int(token))
    return stream_ids


def parse_reassembly_errors(tool_output: str) -> set[int]:
    """Return the set of streams that carry a TCP reassembly error."""
    streams: set[int] = set()
    for line in tool_output.splitlines():
        token = line.strip()
        if not token or not _VALID_INT.match(token):
            continue
        streams.add(int(token))
    return streams


def parse_follow_output(tool_output: str) -> tuple[bytes, bytes, str, str, bool]:
    """Parse ``follow,tcp,raw,<id>`` output into the two node byte-streams.

    Returns ``(node0_bytes, node1_bytes, node0_endpoint, node1_endpoint,
    incomplete)``. Non-tabbed lines originate from node 0, tabbed lines from
    node 1 (per TShark follow output). Endpoints are ``ip:port`` strings from
    the ``Node N: <ip>:<port>`` headers; ``incomplete`` is True when TShark
    emitted its `...` lost-bytes marker. The caller maps node0/node1 to its own
    client/server by matching endpoints, never by assuming node order.
    """
    node0 = bytearray()
    node1 = bytearray()
    node0_endpoint = ""
    node1_endpoint = ""
    incomplete = False
    for line in tool_output.splitlines():
        if line.startswith("Node 0:"):
            node0_endpoint = line.split(":", 1)[1].strip()
            continue
        if line.startswith("Node 1:"):
            node1_endpoint = line.split(":", 1)[1].strip()
            continue
        if not line or "===" in line or line.startswith("Follow:") or line.startswith("Filter:"):
            continue
        is_node1 = line.startswith("\t")
        token = line[1:] if is_node1 else line
        token = token.strip()
        if not token:
            continue
        if token == "...":
            incomplete = True
            continue
        if _HEX_LINE_RE.match(token):
            raw = bytes.fromhex(token)
            if is_node1:
                node1.extend(raw)
            else:
                node0.extend(raw)
    return bytes(node0), bytes(node1), node0_endpoint, node1_endpoint, incomplete


def parse_epoch_extremes(tool_output: str) -> tuple[Decimal | None, Decimal | None]:
    """Return ``(first_epoch, last_epoch)`` Decimals across all listed packets.

    Each non-empty line is a ``frame.time_epoch`` value from every packet in
    the capture (not just the TCP-filtered subset). A malformed/non-numeric
    value is surfaced as a typed parse error rather than silently ignored.
    """
    epochs: list[Decimal] = []
    for line in tool_output.splitlines():
        token = line.strip()
        if not token:
            continue
        try:
            epochs.append(Decimal(token))
        except (ValueError, ArithmeticError):
            raise AnalysisError(
                ErrorCode.MALFORMED_TOOL_OUTPUT,
                "tshark",
                f"malformed frame.time_epoch value '{token[:20]}'",
            ) from None
    if not epochs:
        return None, None
    return min(epochs), max(epochs)


def detect_truncation_warning(stderr_diagnostic: str) -> bool:
    """Report whether TShark stderr indicates capture truncation/malformation."""
    lowered = stderr_diagnostic.lower()
    return any(keyword in lowered for keyword in _TRUNCATION_KEYWORDS)


_TRUNCATION_KEYWORDS = (
    "truncated",
    "not fully dissected",
    "malformed packet",
    "cannot reassemble",
    "[malformed",
)
