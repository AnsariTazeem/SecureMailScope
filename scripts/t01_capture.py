"""Bounded dumpcap capture runner for the controlled loopback T01 fixture.

Starts `dumpcap` on the loopback interface with a TCP-port BPF filter before
the client connects, and stops it after the clean connection close. The
process is launched with an argument list and shell=False, bounded by an
auto-stop duration, readiness polling, and stop timeouts. No sudo, no
Docker, no network beyond loopback.
"""

from __future__ import annotations

import re
import signal
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from _fixture_common import FixtureToolError, bound_text

PCAP_FILENAME = "smtp_tls12_valid.pcapng"
CAPTURE_INTERFACE = "lo"
CAPTURE_BPF_FILTER = "tcp port 2525"
READY_TIMEOUT_SECONDS = 15.0
STOP_TIMEOUT_SECONDS = 20.0
MAX_CAPTURE_DURATION_SECONDS = 120
CAPTURE_DRAIN_SECONDS = 1.0
MIN_PCAPNG_HEADER_BYTES = 32

CAPTURE_LOG_DIRNAME = Path("fixtures/capture_logs")
CAPTURE_LOG_FILENAME = "t01_dumpcap.log"

_PACKETS_CAPTURED_LINE = re.compile(r"^Packets captured:\s*(\d+)\s*$", re.MULTILINE)
_RECEIVED_DROPPED_LINE = re.compile(
    r"^Packets received/dropped on interface.*?:\s*(\d+)/(\d+)(?:\s+\(.*\))?\s*$",
    re.MULTILINE,
)


@dataclass(frozen=True)
class DumpcapSummary:
    """Counts reported by dumpcap after a clean stop."""

    captured: int
    received: int
    dropped: int


def parse_dumpcap_summary(tool_output: str) -> DumpcapSummary | None:
    """Parse the installed dumpcap stop summary; None when lines are missing/malformed.

    Accepts the mandatory one-line form where the parenthetical counters follow
    `N/N` on the same line (dumpcap 4.2.2), and stays compatible with a variant
    that emits the parenthetical section on its own next line.
    """
    captured_match = _PACKETS_CAPTURED_LINE.search(tool_output)
    dropped_match = _RECEIVED_DROPPED_LINE.search(tool_output)
    if captured_match is None or dropped_match is None:
        return None
    return DumpcapSummary(
        captured=int(captured_match.group(1)),
        received=int(dropped_match.group(1)),
        dropped=int(dropped_match.group(2)),
    )


class CaptureRunnerError(FixtureToolError):
    """dumpcap could not start, produce output, or stop cleanly."""


class DumpcapRunner:
    """Lifecycle wrapper around one bounded dumpcap invocation."""

    def __init__(
        self,
        pcap_path: Path,
        *,
        interface: str = CAPTURE_INTERFACE,
        bpf_filter: str = CAPTURE_BPF_FILTER,
        max_duration_seconds: int = MAX_CAPTURE_DURATION_SECONDS,
    ) -> None:
        self._pcap_path = pcap_path
        self._interface = interface
        self._bpf_filter = bpf_filter
        self._max_duration_seconds = max_duration_seconds
        self._proc: subprocess.Popen[bytes] | None = None
        self._argv: list[str] = []
        self._stderr_text = ""

    @property
    def pcap_path(self) -> Path:
        return self._pcap_path

    @property
    def collected_stderr(self) -> str:
        """Bounded dumpcap diagnostics retained as capture evidence."""
        return self._stderr_text

    @property
    def argv(self) -> list[str]:
        return list(self._argv)

    def start(self) -> None:
        self._pcap_path.parent.mkdir(parents=True, exist_ok=True)
        argv = [
            "dumpcap",
            "-i",
            self._interface,
            "-f",
            self._bpf_filter,
            "-w",
            str(self._pcap_path),
            "-a",
            f"duration:{self._max_duration_seconds}",
        ]
        self._argv = list(argv)
        try:
            self._proc = subprocess.Popen(  # noqa: S603
                argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                shell=False,
            )
        except OSError as exc:
            raise CaptureRunnerError(
                f"dumpcap could not be launched: {bound_text(str(exc))}"
            ) from exc
        self._wait_until_ready()

    def __enter__(self) -> DumpcapRunner:
        self.start()
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> bool:
        if exc_type is not None:
            self.abort()
            return False
        self.stop()
        return False

    def stop(self) -> None:
        """Stop dumpcap gracefully (SIGTERM), requiring a clean exit code."""
        proc = self._require_running()
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=STOP_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired as exc:
            proc.kill()
            proc.wait(timeout=5)
            self._stderr_text = self._drain_stderr()
            raise CaptureRunnerError(
                f"dumpcap ignored SIGTERM for {STOP_TIMEOUT_SECONDS:g}s and was killed"
            ) from exc
        self._stderr_text = self._drain_stderr()
        if proc.returncode != 0:
            raise CaptureRunnerError(
                f"dumpcap exited with code {proc.returncode}: {bound_text(self._stderr_text)}"
            )

    def abort(self) -> None:
        """Best-effort termination used only on failure paths."""
        proc = self._proc
        if proc is None or proc.poll() is not None:
            return
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
        self._stderr_text = self._drain_stderr()

    def _wait_until_ready(self) -> None:
        assert self._proc is not None
        deadline = time.monotonic() + READY_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            returncode = self._proc.poll()
            if returncode is not None:
                self._stderr_text = self._drain_stderr()
                raise CaptureRunnerError(
                    f"dumpcap exited early with code {returncode}: {bound_text(self._stderr_text)}"
                )
            if (
                self._pcap_path.exists()
                and self._pcap_path.stat().st_size >= MIN_PCAPNG_HEADER_BYTES
            ):
                return
            time.sleep(0.1)
        self.abort()
        raise CaptureRunnerError(
            f"dumpcap produced no readable capture file within {READY_TIMEOUT_SECONDS:g}s"
        )

    def _require_running(self) -> subprocess.Popen[bytes]:
        proc = self._proc
        if proc is None:
            raise CaptureRunnerError("stop() called before start()")
        if proc.poll() is not None:
            self._stderr_text = self._drain_stderr()
            raise CaptureRunnerError(
                f"dumpcap already exited with code {proc.returncode}: "
                f"{bound_text(self._stderr_text)}"
            )
        return proc

    def _drain_stderr(self) -> str:
        proc = self._proc
        if proc is None or proc.stderr is None:
            return ""
        try:
            raw = proc.stderr.read()
        except (OSError, ValueError):
            return ""
        finally:
            if proc.stderr is not None:
                try:
                    proc.stderr.close()
                except (OSError, ValueError):
                    pass
        return raw.decode(encoding="utf-8", errors="replace")
