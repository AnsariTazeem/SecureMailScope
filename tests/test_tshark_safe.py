"""Safe TShark wrapper tests (pure parsing + real bounded subprocess runner)."""

from __future__ import annotations

import sys
from decimal import Decimal
from pathlib import Path

import pytest

from securemailscope.errors import AnalysisError, ErrorCode
from securemailscope.models import CaptureFormat
from securemailscope.tshark import (
    build_follow_argv,
    build_tshark_argv,
    decode_as_arg,
    parse_capture_format,
    parse_epoch_extremes,
    parse_follow_output,
    parse_packet_count,
    run_tool,
    sanitize_argv,
    validate_port,
)

_PY = sys.executable


def test_sanitize_argv_rejects_shell_string() -> None:
    with pytest.raises(AnalysisError) as exc:
        sanitize_argv("tshark -r x.pcap")  # type: ignore[arg-type]
    assert exc.value.code is ErrorCode.TOOL_UNAVAILABLE


def test_run_tool_returns_bounded_output_really() -> None:
    record, out = run_tool([_PY, "-c", "print('ok output')"], stage="test")
    assert out.strip() == "ok output"
    assert record.succeeded
    assert record.exit_code == 0
    assert record.tool == _PY


def test_run_tool_argument_summary_never_leaks_full_path() -> None:
    code = "import sys; print(sys.argv[1:])"
    record, _out = run_tool([_PY, "-c", code, "/home/user/secret/x.pcap"], stage="test")
    assert "/home/user/secret" not in record.argument_summary
    assert "x.pcap" in record.argument_summary


def test_run_tool_nonzero_exit_with_stderr() -> None:
    code = "import sys; sys.stderr.write('boom'); sys.exit(3)"
    with pytest.raises(AnalysisError) as exc:
        run_tool([_PY, "-c", code], stage="test")
    assert exc.value.code is ErrorCode.TOOL_NONZERO_EXIT
    assert "boom" in exc.value.detail


def test_run_tool_missing_executable() -> None:
    with pytest.raises(AnalysisError) as exc:
        run_tool(["definitely-not-a-real-command-xyz"], stage="test")
    assert exc.value.code is ErrorCode.TOOL_UNAVAILABLE


def test_run_tool_timeout_terminates_and_reaps() -> None:
    code = "import time; time.sleep(30)"
    with pytest.raises(AnalysisError) as exc:
        run_tool([_PY, "-c", code], stage="test", timeout_seconds=0.4)
    assert exc.value.code is ErrorCode.TOOL_TIMEOUT


def test_run_tool_stops_reading_once_bound_crossed() -> None:
    """Reader must stop at the byte bound and the process must be killed fast."""
    code = "import sys; sys.stdout.write('x' * 1_000_000); sys.stdout.flush()"
    with pytest.raises(AnalysisError) as exc:
        run_tool([_PY, "-c", code], stage="test", max_output_chars=1000)
    assert exc.value.code is ErrorCode.TOOL_OUTPUT_TOO_LARGE
    assert exc.value.message != ""


def test_run_tool_single_fast_write_over_bound_raises() -> None:
    """A fast 10,001-byte write with a 10,000 cap must raise, never truncate."""
    code = "import sys; sys.stdout.write('x' * 10_001)"
    with pytest.raises(AnalysisError) as exc:
        run_tool([_PY, "-c", code], stage="test", max_output_chars=10_000)
    assert exc.value.code is ErrorCode.TOOL_OUTPUT_TOO_LARGE


def test_run_tool_exact_limit_succeeds_without_truncation() -> None:
    """Exactly 10,000 bytes must be returned in full, not flagged as overflow."""
    code = "import sys; sys.stdout.write('x' * 10_000)"
    record, out = run_tool([_PY, "-c", code], stage="test", max_output_chars=10_000)
    assert len(out) == 10_000
    assert set(out) == {"x"}
    assert record.succeeded


def test_run_tool_multiple_writes_below_limit_return_all_bytes() -> None:
    """Several writes in one run must all be returned without early termination."""
    code = (
        "import sys; "
        "sys.stdout.write('a' * 1000); "
        "sys.stdout.write('b' * 1000); "
        "sys.stdout.write('c' * 500); "
        "sys.stdout.write('d' * 100)"
    )
    record, out = run_tool([_PY, "-c", code], stage="test", max_output_chars=10_000)
    assert len(out) == 2600
    assert out.count("a") == 1000
    assert out.count("b") == 1000
    assert out.count("c") == 500
    assert out.count("d") == 100
    assert record.succeeded


def test_validate_port_rejects_out_of_range() -> None:
    with pytest.raises(AnalysisError):
        validate_port(-1)
    with pytest.raises(AnalysisError):
        validate_port(70000)
    assert validate_port(2525) == 2525


def test_build_tshark_argv_uses_two_pass_and_reassembly() -> None:
    argv = build_tshark_argv(
        Path("/tmp/x.pcap"),
        display_filter="tcp",
        fields=("tcp.stream", "frame.number"),
        decode_as=None,
    )
    assert "-2" in argv
    assert "-r" in argv
    assert "-Y" in argv
    assert "-T" in argv and "fields" in argv
    assert argv[-2:] == ["-e", "frame.number"]


def test_build_tshark_argv_never_shell() -> None:
    argv = build_tshark_argv(
        Path("/tmp/x.pcap"), display_filter="tcp.stream==3", fields=("tcp.stream",)
    )
    assert isinstance(argv, list)
    assert all(isinstance(part, str) for part in argv)


def test_build_follow_argv_validates_stream() -> None:
    argv = build_follow_argv(Path("/tmp/x.pcap"), 0)
    assert argv == ["tshark", "-q", "-r", "/tmp/x.pcap", "-z", "follow,tcp,raw,0"]
    with pytest.raises(AnalysisError):
        build_follow_argv(Path("/tmp/x.pcap"), -1)


def test_decode_as_arg_validates_port() -> None:
    with pytest.raises(AnalysisError):
        decode_as_arg(70000, "data")
    assert decode_as_arg(2525, "data") == "tcp.port==2525,data"


def test_parse_packet_count() -> None:
    out = "File type = Wireshark/tcpdump/... - pcapng\nNumber of packets: 42\n"
    assert parse_packet_count(out) == 42


def test_parse_capture_format_from_content_not_extension() -> None:
    assert parse_capture_format("File type = Wireshark - pcapng") is CaptureFormat.PCAPNG
    assert parse_capture_format("File type = pcap") is CaptureFormat.PCAP
    assert parse_capture_format("unrecognized") is CaptureFormat.UNKNOWN


def test_parse_follow_output_maps_nodes_and_incomplete() -> None:
    sample = (
        "===================================================================\n"
        "Follow: tcp,raw\n"
        "Filter: tcp.stream eq 0\n"
        "Node 0: 127.0.0.1:49046\n"
        "Node 1: 127.0.0.1:2525\n"
        "\t3232302068616c6c6f\r\n"
        "45484c4f0d0a\r\n"
        "...\r\n"
        "494d41500d0a\r\n"
        "===================================================================\n"
    )
    node0, node1, ep0, ep1, incomplete = parse_follow_output(sample)
    assert ep0 == "127.0.0.1:49046"
    assert ep1 == "127.0.0.1:2525"
    assert node1 == b"220 hallo"
    assert node0 == b"EHLO\r\nIMAP\r\n"
    assert incomplete is True


def test_parse_epoch_extremes_all_packets() -> None:
    out = "100.5\n100.1\n99.9999\n"
    first, last = parse_epoch_extremes(out)
    assert first == Decimal("99.9999")
    assert last == Decimal("100.5")
    assert parse_epoch_extremes("") == (None, None)


def test_parse_epoch_extremes_rejects_malformed() -> None:
    with pytest.raises(AnalysisError) as exc:
        parse_epoch_extremes("not-a-decimal\n")
    assert exc.value.code is ErrorCode.MALFORMED_TOOL_OUTPUT
