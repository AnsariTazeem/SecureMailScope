"""Capture intake/provenance tests (external tools mocked)."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from securemailscope.errors import AnalysisError, ErrorCode
from securemailscope.intake import (
    build_capture_provenance,
    validate_input_path,
)
from securemailscope.models import CaptureFormat, ProvenanceStatus
from securemailscope.tshark import ToolExecutionRecord


def _write_pcap(path: Path, content: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return path


def _sha(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _fake_run(argv: list[str], *, stage: str, timeout_seconds: float):
    tool = argv[0]
    return ToolExecutionRecord(
        tool=tool,
        argument_summary=" ".join(argv[1:]),
        stage=stage,
        timeout_seconds=timeout_seconds,
        runtime_seconds=0.01,
        exit_code=0,
        succeeded=True,
        output_char_count=0,
    ), _stdout_for(tool, argv)


def _stdout_for(tool: str, argv: list[str]) -> str:
    if tool == "tshark":
        return "TShark (Wireshark) 4.2.0\n"
    if tool == "capinfos":
        if "-c" in argv:
            return "Number of packets: 7\n"
        return "File type = Wireshark/tcpdump/... - pcapng\n"
    return ""


def test_validate_input_path_typed_errors(tmp_path: Path) -> None:
    missing = tmp_path / "missing.pcap"
    with pytest.raises(AnalysisError) as exc:
        validate_input_path(missing)
    assert exc.value.code is ErrorCode.PATH_NOT_FOUND

    empty = _write_pcap(tmp_path / "empty.pcap", b"")
    with pytest.raises(AnalysisError) as exc:
        validate_input_path(empty)
    assert exc.value.code is ErrorCode.EMPTY_INPUT

    directory = tmp_path
    with pytest.raises(AnalysisError) as exc:
        validate_input_path(directory)
    assert exc.value.code is ErrorCode.NOT_A_REGULAR_FILE


def test_validate_input_path_rejects_oversize(tmp_path: Path) -> None:
    cap = _write_pcap(tmp_path / "big.pcap", b"x" * 64)
    with pytest.raises(AnalysisError) as exc:
        validate_input_path(cap, max_input_bytes=8)
    assert exc.value.code is ErrorCode.INPUT_TOO_LARGE


def test_build_provenance_with_mocked_tools(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    content = b"pcapng-bytes-for-provenance"
    cap = _write_pcap(tmp_path / "x.pcapng", content)
    from securemailscope import intake as intake_mod

    monkeypatch.setattr(intake_mod, "run_tool", _fake_run)
    records: list[ToolExecutionRecord] = []
    prov = build_capture_provenance(cap, tool_records=records, timeout_seconds=5.0)
    assert prov.capture_format is CaptureFormat.PCAPNG
    assert prov.sha256 == _sha(content)
    assert prov.size_bytes == len(content)
    assert prov.packet_count == 7
    assert prov.status is ProvenanceStatus.OK
    assert records, "execution records should be appended"
    assert prov.tshark_version


def _fake_run_with_stats(stats_out: str):
    def fake_run(argv: list[str], *, stage: str, timeout_seconds: float):  # noqa: ANN001
        tool = argv[0]
        if tool == "capinfos" and "-c" in argv:
            out = stats_out
        else:
            out = _stdout_for(tool, argv)
        return ToolExecutionRecord(
            tool=tool,
            argument_summary=" ".join(argv[1:]),
            stage=stage,
            timeout_seconds=timeout_seconds,
            runtime_seconds=0.01,
            exit_code=0,
            succeeded=True,
            output_char_count=0,
        ), out

    return fake_run


def test_zero_packet_count_raises_no_packets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cap = _write_pcap(tmp_path / "zero.pcap", b"data")
    from securemailscope import intake as intake_mod

    monkeypatch.setattr(intake_mod, "run_tool", _fake_run_with_stats("Number of packets: 0\n"))
    with pytest.raises(AnalysisError) as exc:
        build_capture_provenance(cap, timeout_seconds=5.0)
    assert exc.value.code is ErrorCode.NO_PACKETS


def test_malformed_packet_count_is_not_no_packets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cap = _write_pcap(tmp_path / "bad.pcap", b"data")
    from securemailscope import intake as intake_mod

    monkeypatch.setattr(intake_mod, "run_tool", _fake_run_with_stats("garbage output\n"))
    with pytest.raises(AnalysisError) as exc:
        build_capture_provenance(cap, timeout_seconds=5.0)
    assert exc.value.code is ErrorCode.MALFORMED_TOOL_OUTPUT
