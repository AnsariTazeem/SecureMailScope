"""Doctor command tests.

Every external command is mocked; no real tool is invoked, nothing is
captured, and no network access occurs.
"""

from __future__ import annotations

import json
import subprocess
from typing import Any

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from securemailscope import tooling
from securemailscope.cli import EXIT_OK, EXIT_PREREQUISITE_FAILURE, app
from securemailscope.models import CheckStatus, DoctorCheck, DoctorReport
from securemailscope.tooling import REQUIRED_TOOLS, REQUIRED_TSHARK_FIELDS

runner = CliRunner()

DECOY_FIELDS = ("frame.number", "frame.time_epoch", "ip.src")

EXPECTED_CHECK_IDS = (
    "python-version",
    *(f"{tool}-available" for tool in REQUIRED_TOOLS),
    "dumpcap-loopback",
    "tshark-fields-query",
    "tshark-required-fields",
)


def _completed(
    command: list[str], *, returncode: int = 0, stdout: bytes = b"", stderr: bytes = b""
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.CompletedProcess(command, returncode, stdout, stderr)


def _fields_stdout(fields: set[str]) -> bytes:
    return "".join(
        f"F\tDisplay Name\t{name}\tFT_NONE\tsome.protocol\tBASE_DEC\t0x0\t\n"
        for name in sorted(fields)
    ).encode()


def _install_environment(
    monkeypatch: pytest.MonkeyPatch,
    *,
    tools: tuple[str, ...] | set[str] = REQUIRED_TOOLS,
    dumpcap_outcome: subprocess.CompletedProcess[bytes] | Exception | None = None,
    tshark_outcome: subprocess.CompletedProcess[bytes] | Exception | None = None,
) -> None:
    available = set(tools)
    dumpcap_default = _completed(["dumpcap", "-D"], stdout=b"1. lo\n2. eth0\n")
    tshark_default = _completed(
        ["tshark", "-G", "fields"],
        stdout=_fields_stdout(set(REQUIRED_TSHARK_FIELDS) | set(DECOY_FIELDS)),
    )

    def fake_which(name: str) -> str | None:
        return f"/usr/bin/{name}" if name in available else None

    def fake_run_subprocess(
        command: list[str], *, timeout_seconds: float
    ) -> subprocess.CompletedProcess[bytes]:
        assert isinstance(command, list)
        assert isinstance(timeout_seconds, float)
        assert 0 < timeout_seconds < 3600
        if command == ["dumpcap", "-D"]:
            outcome: Any = dumpcap_default if dumpcap_outcome is None else dumpcap_outcome
        elif command == ["tshark", "-G", "fields"]:
            outcome = tshark_default if tshark_outcome is None else tshark_outcome
        else:
            raise AssertionError(f"unexpected command probed: {command}")
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    monkeypatch.setattr(tooling, "which", fake_which)
    monkeypatch.setattr(tooling, "_run_subprocess", fake_run_subprocess)


def test_complete_environment_passes_in_deterministic_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_environment(monkeypatch)

    report = tooling.collect_doctor_report()

    assert report.schema_version == "1.0"
    assert report.command == "doctor"
    assert report.ready is True
    assert [check.id for check in report.checks] == list(EXPECTED_CHECK_IDS)
    assert all(check.status is CheckStatus.PASS for check in report.checks)
    assert all(check.required is True for check in report.checks)


def test_missing_executable_fails_only_that_check(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_environment(monkeypatch, tools=set(REQUIRED_TOOLS) - {"jq"})

    report = tooling.collect_doctor_report()

    jq_check = next(check for check in report.checks if check.id == "jq-available")
    assert jq_check.status is CheckStatus.FAIL
    assert jq_check.observed == "not found on PATH"
    assert report.ready is False
    others = [check for check in report.checks if check.id != "jq-available"]
    assert all(check.status is CheckStatus.PASS for check in others)


def test_missing_required_tshark_field_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    reduced_fields = set(REQUIRED_TSHARK_FIELDS) - {"tls.handshake.ciphersuite"}
    reduced_fields |= set(DECOY_FIELDS)
    _install_environment(
        monkeypatch,
        tshark_outcome=_completed(
            ["tshark", "-G", "fields"], stdout=_fields_stdout(reduced_fields)
        ),
    )

    report = tooling.collect_doctor_report()

    query_check = next(c for c in report.checks if c.id == "tshark-fields-query")
    fields_check = next(c for c in report.checks if c.id == "tshark-required-fields")
    assert query_check.status is CheckStatus.PASS
    assert fields_check.status is CheckStatus.FAIL
    assert "tls.handshake.ciphersuite" in fields_check.observed
    assert report.ready is False


def test_failed_dumpcap_subprocess_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_environment(
        monkeypatch,
        dumpcap_outcome=_completed(
            ["dumpcap", "-D"], returncode=1, stderr=b"dumppcap: permission denied\n"
        ),
    )

    report = tooling.collect_doctor_report()

    loopback_check = next(check for check in report.checks if check.id == "dumpcap-loopback")
    assert loopback_check.status is CheckStatus.FAIL
    assert "exited with code 1" in loopback_check.observed
    assert report.ready is False


def test_timed_out_subprocess_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_environment(
        monkeypatch,
        dumpcap_outcome=subprocess.TimeoutExpired(cmd=["dumpcap", "-D"], timeout=15.0),
    )

    report = tooling.collect_doctor_report()

    loopback_check = next(check for check in report.checks if check.id == "dumpcap-loopback")
    assert loopback_check.status is CheckStatus.FAIL
    assert "timed out" in loopback_check.observed
    assert report.ready is False


def test_file_not_found_probe_fails_both_tshark_checks(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_environment(monkeypatch, tshark_outcome=FileNotFoundError("tshark vanished"))

    report = tooling.collect_doctor_report()

    query_check = next(c for c in report.checks if c.id == "tshark-fields-query")
    fields_check = next(c for c in report.checks if c.id == "tshark-required-fields")
    assert query_check.status is CheckStatus.FAIL
    assert fields_check.status is CheckStatus.FAIL
    assert "not evaluated" in fields_check.observed
    assert report.ready is False


def test_cli_json_output_is_pure_valid_json_and_exits_zero(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_environment(monkeypatch)

    result = runner.invoke(app, ["doctor", "--json"])

    assert result.exit_code == EXIT_OK
    payload = json.loads(result.stdout)
    assert set(payload) == {"schema_version", "command", "ready", "checks"}
    assert payload["schema_version"] == "1.0"
    assert payload["command"] == "doctor"
    assert payload["ready"] is True
    assert [check["id"] for check in payload["checks"]] == list(EXPECTED_CHECK_IDS)
    for check in payload["checks"]:
        assert set(check) == {"id", "requirement", "status", "observed", "required"}
        assert check["status"] in {"pass", "fail"}
        assert isinstance(check["required"], bool)


def test_cli_exits_three_when_not_ready(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_environment(monkeypatch, tools=set(REQUIRED_TOOLS) - {"openssl"})

    result = runner.invoke(app, ["doctor", "--json"])

    assert result.exit_code == EXIT_PREREQUISITE_FAILURE
    payload = json.loads(result.stdout)
    assert payload["ready"] is False


def test_cli_plain_output_reports_summary_and_exit_codes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_environment(monkeypatch)
    ready_result = runner.invoke(app, ["doctor"])
    assert ready_result.exit_code == EXIT_OK
    assert "READY" in ready_result.stdout

    _install_environment(monkeypatch, tools=set(REQUIRED_TOOLS) - {"jq"})
    not_ready_result = runner.invoke(app, ["doctor"])
    assert not_ready_result.exit_code == EXIT_PREREQUISITE_FAILURE
    assert "NOT READY" in not_ready_result.stdout


def test_required_fields_include_server_named_curve() -> None:
    assert "tls.handshake.server_named_curve" in REQUIRED_TSHARK_FIELDS
    assert len(set(REQUIRED_TSHARK_FIELDS)) == len(REQUIRED_TSHARK_FIELDS)


def test_models_reject_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        DoctorCheck(
            id="x",
            requirement="y",
            status=CheckStatus.PASS,
            observed="z",
            required=True,
            unexpected="nope",
        )
    with pytest.raises(ValidationError):
        DoctorReport(schema_version="1.0", command="doctor", ready=True, checks=[], unexpected=1)
