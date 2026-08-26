"""Deterministic prerequisite checks backing the `doctor` command.

This module owns environment inspection only; presentation and exit codes
belong to the CLI layer.
"""

from __future__ import annotations

import platform
import re
import subprocess
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from shutil import which

from securemailscope.models import CheckStatus, DoctorCheck, DoctorReport

SCHEMA_VERSION = "1.0"
DOCTOR_COMMAND = "doctor"

PYTHON_REQUIRED_SPEC = ">=3.12,<3.13"
_PYTHON_MINIMUM = (3, 12)
_PYTHON_NEXT_MINOR = (3, 13)

SUBPROCESS_TIMEOUT_SECONDS = 15.0
_OBSERVED_TEXT_LIMIT = 240

REQUIRED_TOOLS: tuple[str, ...] = (
    "tshark",
    "dumpcap",
    "capinfos",
    "editcap",
    "tcpdump",
    "openssl",
    "jq",
)

REQUIRED_TSHARK_FIELDS: tuple[str, ...] = (
    "tcp.stream",
    "tcp.reassembled.data",
    "tls.handshake.type",
    "tls.handshake.version",
    "tls.handshake.ciphersuite",
    "tls.handshake.extensions.supported_version",
    "tls.handshake.certificate",
    "tls.handshake.extensions_key_share_group",
    "tls.handshake.extensions_key_share_selected_group",
    "tls.handshake.extensions_supported_groups",
    "tls.handshake.server_named_curve",
)

_DUMPCAP_INTERFACE_PATTERN = re.compile(r"^\s*\d+\.\s*(\S+)")


@dataclass(frozen=True)
class CommandResult:
    """Bounded outcome of one external command execution."""

    succeeded: bool
    stdout_text: str
    error_summary: str


def collect_doctor_report() -> DoctorReport:
    """Run every prerequisite check in deterministic order and build the report."""
    checks: list[DoctorCheck] = [_check_python_version()]
    checks.extend(_check_tool_available(tool) for tool in REQUIRED_TOOLS)
    checks.append(_check_dumpcap_loopback())
    checks.extend(_check_tshark_display_fields())
    ready = all(check.status is CheckStatus.PASS for check in checks if check.required)
    return DoctorReport(
        schema_version=SCHEMA_VERSION,
        command=DOCTOR_COMMAND,
        ready=ready,
        checks=checks,
    )


def _check_python_version() -> DoctorCheck:
    current_minor = sys.version_info[:2]
    satisfied = _PYTHON_MINIMUM <= current_minor < _PYTHON_NEXT_MINOR
    observed = f"running Python {platform.python_version()} (requires {PYTHON_REQUIRED_SPEC})"
    return _make_check(
        check_id="python-version",
        requirement=f"Running Python version satisfies {PYTHON_REQUIRED_SPEC}",
        passed=satisfied,
        observed=observed,
    )


def _check_tool_available(tool: str) -> DoctorCheck:
    resolved = which(tool)
    observed = f"resolved to '{resolved}'" if resolved else "not found on PATH"
    return _make_check(
        check_id=f"{tool}-available",
        requirement=f"The '{tool}' executable is available on PATH",
        passed=resolved is not None,
        observed=observed,
    )


def _check_dumpcap_loopback() -> DoctorCheck:
    requirement = (
        "The 'dumpcap -D' interface listing succeeds and exposes the 'lo' loopback interface"
    )
    result = _execute(("dumpcap", "-D"))
    if not result.succeeded:
        return _make_check("dumpcap-loopback", requirement, False, result.error_summary)
    interfaces = _parse_dumpcap_interfaces(result.stdout_text)
    if "lo" in interfaces:
        observed = f"'lo' exposed among {len(interfaces)} listed interface(s)"
        return _make_check("dumpcap-loopback", requirement, True, observed)
    if interfaces:
        observed = f"'lo' missing; dumpcap listed: {', '.join(interfaces)}"
    else:
        observed = "'lo' missing; dumpcap listed no interfaces"
    return _make_check("dumpcap-loopback", requirement, False, observed)


def _check_tshark_display_fields() -> tuple[DoctorCheck, DoctorCheck]:
    query_requirement = "The 'tshark -G fields' query succeeds"
    fields_requirement = "Installed TShark exposes every required display field"
    result = _execute(("tshark", "-G", "fields"))
    if not result.succeeded:
        query = _make_check("tshark-fields-query", query_requirement, False, result.error_summary)
        fields = _make_check(
            "tshark-required-fields",
            fields_requirement,
            False,
            "not evaluated because the 'tshark -G fields' query failed",
        )
        return query, fields
    available_fields = frozenset(_parse_tshark_field_names(result.stdout_text))
    if not available_fields:
        query = _make_check(
            "tshark-fields-query",
            query_requirement,
            False,
            "query succeeded but returned no fields",
        )
        fields = _make_check(
            "tshark-required-fields",
            fields_requirement,
            False,
            "not evaluated because no display fields were reported",
        )
        return query, fields
    missing = [name for name in REQUIRED_TSHARK_FIELDS if name not in available_fields]
    query = _make_check(
        "tshark-fields-query",
        query_requirement,
        True,
        f"TShark exposes {len(available_fields)} display fields",
    )
    if missing:
        fields = _make_check(
            "tshark-required-fields",
            fields_requirement,
            False,
            f"missing required field(s): {', '.join(missing)}",
        )
    else:
        fields = _make_check(
            "tshark-required-fields",
            fields_requirement,
            True,
            f"all {len(REQUIRED_TSHARK_FIELDS)} required fields are available",
        )
    return query, fields


def _make_check(check_id: str, requirement: str, passed: bool, observed: str) -> DoctorCheck:
    return DoctorCheck(
        id=check_id,
        requirement=requirement,
        status=CheckStatus.PASS if passed else CheckStatus.FAIL,
        observed=_bound_text(observed),
        required=True,
    )


def _execute(command: Sequence[str]) -> CommandResult:
    program = command[0]
    try:
        completed = _run_subprocess(list(command), timeout_seconds=SUBPROCESS_TIMEOUT_SECONDS)
    except FileNotFoundError:
        return CommandResult(False, "", f"'{program}' could not be executed: file not found")
    except subprocess.TimeoutExpired:
        return CommandResult(
            False, "", f"'{program}' timed out after {SUBPROCESS_TIMEOUT_SECONDS:g} seconds"
        )
    if completed.returncode != 0:
        diagnostic = _to_text(completed.stderr) or _to_text(completed.stdout)
        detail = f" ({diagnostic})" if diagnostic else ""
        return CommandResult(
            False,
            "",
            f"'{program}' exited with code {completed.returncode}{detail}",
        )
    return CommandResult(True, _to_text(completed.stdout), "")


def _run_subprocess(
    command: list[str], *, timeout_seconds: float
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        command,
        capture_output=True,
        check=False,
        shell=False,
        timeout=timeout_seconds,
    )


def _parse_dumpcap_interfaces(stdout_text: str) -> tuple[str, ...]:
    interfaces: list[str] = []
    for line in stdout_text.splitlines():
        match = _DUMPCAP_INTERFACE_PATTERN.match(line)
        if match:
            interfaces.append(match.group(1))
    return tuple(interfaces)


def _parse_tshark_field_names(stdout_text: str) -> tuple[str, ...]:
    names: list[str] = []
    for line in stdout_text.splitlines():
        columns = line.split("\t")
        if len(columns) >= 3 and columns[0] == "F":
            names.append(columns[2])
    return tuple(dict.fromkeys(names))


def _to_text(raw: bytes | None) -> str:
    if not raw:
        return ""
    return raw.decode(encoding="utf-8", errors="replace").strip()


def _bound_text(observed: str, limit: int = _OBSERVED_TEXT_LIMIT) -> str:
    collapsed = " ".join(observed.split())
    if len(collapsed) <= limit:
        return collapsed
    return collapsed[: limit - 3].rstrip() + "..."
