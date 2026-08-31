"""Security and caller-owned capture tests for synchronous orchestration."""

from __future__ import annotations

import os
from dataclasses import replace
from pathlib import Path

import pytest
from orchestration_helpers import build_analyze_result, default_policy_pack, execution_context

from securemailscope.api.repository import InMemoryAnalysisChainRepository
from securemailscope.chain.errors import ChainAdapterError, ChainErrorCode
from securemailscope.errors import AnalysisError, ErrorCode
from securemailscope.intake import validate_input_path
from securemailscope.models import AnalyzeResult
from securemailscope.orchestration import (
    OrchestrationDependencies,
    OrchestrationError,
    OrchestrationErrorCode,
    analyze_capture_to_chain,
)


def _run(path: Path, dependencies: OrchestrationDependencies):
    return analyze_capture_to_chain(
        path,
        registry=InMemoryAnalysisChainRepository(max_entries=2),
        policy_pack=default_policy_pack(),
        context=execution_context(),
        dependencies=dependencies,
    )


def test_caller_owned_capture_is_unchanged_on_success_and_adapter_failure(tmp_path: Path) -> None:
    capture = tmp_path / "caller-owned.pcapng"
    original = b"caller-owned-capture-bytes"
    capture.write_bytes(original)
    base = OrchestrationDependencies(
        analyze=lambda path, **kwargs: build_analyze_result(capture_path=path),
    )

    _run(capture, base)
    assert capture.read_bytes() == original

    adapter_failure = ChainAdapterError(
        ChainErrorCode.ADAPTER_MAPPING_FAILED,
        "adapter",
        "MAIL FROM:<private@example.test> /private/capture.pcapng",
    )

    def fail_adapter(*args, **kwargs):  # noqa: ANN002, ANN003
        raise adapter_failure

    with pytest.raises(OrchestrationError):
        _run(capture, replace(base, adapt=fail_adapter))

    assert capture.read_bytes() == original


def test_safe_failure_does_not_expose_path_payload_or_tool_detail(tmp_path: Path) -> None:
    capture = tmp_path / "private capture.pcapng"
    capture.write_bytes(b"AUTH secret\r\n")
    lower = AnalysisError(
        ErrorCode.TOOL_TIMEOUT,
        "tshark_observe",
        f"failed for {capture}",
        detail="AUTH secret MAIL FROM:<private@example.test> tshark -r /private/file",
    )

    def fail_analyzer(*args, **kwargs):  # noqa: ANN002, ANN003
        raise lower

    with pytest.raises(OrchestrationError) as exc:
        _run(capture, OrchestrationDependencies(analyze=fail_analyzer))

    assert exc.value.code is OrchestrationErrorCode.ANALYZER_FAILED
    assert exc.value.__cause__ is lower
    public = str(exc.value)
    for forbidden in (
        str(capture),
        "AUTH secret",
        "private@example.test",
        "tshark -r",
        "Traceback",
    ):
        assert forbidden not in public
    assert capture.read_bytes() == b"AUTH secret\r\n"


def test_existing_intake_rejects_directory_before_external_tool_execution(tmp_path: Path) -> None:
    with pytest.raises(OrchestrationError) as exc:
        analyze_capture_to_chain(
            tmp_path,
            registry=InMemoryAnalysisChainRepository(max_entries=2),
            policy_pack=default_policy_pack(),
            context=execution_context(),
        )

    assert exc.value.code is OrchestrationErrorCode.INVALID_CAPTURE
    assert isinstance(exc.value.__cause__, AnalysisError)
    assert exc.value.__cause__.code is ErrorCode.NOT_A_REGULAR_FILE


def test_existing_intake_rejects_unsupported_special_file(tmp_path: Path) -> None:
    fifo = tmp_path / "capture.pipe"
    os.mkfifo(fifo)

    with pytest.raises(OrchestrationError) as exc:
        analyze_capture_to_chain(
            fifo,
            registry=InMemoryAnalysisChainRepository(max_entries=2),
            policy_pack=default_policy_pack(),
            context=execution_context(),
        )

    assert exc.value.code is OrchestrationErrorCode.INVALID_CAPTURE
    assert isinstance(exc.value.__cause__, AnalysisError)
    assert exc.value.__cause__.code is ErrorCode.NOT_A_REGULAR_FILE


def test_symlink_to_regular_file_follows_existing_intake_contract(tmp_path: Path) -> None:
    target = tmp_path / "capture-target.pcapng"
    target_bytes = b"unchanged-target"
    target.write_bytes(target_bytes)
    link = tmp_path / "capture-link.pcapng"
    link.symlink_to(target)

    def analyze_with_intake(
        path: Path,
        *,
        max_input_bytes: int,
        timeout_seconds: float,
    ) -> AnalyzeResult:
        validated = validate_input_path(path, max_input_bytes=max_input_bytes)
        assert validated == link
        assert timeout_seconds > 0
        return build_analyze_result(capture_path=path)

    result = _run(
        link,
        OrchestrationDependencies(analyze=analyze_with_intake),
    )

    assert result.chain.captures[0].original_filename_sanitized == link.name
    assert link.is_symlink()
    assert target.read_bytes() == target_bytes


def test_orchestration_creates_no_temporary_or_persistent_files(tmp_path: Path) -> None:
    capture = tmp_path / "input.pcap"
    capture.write_bytes(b"unchanged")
    before = {path.name for path in tmp_path.iterdir()}
    dependencies = OrchestrationDependencies(
        analyze=lambda path, **kwargs: build_analyze_result(capture_path=path),
    )

    _run(capture, dependencies)

    assert {path.name for path in tmp_path.iterdir()} == before
    assert capture.exists()
