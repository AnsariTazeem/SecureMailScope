"""Commit 6B secure multipart submission and orchestration-boundary tests."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient
from orchestration_helpers import BASE_TIME, build_analyze_result

from securemailscope.api import ApiSettings, InMemoryAnalysisChainRepository, create_app
from securemailscope.api.uploads import MAX_MULTIPART_OVERHEAD_BYTES
from securemailscope.errors import AnalysisError, ErrorCode
from securemailscope.models import AnalyzeResult, CaptureFormat
from securemailscope.orchestration import OrchestrationDependencies


def _result_for_upload(path: Path) -> AnalyzeResult:
    content = path.read_bytes()
    result = build_analyze_result(
        capture_path=path,
        capture_sha256=hashlib.sha256(content).hexdigest(),
    )
    capture_format = CaptureFormat.PCAP if path.suffix == ".pcap" else CaptureFormat.PCAPNG
    provenance = result.provenance.model_copy(
        update={"capture_format": capture_format, "size_bytes": len(content)}
    )
    return result.model_copy(update={"provenance": provenance})


def _recording_analyzer(
    paths: list[Path],
) -> Callable[..., AnalyzeResult]:
    def analyze(path: Path, *, max_input_bytes: int, timeout_seconds: float) -> AnalyzeResult:
        assert path.is_file()
        assert path.stat().st_size <= max_input_bytes
        assert timeout_seconds > 0
        paths.append(path)
        return _result_for_upload(path)

    return analyze


def _upload_app(
    analyze: Callable[..., AnalyzeResult],
    *,
    max_upload_bytes: int = 1024 * 1024,
    repository: InMemoryAnalysisChainRepository | None = None,
    clock: Callable[[], datetime] | None = None,
):
    settings = ApiSettings(
        max_repository_entries=(repository.max_entries if repository is not None else 8),
        max_upload_bytes=max_upload_bytes,
    )
    active_repository = repository or InMemoryAnalysisChainRepository(max_entries=8)
    return create_app(
        settings=settings,
        repository=active_repository,
        orchestration_dependencies=OrchestrationDependencies(analyze=analyze),
        clock=clock or (lambda: BASE_TIME),
    )


async def _post_capture(
    app,
    *,
    filename: str,
    content: bytes,
    content_type: str = "application/octet-stream",
):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        return await client.post(
            "/api/v1/analyses",
            files={"capture": (filename, content, content_type)},
        )


@pytest.mark.parametrize("suffix", [".pcap", ".pcapng"])
async def test_supported_capture_upload_reaches_commit_6a_and_succeeds(suffix: str) -> None:
    paths: list[Path] = []
    app = _upload_app(_recording_analyzer(paths))

    response = await _post_capture(
        app,
        filename=f"mail{suffix}",
        content=b"bounded synthetic capture",
        content_type="text/plain",
    )
    assert response.status_code == 201
    assert response.json() == {
        "api_version": "v1",
        "analysis_id": response.json()["analysis_id"],
        "analysis_status": "complete",
    }
    assert response.json()["analysis_id"].startswith("ana_")
    assert len(paths) == 1
    assert paths[0].name == f"capture{suffix}"
    assert not paths[0].exists()


async def test_submission_id_is_immediately_retrievable_from_existing_read_api() -> None:
    paths: list[Path] = []
    app = _upload_app(_recording_analyzer(paths))

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        submitted = await client.post(
            "/api/v1/analyses",
            files={"capture": ("capture.pcapng", b"registered capture", "image/png")},
        )
        analysis_id = submitted.json()["analysis_id"]
        summary = await client.get(f"/api/v1/analyses/{analysis_id}")
        chain = await client.get(f"/api/v1/analyses/{analysis_id}/chain")

    assert submitted.status_code == 201
    assert summary.status_code == 200
    assert summary.json()["analysis_id"] == analysis_id
    assert chain.status_code == 200
    assert chain.json()["analysis"]["analysis_id"] == analysis_id


async def test_unsupported_extension_is_rejected_before_orchestration() -> None:
    paths: list[Path] = []
    response = await _post_capture(
        _upload_app(_recording_analyzer(paths)),
        filename="capture.txt",
        content=b"not accepted",
    )

    assert response.status_code == 415
    assert response.json() == {
        "error": {
            "code": "unsupported_capture_type",
            "message": "capture extension is not supported",
        }
    }
    assert paths == []


async def test_empty_upload_is_rejected_before_orchestration() -> None:
    paths: list[Path] = []
    response = await _post_capture(
        _upload_app(_recording_analyzer(paths)),
        filename="empty.pcap",
        content=b"",
    )

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "empty_upload"
    assert paths == []


async def test_oversized_upload_is_rejected_by_bounded_request_stream() -> None:
    paths: list[Path] = []
    maximum = 16
    response = await _post_capture(
        _upload_app(_recording_analyzer(paths), max_upload_bytes=maximum),
        filename="large.pcapng",
        content=b"x" * (maximum + MAX_MULTIPART_OVERHEAD_BYTES + 1),
    )

    assert response.status_code == 413
    assert response.json()["error"]["code"] == "upload_too_large"
    assert paths == []


async def test_path_traversal_filename_cannot_escape_server_intake() -> None:
    paths: list[Path] = []
    response = await _post_capture(
        _upload_app(_recording_analyzer(paths)),
        filename="../../capture.pcap",
        content=b"safe destination",
    )

    assert response.status_code == 201
    assert len(paths) == 1
    assert paths[0].name == "capture.pcap"
    assert ".." not in paths[0].parts
    assert not paths[0].exists()


async def test_caller_filename_cannot_control_destination_path(tmp_path: Path) -> None:
    paths: list[Path] = []
    caller_destination = tmp_path / "caller-selected.pcapng"
    response = await _post_capture(
        _upload_app(_recording_analyzer(paths)),
        filename=str(caller_destination),
        content=b"server-selected destination",
    )

    assert response.status_code == 201
    assert len(paths) == 1
    assert paths[0] != caller_destination
    assert paths[0].name == "capture.pcapng"
    assert not caller_destination.exists()


async def test_caller_cannot_inject_capture_metadata_or_provenance() -> None:
    paths: list[Path] = []
    app = _upload_app(_recording_analyzer(paths))
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            "/api/v1/analyses",
            data={
                "capture_metadata": '{"snaplen":1}',
                "provenance": '{"sha256":"forged"}',
            },
            files={"capture": ("capture.pcapng", b"capture", "application/octet-stream")},
        )

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "invalid_request"
    assert paths == []


async def test_typed_intake_error_becomes_sanitized_http_response() -> None:
    def fail(*args, **kwargs):  # noqa: ANN002, ANN003, ANN202
        raise AnalysisError(
            ErrorCode.TOOL_NONZERO_EXIT,
            "intake",
            "failed for /private/captures/secret.pcapng",
            detail="tshark -r /private/captures/secret.pcapng AUTH credential",
        )

    response = await _post_capture(
        _upload_app(fail),
        filename="capture.pcapng",
        content=b"malformed capture",
    )

    assert response.status_code == 422
    assert response.json() == {
        "error": {"code": "invalid_capture", "message": "capture validation failed"}
    }
    for forbidden in ("/private", "tshark", "AUTH", "credential", "Traceback"):
        assert forbidden not in response.text


async def test_unexpected_internal_exception_is_sanitized() -> None:
    def explode(*args, **kwargs):  # noqa: ANN002, ANN003, ANN202
        raise RuntimeError("secret /private/path tshark -r command")

    app = _upload_app(explode)
    transport = ASGITransport(app=app, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/api/v1/analyses",
            files={"capture": ("capture.pcapng", b"capture", "application/octet-stream")},
        )

    assert response.status_code == 500
    assert response.json() == {"error": {"code": "internal_error", "message": "internal error"}}
    assert "/private" not in response.text
    assert "RuntimeError" not in response.text


async def test_temporary_capture_is_removed_after_success() -> None:
    paths: list[Path] = []
    response = await _post_capture(
        _upload_app(_recording_analyzer(paths)),
        filename="capture.pcapng",
        content=b"successful capture",
    )

    assert response.status_code == 201
    assert paths and all(not path.exists() for path in paths)
    assert all(not path.parent.exists() for path in paths)


async def test_temporary_capture_is_removed_after_orchestration_failure() -> None:
    paths: list[Path] = []

    def fail(path: Path, **kwargs):  # noqa: ANN003, ANN202
        paths.append(path)
        assert path.is_file()
        raise AnalysisError(
            ErrorCode.TOOL_TIMEOUT,
            "tshark_observe",
            "private timeout detail",
        )

    response = await _post_capture(
        _upload_app(fail),
        filename="capture.pcapng",
        content=b"failing capture",
    )

    assert response.status_code == 500
    assert response.json()["error"]["code"] == "analysis_failed"
    assert paths and all(not path.exists() for path in paths)
    assert all(not path.parent.exists() for path in paths)


async def test_commit_6a_repository_conflict_maps_to_409_without_replacement() -> None:
    paths: list[Path] = []
    repository = InMemoryAnalysisChainRepository(max_entries=2)
    times = iter((BASE_TIME, BASE_TIME + timedelta(seconds=1)))
    app = _upload_app(
        _recording_analyzer(paths),
        repository=repository,
        clock=lambda: next(times),
    )

    first = await _post_capture(app, filename="capture.pcapng", content=b"same capture")
    second = await _post_capture(app, filename="capture.pcapng", content=b"same capture")

    assert first.status_code == 201
    assert second.status_code == 409
    assert second.json()["error"]["code"] == "analysis_conflict"
    assert repository.count == 1


async def test_repository_capacity_maps_to_sanitized_503() -> None:
    paths: list[Path] = []
    repository = InMemoryAnalysisChainRepository(max_entries=1)
    app = _upload_app(_recording_analyzer(paths), repository=repository)

    first = await _post_capture(app, filename="first.pcapng", content=b"first capture")
    second = await _post_capture(app, filename="second.pcapng", content=b"second capture")

    assert first.status_code == 201
    assert second.status_code == 503
    assert second.json() == {
        "error": {
            "code": "analysis_capacity_unavailable",
            "message": "analysis capacity is unavailable",
        }
    }
    assert repository.count == 1
