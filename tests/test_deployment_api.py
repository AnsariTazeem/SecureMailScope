"""Deployment HTTP regressions using injected analysis, with no external tools."""

from __future__ import annotations

import asyncio
import hashlib
import tempfile
import threading
from pathlib import Path

import jsonschema
import pytest
from httpx import ASGITransport, AsyncClient
from orchestration_helpers import build_analyze_result

from securemailscope.api import create_app
from securemailscope.api.execution import BoundedAnalysisExecution
from securemailscope.deployment import DeploymentSettings, create_deployment_app
from securemailscope.errors import AnalysisError, ErrorCode
from securemailscope.orchestration import OrchestrationDependencies

ORIGIN = "https://secure-mail-scope.vercel.app"
BUSY = {
    "error": {
        "code": "analysis_capacity_unavailable",
        "message": "analysis capacity is unavailable",
    }
}


@pytest.fixture(autouse=True)
def private_spooling(tmp_path, monkeypatch):
    directory = tmp_path / "private"
    directory.mkdir(mode=0o700)
    monkeypatch.setattr(tempfile, "tempdir", str(directory))


def result(path: Path, **kwargs):
    return build_analyze_result(
        capture_path=path,
        capture_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
    )


def app_for(tmp_path, *, analyze=result, **environment):
    settings = DeploymentSettings.from_environment(
        {
            "SECUREMAILSCOPE_ALLOWED_ORIGINS": ORIGIN,
            "TMPDIR": str(tmp_path / "private"),
            **environment,
        }
    )
    return create_deployment_app(
        settings, orchestration_dependencies=OrchestrationDependencies(analyze=analyze)
    )


def client_for(app):
    return AsyncClient(
        transport=ASGITransport(app=app, raise_app_exceptions=False),
        base_url="http://test",
    )


async def upload(client, content=b"synthetic injected analyzer input", filename="capture.pcapng"):
    return await client.post(
        "/api/v1/analyses",
        headers={"Origin": ORIGIN},
        files={"capture": (filename, content, "application/octet-stream")},
    )


async def started(event):
    async with asyncio.timeout(2):
        while not event.is_set():
            await asyncio.sleep(0.005)


async def test_vercel_preflight_post_and_unknown_origin(tmp_path):
    app = app_for(tmp_path)
    assert app.state.api_state.repository.count == 0
    async with client_for(app) as client:
        headers = {
            "Origin": ORIGIN,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        }
        options = await client.options("/api/v1/analyses", headers=headers)
        assert options.status_code == 200
        assert options.headers["access-control-allow-origin"] == ORIGIN
        assert "*" not in options.headers["access-control-allow-headers"]
        assert options.headers["access-control-allow-methods"] == "GET, POST"
        assert "access-control-allow-credentials" not in options.headers
        response = await upload(client)
        assert response.status_code == 201
        assert response.headers["access-control-allow-origin"] == ORIGIN
        for origin in ["https://unknown.example", "http://localhost:4181"]:
            rejected = await client.options(
                "/api/v1/analyses", headers={**headers, "Origin": origin}
            )
            assert rejected.status_code == 400
            assert "access-control-allow-origin" not in rejected.headers
            actual = await client.get("/api/v1/health", headers={"Origin": origin})
            assert actual.status_code == 200
            assert "access-control-allow-origin" not in actual.headers
        for header in ["authorization", "x-unneeded-header"]:
            rejected = await client.options(
                "/api/v1/analyses", headers={**headers, "Access-Control-Request-Headers": header}
            )
            assert rejected.status_code == 400
        rejected = await client.options(
            "/api/v1/analyses", headers={**headers, "Access-Control-Request-Method": "DELETE"}
        )
        assert rejected.status_code == 400


async def test_default_deployment_upload_bound_rejects_before_analysis(tmp_path):
    calls = []

    def analyze(path, **kwargs):
        calls.append(path)
        return result(path)

    app = app_for(tmp_path, analyze=analyze)
    async with client_for(app) as client:
        response = await upload(client, b"x" * (1048576 + 1))
        assert response.status_code == 413
        assert response.json()["error"]["code"] == "upload_too_large"
        assert response.headers["access-control-allow-origin"] == ORIGIN
        assert not calls
        assert app.state.api_state.repository.count == 0
        assert (await upload(client, b"valid next upload")).status_code == 201
    assert len(calls) == 1
    assert list((tmp_path / "private").iterdir()) == []


async def test_exact_repository_capacity_and_repeat_conflict(tmp_path):
    app = app_for(tmp_path)
    assert app.state.api_state.repository.max_entries == 16
    async with client_for(app) as client:
        for index in range(16):
            response = await upload(client, f"capture {index}".encode())
            assert response.status_code == 201
        assert app.state.api_state.repository.count == 16
        response = await upload(client, b"seventeenth capture")
        assert response.status_code == 503
        assert response.json() == BUSY
        repeated = await upload(client, b"capture 0")
        assert repeated.status_code == 409
        assert repeated.json()["error"]["code"] == "analysis_conflict"
    assert app.state.api_state.repository.count == 16


@pytest.mark.parametrize("capacity", [1, 2])
async def test_analysis_gate_is_fail_fast_and_health_is_responsive(tmp_path, capacity):
    reached = threading.Event()
    release = threading.Event()
    lock = threading.Lock()
    paths = []
    threads = []
    main_thread = threading.get_ident()

    def slow(path, **kwargs):
        with lock:
            paths.append(path)
            threads.append(threading.get_ident())
            if len(paths) == capacity:
                reached.set()
        assert release.wait(5), "test did not release analysis"
        assert path.is_file()
        return result(path)

    app = app_for(
        tmp_path,
        analyze=slow,
        SECUREMAILSCOPE_MAX_CONCURRENT_ANALYSES=str(capacity),
    )
    async with client_for(app) as client:
        tasks = [
            asyncio.create_task(upload(client, f"capture {index}".encode()))
            for index in range(capacity)
        ]
        try:
            await started(reached)
            health = await asyncio.wait_for(client.get("/api/v1/health"), timeout=0.5)
            assert health.json() == {"status": "ok", "api_version": "v1"}
            # A busy request is rejected before parsing even an invalid/oversized body.
            busy = await asyncio.wait_for(
                client.post("/api/v1/analyses", content=b"not multipart"), timeout=0.5
            )
            assert busy.status_code == 503
            assert busy.json() == BUSY
            assert busy.headers["cache-control"] == "no-store"
            assert busy.headers["x-content-type-options"] == "nosniff"
            assert len(paths) == capacity
            assert all(thread != main_thread for thread in threads)
            assert all(path.exists() for path in paths)
        finally:
            release.set()
            responses = await asyncio.gather(*tasks)
        assert all(response.status_code == 201 for response in responses)
        assert all(not path.parent.exists() for path in paths)
        assert (await upload(client, b"capacity released")).status_code == 201


@pytest.mark.parametrize("failure", [False, True])
async def test_cancellation_retains_capture_and_slot_until_worker_finishes(tmp_path, failure):
    reached = threading.Event()
    release = threading.Event()
    paths = []

    def slow(path, **kwargs):
        paths.append(path)
        reached.set()
        assert release.wait(5)
        assert path.is_file(), "capture was deleted while the worker was still reading"
        if failure:
            raise RuntimeError("private worker failure after client cancellation")
        return result(path)

    app = app_for(tmp_path, analyze=slow)
    async with client_for(app) as client:
        task = asyncio.create_task(upload(client))
        try:
            await started(reached)
            task.cancel()
            await asyncio.sleep(0)
            task.cancel()
            await asyncio.sleep(0)
            assert not task.done()
            assert paths[0].exists()
            assert app.state.api_state.repository.count == 0
            assert (await upload(client, b"second")).json() == BUSY
            assert (await client.get("/api/v1/health")).status_code == 200
        finally:
            release.set()
            with pytest.raises(asyncio.CancelledError):
                await task
        assert not paths[0].parent.exists()
        assert list((tmp_path / "private").iterdir()) == []
        assert app.state.api_state.repository.count == (0 if failure else 1)
        # A failed worker has not registered a partial Chain, and admission is released.
        response = await upload(client, b"next analysis")
        assert response.status_code == (500 if failure else 201)


@pytest.mark.parametrize(
    ("failure", "status", "code", "message"),
    [
        ("timeout", 500, "analysis_failed", "analysis failed"),
        ("intake", 422, "invalid_capture", "capture validation failed"),
        ("unexpected", 500, "internal_error", "internal error"),
    ],
)
async def test_failures_keep_safe_envelopes_and_cleanup_without_partial_results(
    tmp_path, failure, status, code, message
):
    paths = []

    def fail(path, **kwargs):
        paths.append(path)
        if failure == "timeout":
            raise AnalysisError(ErrorCode.TOOL_TIMEOUT, "tshark", "secret /private/path")
        if failure == "intake":
            raise AnalysisError(ErrorCode.UNSUPPORTED_CAPTURE, "intake", "secret /private/path")
        raise RuntimeError("secret /private/path")

    app = app_for(tmp_path, analyze=fail)
    async with client_for(app) as client:
        response = await upload(client)
        again = await upload(client)
    assert response.status_code == again.status_code == status
    assert response.json() == {"error": {"code": code, "message": message}}
    assert "secret" not in response.text and "/private" not in response.text
    assert app.state.api_state.repository.count == 0
    assert all(not path.parent.exists() for path in paths)


@pytest.mark.parametrize(
    ("filename", "content", "status", "code"),
    [
        ("capture.txt", b"capture", 415, "unsupported_capture_type"),
        ("empty.pcap", b"", 422, "empty_upload"),
    ],
)
async def test_upload_rejections_retain_existing_contract(
    tmp_path, filename, content, status, code
):
    app = app_for(tmp_path)
    async with client_for(app) as client:
        response = await upload(client, content, filename)
        assert response.status_code == status
        assert response.json()["error"]["code"] == code
        assert app.state.api_state.repository.count == 0
        malformed = await client.post("/api/v1/analyses", content=b"not multipart")
        assert malformed.status_code == 422
        assert malformed.json()["error"]["code"] == "invalid_request"
        assert (await upload(client, b"valid next upload")).status_code == 201
    assert app.state.api_state.repository.count == 1
    assert list((tmp_path / "private").iterdir()) == []


async def test_full_api_openapi_artifacts_and_empty_restart_regressions(tmp_path):
    paths = []

    def analyze(path, **kwargs):
        paths.append(path)
        assert path.parent.parent == tmp_path / "private"
        assert kwargs["max_input_bytes"] == 1048576
        return result(path)

    app = app_for(tmp_path, analyze=analyze)
    baseline = create_app().openapi()
    schema = app.openapi()
    assert schema == baseline
    assert {(r.path, tuple(sorted(r.methods or []))) for r in app.routes} == {
        (r.path, tuple(sorted(r.methods or []))) for r in create_app().routes
    }
    async with client_for(app) as client:
        submitted = await upload(client)
        assert submitted.status_code == 201
        document = submitted.json()
        response_schema = schema["paths"]["/api/v1/analyses"]["post"]["responses"]["201"][
            "content"
        ]["application/json"]["schema"]
        jsonschema.validate(
            document,
            {"$ref": response_schema["$ref"], "components": schema["components"]},
        )
        analysis_id = document["analysis_id"]
        root = f"/api/v1/analyses/{analysis_id}"
        summary = await client.get(root)
        chain = await client.get(root + "/chain")
        assert summary.status_code == chain.status_code == 200
        data = chain.json()
        assert data["policy_risk"] is not None
        assert data["analysis"]["ml_engine_status"] == "not_run"
        assert data["anomaly_results"] == []
        sid = data["sessions"][0]["session_id"]
        eid = data["evidence"][0]["evidence_id"]
        fid = data["findings"][0]["finding_id"]
        for path in [f"/sessions/{sid}/events", f"/evidence/{eid}", f"/findings/{fid}"]:
            response = await client.get(root + path)
            assert response.status_code == 200
            assert "/private/" not in response.text
        for format, media_type in [
            ("json", "application/json"),
            ("html", "text/html"),
            ("pdf", "application/pdf"),
        ]:
            artifact = await client.get(root + f"/findings/{fid}/artifacts/{format}")
            assert artifact.status_code == 200
            assert media_type in artifact.headers["content-type"]
            assert (
                artifact.headers["x-content-sha256"] == hashlib.sha256(artifact.content).hexdigest()
            )
            if format == "pdf":
                assert artifact.content.startswith(b"%PDF-")
            if format == "html":
                assert "default-src 'none'" in artifact.headers["content-security-policy"]
        assert all(not path.parent.exists() for path in paths)
        assert list((tmp_path / "private").iterdir()) == []
    fresh = app_for(tmp_path)
    assert fresh.state.api_state.repository.count == 0
    async with client_for(fresh) as client:
        assert (await client.get(root)).status_code == 404


def test_invalid_concurrency_is_rejected():
    for value in [0, -1, True, 1.5]:
        with pytest.raises(ValueError):
            BoundedAnalysisExecution(value)
