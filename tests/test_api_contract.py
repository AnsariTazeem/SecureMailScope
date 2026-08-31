"""Route contract tests for Commit 5B: every required route tested."""

from __future__ import annotations

import hashlib

import pytest
from api_helpers import make_app, make_empty_app
from httpx import ASGITransport, AsyncClient
from presentation_helpers import build_evaluated_chain

from securemailscope.api import create_app
from securemailscope.api.responses import canonical_response_bytes
from securemailscope.chain.models import ChainOfProof
from securemailscope.presentation import (
    FindingPresentation,
    build_finding_presentation,
    render_chain_json,
    render_finding_html,
    render_finding_pdf,
)

MISSING_ANALYSIS_ID = "ana_0000000000000000"
MISSING_SESSION_ID = "ses_0000000000000000"
MISSING_EVIDENCE_ID = "ev_0000000000000000"
MISSING_FINDING_ID = "fnd_0000000000000000"


class ReadOnlyRepository:
    def __init__(self, chain: ChainOfProof | None) -> None:
        self.chain = chain
        self.get_calls = 0

    def get(self, analysis_id: str) -> ChainOfProof | None:
        self.get_calls += 1
        if self.chain is None or self.chain.analysis.analysis_id != analysis_id:
            return None
        return self.chain


@pytest.fixture
def chain():
    return build_evaluated_chain()


@pytest.fixture
def app(chain):
    return make_app(chain)


@pytest.fixture
def empty_app():
    return make_empty_app()


# ---------------------------------------------------------------------------
#  Health
# ---------------------------------------------------------------------------


class TestHealth:
    async def test_health_status_and_content_type(self, app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get("/api/v1/health")
        assert resp.status_code == 200
        assert resp.headers["content-type"] == "application/json"
        body = resp.json()
        assert body["status"] == "ok"
        assert body["api_version"] == "v1"

    async def test_health_deterministic_byte_identical(self, app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r1 = await c.get("/api/v1/health")
            r2 = await c.get("/api/v1/health")
        assert r1.content == r2.content
        assert r1.headers["etag"] == r2.headers["etag"]
        assert r1.headers["x-content-sha256"] == r2.headers["x-content-sha256"]

    async def test_health_etag_matches_content_hash(self, app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get("/api/v1/health")
        expected = hashlib.sha256(resp.content).hexdigest()
        assert resp.headers["x-content-sha256"] == expected
        assert f'"{expected}"' == resp.headers["etag"]

    async def test_health_has_required_headers(self, app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get("/api/v1/health")
        assert resp.headers["cache-control"] == "no-store"
        assert resp.headers["x-content-type-options"] == "nosniff"
        assert resp.headers["content-length"] == str(len(resp.content))


# ---------------------------------------------------------------------------
#  Analysis summary
# ---------------------------------------------------------------------------


class TestAnalysisSummary:
    async def test_analysis_summary_success(self, app, chain):
        aid = chain.analysis.analysis_id
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get(f"/api/v1/analyses/{aid}")
        assert resp.status_code == 200
        body = resp.json()
        assert body["analysis_id"] == aid
        assert body["api_version"] == "v1"
        assert body["chain_schema_version"] == "1.0.0"
        assert body["finding_count"] == len(chain.findings)
        assert body["session_count"] == len(chain.sessions)
        assert body["evidence_count"] == len(chain.evidence)
        assert body["capture_count"] == len(chain.captures)

    async def test_analysis_summary_deterministic(self, app, chain):
        aid = chain.analysis.analysis_id
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r1 = await c.get(f"/api/v1/analyses/{aid}")
            r2 = await c.get(f"/api/v1/analyses/{aid}")
        assert r1.content == r2.content

    async def test_analysis_summary_missing_404(self, empty_app):
        async with AsyncClient(transport=ASGITransport(app=empty_app), base_url="http://test") as c:
            resp = await c.get(f"/api/v1/analyses/{MISSING_ANALYSIS_ID}")
        assert resp.status_code == 404
        body = resp.json()
        assert body["error"]["code"] == "analysis_not_found"

    async def test_analysis_summary_has_required_headers(self, app, chain):
        aid = chain.analysis.analysis_id
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get(f"/api/v1/analyses/{aid}")
        assert resp.headers["cache-control"] == "no-store"
        assert resp.headers["x-content-type-options"] == "nosniff"
        expected = hashlib.sha256(resp.content).hexdigest()
        assert resp.headers["x-content-sha256"] == expected
        assert f'"{expected}"' == resp.headers["etag"]

    async def test_analysis_summary_sorted_ids(self, app, chain):
        aid = chain.analysis.analysis_id
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get(f"/api/v1/analyses/{aid}")
        body = resp.json()
        assert body["capture_ids"] == sorted(body["capture_ids"])
        assert body["session_ids"] == sorted(body["session_ids"])
        assert body["finding_ids"] == sorted(body["finding_ids"])


# ---------------------------------------------------------------------------
#  Chain
# ---------------------------------------------------------------------------


class TestChain:
    async def test_chain_returns_canonical_json(self, app, chain):
        aid = chain.analysis.analysis_id
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get(f"/api/v1/analyses/{aid}/chain")
        assert resp.status_code == 200
        assert resp.headers["content-type"] == "application/json"
        expected = render_chain_json(chain)
        assert resp.content == expected

    async def test_chain_deterministic_byte_identical(self, app, chain):
        aid = chain.analysis.analysis_id
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r1 = await c.get(f"/api/v1/analyses/{aid}/chain")
            r2 = await c.get(f"/api/v1/analyses/{aid}/chain")
        assert r1.content == r2.content

    async def test_chain_etag(self, app, chain):
        aid = chain.analysis.analysis_id
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get(f"/api/v1/analyses/{aid}/chain")
        expected = hashlib.sha256(resp.content).hexdigest()
        assert resp.headers["x-content-sha256"] == expected

    async def test_chain_missing_404(self, empty_app):
        async with AsyncClient(transport=ASGITransport(app=empty_app), base_url="http://test") as c:
            resp = await c.get(f"/api/v1/analyses/{MISSING_ANALYSIS_ID}/chain")
        assert resp.status_code == 404

    async def test_chain_schema_id_present(self, app, chain):
        aid = chain.analysis.analysis_id
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get(f"/api/v1/analyses/{aid}/chain")
        body = resp.json()
        assert body["schema_id"] == "urn:securemailscope:schema:chain-of-proof:1.0.0"
        assert body["chain_schema_version"] == "1.0.0"


# ---------------------------------------------------------------------------
#  Session events
# ---------------------------------------------------------------------------


class TestSessionEvents:
    async def test_session_events_success(self, app, chain):
        aid = chain.analysis.analysis_id
        sid = chain.sessions[0].session_id
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get(f"/api/v1/analyses/{aid}/sessions/{sid}/events")
        assert resp.status_code == 200
        body = resp.json()
        assert body["session_id"] == sid
        assert body["analysis_id"] == aid
        assert body["protocol"] == chain.sessions[0].protocol.value
        assert len(body["events"]) > 0
        source_events = {event.event_id: event for event in chain.protocol_events}
        for event in body["events"]:
            source = source_events[event["event_id"]]
            assert event["protocol"] == chain.sessions[0].protocol.value
            assert event["state_before"] == source.state_before.value
            assert event["state_after"] == source.state_after.value

    async def test_session_events_ordered_by_sequence_index_event_id(self, app, chain):
        aid = chain.analysis.analysis_id
        sid = chain.sessions[0].session_id
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get(f"/api/v1/analyses/{aid}/sessions/{sid}/events")
        body = resp.json()
        events = body["events"]
        indices = [(e["sequence_index"], e["event_id"]) for e in events]
        assert indices == sorted(indices)

    async def test_session_events_deterministic(self, app, chain):
        aid = chain.analysis.analysis_id
        sid = chain.sessions[0].session_id
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r1 = await c.get(f"/api/v1/analyses/{aid}/sessions/{sid}/events")
            r2 = await c.get(f"/api/v1/analyses/{aid}/sessions/{sid}/events")
        assert r1.content == r2.content

    async def test_session_events_missing_session_404(self, app, chain):
        aid = chain.analysis.analysis_id
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get(f"/api/v1/analyses/{aid}/sessions/{MISSING_SESSION_ID}/events")
        assert resp.status_code == 404
        body = resp.json()
        assert body["error"]["code"] == "session_not_found"

    async def test_session_events_evidence_ids_sorted(self, app, chain):
        aid = chain.analysis.analysis_id
        sid = chain.sessions[0].session_id
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get(f"/api/v1/analyses/{aid}/sessions/{sid}/events")
        body = resp.json()
        for event in body["events"]:
            assert event["evidence_ids"] == sorted(event["evidence_ids"])

    async def test_session_events_cross_analysis_rejected(self, app, chain):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get(
                f"/api/v1/analyses/{MISSING_ANALYSIS_ID}/sessions/{MISSING_SESSION_ID}/events"
            )
        assert resp.status_code == 404
        assert resp.json()["error"]["code"] == "analysis_not_found"


# ---------------------------------------------------------------------------
#  Evidence
# ---------------------------------------------------------------------------


class TestEvidence:
    async def test_evidence_success(self, app, chain):
        aid = chain.analysis.analysis_id
        ev = chain.evidence[0]
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get(f"/api/v1/analyses/{aid}/evidence/{ev.evidence_id}")
        assert resp.status_code == 200
        body = resp.json()
        assert body["evidence_id"] == ev.evidence_id
        assert body["capture_sha256"] == ev.capture_sha256
        assert body["session_id"] == ev.session_id
        assert body["frame_numbers"] == sorted(set(ev.frame_numbers))

    async def test_evidence_excludes_forbidden_fields(self, app, chain):
        aid = chain.analysis.analysis_id
        ev = chain.evidence[0]
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get(f"/api/v1/analyses/{aid}/evidence/{ev.evidence_id}")
        body = resp.json()
        for field in (
            "occurrence_index",
            "normalized_value",
            "safe_excerpt",
            "display_filter",
            "extractor_version",
        ):
            assert field not in body

    async def test_evidence_deterministic(self, app, chain):
        aid = chain.analysis.analysis_id
        ev = chain.evidence[0]
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r1 = await c.get(f"/api/v1/analyses/{aid}/evidence/{ev.evidence_id}")
            r2 = await c.get(f"/api/v1/analyses/{aid}/evidence/{ev.evidence_id}")
        assert r1.content == r2.content

    async def test_evidence_missing_404(self, app, chain):
        aid = chain.analysis.analysis_id
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get(f"/api/v1/analyses/{aid}/evidence/{MISSING_EVIDENCE_ID}")
        assert resp.status_code == 404

    async def test_evidence_etag(self, app, chain):
        aid = chain.analysis.analysis_id
        ev = chain.evidence[0]
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get(f"/api/v1/analyses/{aid}/evidence/{ev.evidence_id}")
        expected = hashlib.sha256(resp.content).hexdigest()
        assert resp.headers["x-content-sha256"] == expected


# ---------------------------------------------------------------------------
#  Finding projection
# ---------------------------------------------------------------------------


class TestFinding:
    async def test_finding_success(self, app, chain):
        aid = chain.analysis.analysis_id
        fid = chain.findings[0].finding_id
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get(f"/api/v1/analyses/{aid}/findings/{fid}")
        assert resp.status_code == 200
        body = resp.json()
        assert body["finding_id"] == fid
        assert body["analysis_id"] == aid
        assert body["rule_id"] == chain.findings[0].rule_id
        assert body["severity"] == chain.findings[0].severity.value

    async def test_finding_matches_build_finding_presentation(self, app, chain):
        aid = chain.analysis.analysis_id
        fid = chain.findings[0].finding_id
        expected = build_finding_presentation(chain, fid)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get(f"/api/v1/analyses/{aid}/findings/{fid}")
        expected_bytes = canonical_response_bytes(expected.model_dump(mode="python"))
        assert isinstance(expected, FindingPresentation)
        assert resp.content == expected_bytes

    async def test_finding_has_policy_risk(self, app, chain):
        aid = chain.analysis.analysis_id
        fid = chain.findings[0].finding_id
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get(f"/api/v1/analyses/{aid}/findings/{fid}")
        body = resp.json()
        assert body["policy_risk"] is not None
        assert body["policy_risk"]["capped_score"] >= 0

    async def test_finding_has_ml_anomaly(self, app, chain):
        aid = chain.analysis.analysis_id
        fid = chain.findings[0].finding_id
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get(f"/api/v1/analyses/{aid}/findings/{fid}")
        body = resp.json()
        assert body["ml_anomaly"]["engine_status"] == "not_run"

    async def test_finding_deterministic(self, app, chain):
        aid = chain.analysis.analysis_id
        fid = chain.findings[0].finding_id
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r1 = await c.get(f"/api/v1/analyses/{aid}/findings/{fid}")
            r2 = await c.get(f"/api/v1/analyses/{aid}/findings/{fid}")
        assert r1.content == r2.content

    async def test_finding_events_chronological(self, app, chain):
        aid = chain.analysis.analysis_id
        fid = chain.findings[0].finding_id
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get(f"/api/v1/analyses/{aid}/findings/{fid}")
        body = resp.json()
        events = body["events"]
        indices = [(e["sequence_index"], e["event_id"]) for e in events]
        assert indices == sorted(indices)

    async def test_finding_missing_404(self, empty_app):
        async with AsyncClient(transport=ASGITransport(app=empty_app), base_url="http://test") as c:
            resp = await c.get(
                f"/api/v1/analyses/{MISSING_ANALYSIS_ID}/findings/{MISSING_FINDING_ID}"
            )
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
#  Artifacts
# ---------------------------------------------------------------------------


class TestArtifacts:
    async def test_json_artifact(self, app, chain):
        aid = chain.analysis.analysis_id
        fid = chain.findings[0].finding_id
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get(f"/api/v1/analyses/{aid}/findings/{fid}/artifacts/json")
        assert resp.status_code == 200
        assert resp.headers["content-type"] == "application/json"
        expected = render_chain_json(chain)
        assert resp.content == expected
        assert f'"{aid}.chain.json"' in resp.headers.get("content-disposition", "")

    async def test_html_artifact(self, app, chain):
        aid = chain.analysis.analysis_id
        fid = chain.findings[0].finding_id
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get(f"/api/v1/analyses/{aid}/findings/{fid}/artifacts/html")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]
        expected = render_finding_html(chain, fid)
        assert resp.content == expected
        assert f'"{fid}.finding.html"' in resp.headers.get("content-disposition", "")
        assert "content-security-policy" in resp.headers

    async def test_pdf_artifact(self, app, chain):
        aid = chain.analysis.analysis_id
        fid = chain.findings[0].finding_id
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get(f"/api/v1/analyses/{aid}/findings/{fid}/artifacts/pdf")
        assert resp.status_code == 200
        assert "application/pdf" in resp.headers["content-type"]
        expected = render_finding_pdf(chain, fid)
        assert resp.content == expected
        assert f'"{fid}.finding.pdf"' in resp.headers.get("content-disposition", "")

    async def test_artifact_unsupported_format_422(self, app, chain):
        aid = chain.analysis.analysis_id
        fid = chain.findings[0].finding_id
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get(f"/api/v1/analyses/{aid}/findings/{fid}/artifacts/png")
        assert resp.status_code == 422
        assert resp.json() == {"error": {"code": "invalid_request", "message": "malformed request"}}
        assert "png" not in resp.text

    async def test_artifact_deterministic(self, app, chain):
        aid = chain.analysis.analysis_id
        fid = chain.findings[0].finding_id
        for fmt in ("json", "html", "pdf"):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r1 = await c.get(f"/api/v1/analyses/{aid}/findings/{fid}/artifacts/{fmt}")
                r2 = await c.get(f"/api/v1/analyses/{aid}/findings/{fid}/artifacts/{fmt}")
            assert r1.content == r2.content

    async def test_artifact_missing_analysis_404(self, empty_app):
        async with AsyncClient(transport=ASGITransport(app=empty_app), base_url="http://test") as c:
            resp = await c.get(
                f"/api/v1/analyses/{MISSING_ANALYSIS_ID}/findings/"
                f"{MISSING_FINDING_ID}/artifacts/json"
            )
        assert resp.status_code == 404

    async def test_html_artifact_csp_present(self, app, chain):
        aid = chain.analysis.analysis_id
        fid = chain.findings[0].finding_id
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get(f"/api/v1/analyses/{aid}/findings/{fid}/artifacts/html")
        csp = resp.headers.get("content-security-policy", "")
        assert "default-src 'none'" in csp
        assert "script-src 'none'" in csp


# ---------------------------------------------------------------------------
#  Read-only boundary
# ---------------------------------------------------------------------------


class TestReadOnlyBoundary:
    async def test_post_health_returns_method_not_allowed(self, app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post("/api/v1/health")
        assert resp.status_code == 405

    async def test_post_analyses_not_found(self, app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post("/api/v1/analyses", json={})
        assert resp.status_code == 404

    async def test_put_analyses_not_found(self, app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.put("/api/v1/analyses/ana_0000000000000001", json={})
        assert resp.status_code == 405

    async def test_delete_analyses_not_found(self, app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.delete("/api/v1/analyses/ana_0000000000000001")
        assert resp.status_code == 405

    async def test_patch_analyses_not_found(self, app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.patch("/api/v1/analyses/ana_0000000000000001", json={})
        assert resp.status_code == 405


class TestRepositoryProtocolBoundary:
    async def test_custom_read_only_repository_is_supported(self, chain):
        repository = ReadOnlyRepository(chain)
        app = create_app(repository=repository)

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get(f"/api/v1/analyses/{chain.analysis.analysis_id}")

        assert resp.status_code == 200
        assert resp.json()["analysis_id"] == chain.analysis.analysis_id
        assert repository.get_calls == 1

    async def test_invalid_chain_from_custom_repository_is_rejected_safely(self, chain):
        analysis = chain.analysis.model_copy(update={"chain_schema_version": "2.0.0"})
        invalid_chain = chain.model_copy(update={"analysis": analysis})
        app = create_app(repository=ReadOnlyRepository(invalid_chain))
        expected = canonical_response_bytes(
            {"error": {"code": "invalid_chain", "message": "invalid stored chain"}}
        )

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get(f"/api/v1/analyses/{chain.analysis.analysis_id}")

        assert resp.status_code == 500
        assert resp.content == expected
        assert "2.0.0" not in resp.text
        assert "Traceback" not in resp.text


class TestPathValidation:
    @pytest.mark.parametrize(
        "path_template",
        [
            "/api/v1/analyses/not-an-id",
            "/api/v1/analyses/ses_0000000000000000",
            "/api/v1/analyses/ana_0000",
            "/api/v1/analyses/ana_000000000000000g",
            "/api/v1/analyses/{aid}/sessions/fnd_0000000000000000/events",
            "/api/v1/analyses/{aid}/sessions/ses_short/events",
            "/api/v1/analyses/{aid}/evidence/fnd_0000000000000000",
            "/api/v1/analyses/{aid}/evidence/ev_000000000000000g",
            "/api/v1/analyses/{aid}/findings/ev_0000000000000000",
            "/api/v1/analyses/{aid}/findings/fnd_%20",
        ],
    )
    async def test_malformed_identifiers_are_rejected_before_lookup(self, chain, path_template):
        repository = ReadOnlyRepository(chain)
        app = create_app(repository=repository)
        path = path_template.format(aid=chain.analysis.analysis_id)

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get(path)

        assert resp.status_code == 422
        assert resp.json() == {"error": {"code": "invalid_request", "message": "malformed request"}}
        assert repository.get_calls == 0


class TestResponseBounds:
    async def test_json_response_limit_returns_exact_413(self, chain):
        app = make_app(chain, max_json_response_bytes=1)

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get(f"/api/v1/analyses/{chain.analysis.analysis_id}")

        assert resp.status_code == 413
        assert resp.json() == {
            "error": {
                "code": "response_too_large",
                "message": "response exceeds size limit",
            }
        }


class TestOpenApiContract:
    def test_openapi_documents_exact_read_only_routes_and_models(self, app):
        schema = app.openapi()
        assert app.openapi_url == "/api/v1/openapi.json"
        expected_models = {
            "/api/v1/health": "HealthResponse",
            "/api/v1/analyses/{analysis_id}": "AnalysisSummary",
            "/api/v1/analyses/{analysis_id}/chain": "ChainOfProof",
            "/api/v1/analyses/{analysis_id}/sessions/{session_id}/events": (
                "SessionEventsResponse"
            ),
            "/api/v1/analyses/{analysis_id}/evidence/{evidence_id}": "SafeEvidenceDetail",
            "/api/v1/analyses/{analysis_id}/findings/{finding_id}": "FindingPresentation",
        }
        artifact_path = (
            "/api/v1/analyses/{analysis_id}/findings/{finding_id}/artifacts/{artifact_format}"
        )

        assert set(schema["paths"]) == {*expected_models, artifact_path}
        for path, model_name in expected_models.items():
            operation = schema["paths"][path]
            assert set(operation) == {"get"}
            success_schema = operation["get"]["responses"]["200"]["content"]["application/json"][
                "schema"
            ]
            assert success_schema["$ref"] == f"#/components/schemas/{model_name}"
            error_status = "500" if path == "/api/v1/health" else "422"
            error_schema = operation["get"]["responses"][error_status]["content"][
                "application/json"
            ]["schema"]
            assert error_schema["$ref"] == "#/components/schemas/ErrorResponse"

        assert "FindingResponse" not in schema["components"]["schemas"]
        assert "FindingPresentation" in schema["components"]["schemas"]
        artifact_operation = schema["paths"][artifact_path]
        assert set(artifact_operation) == {"get"}
        artifact_content = artifact_operation["get"]["responses"]["200"]["content"]
        assert set(artifact_content) == {
            "application/json",
            "text/html",
            "application/pdf",
        }
        artifact_error = artifact_operation["get"]["responses"]["422"]["content"][
            "application/json"
        ]["schema"]
        assert artifact_error["$ref"] == "#/components/schemas/ErrorResponse"

        assert "ErrorResponse" in schema["components"]["schemas"]
        assert "/api/v1/analyses" not in schema["paths"]
