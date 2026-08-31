"""Security tests for Commit 5B: error safety, injection, CORS, read-only."""

from __future__ import annotations

import hashlib
import re
from io import BytesIO

import pytest
from api_helpers import make_app, make_empty_app
from httpx import ASGITransport, AsyncClient
from presentation_helpers import build_evaluated_chain
from pydantic import ValidationError
from pypdf import PdfReader

from securemailscope.api import ApiSettings, create_app
from securemailscope.api.responses import canonical_response_bytes
from securemailscope.chain.models import ChainOfProof

MISSING_ANALYSIS_ID = "ana_0000000000000000"
MISSING_SESSION_ID = "ses_0000000000000000"
MISSING_EVIDENCE_ID = "ev_0000000000000000"
MISSING_FINDING_ID = "fnd_0000000000000000"


class ExplodingRepository:
    def get(self, analysis_id: str) -> ChainOfProof | None:
        raise RuntimeError("unexpected repository failure at /private/work/secret")


def _pdf_text(content: bytes) -> str:
    extracted = "\n".join(page.extract_text() or "" for page in PdfReader(BytesIO(content)).pages)
    return re.sub(r"\s+", " ", extracted).strip()


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
#  Error safety
# ---------------------------------------------------------------------------


class TestErrorSafety:
    async def test_missing_analysis_no_traceback(self, empty_app):
        async with AsyncClient(transport=ASGITransport(app=empty_app), base_url="http://test") as c:
            resp = await c.get(f"/api/v1/analyses/{MISSING_ANALYSIS_ID}")
        body = resp.json()
        assert "error" in body
        text = resp.text
        assert "Traceback" not in text
        assert "Exception" not in text or "exception" in body["error"]["code"]

    async def test_missing_session_no_traceback(self, app, chain):
        aid = chain.analysis.analysis_id
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get(f"/api/v1/analyses/{aid}/sessions/{MISSING_SESSION_ID}/events")
        text = resp.text
        assert "Traceback" not in text

    async def test_missing_evidence_no_traceback(self, app, chain):
        aid = chain.analysis.analysis_id
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get(f"/api/v1/analyses/{aid}/evidence/{MISSING_EVIDENCE_ID}")
        text = resp.text
        assert "Traceback" not in text

    async def test_missing_finding_no_traceback(self, app, chain):
        aid = chain.analysis.analysis_id
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get(f"/api/v1/analyses/{aid}/findings/{MISSING_FINDING_ID}")
        text = resp.text
        assert "Traceback" not in text

    async def test_unsupported_artifact_format_no_traceback(self, app, chain):
        aid = chain.analysis.analysis_id
        fid = chain.findings[0].finding_id
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get(f"/api/v1/analyses/{aid}/findings/{fid}/artifacts/bmp")
        text = resp.text
        assert "Traceback" not in text

    async def test_error_envelope_shape(self, empty_app):
        async with AsyncClient(transport=ASGITransport(app=empty_app), base_url="http://test") as c:
            resp = await c.get(f"/api/v1/analyses/{MISSING_ANALYSIS_ID}")
        body = resp.json()
        assert "error" in body
        assert "code" in body["error"]
        assert "message" in body["error"]
        assert isinstance(body["error"]["code"], str)
        assert isinstance(body["error"]["message"], str)

    async def test_error_response_has_canonical_digest_and_security_headers(self, empty_app):
        async with AsyncClient(transport=ASGITransport(app=empty_app), base_url="http://test") as c:
            resp = await c.get(f"/api/v1/analyses/{MISSING_ANALYSIS_ID}")

        expected_digest = hashlib.sha256(resp.content).hexdigest()
        expected_content = canonical_response_bytes(
            {"error": {"code": "analysis_not_found", "message": "analysis does not exist"}}
        )
        assert resp.content == expected_content
        assert resp.headers["cache-control"] == "no-store"
        assert resp.headers["x-content-type-options"] == "nosniff"
        assert resp.headers["content-length"] == str(len(resp.content))
        assert resp.headers["x-content-sha256"] == expected_digest
        assert resp.headers["etag"] == f'"{expected_digest}"'

    async def test_unexpected_repository_error_uses_safe_global_envelope(self):
        app = create_app(repository=ExplodingRepository())
        expected = canonical_response_bytes(
            {"error": {"code": "internal_error", "message": "internal error"}}
        )
        transport = ASGITransport(app=app, raise_app_exceptions=False)

        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.get(f"/api/v1/analyses/{MISSING_ANALYSIS_ID}")

        assert resp.status_code == 500
        assert resp.content == expected
        assert "/private/work/secret" not in resp.text
        assert "RuntimeError" not in resp.text


# ---------------------------------------------------------------------------
#  Security: sensitive data exclusion
# ---------------------------------------------------------------------------


class TestSensitiveDataExclusion:
    SENSITIVE_STRINGS = [
        "/private/work/",
        "MAIL FROM:<secret-sender@example.test>",
        "RCPT TO:<secret-recipient@example.test>",
        "secret-sender@example.test",
        "secret-recipient@example.test",
    ]

    async def test_api_outputs_exclude_sensitive_strings(self, app, chain):
        aid = chain.analysis.analysis_id
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            summary = await c.get(f"/api/v1/analyses/{aid}")
            chain_resp = await c.get(f"/api/v1/analyses/{aid}/chain")
            sid = chain.sessions[0].session_id
            events = await c.get(f"/api/v1/analyses/{aid}/sessions/{sid}/events")
            ev = chain.evidence[0]
            evidence = await c.get(f"/api/v1/analyses/{aid}/evidence/{ev.evidence_id}")
            fid = chain.findings[0].finding_id
            finding = await c.get(f"/api/v1/analyses/{aid}/findings/{fid}")
            html_art = await c.get(f"/api/v1/analyses/{aid}/findings/{fid}/artifacts/html")
            pdf_art = await c.get(f"/api/v1/analyses/{aid}/findings/{fid}/artifacts/pdf")

        assert html_art.status_code == 200
        assert pdf_art.status_code == 200
        assert "default-src 'none'" in html_art.headers["content-security-policy"]
        assert "script-src 'none'" in html_art.headers["content-security-policy"]
        assert html_art.headers["x-content-type-options"] == "nosniff"
        assert pdf_art.headers["x-content-type-options"] == "nosniff"

        for resp in (summary, chain_resp, events, evidence, finding, html_art):
            text = resp.text
            for sensitive in self.SENSITIVE_STRINGS:
                assert sensitive not in text, f"Found {sensitive!r} in {resp.url}"

        pdf_text = _pdf_text(pdf_art.content)
        for sensitive in self.SENSITIVE_STRINGS:
            assert sensitive not in pdf_text, f"Found {sensitive!r} in extracted PDF text"

    async def test_html_artifact_excludes_sensitive_strings(self, app, chain):
        aid = chain.analysis.analysis_id
        fid = chain.findings[0].finding_id
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get(f"/api/v1/analyses/{aid}/findings/{fid}/artifacts/html")
        text = resp.text
        for sensitive in self.SENSITIVE_STRINGS:
            assert sensitive not in text

    async def test_evidence_endpoint_excludes_forbidden_fields(self, app, chain):
        aid = chain.analysis.analysis_id
        ev = chain.evidence[0]
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get(f"/api/v1/analyses/{aid}/evidence/{ev.evidence_id}")
        body = resp.json()
        for field in (
            "normalized_value",
            "safe_excerpt",
            "display_filter",
            "extractor_version",
            "occurrence_index",
        ):
            assert field not in body, f"Field {field!r} should not be exposed"

    async def test_anomaly_feature_snapshot_not_exposed(self, app, chain):
        aid = chain.analysis.analysis_id
        fid = chain.findings[0].finding_id
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get(f"/api/v1/analyses/{aid}/findings/{fid}")
        text = resp.text
        assert "feature_snapshot" not in text


# ---------------------------------------------------------------------------
#  Security: XSS injection
# ---------------------------------------------------------------------------


class TestXssSafety:
    async def test_html_artifact_escapes_script_tag(self, chain):
        malicious = '<script data-secret="credential">alert(1)</script>'
        finding = chain.findings[0].model_copy(update={"title": malicious})
        malicious_chain = chain.model_copy(update={"findings": [finding]})
        malicious_app = make_app(malicious_chain)
        aid = malicious_chain.analysis.analysis_id
        fid = finding.finding_id
        async with AsyncClient(
            transport=ASGITransport(app=malicious_app),
            base_url="http://test",
        ) as c:
            resp = await c.get(f"/api/v1/analyses/{aid}/findings/{fid}/artifacts/html")
        text = resp.text
        assert resp.status_code == 200
        assert malicious not in text
        assert "<script" not in text.lower()
        assert "&lt;script data-secret=&#34;credential&#34;&gt;alert(1)&lt;/script&gt;" in text
        assert "content-security-policy" in resp.headers
        assert "script-src 'none'" in resp.headers["content-security-policy"]

    async def test_html_artifact_no_raw_script(self, app, chain):
        aid = chain.analysis.analysis_id
        fid = chain.findings[0].finding_id
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get(f"/api/v1/analyses/{aid}/findings/{fid}/artifacts/html")
        text = resp.text
        assert "<script>" not in text
        assert "javascript:" not in text

    async def test_html_csp_present(self, app, chain):
        aid = chain.analysis.analysis_id
        fid = chain.findings[0].finding_id
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get(f"/api/v1/analyses/{aid}/findings/{fid}/artifacts/html")
        csp = resp.headers.get("content-security-policy", "")
        assert "script-src 'none'" in csp
        assert "default-src 'none'" in csp

    async def test_json_remains_valid_with_special_chars(self, app, chain):
        aid = chain.analysis.analysis_id
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get(f"/api/v1/analyses/{aid}")
        import json

        body = json.loads(resp.content)
        assert isinstance(body, dict)


# ---------------------------------------------------------------------------
#  CORS
# ---------------------------------------------------------------------------


class TestCors:
    async def test_no_cors_by_default(self):
        app = make_empty_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.options(
                "/api/v1/health",
                headers={
                    "Origin": "http://evil.example.com",
                    "Access-Control-Request-Method": "GET",
                },
            )
        assert "access-control-allow-origin" not in resp.headers

    async def test_one_configured_origin_allowed(self):
        app = make_empty_app(allowed_origins=("http://frontend.example.com",))
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.options(
                "/api/v1/health",
                headers={
                    "Origin": "http://frontend.example.com",
                    "Access-Control-Request-Method": "GET",
                },
            )
        assert resp.headers.get("access-control-allow-origin") == "http://frontend.example.com"

    async def test_unconfigured_origin_not_allowed(self):
        app = make_empty_app(allowed_origins=("http://frontend.example.com",))
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.options(
                "/api/v1/health",
                headers={
                    "Origin": "http://evil.example.com",
                    "Access-Control-Request-Method": "GET",
                },
            )
        assert "access-control-allow-origin" not in resp.headers

    async def test_wildcard_rejected(self):
        with pytest.raises(ValidationError):
            ApiSettings(allowed_origins=("*",))

    async def test_credentials_disabled(self):
        app = make_empty_app(allowed_origins=("http://frontend.example.com",))
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.options(
                "/api/v1/health",
                headers={
                    "Origin": "http://frontend.example.com",
                    "Access-Control-Request-Method": "GET",
                },
            )
        assert "access-control-allow-credentials" not in resp.headers


# ---------------------------------------------------------------------------
#  Read-only boundary
# ---------------------------------------------------------------------------


class TestReadOnlyBoundary:
    async def test_no_post_analyses_route(self, app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post("/api/v1/analyses", json={})
        assert resp.status_code == 404

    async def test_post_put_patch_delete_cannot_modify(self, app, chain):
        aid = chain.analysis.analysis_id
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(f"/api/v1/analyses/{aid}", json={})
            assert resp.status_code == 405
            resp = await c.put(f"/api/v1/analyses/{aid}", json={})
            assert resp.status_code == 405
            resp = await c.patch(f"/api/v1/analyses/{aid}", json={})
            assert resp.status_code == 405
            resp = await c.delete(f"/api/v1/analyses/{aid}")
            assert resp.status_code == 405


# ---------------------------------------------------------------------------
#  Policy-risk and ML separation
# ---------------------------------------------------------------------------


class TestPolicyRiskMlSeparation:
    async def test_policy_risk_fields_remain_policy_risk(self, app, chain):
        aid = chain.analysis.analysis_id
        fid = chain.findings[0].finding_id
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get(f"/api/v1/analyses/{aid}/findings/{fid}")
        body = resp.json()
        assert body["policy_risk"]["capped_score"] >= 0
        assert body["ml_anomaly"]["engine_status"] == "not_run"
        assert body["ml_anomaly"]["results"] == []

    async def test_ml_not_run_not_numeric_zero(self, app, chain):
        aid = chain.analysis.analysis_id
        fid = chain.findings[0].finding_id
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get(f"/api/v1/analyses/{aid}/findings/{fid}")
        body = resp.json()
        assert body["ml_anomaly"]["engine_status"] == "not_run"
        assert body["ml_anomaly"]["engine_status"] != 0
        assert body["ml_anomaly"]["engine_status"] != "0"


# ---------------------------------------------------------------------------
#  API version
# ---------------------------------------------------------------------------


class TestApiVersion:
    def test_non_v1_configuration_rejected(self):
        with pytest.raises(ValidationError):
            ApiSettings(api_version="v2")  # type: ignore[arg-type]

    async def test_api_version_in_health(self, app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get("/api/v1/health")
        assert resp.json()["api_version"] == "v1"

    async def test_api_version_in_analysis_summary(self, app, chain):
        aid = chain.analysis.analysis_id
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get(f"/api/v1/analyses/{aid}")
        assert resp.json()["api_version"] == "v1"

    async def test_api_version_in_session_events(self, app, chain):
        aid = chain.analysis.analysis_id
        sid = chain.sessions[0].session_id
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get(f"/api/v1/analyses/{aid}/sessions/{sid}/events")
        assert resp.json()["api_version"] == "v1"
