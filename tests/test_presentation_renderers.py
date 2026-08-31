"""Deterministic JSON/HTML/PDF renderer and artifact parity tests."""

from __future__ import annotations

import hashlib
import json
import re
from io import BytesIO

import presentation_helpers
from presentation_helpers import build_evaluated_chain, canonical_chain
from pypdf import PdfReader

from securemailscope.chain.canonical import datetime_canonical_str
from securemailscope.presentation import (
    build_finding_presentation,
    render_chain_json,
    render_finding_artifacts,
    render_finding_html,
    render_finding_pdf,
)


def _pdf_text(content: bytes) -> str:
    extracted = "\n".join(page.extract_text() or "" for page in PdfReader(BytesIO(content)).pages)
    return re.sub(r"\s+", " ", extracted).strip()


def _assert_timeline_values(rendered: str, presentation) -> None:  # noqa: ANN001
    assert "Evidence-backed event timeline" in rendered
    for event in presentation.events:
        required = [
            event.event_id,
            event.event_type.value,
            str(event.sequence_index),
            datetime_canonical_str(event.timestamp),
            event.direction.value,
            event.event_status.value,
            event.observability.value,
            *event.evidence_ids,
        ]
        assert all(value in rendered for value in required)


def test_json_html_and_pdf_are_byte_identical_across_two_renders():
    chain = build_evaluated_chain()
    finding_id = chain.findings[0].finding_id

    assert render_chain_json(chain) == render_chain_json(chain)
    assert render_finding_html(chain, finding_id) == render_finding_html(chain, finding_id)
    assert render_finding_pdf(chain, finding_id) == render_finding_pdf(chain, finding_id)


def test_html_contains_required_finding_evidence_timeline_and_separate_scores(monkeypatch):
    monkeypatch.setattr(presentation_helpers, "CAPTURE_SHA256", "b" * 64)
    chain = build_evaluated_chain()
    finding = chain.findings[0]
    presentation = build_finding_presentation(chain, finding.finding_id)
    html = render_finding_html(chain, finding.finding_id).decode("utf-8")

    required = [
        chain.analysis.analysis_id,
        finding.finding_id,
        finding.title,
        finding.severity.value,
        finding.rule_id,
        finding.rule_version,
        finding.recommendation_id,
        chain.captures[0].sha256,
        *finding.evidence_ids,
    ]
    assert all(value in html for value in required)
    assert "Policy risk" in html
    assert "ML anomaly: not run" in html
    assert "ML anomaly: 0" not in html
    assert all(limitation.summary in html for limitation in finding.limitations)
    _assert_timeline_values(html, presentation)
    positions = [html.index(event.event_id) for event in presentation.events]
    assert positions == sorted(positions)


def test_pdf_contains_required_finding_values_without_truncation():
    chain = build_evaluated_chain()
    finding = chain.findings[0]
    presentation = build_finding_presentation(chain, finding.finding_id)
    text = _pdf_text(render_finding_pdf(chain, finding.finding_id))

    required = [
        chain.analysis.analysis_id,
        finding.finding_id,
        finding.title,
        finding.severity.value,
        finding.rule_id,
        finding.rule_version,
        finding.recommendation_id,
        *finding.evidence_ids,
        *(limitation.summary for limitation in finding.limitations),
    ]
    assert all(value in text for value in required)
    assert "ML anomaly: not run" in text
    _assert_timeline_values(text, presentation)


def test_json_html_pdf_semantically_agree_on_selected_finding():
    chain = build_evaluated_chain()
    finding = chain.findings[0]
    artifacts = render_finding_artifacts(chain, finding.finding_id)
    data = json.loads(artifacts.json_artifact.content)
    json_finding = next(
        item for item in data["findings"] if item["finding_id"] == finding.finding_id
    )
    html = artifacts.html_artifact.content.decode("utf-8")
    pdf = _pdf_text(artifacts.pdf_artifact.content)
    common_values = [
        data["analysis"]["analysis_id"],
        json_finding["finding_id"],
        json_finding["title"],
        json_finding["severity"],
        json_finding["rule_id"],
        json_finding["rule_version"],
        json_finding["recommendation_id"],
        *json_finding["evidence_ids"],
        *(item["summary"] for item in json_finding["limitations"]),
    ]
    assert all(value in html for value in common_values)
    assert all(value in pdf for value in common_values)


def test_artifact_filenames_media_types_hashes_and_lengths_are_exact():
    chain = build_evaluated_chain()
    finding_id = chain.findings[0].finding_id
    artifacts = render_finding_artifacts(chain, finding_id)

    assert artifacts.json_artifact.filename == f"{chain.analysis.analysis_id}.chain.json"
    assert artifacts.html_artifact.filename == f"{finding_id}.finding.html"
    assert artifacts.pdf_artifact.filename == f"{finding_id}.finding.pdf"
    assert artifacts.json_artifact.media_type == "application/json"
    assert artifacts.html_artifact.media_type == "text/html; charset=utf-8"
    assert artifacts.pdf_artifact.media_type == "application/pdf"
    for artifact in (
        artifacts.json_artifact,
        artifacts.html_artifact,
        artifacts.pdf_artifact,
    ):
        assert artifact.sha256 == hashlib.sha256(artifact.content).hexdigest()
        assert artifact.byte_length == len(artifact.content)


def test_artifacts_autoescape_html_and_never_expose_raw_payloads():
    chain = build_evaluated_chain()
    finding = chain.findings[0]
    malicious = '<script data-secret="credential">alert(1)</script>'
    changed = finding.model_copy(update={"title": malicious})
    chain = chain.model_copy(update={"findings": [changed]})
    before = canonical_chain(chain)

    artifacts = render_finding_artifacts(chain, changed.finding_id)
    json_text = artifacts.json_artifact.content.decode("utf-8")
    html = artifacts.html_artifact.content.decode("utf-8")
    pdf = _pdf_text(artifacts.pdf_artifact.content)

    assert malicious not in html
    assert "&lt;script data-secret=&#34;credential&#34;&gt;" in html
    assert json.loads(json_text)["analysis"]["analysis_id"] == chain.analysis.analysis_id
    for secret in (
        "MAIL FROM:<secret-sender@example.test>",
        "RCPT TO:<secret-recipient@example.test>",
        "secret-sender@example.test",
        "secret-recipient@example.test",
        "/private/work/",
    ):
        assert all(secret not in content for content in (json_text, html, pdf))
    assert canonical_chain(chain) == before


def test_equivalent_reordered_source_collections_render_identically():
    chain = build_evaluated_chain()
    finding_id = chain.findings[0].finding_id
    reordered = chain.model_copy(
        update={
            "captures": list(reversed(chain.captures)),
            "sessions": list(reversed(chain.sessions)),
            "evidence": list(reversed(chain.evidence)),
            "protocol_events": list(reversed(chain.protocol_events)),
            "derived_facts": list(reversed(chain.derived_facts)),
            "rule_evaluations": list(reversed(chain.rule_evaluations)),
            "findings": list(reversed(chain.findings)),
            "anomaly_results": list(reversed(chain.anomaly_results)),
            "recommendations": list(reversed(chain.recommendations)),
        }
    )

    assert render_chain_json(chain) == render_chain_json(reordered)
    assert render_finding_html(chain, finding_id) == render_finding_html(reordered, finding_id)
    assert render_finding_pdf(chain, finding_id) == render_finding_pdf(reordered, finding_id)


def test_present_anomaly_remains_separate_in_html_and_pdf():
    chain = build_evaluated_chain(with_anomaly=True)
    finding_id = chain.findings[0].finding_id
    html = render_finding_html(chain, finding_id).decode("utf-8")
    pdf = _pdf_text(render_finding_pdf(chain, finding_id))

    assert "Policy risk: capped 25" in html
    assert "ML anomaly engine: complete" in html
    assert "0.75" in html
    assert "Policy risk: capped 25" in pdf
    assert "ML anomaly engine: complete" in pdf
    assert "0.75" in pdf
