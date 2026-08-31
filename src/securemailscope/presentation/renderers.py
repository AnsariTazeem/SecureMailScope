"""Pure deterministic JSON, HTML, PDF, and digest renderers."""

from __future__ import annotations

import hashlib
from html import escape
from io import BytesIO
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, StrictUndefined
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfgen.canvas import Canvas
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from securemailscope.chain.canonical import canonical_json, datetime_canonical_str
from securemailscope.chain.enums import EngineStatus
from securemailscope.chain.errors import ChainErrorCode, ChainValidationError, PresentationError
from securemailscope.chain.invariants import assert_chain_valid
from securemailscope.chain.models import ChainOfProof
from securemailscope.presentation.builder import build_finding_presentation
from securemailscope.presentation.models import (
    FindingArtifact,
    FindingArtifactSet,
    FindingPresentation,
)

_TEMPLATE_DIRECTORY = Path(__file__).resolve().parent / "templates"
_HTML_ENVIRONMENT = Environment(
    loader=FileSystemLoader(_TEMPLATE_DIRECTORY),
    autoescape=True,
    undefined=StrictUndefined,
    trim_blocks=True,
    lstrip_blocks=True,
    keep_trailing_newline=True,
)
_HTML_ENVIRONMENT.filters["timestamp"] = datetime_canonical_str


def _assert_valid_for_presentation(chain: ChainOfProof) -> None:
    try:
        assert_chain_valid(chain)
    except ChainValidationError as exc:
        raise PresentationError(
            ChainErrorCode.PRESENTATION_INVALID_CHAIN,
            "chain failed presentation validation",
        ) from exc


def _canonical_chain_data(chain: ChainOfProof) -> dict:
    data = chain.model_dump(mode="python")
    ordering = {
        "captures": lambda item: item["capture_id"],
        "sessions": lambda item: (item["stable_session_key"], item["session_id"]),
        "evidence": lambda item: item["evidence_id"],
        "protocol_events": lambda item: (
            item["session_id"],
            item["sequence_index"],
            item["event_id"],
        ),
        "crypto_observations": lambda item: item["observation_id"],
        "derived_facts": lambda item: item["fact_id"],
        "rule_evaluations": lambda item: item["evaluation_id"],
        "findings": lambda item: item["finding_id"],
        "anomaly_results": lambda item: item["anomaly_result_id"],
        "recommendations": lambda item: item["recommendation_id"],
        "artifacts": lambda item: item["artifact_manifest_id"],
    }
    for field, key in ordering.items():
        data[field] = sorted(data[field], key=key)
    if data["policy_risk"] is not None:
        data["policy_risk"]["contributions"] = sorted(
            data["policy_risk"]["contributions"],
            key=lambda item: item["contribution_id"],
        )
    return data


def render_chain_json(chain: ChainOfProof) -> bytes:
    """Emit the complete validated Chain as canonical UTF-8 JSON bytes."""
    _assert_valid_for_presentation(chain)
    try:
        return canonical_json(_canonical_chain_data(chain)).encode("utf-8")
    except PresentationError:
        raise
    except Exception as exc:
        raise PresentationError(
            ChainErrorCode.PRESENTATION_RENDER_FAILED,
            "canonical JSON rendering failed",
        ) from exc


def _render_html_presentation(presentation: FindingPresentation) -> bytes:
    try:
        template = _HTML_ENVIRONMENT.get_template("finding.html.j2")
        fact_values = {fact.fact_id: canonical_json(fact.value) for fact in presentation.facts}
        rendered = template.render(
            presentation=presentation,
            fact_values=fact_values,
            ml_not_run=presentation.ml_anomaly.engine_status is EngineStatus.NOT_RUN,
        )
        return rendered.encode("utf-8")
    except PresentationError:
        raise
    except Exception as exc:
        raise PresentationError(
            ChainErrorCode.PRESENTATION_RENDER_FAILED,
            "HTML rendering failed",
        ) from exc


def render_finding_html(chain: ChainOfProof, finding_id: str) -> bytes:
    """Render one autoescaped, self-contained finding HTML document."""
    return _render_html_presentation(build_finding_presentation(chain, finding_id))


def _pdf_date(value) -> str:  # noqa: ANN001
    utc = value.utctimetuple()
    return (
        f"D:{utc.tm_year:04d}{utc.tm_mon:02d}{utc.tm_mday:02d}"
        f"{utc.tm_hour:02d}{utc.tm_min:02d}{utc.tm_sec:02d}+00'00'"
    )


def _pdf_canvas_factory(timestamp):  # noqa: ANN001
    embedded_date = _pdf_date(timestamp)

    def factory(filename, **kwargs):  # noqa: ANN001
        kwargs["invariant"] = 1
        kwargs["pageCompression"] = 0
        canvas = Canvas(filename, **kwargs)
        canvas.setDateFormatter(lambda *_parts: embedded_date)
        return canvas

    return factory


def _paragraph(text: object, style) -> Paragraph:  # noqa: ANN001
    return Paragraph(escape(str(text), quote=True), style)


def _labelled(label: str, value: object, style) -> Paragraph:  # noqa: ANN001
    return Paragraph(f"<b>{escape(label)}:</b> {escape(str(value), quote=True)}", style)


def _append_limitations(story: list, presentation: FindingPresentation, styles) -> None:  # noqa: ANN001
    story.append(_paragraph("Limitations", styles["Heading2"]))
    story.append(Spacer(1, 2 * mm))
    if not presentation.limitations:
        story.append(_paragraph("None recorded.", styles["BodyText"]))
        return
    for limitation in presentation.limitations:
        detail = f" ({limitation.detail})" if limitation.detail else ""
        story.append(
            _paragraph(
                f"- {limitation.code.value}: {limitation.summary}{detail}",
                styles["BodyText"],
            )
        )


def _render_pdf_presentation(presentation: FindingPresentation) -> bytes:
    try:
        output = BytesIO()
        styles = getSampleStyleSheet()
        styles.add(
            ParagraphStyle(
                name="FindingTitle",
                parent=styles["Title"],
                alignment=TA_CENTER,
                fontName="Helvetica-Bold",
                fontSize=16,
                leading=20,
                spaceAfter=6 * mm,
            )
        )
        styles["BodyText"].fontName = "Helvetica"
        styles["BodyText"].fontSize = 9
        styles["BodyText"].leading = 12
        styles["Heading2"].fontName = "Helvetica-Bold"
        styles["Heading2"].fontSize = 12
        styles["Heading2"].spaceBefore = 4 * mm
        styles["Heading2"].spaceAfter = 2 * mm

        document = SimpleDocTemplate(
            output,
            pagesize=A4,
            rightMargin=16 * mm,
            leftMargin=16 * mm,
            topMargin=14 * mm,
            bottomMargin=14 * mm,
            title=presentation.title,
            author="SecureMailScope",
            subject=f"Evidence-backed finding {presentation.finding_id}",
            creator="SecureMailScope",
        )
        story: list = [
            _paragraph("SecureMailScope finding", styles["FindingTitle"]),
            _paragraph(presentation.title, styles["Heading1"]),
        ]
        summary_rows = [
            ("Analysis ID", presentation.analysis_id),
            ("Finding ID", presentation.finding_id),
            ("Severity", presentation.severity.value),
            ("Category", presentation.category.value),
            ("Rule", f"{presentation.rule_id} / {presentation.rule_version}"),
            ("Rule outcome", presentation.rule_outcome.value),
            ("Policy-risk contribution", presentation.policy_risk_contribution),
            ("Evidence confidence", presentation.evidence_confidence.value),
            ("Capture SHA-256", presentation.capture_sha256),
            ("Session", f"{presentation.protocol.value} / {presentation.session_id}"),
            ("Evaluated", datetime_canonical_str(presentation.evaluated_at)),
            ("Created", datetime_canonical_str(presentation.created_at)),
        ]
        table = Table(
            [
                [
                    _paragraph(label, styles["BodyText"]),
                    _paragraph(value, styles["BodyText"]),
                ]
                for label, value in summary_rows
            ],
            colWidths=[48 * mm, 125 * mm],
            repeatRows=0,
        )
        table.setStyle(
            TableStyle(
                [
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#A8B4C0")),
                    ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#E9EEF3")),
                    ("LEFTPADDING", (0, 0), (-1, -1), 5),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ]
            )
        )
        story.extend(
            [
                table,
                _paragraph("Rationale", styles["Heading2"]),
                _paragraph(presentation.rationale, styles["BodyText"]),
                _paragraph("Impact", styles["Heading2"]),
                _paragraph(presentation.impact, styles["BodyText"]),
                _paragraph("Derived facts", styles["Heading2"]),
            ]
        )
        for fact in presentation.facts:
            story.append(
                _labelled(
                    fact.fact_id,
                    f"{fact.fact_type} = {canonical_json(fact.value)}; "
                    f"observability={fact.observability.value}; "
                    f"confidence={fact.confidence_level.value}",
                    styles["BodyText"],
                )
            )

        story.append(_paragraph("Evidence-backed event timeline", styles["Heading2"]))
        for event in presentation.events:
            evidence_ids = ", ".join(event.evidence_ids)
            value = (
                f"event_id={event.event_id}; "
                f"canonical timestamp={datetime_canonical_str(event.timestamp)}; "
                f"direction={event.direction.value}; "
                f"event_type={event.event_type.value}; "
                f"event_status={event.event_status.value}; "
                f"observability={event.observability.value}; "
                f"linked evidence_ids={evidence_ids}"
            )
            story.append(
                _labelled(
                    "Sequence index",
                    f"{event.sequence_index}; {value}",
                    styles["BodyText"],
                )
            )

        story.append(_paragraph("Evidence references", styles["Heading2"]))
        for evidence in presentation.evidence:
            frames = ", ".join(str(frame) for frame in evidence.frame_numbers)
            value = (
                f"frames {frames}; {datetime_canonical_str(evidence.timestamp_start)} to "
                f"{datetime_canonical_str(evidence.timestamp_end)}; "
                f"{evidence.source_kind.value}/{evidence.source_field}; "
                f"redaction={evidence.redaction.value}"
            )
            story.append(_labelled(evidence.evidence_id, value, styles["BodyText"]))

        recommendation = presentation.recommendation
        story.extend(
            [
                _paragraph("Recommendation", styles["Heading2"]),
                _labelled(
                    "Recommendation ID",
                    recommendation.recommendation_id,
                    styles["BodyText"],
                ),
                _paragraph(recommendation.title, styles["Heading3"]),
                _paragraph(recommendation.summary, styles["BodyText"]),
                _paragraph("Action steps", styles["Heading3"]),
            ]
        )
        for step in recommendation.action_steps:
            story.append(_paragraph(f"- {step}", styles["BodyText"]))
        story.append(_paragraph("Verification steps", styles["Heading3"]))
        for step in recommendation.verification_steps:
            story.append(_paragraph(f"- {step}", styles["BodyText"]))

        story.append(_paragraph("Standards references", styles["Heading2"]))
        for standard in presentation.standards_references:
            section = f", section {standard.section}" if standard.section else ""
            story.append(_paragraph(f"- {standard.id}{section}", styles["BodyText"]))

        story.append(PageBreak())
        story.append(_paragraph("Policy risk", styles["Heading2"]))
        if presentation.policy_risk is None:
            story.append(_paragraph("Policy risk: unavailable", styles["BodyText"]))
        else:
            story.append(
                _paragraph(
                    f"Policy risk: capped {presentation.policy_risk.capped_score}; "
                    f"uncapped {presentation.policy_risk.uncapped_score}; "
                    f"profile {presentation.policy_risk.profile_id}",
                    styles["BodyText"],
                )
            )

        story.append(_paragraph("ML anomaly", styles["Heading2"]))
        if presentation.ml_anomaly.engine_status is EngineStatus.NOT_RUN:
            story.append(_paragraph("ML anomaly: not run", styles["BodyText"]))
        elif not presentation.ml_anomaly.results:
            story.append(
                _paragraph(
                    f"ML anomaly: {presentation.ml_anomaly.engine_status.value}; no result "
                    "for this session",
                    styles["BodyText"],
                )
            )
        else:
            story.append(
                _paragraph(
                    f"ML anomaly engine: {presentation.ml_anomaly.engine_status.value}",
                    styles["BodyText"],
                )
            )
            for anomaly in presentation.ml_anomaly.results:
                story.append(
                    _labelled(
                        anomaly.anomaly_result_id,
                        f"band={anomaly.band.value}; normalized_score="
                        f"{anomaly.normalized_score}; {anomaly.interpretation_note}",
                        styles["BodyText"],
                    )
                )

        _append_limitations(story, presentation, styles)
        document.build(
            story,
            canvasmaker=_pdf_canvas_factory(presentation.evaluated_at),
        )
        return output.getvalue()
    except PresentationError:
        raise
    except Exception as exc:
        raise PresentationError(
            ChainErrorCode.PRESENTATION_RENDER_FAILED,
            "PDF rendering failed",
        ) from exc


def render_finding_pdf(chain: ChainOfProof, finding_id: str) -> bytes:
    """Render one deterministic ReportLab PDF directly from the projection."""
    return _render_pdf_presentation(build_finding_presentation(chain, finding_id))


def _artifact(filename: str, media_type: str, content: bytes) -> FindingArtifact:
    return FindingArtifact(
        filename=filename,
        media_type=media_type,
        content=content,
        sha256=hashlib.sha256(content).hexdigest(),
        byte_length=len(content),
    )


def render_finding_artifacts(
    chain: ChainOfProof,
    finding_id: str,
) -> FindingArtifactSet:
    """Return in-memory JSON/HTML/PDF finding artifacts and exact digests."""
    presentation = build_finding_presentation(chain, finding_id)
    json_content = render_chain_json(chain)
    html_content = _render_html_presentation(presentation)
    pdf_content = _render_pdf_presentation(presentation)
    return FindingArtifactSet(
        json_artifact=_artifact(
            f"{chain.analysis.analysis_id}.chain.json",
            "application/json",
            json_content,
        ),
        html_artifact=_artifact(
            f"{finding_id}.finding.html",
            "text/html; charset=utf-8",
            html_content,
        ),
        pdf_artifact=_artifact(
            f"{finding_id}.finding.pdf",
            "application/pdf",
            pdf_content,
        ),
    )
