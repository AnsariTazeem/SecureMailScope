"""FastAPI application factory, routes, and error handlers.

Route handlers remain adapters over the injected repository, Commit 5A
presentation services, and Commit 6A synchronous orchestration service.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated

from fastapi import FastAPI, Path, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import Response

from securemailscope.api.errors import ApiErrorCode, ErrorDetail, ErrorResponse
from securemailscope.api.models import (
    AnalysisSubmissionResponse,
    AnalysisSummary,
    HealthResponse,
    LimitationDetail,
    PolicyRiskSummary,
    SafeEvidenceDetail,
    SessionEventDetail,
    SessionEventsResponse,
)
from securemailscope.api.repository import (
    AnalysisChainRepository,
    InMemoryAnalysisChainRepository,
)
from securemailscope.api.responses import (
    add_common_headers,
    add_html_security_headers,
    canonical_response_bytes,
)
from securemailscope.api.settings import ApiSettings
from securemailscope.api.uploads import (
    CaptureUploadError,
    CaptureUploadErrorCode,
    parse_capture_upload,
    temporary_capture_path,
)
from securemailscope.chain.errors import ChainValidationError, PresentationError
from securemailscope.chain.ids import (
    COMPACT_ID_PATTERN,
    PREFIX_ANALYSIS,
    PREFIX_EVIDENCE,
    PREFIX_FINDING,
    PREFIX_SESSION,
)
from securemailscope.chain.invariants import assert_chain_valid
from securemailscope.chain.models import ChainOfProof
from securemailscope.chain.policy.loader import load_default_policy_pack
from securemailscope.chain.policy.models import PolicyPack
from securemailscope.orchestration import (
    OrchestrationDependencies,
    OrchestrationError,
    OrchestrationErrorCode,
    OrchestrationExecutionContext,
    OrchestrationSettings,
    analyze_capture_to_chain,
)
from securemailscope.presentation import (
    FindingPresentation,
    build_finding_presentation,
    render_chain_json,
    render_finding_html,
    render_finding_pdf,
)


class ArtifactFormat(StrEnum):
    JSON = "json"
    HTML = "html"
    PDF = "pdf"


AnalysisId = Annotated[str, Path(pattern=COMPACT_ID_PATTERN[PREFIX_ANALYSIS])]
SessionId = Annotated[str, Path(pattern=COMPACT_ID_PATTERN[PREFIX_SESSION])]
EvidenceId = Annotated[str, Path(pattern=COMPACT_ID_PATTERN[PREFIX_EVIDENCE])]
FindingId = Annotated[str, Path(pattern=COMPACT_ID_PATTERN[PREFIX_FINDING])]


@dataclass(frozen=True)
class _AppState:
    settings: ApiSettings
    repository: AnalysisChainRepository
    policy_pack: PolicyPack
    orchestration_settings: OrchestrationSettings
    orchestration_dependencies: OrchestrationDependencies | None
    source_configuration_digest: str
    clock: Callable[[], datetime]


def _get_state(request: Request) -> _AppState:
    return request.app.state.api_state


def _get_settings(request: Request) -> ApiSettings:
    return _get_state(request).settings


def _get_repo(request: Request) -> AnalysisChainRepository:
    return _get_state(request).repository


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _source_configuration_digest(settings: ApiSettings) -> str:
    content = canonical_response_bytes(
        {
            "max_input_bytes": settings.max_upload_bytes,
            "timeout_seconds": settings.analysis_timeout_seconds,
        }
    )
    return hashlib.sha256(content).hexdigest()


def _execution_context(state: _AppState) -> OrchestrationExecutionContext:
    boundary_time = state.clock()
    return OrchestrationExecutionContext(
        source_configuration_digest=state.source_configuration_digest,
        analyzer_version=state.settings.analyzer_version,
        profile_id=state.settings.analysis_profile_id,
        created_at=boundary_time,
        started_at=boundary_time,
        completed_at=boundary_time,
        evaluated_at=boundary_time,
    )


def _error_response(status_code: int, code: ApiErrorCode, message: str) -> Response:
    body = ErrorResponse(error=ErrorDetail(code=code, message=message))
    content = canonical_response_bytes(body.model_dump(mode="python"))
    response = Response(
        content=content,
        status_code=status_code,
        media_type="application/json",
    )
    add_common_headers(response, content)
    return response


def _ok_response(content: bytes, media_type: str, *, status_code: int = 200) -> Response:
    return Response(
        content=content,
        status_code=status_code,
        media_type=media_type,
    )


def _documented_error(description: str) -> dict[str, object]:
    return {"model": ErrorResponse, "description": description}


def _upload_error_response(exc: CaptureUploadError) -> Response:
    mapping = {
        CaptureUploadErrorCode.INVALID_MULTIPART: (
            422,
            ApiErrorCode.INVALID_REQUEST,
            "malformed multipart request",
        ),
        CaptureUploadErrorCode.UNSUPPORTED_CAPTURE_TYPE: (
            415,
            ApiErrorCode.UNSUPPORTED_CAPTURE_TYPE,
            "capture extension is not supported",
        ),
        CaptureUploadErrorCode.EMPTY_UPLOAD: (
            422,
            ApiErrorCode.EMPTY_UPLOAD,
            "capture upload is empty",
        ),
        CaptureUploadErrorCode.UPLOAD_TOO_LARGE: (
            413,
            ApiErrorCode.UPLOAD_TOO_LARGE,
            "capture upload exceeds size limit",
        ),
    }
    return _error_response(*mapping[exc.code])


def _orchestration_error_response(exc: OrchestrationError) -> Response:
    if exc.code is OrchestrationErrorCode.INVALID_CAPTURE:
        return _error_response(422, ApiErrorCode.INVALID_CAPTURE, "capture validation failed")
    if exc.code is OrchestrationErrorCode.REPOSITORY_CONFLICT:
        return _error_response(
            409,
            ApiErrorCode.ANALYSIS_CONFLICT,
            "analysis conflicts with an existing result",
        )
    if exc.code is OrchestrationErrorCode.REPOSITORY_CAPACITY:
        return _error_response(
            503,
            ApiErrorCode.ANALYSIS_CAPACITY_UNAVAILABLE,
            "analysis capacity is unavailable",
        )
    return _error_response(500, ApiErrorCode.ANALYSIS_FAILED, "analysis failed")


def _require_chain(repo: AnalysisChainRepository, analysis_id: str) -> ChainOfProof:
    chain = repo.get(analysis_id)
    if chain is None:
        raise _NotFound(ApiErrorCode.ANALYSIS_NOT_FOUND, "analysis does not exist")
    assert_chain_valid(chain)
    return chain


def _require_session(chain: ChainOfProof, session_id: str) -> None:
    for session in chain.sessions:
        if session.session_id == session_id:
            return
    raise _NotFound(ApiErrorCode.SESSION_NOT_FOUND, "session does not exist")


def _require_evidence(chain: ChainOfProof, evidence_id: str) -> None:
    for evidence in chain.evidence:
        if evidence.evidence_id == evidence_id:
            if evidence.session_id not in {s.session_id for s in chain.sessions}:
                raise _NotFound(
                    ApiErrorCode.EVIDENCE_NOT_FOUND,
                    "evidence does not belong to this analysis",
                )
            return
    raise _NotFound(ApiErrorCode.EVIDENCE_NOT_FOUND, "evidence does not exist")


def _require_finding(chain: ChainOfProof, finding_id: str) -> None:
    for finding in chain.findings:
        if finding.finding_id == finding_id:
            if finding.analysis_id != chain.analysis.analysis_id:
                raise _NotFound(
                    ApiErrorCode.FINDING_NOT_FOUND,
                    "finding does not belong to this analysis",
                )
            return
    raise _NotFound(ApiErrorCode.FINDING_NOT_FOUND, "finding does not exist")


class _NotFound(Exception):
    def __init__(self, code: ApiErrorCode, message: str) -> None:
        self.code = code
        self.message = message


# ---------------------------------------------------------------------------
#  Route handlers
# ---------------------------------------------------------------------------


async def health(request: Request) -> Response:
    body = HealthResponse(status="ok", api_version=_get_settings(request).api_version)
    content = canonical_response_bytes(body.model_dump(mode="python"))
    resp = _ok_response(content, "application/json")
    add_common_headers(resp, content)
    return resp


async def submit_analysis(request: Request) -> Response:
    """Accept one bounded capture and delegate once to Commit 6A orchestration."""
    state = _get_state(request)
    async with parse_capture_upload(
        request,
        max_upload_bytes=state.settings.max_upload_bytes,
    ) as parsed:
        async with temporary_capture_path(
            parsed,
            max_upload_bytes=state.settings.max_upload_bytes,
        ) as capture_path:
            result = analyze_capture_to_chain(
                capture_path,
                registry=state.repository,
                policy_pack=state.policy_pack,
                context=_execution_context(state),
                settings=state.orchestration_settings,
                dependencies=state.orchestration_dependencies,
            )

    body = AnalysisSubmissionResponse(
        api_version=state.settings.api_version,
        analysis_id=result.analysis_id,
        analysis_status=result.chain.analysis.analysis_status,
    )
    content = canonical_response_bytes(body.model_dump(mode="python"))
    response = _ok_response(content, "application/json", status_code=201)
    add_common_headers(response, content)
    return response


async def get_analysis(
    analysis_id: AnalysisId,
    request: Request,
) -> Response:
    repo = _get_repo(request)
    settings = _get_settings(request)
    chain = _require_chain(repo, analysis_id)

    captures = sorted(chain.captures, key=lambda c: c.capture_id)
    sessions = sorted(chain.sessions, key=lambda s: s.session_id)
    findings = sorted(chain.findings, key=lambda f: f.finding_id)
    recommendations = chain.recommendations

    policy_risk_summary = None
    if chain.policy_risk is not None:
        policy_risk_summary = PolicyRiskSummary(
            policy_risk_id=chain.policy_risk.policy_risk_id,
            profile_id=chain.policy_risk.profile_id,
            uncapped_score=chain.policy_risk.uncapped_score,
            capped_score=chain.policy_risk.capped_score,
            available=True,
        )

    summary = AnalysisSummary(
        api_version=settings.api_version,
        chain_schema_version=chain.chain_schema_version,
        analysis_id=chain.analysis.analysis_id,
        analyzer_version=chain.analysis.analyzer_version,
        analysis_status=chain.analysis.analysis_status.value,
        rule_engine_status=chain.analysis.rule_engine_status,
        ml_engine_status=chain.analysis.ml_engine_status,
        capture_ids=[c.capture_id for c in captures],
        session_ids=[s.session_id for s in sessions],
        finding_ids=[f.finding_id for f in findings],
        capture_count=len(chain.captures),
        session_count=len(chain.sessions),
        evidence_count=len(chain.evidence),
        protocol_event_count=len(chain.protocol_events),
        derived_fact_count=len(chain.derived_facts),
        rule_evaluation_count=len(chain.rule_evaluations),
        finding_count=len(chain.findings),
        recommendation_count=len(recommendations),
        policy_risk=policy_risk_summary,
        limitations=[
            LimitationDetail.model_validate(limitation.model_dump(mode="python"))
            for limitation in chain.analysis.limitations
        ],
    )

    content = canonical_response_bytes(summary.model_dump(mode="python"))
    if len(content) > settings.max_json_response_bytes:
        return _error_response(413, ApiErrorCode.RESPONSE_TOO_LARGE, "response exceeds size limit")
    resp = _ok_response(content, "application/json")
    add_common_headers(resp, content)
    return resp


async def get_chain(analysis_id: AnalysisId, request: Request) -> Response:
    repo = _get_repo(request)
    settings = _get_settings(request)
    chain = _require_chain(repo, analysis_id)

    try:
        content = render_chain_json(chain)
    except PresentationError:
        return _error_response(500, ApiErrorCode.PRESENTATION_UNAVAILABLE, "chain rendering failed")

    if len(content) > settings.max_json_response_bytes:
        return _error_response(413, ApiErrorCode.RESPONSE_TOO_LARGE, "response exceeds size limit")

    resp = _ok_response(content, "application/json")
    add_common_headers(resp, content)
    return resp


async def get_session_events(
    analysis_id: AnalysisId,
    session_id: SessionId,
    request: Request,
) -> Response:
    repo = _get_repo(request)
    settings = _get_settings(request)
    chain = _require_chain(repo, analysis_id)
    _require_session(chain, session_id)

    target_session = next(s for s in chain.sessions if s.session_id == session_id)
    events = sorted(
        (e for e in chain.protocol_events if e.session_id == session_id),
        key=lambda e: (e.sequence_index, e.event_id),
    )

    event_details = [
        SessionEventDetail(
            event_id=e.event_id,
            session_id=e.session_id,
            protocol=target_session.protocol,
            sequence_index=e.sequence_index,
            event_type=e.event_type,
            state_before=e.state_before,
            state_after=e.state_after,
            timestamp=e.timestamp,
            direction=e.direction,
            evidence_ids=sorted(set(e.evidence_ids)),
            event_status=e.event_status,
            observability=e.observability,
            limitations=[
                LimitationDetail.model_validate(limitation.model_dump(mode="python"))
                for limitation in e.limitations
            ],
        )
        for e in events
    ]

    response = SessionEventsResponse(
        api_version=settings.api_version,
        analysis_id=analysis_id,
        session_id=session_id,
        stable_session_key=target_session.stable_session_key,
        protocol=target_session.protocol,
        events=event_details,
    )

    content = canonical_response_bytes(response.model_dump(mode="python"))
    if len(content) > settings.max_json_response_bytes:
        return _error_response(413, ApiErrorCode.RESPONSE_TOO_LARGE, "response exceeds size limit")
    resp = _ok_response(content, "application/json")
    add_common_headers(resp, content)
    return resp


async def get_evidence(
    analysis_id: AnalysisId,
    evidence_id: EvidenceId,
    request: Request,
) -> Response:
    repo = _get_repo(request)
    settings = _get_settings(request)
    chain = _require_chain(repo, analysis_id)
    _require_evidence(chain, evidence_id)

    evidence = next(e for e in chain.evidence if e.evidence_id == evidence_id)
    safe_detail = SafeEvidenceDetail(
        evidence_id=evidence.evidence_id,
        capture_id=evidence.capture_id,
        capture_sha256=evidence.capture_sha256,
        session_id=evidence.session_id,
        frame_numbers=sorted(set(evidence.frame_numbers)),
        timestamp_start=evidence.timestamp_start,
        timestamp_end=evidence.timestamp_end,
        direction=evidence.direction,
        source_kind=evidence.source_kind,
        source_field=evidence.source_field,
        observability=evidence.observability,
        redaction=evidence.redaction,
    )

    content = canonical_response_bytes(safe_detail.model_dump(mode="python"))
    if len(content) > settings.max_json_response_bytes:
        return _error_response(413, ApiErrorCode.RESPONSE_TOO_LARGE, "response exceeds size limit")
    resp = _ok_response(content, "application/json")
    add_common_headers(resp, content)
    return resp


async def get_finding(
    analysis_id: AnalysisId,
    finding_id: FindingId,
    request: Request,
) -> Response:
    repo = _get_repo(request)
    settings = _get_settings(request)
    chain = _require_chain(repo, analysis_id)
    _require_finding(chain, finding_id)

    try:
        presentation = build_finding_presentation(chain, finding_id)
    except PresentationError:
        return _error_response(
            500,
            ApiErrorCode.PRESENTATION_UNAVAILABLE,
            "finding projection failed",
        )

    content = canonical_response_bytes(presentation.model_dump(mode="python"))
    if len(content) > settings.max_json_response_bytes:
        return _error_response(413, ApiErrorCode.RESPONSE_TOO_LARGE, "response exceeds size limit")

    resp = _ok_response(content, "application/json")
    add_common_headers(resp, content)
    return resp


async def get_artifact(
    analysis_id: AnalysisId,
    finding_id: FindingId,
    artifact_format: ArtifactFormat,
    request: Request,
) -> Response:
    repo = _get_repo(request)
    settings = _get_settings(request)
    chain = _require_chain(repo, analysis_id)
    _require_finding(chain, finding_id)

    try:
        if artifact_format is ArtifactFormat.JSON:
            content = render_chain_json(chain)
            media_type = "application/json"
            filename = f"{analysis_id}.chain.json"
            size_limit = settings.max_json_response_bytes
        elif artifact_format is ArtifactFormat.HTML:
            content = render_finding_html(chain, finding_id)
            media_type = "text/html; charset=utf-8"
            filename = f"{finding_id}.finding.html"
            size_limit = settings.max_html_response_bytes
        else:
            content = render_finding_pdf(chain, finding_id)
            media_type = "application/pdf"
            filename = f"{finding_id}.finding.pdf"
            size_limit = settings.max_pdf_response_bytes
    except PresentationError:
        return _error_response(500, ApiErrorCode.ARTIFACT_UNAVAILABLE, "artifact rendering failed")

    if len(content) > size_limit:
        return _error_response(413, ApiErrorCode.RESPONSE_TOO_LARGE, "response exceeds size limit")

    resp = _ok_response(content, media_type)
    add_common_headers(resp, content)
    resp.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    if artifact_format is ArtifactFormat.HTML:
        add_html_security_headers(resp)
    return resp


# ---------------------------------------------------------------------------
#  Application factory
# ---------------------------------------------------------------------------


def create_app(
    *,
    settings: ApiSettings | None = None,
    repository: AnalysisChainRepository | None = None,
    policy_pack: PolicyPack | None = None,
    orchestration_dependencies: OrchestrationDependencies | None = None,
    clock: Callable[[], datetime] | None = None,
) -> FastAPI:
    """Build the API over injected storage and orchestration boundaries.

    The default application repository is empty. Never seed production
    application state with test/demo data.
    """
    if settings is None:
        settings = ApiSettings()
    if repository is None:
        repository = InMemoryAnalysisChainRepository(max_entries=settings.max_repository_entries)
    if policy_pack is None:
        policy_pack = load_default_policy_pack()

    app = FastAPI(
        title="SecureMailScope",
        version="1.0.0",
        openapi_url="/api/v1/openapi.json",
        docs_url="/api/v1/docs",
        redoc_url="/api/v1/redoc",
    )
    app.state.api_state = _AppState(
        settings=settings,
        repository=repository,
        policy_pack=policy_pack,
        orchestration_settings=OrchestrationSettings(
            max_input_bytes=settings.max_upload_bytes,
            timeout_seconds=settings.analysis_timeout_seconds,
        ),
        orchestration_dependencies=orchestration_dependencies,
        source_configuration_digest=_source_configuration_digest(settings),
        clock=clock or _utc_now,
    )

    if settings.allowed_origins:
        from fastapi.middleware.cors import CORSMiddleware

        app.add_middleware(
            CORSMiddleware,
            allow_origins=list(settings.allowed_origins),
            allow_methods=["GET", "POST"],
            allow_headers=["*"],
            allow_credentials=False,
        )

    # Error handlers

    @app.exception_handler(RequestValidationError)
    async def _validation_error_handler(request: Request, exc: RequestValidationError) -> Response:
        return _error_response(422, ApiErrorCode.INVALID_REQUEST, "malformed request")

    @app.exception_handler(_NotFound)
    async def _not_found_handler(request: Request, exc: _NotFound) -> Response:
        return _error_response(404, exc.code, exc.message)

    @app.exception_handler(CaptureUploadError)
    async def _upload_error_handler(request: Request, exc: CaptureUploadError) -> Response:
        return _upload_error_response(exc)

    @app.exception_handler(OrchestrationError)
    async def _orchestration_error_handler(
        request: Request,
        exc: OrchestrationError,
    ) -> Response:
        return _orchestration_error_response(exc)

    @app.exception_handler(ChainValidationError)
    async def _chain_validation_handler(request: Request, exc: ChainValidationError) -> Response:
        return _error_response(500, ApiErrorCode.INVALID_CHAIN, "invalid stored chain")

    @app.exception_handler(Exception)
    async def _unexpected_handler(request: Request, exc: Exception) -> Response:
        return _error_response(500, ApiErrorCode.INTERNAL_ERROR, "internal error")

    # Routes

    app.add_api_route(
        "/api/v1/health",
        health,
        methods=["GET"],
        response_model=HealthResponse,
        responses={500: _documented_error("Internal error")},
    )
    app.add_api_route(
        "/api/v1/analyses",
        submit_analysis,
        methods=["POST"],
        status_code=201,
        response_model=AnalysisSubmissionResponse,
        responses={
            409: _documented_error("Analysis conflict"),
            413: _documented_error("Upload too large"),
            415: _documented_error("Unsupported capture extension"),
            422: _documented_error("Malformed multipart request or invalid capture"),
            500: _documented_error("Analysis or internal failure"),
            503: _documented_error("Analysis capacity unavailable"),
        },
        openapi_extra={
            "requestBody": {
                "required": True,
                "content": {
                    "multipart/form-data": {
                        "schema": {
                            "type": "object",
                            "required": ["capture"],
                            "properties": {"capture": {"type": "string", "format": "binary"}},
                            "additionalProperties": False,
                        }
                    }
                },
            }
        },
    )
    app.add_api_route(
        "/api/v1/analyses/{analysis_id}",
        get_analysis,
        methods=["GET"],
        response_model=AnalysisSummary,
        responses={
            404: _documented_error("Analysis not found"),
            413: _documented_error("Response too large"),
            422: _documented_error("Malformed request"),
            500: _documented_error("Invalid stored Chain or internal error"),
        },
    )
    app.add_api_route(
        "/api/v1/analyses/{analysis_id}/chain",
        get_chain,
        methods=["GET"],
        response_model=ChainOfProof,
        responses={
            404: _documented_error("Analysis not found"),
            413: _documented_error("Response too large"),
            422: _documented_error("Malformed request"),
            500: _documented_error("Invalid stored Chain or rendering error"),
        },
    )
    app.add_api_route(
        "/api/v1/analyses/{analysis_id}/sessions/{session_id}/events",
        get_session_events,
        methods=["GET"],
        response_model=SessionEventsResponse,
        responses={
            404: _documented_error("Analysis or session not found"),
            413: _documented_error("Response too large"),
            422: _documented_error("Malformed request"),
            500: _documented_error("Invalid stored Chain or internal error"),
        },
    )
    app.add_api_route(
        "/api/v1/analyses/{analysis_id}/evidence/{evidence_id}",
        get_evidence,
        methods=["GET"],
        response_model=SafeEvidenceDetail,
        responses={
            404: _documented_error("Analysis or evidence not found"),
            413: _documented_error("Response too large"),
            422: _documented_error("Malformed request"),
            500: _documented_error("Invalid stored Chain or internal error"),
        },
    )
    app.add_api_route(
        "/api/v1/analyses/{analysis_id}/findings/{finding_id}",
        get_finding,
        methods=["GET"],
        response_model=FindingPresentation,
        responses={
            404: _documented_error("Analysis or finding not found"),
            413: _documented_error("Response too large"),
            422: _documented_error("Malformed request"),
            500: _documented_error("Invalid stored Chain or presentation error"),
        },
    )
    app.add_api_route(
        "/api/v1/analyses/{analysis_id}/findings/{finding_id}/artifacts/{artifact_format}",
        get_artifact,
        methods=["GET"],
        responses={
            200: {
                "description": "Finding artifact",
                "content": {
                    "application/json": {"schema": {"$ref": "#/components/schemas/ChainOfProof"}},
                    "text/html": {"schema": {"type": "string"}},
                    "application/pdf": {"schema": {"type": "string", "format": "binary"}},
                },
            },
            404: _documented_error("Analysis or finding not found"),
            413: _documented_error("Response too large"),
            422: _documented_error("Malformed request or unsupported artifact format"),
            500: _documented_error("Invalid stored Chain or artifact rendering error"),
        },
    )

    return app


app = create_app()
