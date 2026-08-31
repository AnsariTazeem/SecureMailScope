"""Versioned FastAPI boundary for analysis submission and Chain retrieval."""

from typing import Any

from securemailscope.api.errors import ApiErrorCode, ErrorDetail, ErrorResponse
from securemailscope.api.models import AnalysisSubmissionResponse, AnalysisSummary, HealthResponse
from securemailscope.api.repository import (
    AnalysisChainRepository,
    InMemoryAnalysisChainRepository,
)
from securemailscope.api.settings import ApiSettings


def __getattr__(name: str) -> Any:  # noqa: ANN401
    """Load the application factory lazily to avoid repository import cycles."""
    if name in {"app", "create_app"}:
        from securemailscope.api.app import app, create_app

        return {"app": app, "create_app": create_app}[name]
    raise AttributeError(name)


__all__ = [
    "AnalysisChainRepository",
    "ApiErrorCode",
    "ApiSettings",
    "AnalysisSubmissionResponse",
    "AnalysisSummary",
    "ErrorDetail",
    "ErrorResponse",
    "HealthResponse",
    "InMemoryAnalysisChainRepository",
    "app",
    "create_app",
]
