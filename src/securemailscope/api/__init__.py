"""Thin FastAPI exposure layer for validated Chain-of-Proof (Commit 5B)."""

from securemailscope.api.app import app, create_app
from securemailscope.api.errors import ApiErrorCode, ErrorDetail, ErrorResponse
from securemailscope.api.models import AnalysisSummary, HealthResponse
from securemailscope.api.repository import (
    AnalysisChainRepository,
    InMemoryAnalysisChainRepository,
)
from securemailscope.api.settings import ApiSettings

__all__ = [
    "AnalysisChainRepository",
    "ApiErrorCode",
    "ApiSettings",
    "AnalysisSummary",
    "ErrorDetail",
    "ErrorResponse",
    "HealthResponse",
    "InMemoryAnalysisChainRepository",
    "app",
    "create_app",
]
