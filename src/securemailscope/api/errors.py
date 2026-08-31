"""Stable API error envelope and error-code enum for Commit 5B."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict


class ApiErrorCode(StrEnum):
    """Closed machine-readable error codes."""

    INVALID_REQUEST = "invalid_request"
    ANALYSIS_NOT_FOUND = "analysis_not_found"
    SESSION_NOT_FOUND = "session_not_found"
    EVIDENCE_NOT_FOUND = "evidence_not_found"
    FINDING_NOT_FOUND = "finding_not_found"
    INVALID_CHAIN = "invalid_chain"
    PRESENTATION_UNAVAILABLE = "presentation_unavailable"
    ARTIFACT_UNAVAILABLE = "artifact_unavailable"
    RESPONSE_TOO_LARGE = "response_too_large"
    INTERNAL_ERROR = "internal_error"


class ErrorDetail(BaseModel):
    """One error inside the API envelope."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: ApiErrorCode
    message: str


class ErrorResponse(BaseModel):
    """Stable API error envelope."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    error: ErrorDetail
