"""Strict, validated API configuration for the versioned HTTP boundary."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from securemailscope.intake import DEFAULT_MAX_INPUT_BYTES
from securemailscope.tshark import DEFAULT_TIMEOUT_SECONDS

ApiVersion = Literal["v1"]


class ApiSettings(BaseModel):
    """Immutable API configuration with validated resource bounds.

    Tests may inject smaller limits via ``model_validate`` without mutating
    module-level state.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    api_version: ApiVersion = "v1"
    max_repository_entries: int = Field(default=32, ge=1)
    max_json_response_bytes: int = Field(default=16 * 1024 * 1024, ge=1)
    max_html_response_bytes: int = Field(default=8 * 1024 * 1024, ge=1)
    max_pdf_response_bytes: int = Field(default=32 * 1024 * 1024, ge=1)
    max_upload_bytes: int = Field(default=DEFAULT_MAX_INPUT_BYTES, ge=1)
    analysis_timeout_seconds: float = Field(
        default=DEFAULT_TIMEOUT_SECONDS,
        gt=0,
        allow_inf_nan=False,
    )
    analyzer_version: str = Field(default="securemailscope/0.1.0", min_length=1, max_length=128)
    analysis_profile_id: str = Field(default="sms-liberal", min_length=1, max_length=64)
    allowed_origins: tuple[str, ...] = ()

    @model_validator(mode="after")
    def _no_wildcard_origins(self) -> ApiSettings:
        for origin in self.allowed_origins:
            if origin == "*":
                raise ValueError("wildcard '*' is not an allowed origin")
        return self
