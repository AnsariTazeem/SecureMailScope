"""Strict public models for synchronous analysis orchestration."""

from __future__ import annotations

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

from securemailscope.chain.ids import COMPACT_ID_PATTERN, PREFIX_ANALYSIS
from securemailscope.chain.models import ChainOfProof
from securemailscope.intake import DEFAULT_MAX_INPUT_BYTES
from securemailscope.tshark import DEFAULT_TIMEOUT_SECONDS


class OrchestrationExecutionContext(BaseModel):
    """Explicit adapter and policy execution inputs; no ambient clock is consulted."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    source_configuration_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    analyzer_version: str = Field(min_length=1, max_length=128)
    profile_id: str = Field(min_length=1, max_length=64)
    created_at: AwareDatetime
    started_at: AwareDatetime
    completed_at: AwareDatetime
    evaluated_at: AwareDatetime

    @field_validator("analyzer_version", "profile_id")
    @classmethod
    def _reject_blank_values(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("value must not be blank")
        return value

    @model_validator(mode="after")
    def _validate_time_order(self) -> OrchestrationExecutionContext:
        if self.started_at < self.created_at:
            raise ValueError("started_at must not precede created_at")
        if self.completed_at < self.started_at:
            raise ValueError("completed_at must not precede started_at")
        if self.evaluated_at < self.completed_at:
            raise ValueError("evaluated_at must not precede completed_at")
        return self


class OrchestrationSettings(BaseModel):
    """Existing analyzer resource bounds supplied to one synchronous execution."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    max_input_bytes: int = Field(default=DEFAULT_MAX_INPUT_BYTES, ge=1)
    timeout_seconds: float = Field(default=DEFAULT_TIMEOUT_SECONDS, gt=0, allow_inf_nan=False)


class OrchestrationResult(BaseModel):
    """Authoritative registered analysis identity and final validated Chain."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    analysis_id: str = Field(pattern=COMPACT_ID_PATTERN[PREFIX_ANALYSIS])
    chain: ChainOfProof

    @model_validator(mode="after")
    def _identity_matches_chain(self) -> OrchestrationResult:
        if self.analysis_id != self.chain.analysis.analysis_id:
            raise ValueError("analysis_id must equal chain.analysis.analysis_id")
        return self
