"""Strict immutable analysis-job snapshots for Backend V2.

The snapshot deliberately stores identifiers and lifecycle metadata only.  It
contains no capture bytes, packet or email content, filename, temporary path,
credential, token, traceback, internal exception text, service object, or
adapter/ORM object.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator, model_validator

from securemailscope.chain.ids import (
    COMPACT_ID_PATTERN,
    PREFIX_ANALYSIS,
    SHA256_DIGEST_PATTERN,
    is_compact_id,
)
from securemailscope.identity import JOB_ID_PATTERN, is_job_id
from securemailscope.jobs.enums import JobState

PUBLIC_FAILURE_CODE_PATTERN = r"^[a-z][a-z0-9_]{0,63}$"


class JobSnapshot(BaseModel):
    """One complete persistence-neutral view of a submitted execution request.

    This model validates representation invariants only.  It intentionally does
    not decide whether a transition from one valid snapshot to another is legal;
    the durable job-lifecycle milestone owns that state machine.

    ``interrupted`` requires a safe public failure code, matching ``failed``.
    This makes terminal non-success snapshots self-describing without retaining
    an internal exception message.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    job_id: str = Field(pattern=JOB_ID_PATTERN)
    state: JobState
    capture_sha256: str = Field(pattern=SHA256_DIGEST_PATTERN)
    analysis_fingerprint: str | None = Field(pattern=SHA256_DIGEST_PATTERN)
    analysis_id: str | None = Field(pattern=COMPACT_ID_PATTERN[PREFIX_ANALYSIS])
    submitted_at: AwareDatetime
    started_at: AwareDatetime | None
    completed_at: AwareDatetime | None
    public_failure_code: str | None = Field(pattern=PUBLIC_FAILURE_CODE_PATTERN)
    revision: int = Field(ge=0)

    @field_validator("job_id")
    @classmethod
    def _validate_job_id(cls, value: str) -> str:
        if not is_job_id(value):
            raise ValueError("job_id must satisfy the authoritative job-ID contract")
        return value

    @field_validator("analysis_id")
    @classmethod
    def _validate_analysis_id(cls, value: str | None) -> str | None:
        if value is not None and not is_compact_id(PREFIX_ANALYSIS, value):
            raise ValueError("analysis_id must satisfy the authoritative analysis-ID contract")
        return value

    @field_validator("submitted_at", "started_at", "completed_at")
    @classmethod
    def _require_utc(cls, value: datetime | None) -> datetime | None:
        if value is not None and value.utcoffset() != timedelta(0):
            raise ValueError("job timestamps must use UTC")
        return value

    @model_validator(mode="after")
    def _validate_snapshot_invariants(self) -> JobSnapshot:
        if self.started_at is not None and self.started_at < self.submitted_at:
            raise ValueError("started_at must not precede submitted_at")
        if self.completed_at is not None:
            if self.completed_at < self.submitted_at:
                raise ValueError("completed_at must not precede submitted_at")
            if self.started_at is not None and self.completed_at < self.started_at:
                raise ValueError("completed_at must not precede started_at")

        if self.state in {JobState.ACCEPTED, JobState.QUEUED}:
            if self.started_at is not None:
                raise ValueError(f"started_at must be absent when state is {self.state.value}")
            if self.completed_at is not None:
                raise ValueError(f"completed_at must be absent when state is {self.state.value}")
            if self.analysis_id is not None:
                raise ValueError(f"analysis_id must be absent when state is {self.state.value}")
            if self.public_failure_code is not None:
                raise ValueError(
                    f"public_failure_code must be absent when state is {self.state.value}"
                )
        elif self.state is JobState.RUNNING:
            if self.started_at is None:
                raise ValueError("started_at is required when state is running")
            if self.completed_at is not None:
                raise ValueError("completed_at must be absent when state is running")
            if self.analysis_id is not None:
                raise ValueError("analysis_id must be absent when state is running")
            if self.public_failure_code is not None:
                raise ValueError("public_failure_code must be absent when state is running")
        elif self.state is JobState.COMPLETED:
            if self.started_at is None:
                raise ValueError("started_at is required when state is completed")
            if self.completed_at is None:
                raise ValueError("completed_at is required when state is completed")
            if self.analysis_fingerprint is None:
                raise ValueError("analysis_fingerprint is required when state is completed")
            if self.analysis_id is None:
                raise ValueError("analysis_id is required when state is completed")
            if self.public_failure_code is not None:
                raise ValueError("public_failure_code must be absent when state is completed")
        elif self.state in {JobState.FAILED, JobState.INTERRUPTED}:
            if self.completed_at is None:
                raise ValueError(f"completed_at is required when state is {self.state.value}")
            if self.analysis_id is not None:
                raise ValueError(f"analysis_id must be absent when state is {self.state.value}")
            if self.public_failure_code is None:
                raise ValueError(
                    f"public_failure_code is required when state is {self.state.value}"
                )
        return self
