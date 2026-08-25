"""Typed boundary models for the deterministic prerequisite doctor."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict


class CheckStatus(StrEnum):
    """Terminal status of a single doctor check."""

    PASS = "pass"
    FAIL = "fail"


class DoctorCheck(BaseModel):
    """One deterministic prerequisite check result."""

    model_config = ConfigDict(extra="forbid")

    id: str
    requirement: str
    status: CheckStatus
    observed: str
    required: bool


class DoctorReport(BaseModel):
    """Stable machine-readable structure emitted by `securemailscope doctor`."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str
    command: str
    ready: bool
    checks: list[DoctorCheck]
