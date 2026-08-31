"""Typed, path-safe failures for synchronous analysis orchestration."""

from __future__ import annotations

from enum import StrEnum


class OrchestrationErrorCode(StrEnum):
    """Closed machine-readable failure categories owned by orchestration."""

    INVALID_CAPTURE = "invalid_capture"
    ANALYZER_FAILED = "analyzer_failed"
    ADAPTER_FAILED = "adapter_failed"
    FACT_DERIVATION_FAILED = "fact_derivation_failed"
    POLICY_EVALUATION_FAILED = "policy_evaluation_failed"
    FINAL_CHAIN_INVALID = "final_chain_invalid"
    REPOSITORY_CONFLICT = "repository_conflict"
    REPOSITORY_CAPACITY = "repository_capacity"


class OrchestrationError(RuntimeError):
    """A stable orchestration failure whose public text contains no lower-layer detail."""

    def __init__(self, code: OrchestrationErrorCode, stage: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.stage = stage
        self.message = message

    def __str__(self) -> str:
        return f"{self.stage}: {self.message}"
