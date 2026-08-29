"""Typed Chain-of-Proof failures with stable error codes.

Mirrors the analyzer-path convention in :mod:`securemailscope.errors`: every
recoverable condition becomes a typed exception carrying a stable code and a
safe, bounded message. Raw tracebacks are never part of a chain result.
"""

from __future__ import annotations

from enum import StrEnum


class ChainErrorCode(StrEnum):
    """Stable machine-readable codes for chain contract failures."""

    INVALID_REFERENCE = "invalid_reference"
    DUPLICATE_ID = "duplicate_id"
    DETERMINISTIC_ID_MISMATCH = "deterministic_id_mismatch"
    MISSING_REQUIRED_EVIDENCE = "missing_required_evidence"
    CYCLE_DETECTED = "cycle_detected"
    PORT_ONLY_CLASSIFICATION = "port_only_classification"
    NONMONOTONIC_SEQUENCE = "nonmonotonic_sequence"
    TIMESTAMP_ORDER_VIOLATION = "timestamp_order_violation"
    NOT_OBSERVABLE_WITHOUT_REASON = "not_observable_without_reason"
    TLS13_CERTIFICATE_UNOBSERVABLE = "tls13_certificate_unobservable"
    POLICY_SCORE_MISMATCH = "policy_score_mismatch"
    POLICY_ANOMALY_SEPARATION = "policy_anomaly_separation"
    ARTIFACT_HASH_MISMATCH = "artifact_hash_mismatch"
    UNSUPPORTED_JSON_VALUE = "unsupported_json_value"
    NAIVE_DATETIME = "naive_datetime"
    SCHEMA_VALIDATION_ERROR = "schema_validation_error"
    INTERNAL_CHAIN_ERROR = "internal_chain_error"


class ChainError(RuntimeError):
    """A typed chain failure with a stable code and a bounded message."""

    def __init__(
        self,
        code: ChainErrorCode,
        stage: str,
        message: str,
        detail: str = "",
    ) -> None:
        super().__init__(message)
        self.code = code
        self.stage = stage
        self.message = message
        self.detail = detail

    def __str__(self) -> str:
        rendered = f"{self.stage}: {self.message}"
        if self.detail:
            rendered += f" ({self.detail})"
        return rendered


class ChainValidationError(ChainError):
    """One or more graph/business invariant violations on a chain."""

    def __init__(self, problems: list[str], stage: str = "invariants") -> None:
        super().__init__(
            ChainErrorCode.INVALID_REFERENCE,
            stage,
            "chain violated graph or business invariants",
            f"{len(problems)} violation(s)",
        )
        self.problems = list(problems)

    def __str__(self) -> str:
        return "chain invariant violations:\n- " + "\n- ".join(self.problems)
