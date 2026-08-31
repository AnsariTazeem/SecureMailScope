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
    ADAPTER_INPUT_INVALID = "adapter_input_invalid"
    ADAPTER_METADATA_REQUIRED = "adapter_metadata_required"
    ADAPTER_MAPPING_FAILED = "adapter_mapping_failed"
    POLICY_PACK_INVALID = "policy_pack_invalid"
    POLICY_CONTEXT_INVALID = "policy_context_invalid"
    POLICY_EVALUATION_FAILED = "policy_evaluation_failed"
    PRESENTATION_INVALID_CHAIN = "presentation_invalid_chain"
    PRESENTATION_FINDING_NOT_FOUND = "presentation_finding_not_found"
    PRESENTATION_REFERENCE_INVALID = "presentation_reference_invalid"
    PRESENTATION_RENDER_FAILED = "presentation_render_failed"


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


class ChainAdapterError(ChainError):
    """A recoverable mapping failure in an existing-POC to chain adapter.

    ``adapter_input_invalid`` reports context values the adapter cannot map
    (for example authorized TLS 1.3 secrets, which the passive POC adapter never
    supports). ``adapter_metadata_required`` reports missing or unusable capture
    provenance/metadata. ``adapter_mapping_failed`` reports analyzer output that
    cannot be mapped without inventing evidence (duplicate streams, missing
    transitions, response-less accepted/rejected outcomes, empty streams).
    """


class PolicyPackLoadError(ChainError):
    """Policy pack loading failure (YAML parse, validation, or safety violation)."""

    def __init__(self, stage: str, message: str, detail: str = "") -> None:
        super().__init__(
            ChainErrorCode.POLICY_PACK_INVALID,
            stage,
            message,
            detail,
        )


class PolicyContextError(ChainError):
    """Policy evaluation context validation failure."""

    def __init__(self, message: str, detail: str = "") -> None:
        super().__init__(
            ChainErrorCode.POLICY_CONTEXT_INVALID,
            "policy_evaluation",
            message,
            detail,
        )


class PolicyEvaluationError(ChainError):
    """Policy evaluation engine failure."""

    def __init__(self, message: str, detail: str = "") -> None:
        super().__init__(
            ChainErrorCode.POLICY_EVALUATION_FAILED,
            "policy_evaluation",
            message,
            detail,
        )


class PresentationError(ChainError):
    """Safe presentation projection or rendering failure."""

    def __init__(self, code: ChainErrorCode, message: str) -> None:
        super().__init__(code, "presentation", message)
