"""Typed analyzer failures with stable error codes.

The E2/E3A offline analysis path converts every recoverable condition into a
typed ``AnalysisError`` carrying a stable :class:`ErrorCode`. Raw tracebacks are
never surfaced as normal analyzer output; a safe diagnostic and a stage hint are
kept where they do not risk exposing secrets or unbounded tool output.
"""

from __future__ import annotations

from enum import StrEnum


class ErrorCode(StrEnum):
    """Stable machine-readable codes for analyzer-stage failures.

    Codes are intentionally coarse and stable across releases so callers can
    branch on them deterministically.
    """

    PATH_NOT_FOUND = "path_not_found"
    NOT_A_REGULAR_FILE = "not_a_regular_file"
    EMPTY_INPUT = "empty_input"
    UNSUPPORTED_CAPTURE = "unsupported_capture"
    INPUT_TOO_LARGE = "input_too_large"
    TOOL_UNAVAILABLE = "tool_unavailable"
    TOOL_TIMEOUT = "tool_timeout"
    TOOL_NONZERO_EXIT = "tool_nonzero_exit"
    TOOL_OUTPUT_TOO_LARGE = "tool_output_too_large"
    MALFORMED_TOOL_OUTPUT = "malformed_tool_output"
    NO_PACKETS = "no_packets"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"


class AnalysisError(RuntimeError):
    """A typed, stage-targeted analyzer failure.

    Parameters
    ----------
    code:
        Stable :class:`ErrorCode` identifying the failure category.
    stage:
        Short analysis stage name (e.g. ``"intake"``, ``"tshark"``,
        ``"classify"``) for diagnostics.
    message:
        Human-readable but safe (bounded, non-secret) description.
    detail:
        Optional bounded, sanitized diagnostic detail.
    """

    def __init__(
        self,
        code: ErrorCode,
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
