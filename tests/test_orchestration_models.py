"""Public model contract tests for synchronous orchestration."""

from __future__ import annotations

from datetime import datetime
from math import inf

import pytest
from orchestration_helpers import execution_context
from presentation_helpers import build_evaluated_chain
from pydantic import ValidationError

from securemailscope.orchestration.models import (
    OrchestrationExecutionContext,
    OrchestrationResult,
    OrchestrationSettings,
)


def test_execution_context_is_frozen_strict_and_time_ordered() -> None:
    context = execution_context()

    with pytest.raises(ValidationError):
        context.profile_id = "changed"

    data = context.model_dump(mode="python")
    data["evaluated_at"] = context.completed_at.replace(year=2025)
    with pytest.raises(ValidationError, match="evaluated_at"):
        OrchestrationExecutionContext.model_validate(data)


def test_execution_context_rejects_naive_time_and_invalid_digest() -> None:
    data = execution_context().model_dump(mode="python")
    data["started_at"] = datetime(2026, 8, 31, 10, 0, 1)
    data["source_configuration_digest"] = "not-a-digest"

    with pytest.raises(ValidationError) as exc:
        OrchestrationExecutionContext.model_validate(data)

    rendered = str(exc.value)
    assert "started_at" in rendered
    assert "source_configuration_digest" in rendered


def test_execution_context_rejects_caller_supplied_capture_metadata() -> None:
    data = execution_context().model_dump(mode="python")
    data["capture_metadata"] = {
        "link_layer_types": ["ethernet"],
        "snaplen": 262144,
        "truncated_packet_count": 0,
    }
    with pytest.raises(ValidationError, match="capture_metadata"):
        OrchestrationExecutionContext.model_validate(data)


def test_settings_reject_invalid_existing_analyzer_bounds() -> None:
    with pytest.raises(ValidationError):
        OrchestrationSettings(max_input_bytes=0)
    with pytest.raises(ValidationError):
        OrchestrationSettings(timeout_seconds=0.0)
    with pytest.raises(ValidationError):
        OrchestrationSettings(timeout_seconds=inf)


def test_result_requires_authoritative_chain_analysis_id() -> None:
    evaluated_chain = build_evaluated_chain()
    with pytest.raises(ValidationError, match="analysis_id"):
        OrchestrationResult(
            analysis_id="ana_0000000000000000",
            chain=evaluated_chain,
        )
