"""Strict presentation-model contract tests."""

from __future__ import annotations

import pytest
from presentation_helpers import build_evaluated_chain
from pydantic import ValidationError

from securemailscope.presentation import FindingArtifact, FindingPresentation


def test_finding_presentation_is_strict_frozen_and_extra_forbid():
    chain = build_evaluated_chain()
    from securemailscope.presentation import build_finding_presentation

    presentation = build_finding_presentation(chain, chain.findings[0].finding_id)
    data = presentation.model_dump(mode="python")
    data["unexpected"] = "forbidden"

    with pytest.raises(ValidationError):
        FindingPresentation.model_validate(data)
    with pytest.raises(ValidationError):
        FindingPresentation.model_validate(
            {**presentation.model_dump(mode="python"), "policy_risk_contribution": "25"}
        )
    with pytest.raises(ValidationError):
        presentation.title = "changed"


def test_artifact_model_requires_exact_bytes_and_digest_shape():
    artifact = FindingArtifact(
        filename="finding.pdf",
        media_type="application/pdf",
        content=b"%PDF",
        sha256="a" * 64,
        byte_length=4,
    )
    assert artifact.content == b"%PDF"

    with pytest.raises(ValidationError):
        FindingArtifact(
            filename="finding.pdf",
            media_type="application/pdf",
            content="not-bytes",
            sha256="invalid",
            byte_length=4,
        )
