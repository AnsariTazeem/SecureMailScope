"""Deterministic Chain-of-Proof presentation boundary for Commit 5A."""

from securemailscope.presentation.builder import build_finding_presentation
from securemailscope.presentation.models import (
    AnomalyResultPresentation,
    EventPresentation,
    EvidencePresentation,
    FactPresentation,
    FindingArtifact,
    FindingArtifactSet,
    FindingPresentation,
    LimitationPresentation,
    MlAnomalyPresentation,
    ObservationPresentation,
    PolicyRiskContributionPresentation,
    PolicyRiskPresentation,
    RecommendationPresentation,
    StandardPresentation,
)
from securemailscope.presentation.renderers import (
    render_chain_json,
    render_finding_artifacts,
    render_finding_html,
    render_finding_pdf,
)

__all__ = [
    "AnomalyResultPresentation",
    "EventPresentation",
    "EvidencePresentation",
    "FactPresentation",
    "FindingArtifact",
    "FindingArtifactSet",
    "FindingPresentation",
    "LimitationPresentation",
    "MlAnomalyPresentation",
    "ObservationPresentation",
    "PolicyRiskContributionPresentation",
    "PolicyRiskPresentation",
    "RecommendationPresentation",
    "StandardPresentation",
    "build_finding_presentation",
    "render_chain_json",
    "render_finding_artifacts",
    "render_finding_html",
    "render_finding_pdf",
]
