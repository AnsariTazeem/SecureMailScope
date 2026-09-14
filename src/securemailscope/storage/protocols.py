"""Segregated storage protocols for final validated analysis results."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from securemailscope.chain.models import ChainOfProof


@runtime_checkable
class AnalysisResultReader(Protocol):
    """Retrieve an isolated, validated completed Chain when one exists.

    ``None`` preserves the Backend V1 optional-lookup behavior.  Implementations
    fail closed with a storage integrity error when stored state cannot be
    trusted; they never return a partially validated result.
    """

    def get(self, analysis_id: str) -> ChainOfProof | None: ...


@runtime_checkable
class AnalysisResultRegistry(Protocol):
    """Register one final validated Chain under its authoritative analysis ID."""

    def register(self, chain: ChainOfProof) -> None: ...


@runtime_checkable
class AnalysisResultRepository(AnalysisResultReader, AnalysisResultRegistry, Protocol):
    """Composite contract for composition roots that require reading and registration."""
