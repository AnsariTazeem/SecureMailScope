"""Synchronous composition of the verified capture-to-Chain stages."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from securemailscope.analyze import analyze_capture
from securemailscope.api.repository import (
    RepositoryCapacityError,
    RepositoryConflictError,
    RepositoryInvalidChainError,
)
from securemailscope.chain.errors import (
    ChainAdapterError,
    ChainValidationError,
    PolicyContextError,
    PolicyEvaluationError,
)
from securemailscope.chain.invariants import assert_chain_valid
from securemailscope.chain.models import ChainOfProof
from securemailscope.chain.poc_adapter import (
    CaptureMetadata,
    PocAdapterContext,
    build_chain_from_poc_analysis,
)
from securemailscope.chain.policy.engine import evaluate_policy
from securemailscope.chain.policy.models import PolicyEvaluationContext, PolicyPack
from securemailscope.chain.smtp_facts import derive_smtp_transition_facts
from securemailscope.errors import AnalysisError, ErrorCode
from securemailscope.models import AnalyzeResult
from securemailscope.orchestration.errors import (
    OrchestrationError,
    OrchestrationErrorCode,
)
from securemailscope.orchestration.models import (
    OrchestrationExecutionContext,
    OrchestrationResult,
    OrchestrationSettings,
)


class AnalysisChainRegistry(Protocol):
    """Small writable boundary required by orchestration, separate from the API protocol."""

    def get(self, analysis_id: str) -> ChainOfProof | None: ...

    def register(self, chain: ChainOfProof) -> None: ...


@dataclass(frozen=True)
class OrchestrationDependencies:
    """Injectable verified stage callables for deterministic focused tests."""

    analyze: Callable[..., AnalyzeResult] = analyze_capture
    adapt: Callable[..., ChainOfProof] = build_chain_from_poc_analysis
    derive_facts: Callable[[ChainOfProof], ChainOfProof] = derive_smtp_transition_facts
    evaluate_policy: Callable[..., ChainOfProof] = evaluate_policy


_INVALID_CAPTURE_CODES = frozenset(
    {
        ErrorCode.PATH_NOT_FOUND,
        ErrorCode.NOT_A_REGULAR_FILE,
        ErrorCode.EMPTY_INPUT,
        ErrorCode.UNSUPPORTED_CAPTURE,
        ErrorCode.INPUT_TOO_LARGE,
        ErrorCode.NO_PACKETS,
    }
)


def _analysis_failure(exc: AnalysisError) -> OrchestrationError:
    invalid_intake_output = exc.stage == "intake" and exc.code in {
        ErrorCode.TOOL_NONZERO_EXIT,
        ErrorCode.MALFORMED_TOOL_OUTPUT,
    }
    if exc.code in _INVALID_CAPTURE_CODES or invalid_intake_output:
        return OrchestrationError(
            OrchestrationErrorCode.INVALID_CAPTURE,
            "capture",
            "capture validation failed",
        )
    return OrchestrationError(
        OrchestrationErrorCode.ANALYZER_FAILED,
        "analyzer",
        "capture analysis failed",
    )


def _capture_metadata_from_analysis(analysis: AnalyzeResult) -> CaptureMetadata:
    provenance = analysis.provenance
    if not provenance.link_layer_types or provenance.truncated_packet_count is None:
        raise AnalysisError(
            ErrorCode.INSUFFICIENT_EVIDENCE,
            "capture_metadata",
            "completed analyzer result lacks authoritative capture metadata",
        )
    try:
        return CaptureMetadata(
            link_layer_types=provenance.link_layer_types,
            snaplen=provenance.snaplen,
            truncated_packet_count=provenance.truncated_packet_count,
        )
    except ValueError as exc:
        raise AnalysisError(
            ErrorCode.INSUFFICIENT_EVIDENCE,
            "capture_metadata",
            "completed analyzer result contains invalid capture metadata",
        ) from exc


def analyze_capture_to_chain(
    capture_path: Path,
    *,
    registry: AnalysisChainRegistry,
    policy_pack: PolicyPack,
    context: OrchestrationExecutionContext,
    settings: OrchestrationSettings | None = None,
    dependencies: OrchestrationDependencies | None = None,
) -> OrchestrationResult:
    """Run the verified synchronous pipeline and register only its final Chain."""
    active_settings = settings or OrchestrationSettings()
    stages = dependencies or OrchestrationDependencies()

    try:
        analysis = stages.analyze(
            capture_path,
            max_input_bytes=active_settings.max_input_bytes,
            timeout_seconds=active_settings.timeout_seconds,
        )
    except AnalysisError as exc:
        raise _analysis_failure(exc) from exc

    try:
        capture_metadata = _capture_metadata_from_analysis(analysis)
    except AnalysisError as exc:
        raise _analysis_failure(exc) from exc

    adapter_context = PocAdapterContext(
        capture_metadata=capture_metadata,
        source_configuration_digest=context.source_configuration_digest,
        analyzer_version=context.analyzer_version,
        created_at=context.created_at,
        started_at=context.started_at,
        completed_at=context.completed_at,
    )
    try:
        adapted = stages.adapt(analysis, context=adapter_context)
    except (ChainAdapterError, ChainValidationError) as exc:
        raise OrchestrationError(
            OrchestrationErrorCode.ADAPTER_FAILED,
            "adapter",
            "analysis could not be mapped to the Chain",
        ) from exc

    try:
        derived = stages.derive_facts(adapted)
    except ChainValidationError as exc:
        raise OrchestrationError(
            OrchestrationErrorCode.FACT_DERIVATION_FAILED,
            "fact_derivation",
            "SMTP transition fact derivation failed",
        ) from exc

    policy_context = PolicyEvaluationContext(
        profile_id=context.profile_id,
        evaluated_at=context.evaluated_at,
        base_configuration_digest=derived.analysis.configuration_digest,
    )
    try:
        evaluated = stages.evaluate_policy(
            derived,
            pack=policy_pack,
            context=policy_context,
        )
    except (PolicyContextError, PolicyEvaluationError, ChainValidationError) as exc:
        raise OrchestrationError(
            OrchestrationErrorCode.POLICY_EVALUATION_FAILED,
            "policy_evaluation",
            "policy evaluation failed",
        ) from exc

    try:
        assert_chain_valid(evaluated)
    except ChainValidationError as exc:
        raise OrchestrationError(
            OrchestrationErrorCode.FINAL_CHAIN_INVALID,
            "final_validation",
            "final Chain failed invariant validation",
        ) from exc

    analysis_id = evaluated.analysis.analysis_id
    try:
        registry.register(evaluated)
    except RepositoryConflictError as exc:
        raise OrchestrationError(
            OrchestrationErrorCode.REPOSITORY_CONFLICT,
            "repository",
            "analysis conflicts with an existing registered Chain",
        ) from exc
    except RepositoryCapacityError as exc:
        raise OrchestrationError(
            OrchestrationErrorCode.REPOSITORY_CAPACITY,
            "repository",
            "analysis repository capacity was reached",
        ) from exc
    except RepositoryInvalidChainError as exc:
        raise OrchestrationError(
            OrchestrationErrorCode.FINAL_CHAIN_INVALID,
            "repository",
            "repository rejected the final Chain",
        ) from exc

    return OrchestrationResult(analysis_id=analysis_id, chain=evaluated)
