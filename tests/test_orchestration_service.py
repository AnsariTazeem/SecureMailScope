"""Pipeline, atomicity, ID, duplicate, and real-PCAP tests for Commit 6A."""

from __future__ import annotations

import hashlib
import shutil
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import pytest
from orchestration_helpers import (
    build_analyze_result,
    default_policy_pack,
    execution_context,
)

from securemailscope.analyze import analyze_capture
from securemailscope.api.repository import (
    InMemoryAnalysisChainRepository,
    RepositoryInvalidChainError,
)
from securemailscope.chain.canonical import canonical_json
from securemailscope.chain.enums import EngineStatus
from securemailscope.chain.errors import (
    ChainAdapterError,
    ChainErrorCode,
    ChainValidationError,
    PolicyContextError,
    PolicyEvaluationError,
)
from securemailscope.chain.invariants import assert_chain_valid
from securemailscope.chain.models import ChainOfProof
from securemailscope.chain.poc_adapter import build_chain_from_poc_analysis
from securemailscope.chain.policy.engine import evaluate_policy
from securemailscope.chain.policy.loader import load_default_policy_pack
from securemailscope.chain.smtp_facts import derive_smtp_transition_facts
from securemailscope.errors import AnalysisError, ErrorCode
from securemailscope.models import AnalyzeResult
from securemailscope.orchestration import (
    OrchestrationDependencies,
    OrchestrationError,
    OrchestrationErrorCode,
    OrchestrationExecutionContext,
    OrchestrationSettings,
    analyze_capture_to_chain,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
T01_PCAP = REPO_ROOT / "fixtures" / "pcaps" / "smtp_tls12_valid.pcapng"
T01_SHA256 = "772d166b5e2b32516c76833357ff309af0d99d7bc962cf4c685279fc662ab086"


class RecordingRegistry(InMemoryAnalysisChainRepository):
    def __init__(self, order: list[str], max_entries: int = 8) -> None:
        super().__init__(max_entries=max_entries)
        self.order = order
        self.registered: list[ChainOfProof] = []

    def register(self, chain: ChainOfProof) -> None:
        self.order.append("register")
        self.registered.append(chain)
        super().register(chain)


class InvalidChainRejectingRegistry:
    def get(self, analysis_id: str) -> ChainOfProof | None:
        return None

    def register(self, chain: ChainOfProof) -> None:
        raise RepositoryInvalidChainError("rejected")


def _real_stage_dependencies(order: list[str], result=None) -> OrchestrationDependencies:
    analysis_result = result or build_analyze_result()

    def analyze(path, **kwargs):  # noqa: ANN001
        order.append("analyze")
        return analysis_result

    def adapt(value, *, context):  # noqa: ANN001
        order.append("adapt")
        return build_chain_from_poc_analysis(value, context=context)

    def facts(chain):  # noqa: ANN001
        order.append("facts")
        return derive_smtp_transition_facts(chain)

    def policy(chain, *, pack, context):  # noqa: ANN001
        order.append("policy")
        return evaluate_policy(chain, pack=pack, context=context)

    return OrchestrationDependencies(
        analyze=analyze,
        adapt=adapt,
        derive_facts=facts,
        evaluate_policy=policy,
    )


def _run(
    *,
    result=None,
    context=None,
    registry=None,
    dependencies=None,
):
    active_registry = registry or InMemoryAnalysisChainRepository(max_entries=8)
    active_dependencies = dependencies or OrchestrationDependencies(
        analyze=lambda path, **kwargs: result or build_analyze_result(),
    )
    output = analyze_capture_to_chain(
        Path("capture.pcapng"),
        registry=active_registry,
        policy_pack=default_policy_pack(),
        context=context or execution_context(),
        dependencies=active_dependencies,
    )
    return output, active_registry


def test_success_runs_exact_pipeline_and_registers_only_final_chain() -> None:
    order: list[str] = []
    registry = RecordingRegistry(order)
    result = analyze_capture_to_chain(
        Path("capture.pcapng"),
        registry=registry,
        policy_pack=default_policy_pack(),
        context=execution_context(),
        dependencies=_real_stage_dependencies(order),
    )

    assert order == ["analyze", "adapt", "facts", "policy", "register"]
    assert len(registry.registered) == 1
    registered_argument = registry.registered[0]
    assert registered_argument.analysis.rule_engine_status is EngineStatus.COMPLETE
    assert registered_argument.analysis.ml_engine_status is EngineStatus.NOT_RUN
    assert registered_argument.derived_facts
    assert registered_argument.rule_evaluations
    assert registered_argument.policy_risk is not None
    assert registered_argument.anomaly_results == []
    assert result.analysis_id == result.chain.analysis.analysis_id
    assert registry.get(result.analysis_id) == result.chain
    assert_chain_valid(result.chain)


def test_orchestration_settings_reach_analyzer_unchanged() -> None:
    received: dict[str, object] = {}

    def analyze(path: Path, *, max_input_bytes: int, timeout_seconds: float) -> AnalyzeResult:
        received.update(
            path=path,
            max_input_bytes=max_input_bytes,
            timeout_seconds=timeout_seconds,
        )
        return build_analyze_result(capture_path=path)

    settings = OrchestrationSettings(max_input_bytes=123456, timeout_seconds=7.5)
    analyze_capture_to_chain(
        Path("capture.pcapng"),
        registry=InMemoryAnalysisChainRepository(max_entries=2),
        policy_pack=default_policy_pack(),
        context=execution_context(),
        settings=settings,
        dependencies=OrchestrationDependencies(analyze=analyze),
    )

    assert received == {
        "path": Path("capture.pcapng"),
        "max_input_bytes": 123456,
        "timeout_seconds": 7.5,
    }


def test_fixed_inputs_produce_identical_chain_bytes_and_analysis_id() -> None:
    first, _ = _run()
    second, _ = _run()

    assert first.analysis_id == second.analysis_id
    assert canonical_json(first.chain.model_dump(mode="python")) == canonical_json(
        second.chain.model_dump(mode="python")
    )


def test_capture_digest_change_uses_existing_stable_id_semantics() -> None:
    first, _ = _run(result=build_analyze_result(capture_sha256="a" * 64))
    second, _ = _run(result=build_analyze_result(capture_sha256="b" * 64))

    assert first.analysis_id != second.analysis_id
    assert first.chain.captures[0].sha256 == "a" * 64
    assert second.chain.captures[0].sha256 == "b" * 64


def test_source_configuration_digest_change_uses_existing_stable_id_semantics() -> None:
    first, _ = _run()
    context_data = execution_context().model_dump(mode="python")
    context_data["source_configuration_digest"] = "d" * 64
    changed_context = OrchestrationExecutionContext.model_validate(context_data)

    second, _ = _run(context=changed_context)

    assert first.analysis_id != second.analysis_id


def test_identical_registration_is_idempotent_without_created_claim() -> None:
    registry = InMemoryAnalysisChainRepository(max_entries=8)
    first, _ = _run(registry=registry)
    second, _ = _run(registry=registry)

    assert first == second
    assert registry.count == 1
    assert set(second.model_dump()) == {"analysis_id", "chain"}


def test_same_id_different_execution_envelope_conflicts_without_replacement() -> None:
    registry = InMemoryAnalysisChainRepository(max_entries=8)
    first, _ = _run(registry=registry)
    later_context = execution_context(offset=timedelta(hours=1))

    with pytest.raises(OrchestrationError) as exc:
        _run(registry=registry, context=later_context)

    assert exc.value.code is OrchestrationErrorCode.REPOSITORY_CONFLICT
    assert isinstance(exc.value.__cause__, Exception)
    assert registry.count == 1
    assert registry.get(first.analysis_id) == first.chain


@pytest.mark.parametrize(
    ("stage", "expected_code", "failure"),
    [
        (
            "capture",
            OrchestrationErrorCode.INVALID_CAPTURE,
            AnalysisError(ErrorCode.EMPTY_INPUT, "intake", "private /path"),
        ),
        (
            "analyzer",
            OrchestrationErrorCode.ANALYZER_FAILED,
            AnalysisError(ErrorCode.TOOL_TIMEOUT, "tshark_observe", "private /path"),
        ),
        (
            "adapter",
            OrchestrationErrorCode.ADAPTER_FAILED,
            ChainAdapterError(ChainErrorCode.ADAPTER_MAPPING_FAILED, "adapter", "payload"),
        ),
        (
            "facts",
            OrchestrationErrorCode.FACT_DERIVATION_FAILED,
            ChainValidationError(["private invariant detail"]),
        ),
        (
            "policy",
            OrchestrationErrorCode.POLICY_EVALUATION_FAILED,
            PolicyEvaluationError("private policy detail"),
        ),
        (
            "policy_context",
            OrchestrationErrorCode.POLICY_EVALUATION_FAILED,
            PolicyContextError("private policy context detail"),
        ),
    ],
)
def test_stage_failures_are_atomic_and_preserve_typed_causes(stage, expected_code, failure) -> None:
    registry = InMemoryAnalysisChainRepository(max_entries=8)
    base = OrchestrationDependencies(analyze=lambda path, **kwargs: build_analyze_result())

    def fail(*args, **kwargs):  # noqa: ANN002, ANN003
        raise failure

    field = {
        "capture": "analyze",
        "analyzer": "analyze",
        "adapter": "adapt",
        "facts": "derive_facts",
        "policy": "evaluate_policy",
        "policy_context": "evaluate_policy",
    }[stage]
    dependencies = replace(base, **{field: fail})

    with pytest.raises(OrchestrationError) as exc:
        _run(registry=registry, dependencies=dependencies)

    assert exc.value.code is expected_code
    assert exc.value.__cause__ is failure
    assert registry.count == 0


def test_missing_authoritative_analyzer_metadata_fails_before_adapter() -> None:
    result = build_analyze_result()
    incomplete_provenance = result.provenance.model_copy(
        update={"link_layer_types": [], "truncated_packet_count": None}
    )
    incomplete_result = result.model_copy(update={"provenance": incomplete_provenance})
    registry = InMemoryAnalysisChainRepository(max_entries=8)
    adapter_called = False

    def adapter(*args, **kwargs):  # noqa: ANN002, ANN003, ANN202
        nonlocal adapter_called
        adapter_called = True

    dependencies = OrchestrationDependencies(
        analyze=lambda path, **kwargs: incomplete_result,
        adapt=adapter,
    )

    with pytest.raises(OrchestrationError) as exc:
        _run(registry=registry, dependencies=dependencies)

    assert exc.value.code is OrchestrationErrorCode.ANALYZER_FAILED
    assert isinstance(exc.value.__cause__, AnalysisError)
    assert exc.value.__cause__.stage == "capture_metadata"
    assert adapter_called is False
    assert registry.count == 0


def test_adapter_invariant_failure_is_classified_and_atomic() -> None:
    registry = InMemoryAnalysisChainRepository(max_entries=8)
    failure = ChainValidationError(["private adapter invariant"])

    def fail_adapter(*args, **kwargs):  # noqa: ANN002, ANN003
        raise failure

    dependencies = replace(
        OrchestrationDependencies(analyze=lambda path, **kwargs: build_analyze_result()),
        adapt=fail_adapter,
    )

    with pytest.raises(OrchestrationError) as exc:
        _run(registry=registry, dependencies=dependencies)

    assert exc.value.code is OrchestrationErrorCode.ADAPTER_FAILED
    assert exc.value.__cause__ is failure
    assert registry.count == 0


def test_explicit_final_validation_rejects_invalid_policy_output_before_registration() -> None:
    registry = InMemoryAnalysisChainRepository(max_entries=8)

    def invalid_policy(chain, *, pack, context):  # noqa: ANN001
        evaluated = evaluate_policy(chain, pack=pack, context=context)
        invalid_analysis = evaluated.analysis.model_copy(update={"chain_schema_version": "2.0.0"})
        return evaluated.model_copy(update={"analysis": invalid_analysis})

    dependencies = replace(
        OrchestrationDependencies(analyze=lambda path, **kwargs: build_analyze_result()),
        evaluate_policy=invalid_policy,
    )

    with pytest.raises(OrchestrationError) as exc:
        _run(registry=registry, dependencies=dependencies)

    assert exc.value.code is OrchestrationErrorCode.FINAL_CHAIN_INVALID
    assert isinstance(exc.value.__cause__, ChainValidationError)
    assert registry.count == 0


def test_repository_capacity_failure_is_closed_and_preserves_existing_chain() -> None:
    registry = InMemoryAnalysisChainRepository(max_entries=1)
    first, _ = _run(registry=registry, result=build_analyze_result(capture_sha256="a" * 64))

    with pytest.raises(OrchestrationError) as exc:
        _run(registry=registry, result=build_analyze_result(capture_sha256="b" * 64))

    assert exc.value.code is OrchestrationErrorCode.REPOSITORY_CAPACITY
    assert registry.count == 1
    assert registry.get(first.analysis_id) == first.chain


def test_repository_invalid_chain_rejection_is_typed() -> None:
    registry = InvalidChainRejectingRegistry()

    with pytest.raises(OrchestrationError) as exc:
        _run(registry=registry)

    assert exc.value.code is OrchestrationErrorCode.FINAL_CHAIN_INVALID
    assert isinstance(exc.value.__cause__, RepositoryInvalidChainError)


@pytest.mark.skipif(
    not T01_PCAP.is_file() or shutil.which("tshark") is None or shutil.which("capinfos") is None,
    reason="frozen T01 PCAP, tshark, or capinfos is unavailable",
)
def test_real_t01_capture_runs_through_registered_final_chain() -> None:
    original_bytes = T01_PCAP.read_bytes()
    analyzer_results: list[AnalyzeResult] = []

    def real_analyzer(
        path: Path,
        *,
        max_input_bytes: int,
        timeout_seconds: float,
    ) -> AnalyzeResult:
        analyzed = analyze_capture(
            path,
            max_input_bytes=max_input_bytes,
            timeout_seconds=timeout_seconds,
        )
        analyzer_results.append(analyzed)
        return analyzed

    registry = InMemoryAnalysisChainRepository(max_entries=2)

    result = analyze_capture_to_chain(
        T01_PCAP,
        registry=registry,
        policy_pack=load_default_policy_pack(),
        context=execution_context(),
        dependencies=OrchestrationDependencies(analyze=real_analyzer),
    )

    assert len(analyzer_results) == 1
    analyzer_provenance = analyzer_results[0].provenance
    chain_provenance = result.chain.captures[0]
    fixture_digest = hashlib.sha256(original_bytes).hexdigest()
    assert fixture_digest == T01_SHA256
    assert analyzer_provenance.sha256 == fixture_digest
    assert result.chain.captures[0].sha256 == T01_SHA256
    assert analyzer_provenance.link_layer_types
    assert chain_provenance.link_layer_types == analyzer_provenance.link_layer_types
    assert analyzer_provenance.snaplen is None or analyzer_provenance.snaplen > 0
    assert chain_provenance.snaplen == analyzer_provenance.snaplen
    assert analyzer_provenance.truncated_packet_count is not None
    assert chain_provenance.truncated_packet_count == analyzer_provenance.truncated_packet_count
    assert result.chain.analysis.rule_engine_status is EngineStatus.COMPLETE
    assert result.chain.analysis.ml_engine_status is EngineStatus.NOT_RUN
    assert result.chain.derived_facts
    assert result.chain.policy_risk is not None
    assert registry.get(result.analysis_id) == result.chain
    assert_chain_valid(result.chain)
    assert T01_PCAP.read_bytes() == original_bytes
