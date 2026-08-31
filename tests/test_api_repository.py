"""Repository tests for Commit 5B: InMemoryAnalysisChainRepository."""

from __future__ import annotations

import threading

import pytest
from presentation_helpers import build_evaluated_chain

from securemailscope.api.repository import (
    InMemoryAnalysisChainRepository,
    RepositoryCapacityError,
    RepositoryConflictError,
    RepositoryInvalidChainError,
)
from securemailscope.chain.invariants import assert_chain_valid
from securemailscope.chain.models import ChainOfProof


@pytest.fixture
def chain() -> ChainOfProof:
    return build_evaluated_chain()


@pytest.fixture
def repo() -> InMemoryAnalysisChainRepository:
    return InMemoryAnalysisChainRepository(max_entries=8)


def _make_different_chain(seed: str) -> ChainOfProof:
    """Build a chain with a different analysis_id by using a different capture sha256."""
    import sys
    from pathlib import Path

    _tests_dir = Path(__file__).resolve().parent
    if str(_tests_dir) not in sys.path:
        sys.path.insert(0, str(_tests_dir))
    from datetime import UTC, datetime
    from decimal import Decimal

    from _e3a_helpers import frame, stream

    from securemailscope.chain.invariants import assert_chain_valid
    from securemailscope.chain.poc_adapter import (
        CaptureMetadata,
        PocAdapterContext,
        build_chain_from_poc_analysis,
    )
    from securemailscope.chain.policy.engine import evaluate_default_policy
    from securemailscope.chain.policy.models import PolicyEvaluationContext
    from securemailscope.chain.smtp_facts import derive_smtp_transition_facts
    from securemailscope.models import (
        AnalyzeResult,
        CaptureFormat,
        CaptureProvenance,
        Direction,
        Protocol,
        ProvenanceStatus,
    )
    from securemailscope.protocols import classify_stream
    from securemailscope.sessions import build_transition

    sha256 = seed * 64
    C = Direction.CLIENT_TO_SERVER
    S = Direction.SERVER_TO_CLIENT
    frames = [
        frame(1, b"", direction=C, syn=True),
        frame(2, b"", direction=S, syn=True, ack=True),
        frame(3, b"", direction=C, ack=True),
        frame(4, b"220 mail.example ESMTP\r\n", direction=S),
        frame(5, b"EHLO client.example\r\n", direction=C),
        frame(6, b"250-STARTTLS\r\n", direction=S),
        frame(7, b"MAIL FROM:<test@example.test>\r\n", direction=C),
        frame(8, b"QUIT\r\n", direction=C),
    ]
    tcp_stream = stream(frames)
    classification = classify_stream(tcp_stream)
    assert classification.protocol is Protocol.SMTP
    transition = build_transition(tcp_stream, capture_truncation=False)
    result = AnalyzeResult(
        provenance=CaptureProvenance(
            input_path=f"/private/work/{seed}.pcapng",
            sha256=sha256,
            size_bytes=4096,
            capture_format=CaptureFormat.PCAPNG,
            packet_count=len(tcp_stream.frames),
            first_epoch_seconds=Decimal("1800000000.100000000"),
            last_epoch_seconds=Decimal("1800000002.300000000"),
            tshark_version="4.2.5",
            capinfos_version="4.2.5",
            status=ProvenanceStatus.OK,
            warnings=[],
        ),
        tool_records=[],
        streams=[tcp_stream],
        classifications=[classification],
        smtp_transitions=[transition],
        warnings=[],
    )
    chain = build_chain_from_poc_analysis(
        result,
        context=PocAdapterContext(
            capture_metadata=CaptureMetadata(
                link_layer_types=["ethernet"],
                snaplen=262144,
                truncated_packet_count=0,
            ),
            source_configuration_digest="c" * 64,
            analyzer_version="securemailscope/0.5.0",
            created_at=datetime(2026, 8, 27, 9, 59, 0, tzinfo=UTC),
            started_at=datetime(2026, 8, 27, 10, 0, 0, tzinfo=UTC),
            completed_at=datetime(2026, 8, 27, 10, 1, 0, tzinfo=UTC),
        ),
    )
    derived = derive_smtp_transition_facts(chain)
    evaluated = evaluate_default_policy(
        derived,
        context=PolicyEvaluationContext(
            profile_id="sms-liberal",
            evaluated_at=datetime(2026, 8, 27, 11, 0, 0, tzinfo=UTC),
            base_configuration_digest=derived.analysis.configuration_digest,
        ),
    )
    assert_chain_valid(evaluated)
    return evaluated


def test_valid_registration_and_lookup(chain: ChainOfProof, repo: InMemoryAnalysisChainRepository):
    repo.register(chain)
    result = repo.get(chain.analysis.analysis_id)
    assert result is not None
    assert result.analysis.analysis_id == chain.analysis.analysis_id


def test_unknown_analysis_returns_none(repo: InMemoryAnalysisChainRepository):
    assert repo.get("ana_nonexistent0000000000") is None


def test_invalid_chain_rejected(repo: InMemoryAnalysisChainRepository):
    with pytest.raises(RepositoryInvalidChainError):
        repo.register(None)  # type: ignore[arg-type]


def test_chain_failing_invariants_rejected(
    chain: ChainOfProof,
    repo: InMemoryAnalysisChainRepository,
):
    analysis = chain.analysis.model_copy(update={"chain_schema_version": "2.0.0"})
    invalid = chain.model_copy(update={"analysis": analysis})

    with pytest.raises(RepositoryInvalidChainError):
        repo.register(invalid)


def test_repository_key_is_derived_from_chain_analysis_id(
    chain: ChainOfProof,
    repo: InMemoryAnalysisChainRepository,
):
    repo.register(chain)
    assert repo.get(chain.analysis.analysis_id) is not None
    assert repo.get("ana_0000000000000000") is None


def test_maximum_entry_count_enforced(chain: ChainOfProof):
    repo = InMemoryAnalysisChainRepository(max_entries=2)
    repo.register(chain)
    second = _make_different_chain("b")
    repo.register(second)
    third = _make_different_chain("d")
    with pytest.raises(RepositoryCapacityError):
        repo.register(third)


def test_no_silent_eviction(chain: ChainOfProof):
    repo = InMemoryAnalysisChainRepository(max_entries=1)
    repo.register(chain)
    assert repo.count == 1
    second = _make_different_chain("e")
    with pytest.raises(RepositoryCapacityError):
        repo.register(second)
    assert repo.count == 1
    assert repo.get(chain.analysis.analysis_id) is not None


def test_duplicate_identical_registration_is_idempotent(chain: ChainOfProof):
    repo = InMemoryAnalysisChainRepository(max_entries=8)
    repo.register(chain)
    repo.register(chain)
    assert repo.count == 1


def test_conflicting_replacement_rejected(chain: ChainOfProof):
    """A different chain under the same analysis_id key is rejected."""
    repo = InMemoryAnalysisChainRepository(max_entries=8)
    repo.register(chain)
    execution = chain.execution.model_copy(update={"note": "different execution envelope"})
    conflicting = chain.model_copy(update={"execution": execution})
    assert_chain_valid(conflicting)

    with pytest.raises(RepositoryConflictError):
        repo.register(conflicting)


def test_registration_stores_isolated_deep_snapshot(chain: ChainOfProof):
    repo = InMemoryAnalysisChainRepository(max_entries=8)
    original_warnings = list(chain.captures[0].capture_warnings)
    repo.register(chain)
    chain.captures[0].capture_warnings.append("caller mutation")

    stored = repo.get(chain.analysis.analysis_id)
    assert stored is not None
    assert stored.captures[0].capture_warnings == original_warnings
    assert_chain_valid(stored)


def test_retrieval_returns_isolated_deep_snapshot(chain: ChainOfProof):
    repo = InMemoryAnalysisChainRepository(max_entries=8)
    repo.register(chain)
    first = repo.get(chain.analysis.analysis_id)
    assert first is not None
    original_evidence_ids = list(first.protocol_events[0].evidence_ids)
    first.protocol_events[0].evidence_ids.append("ev_0000000000000000")

    second = repo.get(chain.analysis.analysis_id)
    assert second is not None
    assert second.protocol_events[0].evidence_ids == original_evidence_ids
    assert first is not second
    assert first.protocol_events is not second.protocol_events
    assert_chain_valid(second)


def test_concurrent_reads_are_safe(chain: ChainOfProof):
    repo = InMemoryAnalysisChainRepository(max_entries=8)
    repo.register(chain)
    results: list[str | None] = []

    def reader():
        r = repo.get(chain.analysis.analysis_id)
        results.append(r.analysis.analysis_id if r else None)

    threads = [threading.Thread(target=reader) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert all(r == chain.analysis.analysis_id for r in results)


def test_repository_behavior_is_deterministic(chain: ChainOfProof):
    repo = InMemoryAnalysisChainRepository(max_entries=8)
    repo.register(chain)
    first = repo.get(chain.analysis.analysis_id)
    second = repo.get(chain.analysis.analysis_id)
    assert first is not None and second is not None
    assert first.model_dump() == second.model_dump()


def test_repository_max_entries_must_be_positive():
    with pytest.raises(ValueError):
        InMemoryAnalysisChainRepository(max_entries=0)
