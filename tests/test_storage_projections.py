"""Deterministic persistence-neutral result projection tests."""

from __future__ import annotations

from itertools import permutations

import pytest
from presentation_helpers import build_derived_chain, build_evaluated_chain
from pydantic import ValidationError

from securemailscope.chain.enums import AnalysisStatus, SeverityLevel
from securemailscope.chain.ids import evidence_id, session_id_from_key, session_stable_key
from securemailscope.chain.invariants import assert_chain_valid
from securemailscope.chain.models import ChainOfProof
from securemailscope.models import Protocol
from securemailscope.storage.errors import InvalidAnalysisResultError
from securemailscope.storage.projections import (
    AnalysisResultProjection,
    build_analysis_result_projection,
    maximum_policy_severity,
)


def _with_protocol_sessions(
    chain: ChainOfProof,
    protocols: tuple[Protocol, ...],
) -> ChainOfProof:
    capture = chain.captures[0]
    exemplar_session = chain.sessions[0]
    exemplar_evidence = chain.evidence[0]
    sessions = list(chain.sessions)
    evidence = list(chain.evidence)

    for offset, protocol in enumerate(protocols, start=10):
        source_endpoint = exemplar_session.source_endpoint.model_copy(
            update={"port": 10_000 + offset}
        )
        destination_endpoint = exemplar_session.destination_endpoint.model_copy(
            update={"port": 20_000 + offset}
        )
        stable_key = session_stable_key(
            chain.chain_schema_version,
            capture.sha256,
            offset,
            source_endpoint.ip,
            source_endpoint.port,
            destination_endpoint.ip,
            destination_endpoint.port,
        )
        new_session_id = session_id_from_key(stable_key)
        classification_ids: list[str] = []
        if protocol is not Protocol.UNKNOWN:
            source_field = f"{protocol.value}.classification"
            normalized_value = f"classified-{protocol.value}-{offset}"
            new_evidence_id = evidence_id(
                capture.capture_id,
                new_session_id,
                exemplar_evidence.source_kind.value,
                source_field,
                normalized_value,
                exemplar_evidence.frame_numbers,
                exemplar_evidence.direction.value,
                exemplar_evidence.occurrence_index,
            )
            evidence.append(
                exemplar_evidence.model_copy(
                    update={
                        "evidence_id": new_evidence_id,
                        "session_id": new_session_id,
                        "source_field": source_field,
                        "normalized_value": normalized_value,
                    }
                )
            )
            classification_ids.append(new_evidence_id)
        sessions.append(
            exemplar_session.model_copy(
                update={
                    "session_id": new_session_id,
                    "stable_session_key": stable_key,
                    "tcp_stream_id": offset,
                    "source_endpoint": source_endpoint,
                    "destination_endpoint": destination_endpoint,
                    "protocol": protocol,
                    "classification_evidence_ids": classification_ids,
                }
            )
        )

    updated = chain.model_copy(update={"sessions": sessions, "evidence": evidence})
    assert_chain_valid(updated)
    return updated


def test_projection_extracts_authoritative_analysis_fields() -> None:
    chain = build_evaluated_chain()

    projection = build_analysis_result_projection(chain)

    assert projection.analysis_id == chain.analysis.analysis_id
    assert projection.analysis_status is chain.analysis.analysis_status
    assert projection.created_at == chain.analysis.created_at
    assert projection.completed_at == chain.analysis.completed_at
    assert projection.max_policy_severity is SeverityLevel.HIGH
    assert projection.protocols == (Protocol.SMTP,)


def test_no_findings_projects_no_maximum_policy_severity() -> None:
    projection = build_analysis_result_projection(build_derived_chain())

    assert projection.max_policy_severity is None


def test_maximum_severity_uses_explicit_security_ordering() -> None:
    ordered = (
        SeverityLevel.INFO,
        SeverityLevel.LOW,
        SeverityLevel.MEDIUM,
        SeverityLevel.HIGH,
        SeverityLevel.CRITICAL,
    )

    for values in permutations(ordered):
        assert maximum_policy_severity(values) is SeverityLevel.CRITICAL
    assert maximum_policy_severity(()) is None


def test_protocol_membership_is_distinct_canonical_and_preserves_unknown() -> None:
    chain = _with_protocol_sessions(
        build_evaluated_chain(),
        (Protocol.UNKNOWN, Protocol.POP3, Protocol.IMAP, Protocol.SMTP),
    )

    first = build_analysis_result_projection(chain)
    second = build_analysis_result_projection(chain)

    assert first.protocols == (
        Protocol.SMTP,
        Protocol.IMAP,
        Protocol.POP3,
        Protocol.UNKNOWN,
    )
    assert second.protocols == first.protocols


def test_mutated_chain_is_rejected_through_authoritative_validation() -> None:
    chain = build_evaluated_chain()
    mutated_analysis = chain.analysis.model_copy(
        update={"completed_at": chain.analysis.created_at.replace(year=2025)}
    )
    mutated = chain.model_copy(update={"analysis": mutated_analysis})

    with pytest.raises(InvalidAnalysisResultError, match="projection source is invalid"):
        build_analysis_result_projection(mutated)


def test_projection_model_is_strict_frozen_and_forbids_extra_fields() -> None:
    chain = build_evaluated_chain()
    values = build_analysis_result_projection(chain).model_dump(mode="python")

    with pytest.raises(ValidationError, match="analysis_status"):
        AnalysisResultProjection(**{**values, "analysis_status": "complete"})
    with pytest.raises(ValidationError, match="protocol membership must be distinct"):
        AnalysisResultProjection(**{**values, "protocols": (Protocol.SMTP, Protocol.SMTP)})
    with pytest.raises(ValidationError, match="canonical ordering"):
        AnalysisResultProjection(**{**values, "protocols": (Protocol.UNKNOWN, Protocol.SMTP)})
    with pytest.raises(ValidationError, match="extra"):
        AnalysisResultProjection(**values, capture_sha256="a" * 64)  # type: ignore[call-arg]

    projection = AnalysisResultProjection(**values)
    with pytest.raises(ValidationError, match="frozen"):
        projection.analysis_status = AnalysisStatus.FAILED
