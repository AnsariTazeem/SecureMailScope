"""End-to-end tests for deterministic Commit 4 policy evaluation."""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal

import pytest
from _e3a_helpers import frame, stream

from securemailscope.chain.canonical import canonical_json
from securemailscope.chain.enums import (
    AnomalyBand,
    ChainObservability,
    ConfidenceLevel,
    EngineStatus,
    EventStatus,
    ProtocolEventType,
    RuleOutcome,
)
from securemailscope.chain.errors import ChainErrorCode, PolicyContextError
from securemailscope.chain.ids import (
    analysis_id,
    anomaly_result_id,
    fact_id_from_key,
    fact_stable_key,
)
from securemailscope.chain.invariants import assert_chain_valid
from securemailscope.chain.models import (
    ANOMALY_INTERPRETATION_NOTE,
    AnomalyResult,
    ChainOfProof,
    DerivedFact,
)
from securemailscope.chain.poc_adapter import (
    CaptureMetadata,
    PocAdapterContext,
    build_chain_from_poc_analysis,
)
from securemailscope.chain.policy.engine import (
    evaluate_default_policy,
    evaluate_policy,
    policy_configuration_digest,
)
from securemailscope.chain.policy.loader import load_default_policy_pack
from securemailscope.chain.policy.models import (
    PolicyEvaluationContext,
    PolicyPack,
    PolicyProfile,
    PolicyRule,
)
from securemailscope.chain.smtp_facts import derive_smtp_transition_facts
from securemailscope.models import (
    AnalyzeResult,
    CaptureFormat,
    CaptureProvenance,
    Direction,
    Protocol,
    ProvenanceStatus,
    RawFrameObservation,
)
from securemailscope.protocols import classify_stream
from securemailscope.sessions import build_transition

C = Direction.CLIENT_TO_SERVER
S = Direction.SERVER_TO_CLIENT
CAPTURE_SHA256 = "a" * 64
BASE_CONFIGURATION_DIGEST = "c" * 64
EVALUATED_AT = datetime(2026, 8, 27, 11, 0, 0, tzinfo=UTC)


def _handshake() -> list[RawFrameObservation]:
    return [
        frame(1, b"", direction=C, syn=True),
        frame(2, b"", direction=S, syn=True, ack=True),
        frame(3, b"", direction=C, ack=True),
    ]


def _plaintext_continuation_frames() -> list[RawFrameObservation]:
    return [
        *_handshake(),
        frame(4, b"220 secure.example ESMTP\r\n", direction=S),
        frame(5, b"EHLO client.example\r\n", direction=C),
        frame(6, b"250-STARTTLS\r\n", direction=S),
        frame(7, b"MAIL FROM:<redacted@example.test>\r\n", direction=C),
        frame(8, b"RCPT TO:<redacted@example.test>\r\n", direction=C),
        frame(9, b"QUIT\r\n", direction=C),
    ]


def _completed_tls_frames() -> list[RawFrameObservation]:
    return [
        *_handshake(),
        frame(4, b"220 secure.example ESMTP\r\n", direction=S),
        frame(5, b"EHLO client.example\r\n", direction=C),
        frame(6, b"250-STARTTLS\r\n", direction=S),
        frame(7, b"STARTTLS\r\n", direction=C),
        frame(8, b"220 Ready to start TLS\r\n", direction=S),
        frame(9, b"\x16\x03\x01\x00\x05", direction=C, tls_handshake_types=(1,)),
        frame(10, b"\x16\x03\x03\x00\x05", direction=S, tls_handshake_types=(2,)),
        frame(11, b"\x16\x03\x03\x00\x05", direction=S, tls_handshake_types=(11,)),
        frame(12, b"\x16\x03\x03\x00\x05", direction=C, tls_handshake_types=(20,)),
    ]


def _build_chain(
    frames: list[RawFrameObservation] | None = None,
) -> ChainOfProof:
    tcp_stream = stream(frames or _plaintext_continuation_frames())
    classification = classify_stream(tcp_stream)
    assert classification.protocol is Protocol.SMTP
    transition = build_transition(tcp_stream, capture_truncation=False)
    result = AnalyzeResult(
        provenance=CaptureProvenance(
            input_path="capture.pcapng",
            sha256=CAPTURE_SHA256,
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
            source_configuration_digest=BASE_CONFIGURATION_DIGEST,
            analyzer_version="securemailscope/0.4.0",
            created_at=datetime(2026, 8, 27, 9, 59, 0, tzinfo=UTC),
            started_at=datetime(2026, 8, 27, 10, 0, 0, tzinfo=UTC),
            completed_at=datetime(2026, 8, 27, 10, 1, 0, tzinfo=UTC),
        ),
    )
    derived = derive_smtp_transition_facts(chain)
    assert_chain_valid(derived)
    return derived


def _context(chain: ChainOfProof, **updates) -> PolicyEvaluationContext:
    values = {
        "profile_id": "sms-liberal",
        "evaluated_at": EVALUATED_AT,
        "base_configuration_digest": chain.analysis.configuration_digest,
    }
    values.update(updates)
    return PolicyEvaluationContext(**values)


def _rule(rule: PolicyRule, **updates) -> PolicyRule:
    values = rule.model_dump(mode="python")
    values.update(updates)
    return PolicyRule.model_validate(values)


def _profile(profile: PolicyProfile, **updates) -> PolicyProfile:
    values = profile.model_dump(mode="python")
    values.update(updates)
    return PolicyProfile.model_validate(values)


def _pack(
    *,
    rules: list[PolicyRule] | None = None,
    profile: PolicyProfile | None = None,
    pack_id: str = "TEST-POLICY-PACK",
) -> PolicyPack:
    default = load_default_policy_pack()
    return PolicyPack(
        pack_id=pack_id,
        version=default.version,
        profiles=[profile or default.profiles[0]],
        rules=rules or default.rules,
        recommendations=default.recommendations,
    )


def _replace_fact(
    chain: ChainOfProof,
    fact_type: str,
    **updates,
) -> ChainOfProof:
    session = chain.sessions[0]
    replacement = next(fact for fact in chain.derived_facts if fact.fact_type == fact_type)
    values = replacement.model_dump(mode="python")
    values.update(updates)
    stable_key = fact_stable_key(
        chain.analysis.chain_schema_version,
        session.stable_session_key,
        values["fact_type"],
        canonical_json(values["value"]),
        values["source_event_ids"],
        values["source_observation_ids"],
        values["source_fact_ids"],
    )
    values["fact_id"] = fact_id_from_key(stable_key)
    updated_fact = DerivedFact.model_validate(values)
    facts = [updated_fact if fact.fact_type == fact_type else fact for fact in chain.derived_facts]
    updated = chain.model_copy(update={"derived_facts": facts})
    assert_chain_valid(updated)
    return updated


def _replace_all_fact_sources(
    chain: ChainOfProof,
    source_event_ids: list[str],
) -> ChainOfProof:
    updated = chain
    for fact in chain.derived_facts:
        updated = _replace_fact(
            updated,
            fact.fact_type,
            source_event_ids=source_event_ids,
            source_observation_ids=[],
            source_fact_ids=[],
        )
    return updated


def _with_anomaly(chain: ChainOfProof) -> ChainOfProof:
    model_id = "test-isolation-model"
    model_version = "1.0.0"
    feature_schema_version = "1.0.0"
    session = chain.sessions[0]
    fact = chain.derived_facts[0]
    new_analysis_id = analysis_id(
        chain.analysis.chain_schema_version,
        chain.captures[0].sha256,
        chain.analysis.configuration_digest,
        chain.analysis.analyzer_version,
        None,
        None,
        model_id,
        model_version,
    )
    analysis = chain.analysis.model_copy(
        update={
            "analysis_id": new_analysis_id,
            "ml_engine_status": EngineStatus.COMPLETE,
            "model_id": model_id,
            "model_version": model_version,
        }
    )
    anomaly = AnomalyResult(
        anomaly_result_id=anomaly_result_id(
            session.session_id,
            model_id,
            model_version,
            feature_schema_version,
        ),
        session_id=session.session_id,
        model_id=model_id,
        model_version=model_version,
        feature_schema_version=feature_schema_version,
        feature_snapshot={"plaintext_commands": 3},
        raw_score=-0.25,
        normalized_score=0.75,
        threshold=0.5,
        band=AnomalyBand.ELEVATED,
        unusual_feature_indicators=["plaintext_commands"],
        linked_fact_ids=[fact.fact_id],
        linked_observation_ids=[],
        evidence_ids=[chain.evidence[0].evidence_id],
        interpretation_note=ANOMALY_INTERPRETATION_NOTE,
        limitations=[],
    )
    updated = chain.model_copy(update={"analysis": analysis, "anomaly_results": [anomaly]})
    assert_chain_valid(updated)
    return updated


def _policy_output(chain: ChainOfProof) -> str:
    data = chain.model_dump(mode="json")
    return canonical_json(
        {
            "analysis": data["analysis"],
            "rule_evaluations": data["rule_evaluations"],
            "findings": data["findings"],
            "policy_risk": data["policy_risk"],
            "recommendations": data["recommendations"],
        }
    )


def _canonical_chain(chain: ChainOfProof) -> str:
    return canonical_json(chain.model_dump(mode="json"))


def test_default_smtp_rule_matches_with_valid_output_and_unchanged_input():
    chain = _build_chain()
    before = _canonical_chain(chain)

    evaluated = evaluate_default_policy(chain, context=_context(chain))

    assert _canonical_chain(chain) == before
    assert evaluated.rule_evaluations[0].outcome is RuleOutcome.MATCHED
    assert len(evaluated.findings) == 1
    assert len(evaluated.recommendations) == 1
    assert evaluated.policy_risk is not None
    assert_chain_valid(evaluated)


def test_not_matched_produces_zero_finding_policy_risk():
    chain = _build_chain(_completed_tls_frames())

    evaluated = evaluate_default_policy(chain, context=_context(chain))

    assert evaluated.rule_evaluations[0].outcome is RuleOutcome.NOT_MATCHED
    assert evaluated.findings == []
    assert evaluated.recommendations == []
    assert evaluated.policy_risk is not None
    assert evaluated.policy_risk.uncapped_score == 0
    assert evaluated.policy_risk.capped_score == 0
    assert evaluated.policy_risk.contributions == []
    assert_chain_valid(evaluated)


def test_missing_fact_is_insufficient_evidence():
    chain = _build_chain()
    facts = [
        fact for fact in chain.derived_facts if fact.fact_type != "plaintext_commands_after_offer"
    ]
    chain = chain.model_copy(update={"derived_facts": facts})
    assert_chain_valid(chain)

    evaluated = evaluate_default_policy(chain, context=_context(chain))

    assert evaluated.rule_evaluations[0].outcome is RuleOutcome.INSUFFICIENT_EVIDENCE
    assert evaluated.findings == []
    assert evaluated.recommendations == []
    assert evaluated.policy_risk is not None
    assert evaluated.policy_risk.contributions == []


def test_unrelated_event_does_not_satisfy_missing_mandatory_evidence_lineage():
    chain = _build_chain()
    capability = next(
        event
        for event in chain.protocol_events
        if event.event_type is ProtocolEventType.CAPABILITY_ADVERTISED
    )
    plaintext_events = [
        event
        for event in chain.protocol_events
        if event.event_type is ProtocolEventType.PLAINTEXT_COMMAND_AFTER_TLS_OFFER
    ]
    assert plaintext_events
    chain = _replace_all_fact_sources(chain, [capability.event_id])

    evaluated = evaluate_default_policy(chain, context=_context(chain))

    evaluation = evaluated.rule_evaluations[0]
    assert evaluation.outcome is RuleOutcome.INSUFFICIENT_EVIDENCE
    assert evaluated.findings == []
    assert evaluated.recommendations == []
    assert evaluated.policy_risk is not None
    assert evaluated.policy_risk.contributions == []


def test_not_applicable_protocol():
    chain = _build_chain()
    default = load_default_policy_pack()
    rule = _rule(default.rules[0], protocols=[Protocol.IMAP])
    pack = _pack(rules=[rule])

    evaluated = evaluate_policy(chain, pack=pack, context=_context(chain))

    assert evaluated.rule_evaluations[0].outcome is RuleOutcome.NOT_APPLICABLE
    assert evaluated.findings == []


def test_suppressed_by_profile():
    chain = _build_chain()
    default = load_default_policy_pack()
    profile = _profile(
        default.profiles[0],
        suppressed_rule_ids=[default.rules[0].rule_id],
    )
    pack = _pack(profile=profile)

    evaluated = evaluate_policy(chain, pack=pack, context=_context(chain))

    assert evaluated.rule_evaluations[0].outcome is RuleOutcome.SUPPRESSED_BY_PROFILE
    assert evaluated.findings == []
    assert evaluated.recommendations == []


def test_finding_recommendation_and_evaluation_links_are_bidirectional():
    chain = _build_chain()
    evaluated = evaluate_default_policy(chain, context=_context(chain))
    evaluation = evaluated.rule_evaluations[0]
    finding = evaluated.findings[0]
    recommendation = evaluated.recommendations[0]

    assert evaluation.generated_finding_id == finding.finding_id
    assert finding.rule_evaluation_id == evaluation.evaluation_id
    assert finding.recommendation_id == recommendation.recommendation_id
    assert recommendation.affected_finding_ids == [finding.finding_id]


def test_mandatory_event_evidence_is_included_on_finding():
    chain = _build_chain()
    mandatory_types = {
        ProtocolEventType.CAPABILITY_ADVERTISED,
        ProtocolEventType.PLAINTEXT_COMMAND_AFTER_TLS_OFFER,
    }
    expected_evidence = {
        evidence_id
        for event in chain.protocol_events
        if event.event_type in mandatory_types
        and event.event_status is EventStatus.OBSERVED
        and event.observability is ChainObservability.OBSERVED
        for evidence_id in event.evidence_ids
    }

    evaluated = evaluate_default_policy(chain, context=_context(chain))

    assert expected_evidence
    assert expected_evidence <= set(evaluated.findings[0].evidence_ids)


def test_confidence_adjustment_rounding_and_profile_cap():
    chain = _build_chain()
    chain = chain.model_copy(
        update={
            "derived_facts": [
                fact.model_copy(update={"confidence_level": ConfidenceLevel.MEDIUM})
                for fact in chain.derived_facts
            ]
        }
    )
    assert_chain_valid(chain)
    default = load_default_policy_pack()
    profile = _profile(default.profiles[0], risk_cap=10)
    pack = _pack(profile=profile)

    evaluated = evaluate_policy(chain, pack=pack, context=_context(chain))

    assert evaluated.policy_risk is not None
    contribution = evaluated.policy_risk.contributions[0]
    assert contribution.policy_risk_contribution == 25
    assert contribution.confidence_factor == 0.75
    assert contribution.confidence_adjusted_points == 19
    assert evaluated.policy_risk.uncapped_score == 19
    assert evaluated.policy_risk.capped_score == 10


def test_global_policy_risk_cap_applies_across_findings():
    chain = _build_chain()
    default = load_default_policy_pack()
    first = _rule(
        default.rules[0],
        rule_id="TEST-STARTTLS-001",
        policy_risk_contribution=100,
    )
    second = _rule(
        default.rules[0],
        rule_id="TEST-STARTTLS-002",
        policy_risk_contribution=100,
    )
    pack = _pack(rules=[first, second])

    evaluated = evaluate_policy(chain, pack=pack, context=_context(chain))

    assert evaluated.policy_risk is not None
    assert len(evaluated.policy_risk.contributions) == 2
    assert evaluated.policy_risk.uncapped_score == 200
    assert evaluated.policy_risk.capped_score == 100


def test_policy_risk_does_not_mutate_or_absorb_anomaly_output():
    chain = _with_anomaly(_build_chain())
    anomaly_before = chain.anomaly_results

    evaluated = evaluate_default_policy(chain, context=_context(chain))

    assert evaluated.policy_risk is not None
    assert evaluated.anomaly_results == anomaly_before
    assert all(
        contribution.finding_id in {finding.finding_id for finding in evaluated.findings}
        for contribution in evaluated.policy_risk.contributions
    )
    assert_chain_valid(evaluated)


def test_configuration_digest_and_analysis_id_are_stable():
    chain = _build_chain()
    pack = load_default_policy_pack()
    digest = policy_configuration_digest(
        base_configuration_digest=chain.analysis.configuration_digest,
        pack=pack,
        profile_id="sms-liberal",
    )

    first = evaluate_policy(chain, pack=pack, context=_context(chain))
    second = evaluate_policy(chain, pack=pack, context=_context(chain))

    expected_analysis_id = analysis_id(
        chain.analysis.chain_schema_version,
        chain.captures[0].sha256,
        digest,
        chain.analysis.analyzer_version,
        pack.pack_id,
        pack.version,
    )
    assert first.analysis.configuration_digest == digest
    assert first.analysis.analysis_id == expected_analysis_id
    assert second.analysis.analysis_id == expected_analysis_id


def test_reordered_equivalent_input_has_identical_policy_output():
    chain = _build_chain()
    reordered = chain.model_copy(
        update={
            "derived_facts": list(reversed(chain.derived_facts)),
            "protocol_events": list(reversed(chain.protocol_events)),
            "evidence": list(reversed(chain.evidence)),
        }
    )
    assert_chain_valid(reordered)

    first = evaluate_default_policy(chain, context=_context(chain))
    second = evaluate_default_policy(reordered, context=_context(reordered))

    assert first.findings[0].fact_ids == sorted(first.findings[0].fact_ids)
    assert first.findings[0].stable_finding_key == second.findings[0].stable_finding_key
    assert first.findings[0].finding_id == second.findings[0].finding_id
    assert _policy_output(first) == _policy_output(second)


def test_repeat_evaluation_is_idempotent():
    chain = _build_chain()
    context = _context(chain)
    first = evaluate_default_policy(chain, context=context)

    second = evaluate_default_policy(first, context=context)

    assert _canonical_chain(first) == _canonical_chain(second)


@pytest.mark.parametrize(
    ("updates", "message"),
    [
        ({"profile_id": "missing-profile"}, "not found"),
        ({"base_configuration_digest": "d" * 64}, "base_configuration_digest"),
        (
            {"evaluated_at": datetime(2026, 8, 27, 9, 58, 0, tzinfo=UTC)},
            "evaluated_at",
        ),
    ],
)
def test_invalid_context_inputs_raise_typed_policy_errors(updates, message):
    chain = _build_chain()
    context = _context(chain, **updates)
    with pytest.raises(PolicyContextError) as exc:
        evaluate_default_policy(chain, context=context)

    assert exc.value.code is ChainErrorCode.POLICY_CONTEXT_INVALID
    assert message in str(exc.value)


def test_boolean_candidate_is_not_numeric_for_greater_than():
    chain = _replace_fact(
        _build_chain(),
        "plaintext_commands_after_offer",
        value=True,
    )

    evaluated = evaluate_default_policy(chain, context=_context(chain))

    assert evaluated.rule_evaluations[0].outcome is RuleOutcome.INSUFFICIENT_EVIDENCE
    assert evaluated.findings == []


def test_smtp_no_attacker_limitation_is_rule_specific():
    chain = _build_chain()
    default = load_default_policy_pack()
    custom = _rule(default.rules[0], rule_id="TEST-CUSTOM-RULE-001")
    pack = _pack(rules=[custom])

    default_result = evaluate_default_policy(chain, context=_context(chain))
    custom_result = evaluate_policy(chain, pack=pack, context=_context(chain))

    assert default_result.findings[0].limitations[0].detail == "no_attacker_attribution"
    assert custom_result.findings[0].limitations == []
