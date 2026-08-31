"""Deterministic policy evaluation engine (Commit 4).

Implements the pure, atomic policy evaluation that produces RuleEvaluation,
Finding, Recommendation, and PolicyRiskSummary outputs from a ChainOfProof
and a versioned PolicyPack. All behavior is deterministic and idempotent.
"""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from dataclasses import dataclass
from decimal import ROUND_HALF_UP, Decimal
from math import isfinite
from typing import Any

from securemailscope.chain.canonical import canonical_json
from securemailscope.chain.enums import (
    ChainObservability,
    ConfidenceLevel,
    EngineStatus,
    EventStatus,
    LimitationCode,
    ProtocolEventType,
    RuleOutcome,
    RuleReasonCode,
)
from securemailscope.chain.errors import PolicyContextError, PolicyEvaluationError
from securemailscope.chain.ids import (
    compact_id,
    finding_id_from_key,
    finding_stable_key,
    policy_contribution_id,
    policy_risk_id,
    rule_evaluation_id,
)
from securemailscope.chain.invariants import assert_chain_valid
from securemailscope.chain.models import (
    POLICY_RISK_CAP,
    AnalysisLimitation,
    ChainOfProof,
    DerivedFact,
    Finding,
    PolicyRiskContribution,
    PolicyRiskSummary,
    Recommendation,
    RuleEvaluation,
    Session,
)
from securemailscope.chain.policy.loader import (
    canonical_policy_pack_digest,
    load_default_policy_pack,
)
from securemailscope.chain.policy.models import (
    FactRequirement,
    PolicyEvaluationContext,
    PolicyEvidenceRequirement,
    PolicyPack,
    PolicyProfile,
    PolicyRule,
)

# ─────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class _RequirementResult:
    state: str  # TRUE, FALSE, UNKNOWN
    candidate_ids: list[str]
    snapshot_value: Any
    reason: str


def _assert_valid_input(
    chain: ChainOfProof,
    pack: PolicyPack,
    context: PolicyEvaluationContext,
) -> None:
    assert_chain_valid(chain)
    if len(chain.captures) != 1:
        raise PolicyEvaluationError("policy evaluation requires exactly one capture")
    if chain.artifacts:
        raise PolicyEvaluationError("chain must not contain artifacts before policy evaluation")
    # Validate profile exists
    profile = next((p for p in pack.profiles if p.profile_id == context.profile_id), None)
    if profile is None:
        raise PolicyContextError(f"profile {context.profile_id!r} not found in policy pack")
    # Validate base_configuration_digest matches when rule_engine_status is NOT_RUN
    if chain.analysis.rule_engine_status is EngineStatus.NOT_RUN:
        if context.base_configuration_digest != chain.analysis.configuration_digest:
            raise PolicyContextError(
                "base_configuration_digest must equal chain.analysis.configuration_digest "
                "when rule_engine_status is NOT_RUN",
            )
    # Validate timestamp ordering
    if context.evaluated_at < chain.analysis.created_at:
        raise PolicyContextError("evaluated_at must not be before analysis.created_at")
    if context.evaluated_at < chain.analysis.started_at:
        raise PolicyContextError("evaluated_at must not be before analysis.started_at")
    if chain.analysis.completed_at and context.evaluated_at < chain.analysis.completed_at:
        raise PolicyContextError("evaluated_at must not be before existing analysis.completed_at")


def _compute_effective_configuration_digest(
    base_configuration_digest: str,
    pack: PolicyPack,
    profile_id: str,
) -> str:
    """Compute effective configuration digest per frozen design."""
    payload = {
        "kind": "securemailscope.policy.configuration.v1",
        "base_configuration_digest": base_configuration_digest,
        "policy_pack_digest": canonical_policy_pack_digest(pack),
        "profile_id": profile_id,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _recompute_analysis_id(
    chain: ChainOfProof,
    effective_digest: str,
    pack: PolicyPack,
) -> str:
    """Recompute analysis_id with policy pack identity."""
    capture = chain.captures[0]
    return compact_id(
        "ana",
        "analysis",
        chain.analysis.chain_schema_version,
        capture.sha256,
        effective_digest,
        chain.analysis.analyzer_version,
        pack.pack_id,
        pack.version,
        chain.analysis.model_id or "",
        chain.analysis.model_version or "",
    )


def _resolve_facts_for_session(
    session: Session,
    chain: ChainOfProof,
    rule: PolicyRule,
) -> dict[str, list[DerivedFact]]:
    """Collect all candidate facts for each required fact type in the session."""
    candidates_by_type: dict[str, list[DerivedFact]] = defaultdict(list)
    for fact in chain.derived_facts:
        if fact.session_id != session.session_id:
            continue
        for req in rule.requires:
            if fact.fact_type == req.fact:
                candidates_by_type[req.fact].append(fact)
    return candidates_by_type


def _evaluate_requirement(
    req: FactRequirement,
    candidates: list[DerivedFact],
) -> _RequirementResult:
    """Evaluate a single fact requirement against candidates."""
    if not candidates:
        return _RequirementResult(
            state="UNKNOWN",
            candidate_ids=[],
            snapshot_value=None,
            reason="no candidates",
        )

    # Sort candidates by fact_id for deterministic ordering
    candidates = sorted(candidates, key=lambda fact: fact.fact_id)

    # Check observability and value for each candidate
    valid_values = []
    valid_ids = []
    for fact in candidates:
        # Absence/unknown/incomplete/not-applicable -> UNKNOWN for policy matching
        if fact.observability in (
            ChainObservability.NOT_OBSERVABLE,
            ChainObservability.INCOMPLETE_CAPTURE,
            ChainObservability.SESSION_SECRETS_REQUIRED,
            ChainObservability.NOT_APPLICABLE,
        ):
            continue
        # Explicit string states
        val = fact.value
        if isinstance(val, str) and val in ("incomplete_capture", "unknown_insufficient_evidence"):
            continue
        # Wrong type -> UNKNOWN
        if req.operator == "greater_than" and not _is_finite_number(val):
            continue
        if req.operator == "equals" and not _is_json_scalar(val):
            continue
        valid_values.append(val)
        valid_ids.append(fact.fact_id)

    if not valid_values:
        return _RequirementResult(
            state="UNKNOWN",
            candidate_ids=[fact.fact_id for fact in candidates],
            snapshot_value=None,
            reason="no valid candidates",
        )

    # Check for conflicts
    distinct_values = set()
    for v in valid_values:
        distinct_values.add(_canonical_value(v))
    if len(distinct_values) > 1:
        return _RequirementResult(
            state="UNKNOWN",
            candidate_ids=valid_ids,
            snapshot_value=sorted(distinct_values, key=str),
            reason="conflicting values",
        )

    # Single distinct value - evaluate operator
    value = valid_values[0]
    if req.operator == "equals":
        matched = _json_scalar_equals(value, req.value)
        return _RequirementResult(
            state="TRUE" if matched else "FALSE",
            candidate_ids=valid_ids,
            snapshot_value=value,
            reason="equals",
        )
    elif req.operator == "greater_than":
        if not _is_finite_number(value) or not _is_finite_number(req.value):
            return _RequirementResult(
                state="UNKNOWN",
                candidate_ids=valid_ids,
                snapshot_value=value,
                reason="type mismatch for greater_than",
            )
        matched = value > req.value
        return _RequirementResult(
            state="TRUE" if matched else "FALSE",
            candidate_ids=valid_ids,
            snapshot_value=value,
            reason="greater_than",
        )

    return _RequirementResult(
        state="UNKNOWN",
        candidate_ids=valid_ids,
        snapshot_value=value,
        reason="unsupported operator",
    )


def _is_json_scalar(val: Any) -> bool:
    if val is None:
        return True
    if isinstance(val, bool):
        return True
    if isinstance(val, int):
        return True
    if isinstance(val, float):
        return isfinite(val)
    if isinstance(val, str):
        return True
    return False


def _is_finite_number(val: Any) -> bool:
    if isinstance(val, bool):
        return False
    if isinstance(val, int):
        return True
    if isinstance(val, float):
        return isfinite(val)
    return False


def _canonical_value(val: Any) -> str:
    return canonical_json(val)


def _json_scalar_equals(a: Any, b: Any) -> bool:
    # Strict JSON scalar equality: bool != int, etc.
    if type(a) is not type(b):
        return False
    if isinstance(a, float) and isinstance(b, float):
        if a != a or b != b:  # NaN
            return False
    return a == b


def _determine_outcome(
    rule: PolicyRule,
    session: Session,
    results: list[_RequirementResult],
) -> tuple[RuleOutcome, RuleReasonCode, str]:
    """Determine rule outcome from requirement results."""
    # Protocol not supported
    if session.protocol not in rule.protocols:
        return (
            RuleOutcome.NOT_APPLICABLE,
            RuleReasonCode.NOT_APPLICABLE_PROTOCOL,
            "protocol not supported",
        )

    # Suppressed by profile (handled at engine level, but double-check)
    # This is checked before calling _determine_outcome

    # If any requirement is definitively FALSE -> NOT_MATCHED
    for res in results:
        if res.state == "FALSE":
            return RuleOutcome.NOT_MATCHED, RuleReasonCode.RULE_NOT_MATCHED, "requirement false"

    # All TRUE -> check evidence
    all_true = all(res.state == "TRUE" for res in results)
    if all_true:
        # Evidence check deferred to finding construction
        return RuleOutcome.MATCHED, RuleReasonCode.RULE_MATCHED, "all requirements true"

    # Otherwise -> INSUFFICIENT_EVIDENCE
    # Determine specific reason
    has_missing = any(res.state == "UNKNOWN" and not res.candidate_ids for res in results)
    if has_missing:
        return RuleOutcome.INSUFFICIENT_EVIDENCE, RuleReasonCode.FACTS_MISSING, "facts missing"
    return (
        RuleOutcome.INSUFFICIENT_EVIDENCE,
        RuleReasonCode.EVIDENCE_INCOMPLETE,
        "evidence incomplete",
    )


def _resolve_evidence(
    chain: ChainOfProof,
    session: Session,
    rule: PolicyRule,
    requirement_results: list[_RequirementResult],
) -> tuple[list[str], bool]:
    """Resolve mandatory evidence for a matched evaluation.

    Returns (evidence_ids, evidence_complete).
    """
    # Map evidence requirement -> event type
    ev_req_map = {
        PolicyEvidenceRequirement(
            "starttls_advertisement"
        ): ProtocolEventType.CAPABILITY_ADVERTISED,
        PolicyEvidenceRequirement(
            "plaintext_command_after_offer"
        ): ProtocolEventType.PLAINTEXT_COMMAND_AFTER_TLS_OFFER,
    }

    events = {event.event_id: event for event in chain.protocol_events}
    observations = {
        observation.observation_id: observation for observation in chain.crypto_observations
    }
    facts = {fact.fact_id: fact for fact in chain.derived_facts}
    evidence = {item.evidence_id: item for item in chain.evidence}
    evidence_ids: set[str] = set()
    lineage_event_ids: set[str] = set()
    visited_observations: set[str] = set()
    visited_facts: set[str] = set()
    active_facts: set[str] = set()

    def add_evidence(evidence_id: str) -> None:
        item = evidence.get(evidence_id)
        if item is not None and item.session_id == session.session_id:
            evidence_ids.add(evidence_id)

    def traverse_event(event_id: str) -> None:
        event = events.get(event_id)
        if event is None or event.session_id != session.session_id:
            return
        lineage_event_ids.add(event_id)
        for evidence_id in event.evidence_ids:
            add_evidence(evidence_id)

    def traverse_observation(observation_id: str) -> None:
        if observation_id in visited_observations:
            return
        observation = observations.get(observation_id)
        if observation is None or observation.session_id != session.session_id:
            return
        visited_observations.add(observation_id)
        for evidence_id in observation.evidence_ids:
            add_evidence(evidence_id)

    def traverse_fact(fact_id: str) -> None:
        if fact_id in active_facts or fact_id in visited_facts:
            return
        fact = facts.get(fact_id)
        if fact is None or fact.session_id != session.session_id:
            return
        active_facts.add(fact_id)
        for event_id in fact.source_event_ids:
            traverse_event(event_id)
        for observation_id in fact.source_observation_ids:
            traverse_observation(observation_id)
        for source_fact_id in fact.source_fact_ids:
            traverse_fact(source_fact_id)
        active_facts.remove(fact_id)
        visited_facts.add(fact_id)

    for result in requirement_results:
        for candidate_id in result.candidate_ids:
            traverse_fact(candidate_id)

    # Check mandatory evidence requirements
    evidence_complete = True
    for ev_req in rule.evidence_requirements:
        required_event_type = ev_req_map.get(ev_req)
        if not required_event_type:
            evidence_complete = False
            continue
        requirement_satisfied = False
        for event_id in sorted(lineage_event_ids):
            event = events[event_id]
            if (
                event.event_type is required_event_type
                and event.event_status is EventStatus.OBSERVED
                and event.observability == ChainObservability.OBSERVED
            ):
                resolved_ids = [
                    evidence_id
                    for evidence_id in event.evidence_ids
                    if evidence_id in evidence
                    and evidence[evidence_id].session_id == session.session_id
                ]
                if resolved_ids:
                    evidence_ids.update(resolved_ids)
                    requirement_satisfied = True
        if not requirement_satisfied:
            evidence_complete = False

    return sorted(evidence_ids), evidence_complete


def _build_finding(
    chain: ChainOfProof,
    session: Session,
    rule: PolicyRule,
    evaluation: RuleEvaluation,
    context: PolicyEvaluationContext,
    evidence_ids: list[str],
    requirement_results: list[_RequirementResult],
) -> Finding:
    """Construct a Finding from a matched evaluation."""
    # Weakest confidence across all requirement candidates
    all_candidate_facts = []
    for res in requirement_results:
        for cid in res.candidate_ids:
            fact = next((f for f in chain.derived_facts if f.fact_id == cid), None)
            if fact:
                all_candidate_facts.append(fact)

    if all_candidate_facts:
        confidence_order = {
            ConfidenceLevel.NOT_SCORED: 0,
            ConfidenceLevel.LOW: 1,
            ConfidenceLevel.MEDIUM: 2,
            ConfidenceLevel.HIGH: 3,
        }
        weakest = min(all_candidate_facts, key=lambda f: confidence_order[f.confidence_level])
        evidence_confidence = weakest.confidence_level
    else:
        evidence_confidence = ConfidenceLevel.NOT_SCORED

    # Collect all input fact IDs
    fact_ids = []
    for res in requirement_results:
        fact_ids.extend(res.candidate_ids)
    unique_fact_ids = sorted(set(fact_ids))

    # Build stable key and ID
    stable_key = finding_stable_key(
        chain.analysis.chain_schema_version,
        session.stable_session_key,
        rule.rule_id,
        rule.version,
        unique_fact_ids,
    )
    finding_id = finding_id_from_key(stable_key)

    limitations = []
    if rule.rule_id == "SMS-SMTP-STARTTLS-001":
        limitations.append(
            AnalysisLimitation(
                code=LimitationCode.UNKNOWN_INSUFFICIENT_EVIDENCE,
                summary=(
                    "The capture proves plaintext continuation after a STARTTLS offer; "
                    "it does not by itself prove an active downgrade attacker"
                ),
                detail="no_attacker_attribution",
            )
        )

    return Finding(
        finding_id=finding_id,
        stable_finding_key=stable_key,
        analysis_id=chain.analysis.analysis_id,  # will be updated after
        session_id=session.session_id,
        rule_evaluation_id=evaluation.evaluation_id,
        rule_id=rule.rule_id,
        rule_version=rule.version,
        title=rule.title,
        category=rule.category,
        severity=rule.severity,
        policy_risk_contribution=rule.policy_risk_contribution,
        evidence_confidence=evidence_confidence,
        observability=ChainObservability.POLICY_INFERRED,
        fact_ids=unique_fact_ids,
        evidence_ids=evidence_ids,
        rationale=rule.rationale,
        impact=rule.impact,
        recommendation_id=rule.recommendation_id,
        standards_references=rule.standards_references,
        limitations=limitations,
        created_at=context.evaluated_at,
    )


def _build_recommendations(
    pack: PolicyPack,
    findings: list[Finding],
) -> list[Recommendation]:
    """Build recommendations from findings, deduplicated by recommendation_id."""
    # Find referenced recommendation templates
    referenced_ids = {f.recommendation_id for f in findings}
    rec_templates = {r.recommendation_id: r for r in pack.recommendations}

    recommendations = []
    for rec_id in sorted(referenced_ids):
        template = rec_templates[rec_id]
        # Find all findings using this recommendation
        affected = [f.finding_id for f in findings if f.recommendation_id == rec_id]

        recommendations.append(
            Recommendation(
                recommendation_id=template.recommendation_id,
                title=template.title,
                summary=template.summary,
                priority=template.priority,
                affected_finding_ids=affected,
                action_steps=template.action_steps,
                verification_steps=template.verification_steps,
                standards_references=template.standards_references,
                scope=template.scope,
                automation_status=template.automation_status,
            )
        )
    return recommendations


def _compute_risk(
    profile: PolicyProfile,
    findings: list[Finding],
    new_analysis_id: str,
) -> PolicyRiskSummary:
    """Compute PolicyRiskSummary from findings."""
    contributions = []
    uncapped = 0
    for finding in findings:
        factor = profile.confidence_factors[finding.evidence_confidence]
        base = Decimal(finding.policy_risk_contribution)
        adjusted = (base * factor).quantize(Decimal("1"), rounding=ROUND_HALF_UP)
        adjusted_int = int(adjusted)
        uncapped += adjusted_int

        contributions.append(
            PolicyRiskContribution(
                contribution_id=policy_contribution_id(
                    finding.finding_id, finding.rule_id, finding.rule_version
                ),
                rule_id=finding.rule_id,
                rule_version=finding.rule_version,
                finding_id=finding.finding_id,
                severity=finding.severity,
                policy_risk_contribution=finding.policy_risk_contribution,
                evidence_confidence=finding.evidence_confidence,
                confidence_factor=float(factor),
                confidence_adjusted_points=adjusted_int,
            )
        )

    capped = min(uncapped, profile.risk_cap, POLICY_RISK_CAP)

    return PolicyRiskSummary(
        policy_risk_id=policy_risk_id(new_analysis_id, profile.profile_id),
        analysis_id=new_analysis_id,
        profile_id=profile.profile_id,
        uncapped_score=uncapped,
        capped_score=capped,
        contributions=contributions,
        limitations=[],
    )


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────


def policy_configuration_digest(
    *,
    base_configuration_digest: str,
    pack: PolicyPack,
    profile_id: str,
) -> str:
    """Compute the effective policy configuration digest."""
    return _compute_effective_configuration_digest(base_configuration_digest, pack, profile_id)


def evaluate_policy(
    chain: ChainOfProof,
    *,
    pack: PolicyPack,
    context: PolicyEvaluationContext,
) -> ChainOfProof:
    """Evaluate policy on a chain, returning a new validated ChainOfProof.

    Atomic replacement: rule_evaluations, findings, policy_risk, recommendations
    are replaced; all other nodes preserved byte-for-byte.
    """
    _assert_valid_input(chain, pack, context)

    profile = next(p for p in pack.profiles if p.profile_id == context.profile_id)

    # Check if rule is suppressed
    suppressed_rules = set(profile.suppressed_rule_ids)

    # Compute effective configuration digest
    effective_digest = _compute_effective_configuration_digest(
        context.base_configuration_digest, pack, context.profile_id
    )

    # Recompute analysis_id
    new_analysis_id = _recompute_analysis_id(chain, effective_digest, pack)

    # Build session order: stable_session_key then session_id
    sessions = sorted(chain.sessions, key=lambda s: (s.stable_session_key, s.session_id))
    # Build rule order: rule_id then version
    rules = sorted(pack.rules, key=lambda r: (r.rule_id, r.version))

    all_evaluations: list[RuleEvaluation] = []
    all_findings: list[Finding] = []
    for session in sessions:
        for rule in rules:
            # Skip non-matching protocols
            if session.protocol not in rule.protocols:
                eval_id = rule_evaluation_id(
                    session.session_id,
                    rule.rule_id,
                    rule.version,
                    profile.profile_id,
                )
                evaluation = RuleEvaluation(
                    evaluation_id=eval_id,
                    session_id=session.session_id,
                    rule_id=rule.rule_id,
                    rule_version=rule.version,
                    profile_id=profile.profile_id,
                    evaluated_at=context.evaluated_at,
                    input_fact_ids=[],
                    input_snapshot={},
                    outcome=RuleOutcome.NOT_APPLICABLE,
                    reason_code=RuleReasonCode.NOT_APPLICABLE_PROTOCOL,
                    generated_finding_id=None,
                )
                all_evaluations.append(evaluation)
                continue

            # Check suppression
            if rule.rule_id in suppressed_rules:
                eval_id = rule_evaluation_id(
                    session.session_id,
                    rule.rule_id,
                    rule.version,
                    profile.profile_id,
                )
                evaluation = RuleEvaluation(
                    evaluation_id=eval_id,
                    session_id=session.session_id,
                    rule_id=rule.rule_id,
                    rule_version=rule.version,
                    profile_id=profile.profile_id,
                    evaluated_at=context.evaluated_at,
                    input_fact_ids=[],
                    input_snapshot={},
                    outcome=RuleOutcome.SUPPRESSED_BY_PROFILE,
                    reason_code=RuleReasonCode.PROFILE_SUPPRESSED,
                    generated_finding_id=None,
                )
                all_evaluations.append(evaluation)
                continue

            # Resolve facts for requirements
            candidates_by_type = _resolve_facts_for_session(session, chain, rule)

            # Evaluate each requirement
            req_results = []
            input_fact_ids = []
            input_snapshot = {}
            for req in rule.requires:
                candidates = candidates_by_type.get(req.fact, [])
                res = _evaluate_requirement(req, candidates)
                req_results.append(res)
                input_fact_ids.extend(res.candidate_ids)
                # Build snapshot: key follows rule requirement order
                if res.snapshot_value is not None:
                    input_snapshot[req.fact] = res.snapshot_value
                # For conflicts, snapshot shows list
                elif isinstance(res.snapshot_value, list):
                    input_snapshot[req.fact] = res.snapshot_value

            unique_input_fact_ids = sorted(set(input_fact_ids))

            # Determine outcome
            outcome, reason_code, _ = _determine_outcome(rule, session, req_results)

            eval_id = rule_evaluation_id(
                session.session_id,
                rule.rule_id,
                rule.version,
                profile.profile_id,
            )
            finding = None

            if outcome == RuleOutcome.MATCHED:
                evidence_ids, evidence_complete = _resolve_evidence(
                    chain,
                    session,
                    rule,
                    req_results,
                )

                if evidence_complete:
                    evaluation = RuleEvaluation(
                        evaluation_id=eval_id,
                        session_id=session.session_id,
                        rule_id=rule.rule_id,
                        rule_version=rule.version,
                        profile_id=profile.profile_id,
                        evaluated_at=context.evaluated_at,
                        input_fact_ids=unique_input_fact_ids,
                        input_snapshot=input_snapshot,
                        outcome=outcome,
                        reason_code=reason_code,
                        generated_finding_id=None,  # set after finding created
                    )
                    # Build finding
                    finding = _build_finding(
                        chain,
                        session,
                        rule,
                        evaluation,
                        context,
                        evidence_ids,
                        req_results,
                    )
                    # Update analysis_id on finding
                    finding = finding.model_copy(update={"analysis_id": new_analysis_id})
                    # Update evaluation with finding ID
                    evaluation = evaluation.model_copy(
                        update={"generated_finding_id": finding.finding_id}
                    )
                    all_findings.append(finding)
                else:
                    # Evidence incomplete -> INSUFFICIENT_EVIDENCE
                    outcome = RuleOutcome.INSUFFICIENT_EVIDENCE
                    reason_code = RuleReasonCode.EVIDENCE_INCOMPLETE
                    evaluation = RuleEvaluation(
                        evaluation_id=eval_id,
                        session_id=session.session_id,
                        rule_id=rule.rule_id,
                        rule_version=rule.version,
                        profile_id=profile.profile_id,
                        evaluated_at=context.evaluated_at,
                        input_fact_ids=unique_input_fact_ids,
                        input_snapshot=input_snapshot,
                        outcome=outcome,
                        reason_code=reason_code,
                        generated_finding_id=None,
                    )
            else:
                evaluation = RuleEvaluation(
                    evaluation_id=eval_id,
                    session_id=session.session_id,
                    rule_id=rule.rule_id,
                    rule_version=rule.version,
                    profile_id=profile.profile_id,
                    evaluated_at=context.evaluated_at,
                    input_fact_ids=unique_input_fact_ids,
                    input_snapshot=input_snapshot,
                    outcome=outcome,
                    reason_code=reason_code,
                    generated_finding_id=None,
                )

            all_evaluations.append(evaluation)

    # Build recommendations from findings
    all_recommendations = _build_recommendations(pack, all_findings)

    # Compute policy risk
    policy_risk = _compute_risk(profile, all_findings, new_analysis_id)

    # Build updated analysis manifest
    new_analysis = chain.analysis.model_copy(
        update={
            "analysis_id": new_analysis_id,
            "configuration_digest": effective_digest,
            "rule_engine_status": EngineStatus.COMPLETE,
            "rule_pack_id": pack.pack_id,
            "rule_pack_version": pack.version,
            "completed_at": context.evaluated_at,
            "limitations": chain.analysis.limitations,  # preserve existing
        }
    )

    # Build new chain with atomic replacement
    updated = chain.model_copy(
        update={
            "analysis": new_analysis,
            "rule_evaluations": all_evaluations,
            "findings": all_findings,
            "policy_risk": policy_risk,
            "recommendations": all_recommendations,
            # Preserve: captures, sessions, evidence, protocol_events,
            # crypto_observations, derived_facts, anomaly_results, execution, artifacts
        }
    )

    assert_chain_valid(updated)
    return updated


def evaluate_default_policy(
    chain: ChainOfProof,
    *,
    context: PolicyEvaluationContext,
) -> ChainOfProof:
    """Convenience wrapper using the checked-in default policy pack."""
    pack = load_default_policy_pack()
    return evaluate_policy(chain, pack=pack, context=context)
