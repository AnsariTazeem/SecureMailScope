"""Commit 3 fact derivation: deterministic SMTP transition facts.

This module implements spec §7.1 / §21 "Commit 3 — State and facts": a pure,
deterministic function that derives the SMTP STARTTLS transition facts from the
ordered, evidence-backed protocol events of a :class:`ChainOfProof` document.
It never touches packet captures or the analyzer; every emitted
:class:`~securemailscope.chain.models.DerivedFact` references only the chain's
own events and satisfies the graph invariants enforced by
:func:`securemailscope.chain.invariants.assert_chain_valid`.

Rules (all deterministic, conservative, and evidence-sourced):

Only **directly observed** SMTP protocol events can support a fact: an event
must have ``protocol == smtp``, ``event_status == observed``,
``observability == observed``, and non-empty ``evidence_ids``. Inferred,
derived, not-observable, incomplete-capture, or non-SMTP events never support
any fact or confidence claim.

* ``starttls_advertised`` (``chain.smtp.starttls.advertised``): ``true`` when
  at least one observed ``CAPABILITY_ADVERTISED`` event exists. It is never set
  to ``false`` from the absence of an advertisement.
* ``plaintext_commands_after_offer``
  (``chain.smtp.starttls.plaintext_count``): the exact count of observed
  ``PLAINTEXT_COMMAND_AFTER_TLS_OFFER`` events that occur strictly after an
  observed ``CAPABILITY_ADVERTISED`` event. A plaintext command that precedes
  every advertisement is never counted. It is only emitted when the count is
  positive; no zero value is invented from absence.
* ``tls_upgrade_completed`` (``chain.smtp.starttls.completed``): decided by an
  ordered scan of the observed SMTP events, never by global min/max. A
  ``TLS_UPGRADE_REQUESTED`` starts a pending attempt (replacing any previous
  pending request); a ``TLS_UPGRADE_ACCEPTED`` binds only to the immediately
  preceding pending request; a ``TLS_UPGRADE_REJECTED`` likewise binds only to
  the immediately preceding pending request; a ``HANDSHAKE_FINISHED`` completes
  only the currently bound accept pair. The decision, in priority order:
  * ``true`` only from an exact ordered request ``<`` accept ``<`` finished
    transition of one attempt, selected deterministically as the earliest
    completed attempt; the sources are exactly that triple.
  * ``false`` from the earliest exact request ``<`` reject pair (unconditional,
    even under capture truncation); sources are exactly that pair.
  * ``false`` from an accepted request pair followed by qualifying plaintext
    (accept ``<`` plaintext) with no handshake finish in a capture that was not
    ``capture_incomplete``; sources are exactly that request, that acceptance,
    and the qualifying plaintext after it.
  * ``false`` from qualifying plaintext strictly after an observed
    advertisement with no request, reject, or accept in a capture that was not
    ``capture_incomplete``; sources are exactly that advertisement and the
    qualifying plaintext after it. Handshake events alone never trigger this or
    any other completion decision.
  * ``incomplete_capture`` / ``unknown_insufficient_evidence`` when positive
    transition evidence exists but the state cannot be decided; the label
    depends on whether the session's capture was incomplete.
  * It is **not emitted at all** when no qualifying positive transition
    evidence exists, so an advertised-but-silent session does not fabricate a
    conclusion.

Facts owned by this derivation (identified by their ``derivation_id``) are
dropped and recomputed deterministically, so derivation is idempotent; facts
originating from other derivations are preserved byte-for-byte.
"""

from __future__ import annotations

from securemailscope.chain.canonical import canonical_json
from securemailscope.chain.enums import (
    ChainObservability,
    ConfidenceLevel,
    EventStatus,
    LimitationCode,
    ProtocolEventType,
)
from securemailscope.chain.ids import fact_id_from_key, fact_stable_key
from securemailscope.chain.invariants import assert_chain_valid
from securemailscope.chain.models import (
    AnalysisLimitation,
    ChainOfProof,
    DerivedFact,
    ProtocolEvent,
    Session,
)
from securemailscope.models import CompleteStatus, Protocol

DERIVATION_VERSION = "1.0.0"

FACT_TYPE_STARTTLS_ADVERTISED = "starttls_advertised"
FACT_TYPE_TLS_UPGRADE_COMPLETED = "tls_upgrade_completed"
FACT_TYPE_PLAINTEXT_COMMANDS_AFTER_OFFER = "plaintext_commands_after_offer"

DERIVATION_STARTTLS_ADVERTISED = "chain.smtp.starttls.advertised"
DERIVATION_TLS_UPGRADE_COMPLETED = "chain.smtp.starttls.completed"
DERIVATION_PLAINTEXT_COMMANDS_AFTER_OFFER = "chain.smtp.starttls.plaintext_count"

_OWNED_DERIVATIONS: frozenset[str] = frozenset(
    {
        DERIVATION_STARTTLS_ADVERTISED,
        DERIVATION_TLS_UPGRADE_COMPLETED,
        DERIVATION_PLAINTEXT_COMMANDS_AFTER_OFFER,
    }
)

_CONFIDENCE_BASIS_ADVERTISED = ("ordered_starttls_capability_advertisement",)
_CONFIDENCE_BASIS_PLAINTEXT = ("ordered_plaintext_command_after_offer",)
_CONFIDENCE_BASIS_COMPLETED = ("ordered_starttls_acceptance_and_handshake_finished",)
_CONFIDENCE_BASIS_REJECTED = ("ordered_starttls_rejection",)
_CONFIDENCE_BASIS_ACCEPTED_PLAINTEXT = ("accepted_upgrade_followed_by_observed_plaintext",)
_CONFIDENCE_BASIS_PLAINTEXT_CONTINUATION = ("ordered_plaintext_continuation_before_tls_completion",)
_CONFIDENCE_BASIS_INCOMPLETE_CAPTURE = ("capture_ended_before_tls_transition_completion",)
_CONFIDENCE_BASIS_INSUFFICIENT = ("insufficient_ordered_evidence_for_tls_completion",)

_INCOMPLETE_CAPTURE_SUMMARY = "capture ended before the SMTP STARTTLS transition could complete"
_INSUFFICIENT_EVIDENCE_SUMMARY = (
    "insufficient ordered evidence to determine whether the SMTP STARTTLS transition completed"
)

#: Evidence-backed event types that constitute positive transition evidence. A
#: bare ``CAPABILITY_ADVERTISED`` is deliberately excluded: the offer alone
#: says nothing about a completion decision. Handshake event types
#: (``CLIENT_HELLO``, ``SERVER_HELLO``, ``CERTIFICATE_MESSAGE``,
#: ``KEY_EXCHANGE_OBSERVED``, ``HANDSHAKE_FINISHED``,
#: ``ENCRYPTED_APPLICATION_DATA``) are deliberately excluded too: they only
#: participate in a ``true`` decision as the finished leg of an exact, ordered,
#: observed request ``<`` accept ``<`` finish triple, and never stand alone as
#: positive evidence for ``false``/``unknown``.
_POSITIVE_TRANSITION_EVENT_TYPES: frozenset[ProtocolEventType] = frozenset(
    {
        ProtocolEventType.TLS_UPGRADE_REQUESTED,
        ProtocolEventType.TLS_UPGRADE_ACCEPTED,
        ProtocolEventType.TLS_UPGRADE_REJECTED,
        ProtocolEventType.PLAINTEXT_COMMAND_AFTER_TLS_OFFER,
    }
)


def _is_observed_proof(event: ProtocolEvent) -> bool:
    """True when an event is directly observed SMTP evidence.

    Inferred, derived, not-observable, incomplete-capture, or non-SMTP events
    are never allowed to support a fact or a confidence claim.
    """
    return (
        event.protocol is Protocol.SMTP
        and event.event_status is EventStatus.OBSERVED
        and event.observability is ChainObservability.OBSERVED
        and bool(event.evidence_ids)
    )


def _ordered_event_ids(events: list[ProtocolEvent]) -> list[str]:
    """Event ids in chain sequence order, deduplicated."""
    seen: set[str] = set()
    ordered: list[str] = []
    for event in sorted(events, key=lambda event: event.sequence_index):
        if event.event_id in seen:
            continue
        seen.add(event.event_id)
        ordered.append(event.event_id)
    return ordered


def _make_fact(
    *,
    chain_schema_version: str,
    session: Session,
    fact_type: str,
    value: object,
    derivation_id: str,
    source_event_ids: list[str],
    observability: ChainObservability,
    confidence: ConfidenceLevel,
    confidence_basis: tuple[str, ...],
    limitations: list[AnalysisLimitation],
) -> DerivedFact:
    normalized = canonical_json(value)
    stable_key = fact_stable_key(
        chain_schema_version,
        session.stable_session_key,
        fact_type,
        normalized,
        source_event_ids,
        [],
        [],
    )
    return DerivedFact(
        fact_id=fact_id_from_key(stable_key),
        session_id=session.session_id,
        fact_type=fact_type,
        value=value,
        derivation_id=derivation_id,
        derivation_version=DERIVATION_VERSION,
        source_event_ids=source_event_ids,
        source_observation_ids=[],
        source_fact_ids=[],
        observability=observability,
        confidence_level=confidence,
        confidence_basis=list(confidence_basis),
        limitations=limitations,
    )


def _session_capture_incomplete(session: Session) -> bool:
    if session.capture_completeness is CompleteStatus.CAPTURE_INCOMPLETE:
        return True
    return any(
        limitation.code is LimitationCode.CAPTURE_INCOMPLETE for limitation in session.limitations
    )


def _fact_starttls_advertised(
    *,
    chain_schema_version: str,
    session: Session,
    events: list[ProtocolEvent],
) -> DerivedFact:
    return _make_fact(
        chain_schema_version=chain_schema_version,
        session=session,
        fact_type=FACT_TYPE_STARTTLS_ADVERTISED,
        value=True,
        derivation_id=DERIVATION_STARTTLS_ADVERTISED,
        source_event_ids=_ordered_event_ids(events),
        observability=ChainObservability.DERIVED,
        confidence=ConfidenceLevel.HIGH,
        confidence_basis=_CONFIDENCE_BASIS_ADVERTISED,
        limitations=[],
    )


def _fact_plaintext_commands_after_offer(
    *,
    chain_schema_version: str,
    session: Session,
    events: list[ProtocolEvent],
) -> DerivedFact:
    return _make_fact(
        chain_schema_version=chain_schema_version,
        session=session,
        fact_type=FACT_TYPE_PLAINTEXT_COMMANDS_AFTER_OFFER,
        value=len(events),
        derivation_id=DERIVATION_PLAINTEXT_COMMANDS_AFTER_OFFER,
        source_event_ids=_ordered_event_ids(events),
        observability=ChainObservability.DERIVED,
        confidence=ConfidenceLevel.HIGH,
        confidence_basis=_CONFIDENCE_BASIS_PLAINTEXT,
        limitations=[],
    )


def _scan_ordered_attempts(
    events: list[ProtocolEvent],
) -> tuple[
    list[tuple[ProtocolEvent, ProtocolEvent, ProtocolEvent]],
    list[tuple[ProtocolEvent, ProtocolEvent]],
    list[tuple[ProtocolEvent, ProtocolEvent]],
]:
    """Deterministically bind observed requests, responses, and finishes.

    Returns ``(completed_triples, rejected_pairs, accepted_pairs)`` in chain
    order. A request starts (or replaces) the pending attempt; an acceptance or
    rejection binds only to the immediately preceding pending request; a
    finished event completes only the currently bound accept pair — never an
    earlier or later pair, and an accept/reject is never paired with a later
    request.
    """
    completed: list[tuple[ProtocolEvent, ProtocolEvent, ProtocolEvent]] = []
    rejected: list[tuple[ProtocolEvent, ProtocolEvent]] = []
    accepted: list[tuple[ProtocolEvent, ProtocolEvent]] = []
    pending_request: ProtocolEvent | None = None
    active_pair: tuple[ProtocolEvent, ProtocolEvent] | None = None
    for event in events:
        kind = event.event_type
        if kind is ProtocolEventType.TLS_UPGRADE_REQUESTED:
            pending_request = event
            active_pair = None
        elif kind is ProtocolEventType.TLS_UPGRADE_ACCEPTED:
            if pending_request is not None and active_pair is None:
                active_pair = (pending_request, event)
                accepted.append(active_pair)
                pending_request = None
        elif kind is ProtocolEventType.TLS_UPGRADE_REJECTED:
            if pending_request is not None and active_pair is None:
                rejected.append((pending_request, event))
                pending_request = None
        elif kind is ProtocolEventType.HANDSHAKE_FINISHED:
            if active_pair is not None:
                completed.append((active_pair[0], active_pair[1], event))
                active_pair = None
    return completed, rejected, accepted


def _first_completed(
    triples: list[tuple[ProtocolEvent, ProtocolEvent, ProtocolEvent]],
) -> tuple[ProtocolEvent, ProtocolEvent, ProtocolEvent]:
    """Earliest completed attempt by its terminal (finished) event sequence,
    with sequence_index tie-breaking."""
    return min(
        triples,
        key=lambda triple: (
            triple[2].sequence_index,
            triple[0].sequence_index,
            triple[1].sequence_index,
        ),
    )


def _first_rejected(
    rejected: list[tuple[ProtocolEvent, ProtocolEvent]],
) -> tuple[ProtocolEvent, ProtocolEvent]:
    """Earliest rejected pair by its terminal (rejection) event sequence, with
    the request sequence as tie-breaker."""
    return min(
        rejected,
        key=lambda pair: (pair[1].sequence_index, pair[0].sequence_index),
    )


def _tls_upgrade_completed_fact(
    *,
    chain_schema_version: str,
    session: Session,
    events: list[ProtocolEvent],
) -> DerivedFact | None:
    """Decide the ``tls_upgrade_completed`` fact from ordered event evidence."""
    by_type: dict[ProtocolEventType, list[ProtocolEvent]] = {}
    for event in events:
        by_type.setdefault(event.event_type, []).append(event)

    advertised = by_type.get(ProtocolEventType.CAPABILITY_ADVERTISED, [])
    plaintext = by_type.get(ProtocolEventType.PLAINTEXT_COMMAND_AFTER_TLS_OFFER, [])
    qualifying_plaintext = [
        command
        for command in plaintext
        if any(ad.sequence_index < command.sequence_index for ad in advertised)
    ]
    qualifying_indexes = {command.sequence_index for command in qualifying_plaintext}

    triples, rejected, accepted = _scan_ordered_attempts(events)

    if triples:
        requested, accepted_event, finished = _first_completed(triples)
        return _make_fact(
            chain_schema_version=chain_schema_version,
            session=session,
            fact_type=FACT_TYPE_TLS_UPGRADE_COMPLETED,
            value=True,
            derivation_id=DERIVATION_TLS_UPGRADE_COMPLETED,
            source_event_ids=_ordered_event_ids([requested, accepted_event, finished]),
            observability=ChainObservability.DERIVED,
            confidence=ConfidenceLevel.HIGH,
            confidence_basis=_CONFIDENCE_BASIS_COMPLETED,
            limitations=[],
        )

    if rejected:
        requested, rejected_event = _first_rejected(rejected)
        return _make_fact(
            chain_schema_version=chain_schema_version,
            session=session,
            fact_type=FACT_TYPE_TLS_UPGRADE_COMPLETED,
            value=False,
            derivation_id=DERIVATION_TLS_UPGRADE_COMPLETED,
            source_event_ids=_ordered_event_ids([requested, rejected_event]),
            observability=ChainObservability.DERIVED,
            confidence=ConfidenceLevel.HIGH,
            confidence_basis=_CONFIDENCE_BASIS_REJECTED,
            limitations=[],
        )

    if not _session_capture_incomplete(session):
        accepted_paired = [
            pair
            for pair in accepted
            if any(
                pair[1].sequence_index < command.sequence_index for command in qualifying_plaintext
            )
        ]
        if accepted_paired:
            requested, accepted_event = min(
                accepted_paired,
                key=lambda pair: (pair[1].sequence_index, pair[0].sequence_index),
            )
            after_accept = [
                command
                for command in qualifying_plaintext
                if command.sequence_index > accepted_event.sequence_index
            ]
            return _make_fact(
                chain_schema_version=chain_schema_version,
                session=session,
                fact_type=FACT_TYPE_TLS_UPGRADE_COMPLETED,
                value=False,
                derivation_id=DERIVATION_TLS_UPGRADE_COMPLETED,
                source_event_ids=_ordered_event_ids([requested, accepted_event] + after_accept),
                observability=ChainObservability.DERIVED,
                confidence=ConfidenceLevel.HIGH,
                confidence_basis=_CONFIDENCE_BASIS_ACCEPTED_PLAINTEXT,
                limitations=[],
            )

        if advertised and qualifying_plaintext:
            earliest_ad = min(advertised, key=lambda ad: ad.sequence_index)
            after_offer = [
                command
                for command in qualifying_plaintext
                if command.sequence_index > earliest_ad.sequence_index
            ]
            return _make_fact(
                chain_schema_version=chain_schema_version,
                session=session,
                fact_type=FACT_TYPE_TLS_UPGRADE_COMPLETED,
                value=False,
                derivation_id=DERIVATION_TLS_UPGRADE_COMPLETED,
                source_event_ids=_ordered_event_ids([earliest_ad] + after_offer),
                observability=ChainObservability.DERIVED,
                confidence=ConfidenceLevel.HIGH,
                confidence_basis=_CONFIDENCE_BASIS_PLAINTEXT_CONTINUATION,
                limitations=[],
            )

    positive = [
        event
        for event in events
        if event.event_type in _POSITIVE_TRANSITION_EVENT_TYPES
        and (
            event.event_type is not ProtocolEventType.PLAINTEXT_COMMAND_AFTER_TLS_OFFER
            or event.sequence_index in qualifying_indexes
        )
    ]
    if not positive:
        return None
    source_event_ids = _ordered_event_ids(positive)
    if _session_capture_incomplete(session):
        return _make_fact(
            chain_schema_version=chain_schema_version,
            session=session,
            fact_type=FACT_TYPE_TLS_UPGRADE_COMPLETED,
            value="incomplete_capture",
            derivation_id=DERIVATION_TLS_UPGRADE_COMPLETED,
            source_event_ids=source_event_ids,
            observability=ChainObservability.INCOMPLETE_CAPTURE,
            confidence=ConfidenceLevel.NOT_SCORED,
            confidence_basis=_CONFIDENCE_BASIS_INCOMPLETE_CAPTURE,
            limitations=[
                AnalysisLimitation(
                    code=LimitationCode.CAPTURE_INCOMPLETE,
                    summary=_INCOMPLETE_CAPTURE_SUMMARY,
                )
            ],
        )
    return _make_fact(
        chain_schema_version=chain_schema_version,
        session=session,
        fact_type=FACT_TYPE_TLS_UPGRADE_COMPLETED,
        value="unknown_insufficient_evidence",
        derivation_id=DERIVATION_TLS_UPGRADE_COMPLETED,
        source_event_ids=source_event_ids,
        observability=ChainObservability.NOT_OBSERVABLE,
        confidence=ConfidenceLevel.NOT_SCORED,
        confidence_basis=_CONFIDENCE_BASIS_INSUFFICIENT,
        limitations=[
            AnalysisLimitation(
                code=LimitationCode.UNKNOWN_INSUFFICIENT_EVIDENCE,
                summary=_INSUFFICIENT_EVIDENCE_SUMMARY,
            )
        ],
    )


def derive_smtp_transition_facts(chain: ChainOfProof) -> ChainOfProof:
    """Return a copy of ``chain`` with SMTP transition facts derived.

    The input chain must already satisfy the graph invariants
    (:func:`~securemailscope.chain.invariants.assert_chain_valid`); it is
    validated fail-closed before any derivation. Facts owned by this derivation
    (matched by ``derivation_id``) are dropped and recomputed deterministically,
    so repeated application is idempotent; facts originating from other
    derivations are preserved byte-for-byte.
    """
    assert_chain_valid(chain)
    schema_version = chain.analysis.chain_schema_version

    events_by_session: dict[str, list[ProtocolEvent]] = {}
    for event in chain.protocol_events:
        events_by_session.setdefault(event.session_id, []).append(event)

    preserved_facts = [
        fact for fact in chain.derived_facts if fact.derivation_id not in _OWNED_DERIVATIONS
    ]

    session_order = {
        session.session_id: position for position, session in enumerate(chain.sessions)
    }

    derived_facts: list[DerivedFact] = []
    for session in chain.sessions:
        if session.protocol is not Protocol.SMTP:
            continue
        events = sorted(
            (
                event
                for event in events_by_session.get(session.session_id, ())
                if _is_observed_proof(event)
            ),
            key=lambda event: event.sequence_index,
        )
        session_facts: list[DerivedFact] = []
        advertised = [
            event for event in events if event.event_type is ProtocolEventType.CAPABILITY_ADVERTISED
        ]
        if advertised:
            session_facts.append(
                _fact_starttls_advertised(
                    chain_schema_version=schema_version,
                    session=session,
                    events=advertised,
                )
            )
        plaintext = [
            event
            for event in events
            if event.event_type is ProtocolEventType.PLAINTEXT_COMMAND_AFTER_TLS_OFFER
        ]
        qualifying_plaintext = [
            command
            for command in plaintext
            if any(ad.sequence_index < command.sequence_index for ad in advertised)
        ]
        if qualifying_plaintext:
            session_facts.append(
                _fact_plaintext_commands_after_offer(
                    chain_schema_version=schema_version,
                    session=session,
                    events=qualifying_plaintext,
                )
            )
        completed = _tls_upgrade_completed_fact(
            chain_schema_version=schema_version,
            session=session,
            events=events,
        )
        if completed is not None:
            session_facts.append(completed)
        derived_facts.extend(session_facts)

    ordered_facts = sorted(
        derived_facts,
        key=lambda fact: (
            session_order[fact.session_id],
            fact.fact_type,
            canonical_json(fact.value),
            fact.fact_id,
        ),
    )

    updated = chain.model_copy(update={"derived_facts": preserved_facts + ordered_facts})
    assert_chain_valid(updated)
    return updated
