"""Commit 2 adapter: map verified E2/E3A SMTP analysis output into a chain.

This module is the pure, deterministic bridge between the verified analyzer
path (``securemailscope.analyze``) and the frozen Chain-of-Proof contract
(schema ``1.0.0``). It implements the mapping contract of
``docs/CHAIN_OF_PROOF_SPECIFICATION.md`` §21 "Commit 2 — Existing POC adapter":

* capture/session/evidence mapping,
* the current SMTP protocol events reconstructed from the verified SMTP
  STARTTLS transition *and* the independently observed server responses,
* the already-observable TLS-handshake-type evidence (``tls.handshake.type``),
* tool/runtime stage diagnostics and merged, sanitized warnings,
* **no** policy rules, findings, facts, crypto observations, ML anomaly results
  or recommendations (later commits).

Rules of this adapter:

* It is read-only and reproducible. Everything it emits is derived from
  ``analyze.AnalyzeResult`` plus the caller-supplied :class:`PocAdapterContext`;
  no clocks, random values, or live tool invocations are used.
* It never invents evidence. A STARTTLS *request* is only claimed when the
  analyzer proves the complete command (``transition.starttls_command ==
  "STARTTLS\\r\\n"`` with attributable frames); a partial prefix stays an
  incomplete-capture observation. A *response* event is only claimed when the
  actual response frame payload observes ``220`` (acceptance) or ``4xx/5xx``
  (rejection); an unrecognized response produces no synthetic event, and a
  response without a proven complete command is an unmappable shape.
* A *plaintext command after the TLS offer* event is claimed for two cases,
  both only after a ``STARTTLS_CAPABILITY`` server event was observed:
  - an analyzer ``OTHER`` event that resolves to an exact payload line whose
    verb is in the conservative plaintext-command allowlist;
  - a client ``EHLO`` or ``HELO`` event (which the analyzer categorizes as
    ``EHLO``/``HELO``) observed strictly after the advertisement.
  Pre-offer EHLO/HELO remain ``CAPABILITY_REQUEST`` events. DATA message bodies
  and BDAT chunk payloads are never read as commands, lines on partial STARTTLS
  command frames are never read at all, and an unreadable line is silently
  skipped rather than guessed.
* Analysis output that cannot be mapped without guessing raises a typed
  :class:`~securemailscope.chain.errors.ChainAdapterError` (duplicate streams,
  a classification that references a missing stream, an SMTP classification
  without a STARTTLS transition, an accepted or rejected transition without a
  substantiating server response, a stream with no frames, duplicate frame
  numbers, a frame whose ``tcp_stream`` disagrees with its stream, an analyzer
  event that references an unknown frame, a response frame that is not strictly
  after the proven command, ambiguous multiple response frames, an unknown tool
  stage, an empty evidence frame list, or an evidence direction that disagrees
  with the observed frame).
* Capture provenance that is unusable (not ``ok``, malformed sha256) raises
  ``adapter_metadata_required``; adapter-context values that cannot be mapped
  (authorized TLS 1.3 secrets, blank analyzer version, bad configuration
  digest, inverted analysis timestamps) raise ``adapter_input_invalid``.
* Warnings are merged deterministically from the analysis and provenance
  boundaries, deduplicated, stripped of control characters and absolute paths,
  and bounded in length and count.
* Session byte counts come from the TShark-native reassembled byte streams
  (``client_reassembled``/``server_reassembled``), never from summing per-frame
  payloads (retransmissions would double count).
* ``TCP_CONNECTED`` is only emitted when the raw observations prove the ordered
  three-way handshake (client SYN, server SYN+ACK, later client ACK), anchored
  at the final ACK with one exact evidence reference per leg; a lone SYN or an
  incomplete/reordered handshake produces no connection-open proof.
* Every emitted :class:`EvidenceReference` is ``observability=observed`` with a
  numeric-only exact display filter and an empty excerpt; no packet content is
  duplicated into the chain. Multi-frame filters use the exact-set form so an
  unrelated frame between the contributing frames is never selected, and the
  reference direction always agrees with the observed frame direction.
* The resulting :class:`ChainOfProof` is validated with
  :func:`~securemailscope.chain.invariants.assert_chain_valid` before return.

The canonical-content violation rule applies: TLS 1.3 certificate detail is
never fabricated here because the passive POC analyzer supplies no authorized
session secrets and Commit 2 emits no certificate observations at all (a
``tls.handshake.type=11`` observation proves message presence only).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import ROUND_FLOOR, Decimal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator

from securemailscope.chain.enums import (
    AnalysisStatus,
    ChainObservability,
    ConfidenceLevel,
    EngineStatus,
    EventStatus,
    EvidenceRedaction,
    EvidenceSourceKind,
    LimitationCode,
    ProtocolEventType,
    ProtocolState,
    StageId,
    StageStatus,
    Tls13SecretsStatus,
)
from securemailscope.chain.errors import ChainAdapterError, ChainErrorCode
from securemailscope.chain.ids import (
    analysis_id,
    capture_id_from_sha256,
    evidence_id,
    is_sha256_digest,
    protocol_event_id,
    session_id_from_key,
    session_stable_key,
    stable_digest,
)
from securemailscope.chain.invariants import assert_chain_valid
from securemailscope.chain.models import (
    CHAIN_SCHEMA_VERSION,
    SCHEMA_ID,
    AnalysisExecution,
    AnalysisLimitation,
    AnalysisManifest,
    CaptureProvenance,
    ChainOfProof,
    Endpoint,
    EvidenceReference,
    ProtocolEvent,
    Session,
    StageDiagnostic,
)
from securemailscope.models import (
    AnalyzeResult,
    ClassificationStatus,
    CompleteStatus,
    Direction,
    DirectionBasis,
    Protocol,
    ProtocolClassification,
    ProvenanceStatus,
    RawFrameObservation,
    SmtpEvent,
    SmtpEventCategory,
    SmtpTransition,
    TcpStream,
    ToolExecutionRecord,
    TransitionOutcome,
)
from securemailscope.models import CaptureProvenance as PocCaptureProvenance

POC_ADAPTER_VERSION = "1.0.0"

_EXTRACTOR_VERSION = f"poc-adapter/{POC_ADAPTER_VERSION}"

#: Occurrence offset used by the synthetic acceptance/rejection events so they
#: order strictly after every real observed event on the same response frame.
_SYNTHETIC_OCCURRENCE = 100_000

#: The only command form that proves a complete STARTTLS request.
_FULL_STARTTLS_COMMAND = "STARTTLS\r\n"

#: SMTP response semantics applied to the observed response frame payload. The
#: rejection pattern is checked first to match the analyzer's own ordering.
_STARTTLS_ACCEPT_RE = re.compile(rb"^220\b", re.MULTILINE)
_STARTTLS_REJECT_RE = re.compile(rb"^(4[0-9][0-9]|5[0-9][0-9])[ -]", re.MULTILINE)

#: Line splitter identical to the analyzer's own
#: ``securemailscope.sessions._LINE_RE``, so the adapter reads the exact payload
#: line whose index is a category event's ``occurrence``.
_PAYLOAD_LINE_RE = re.compile(rb"[^\r\n]+(?:\r?\n|$)")

#: Evidence token for an observed plaintext SMTP command sent after the
#: STARTTLS offer (advertisement, acceptance, or both).
_PLAINTEXT_EVIDENCE_TOKEN = "smtp:plaintext_command_after_tls_offer"

#: SMTP command verbs that count as observed plaintext commands via ``OTHER``
#: events. The set is conservative: only real command verbs that the passive
#: analysis can observe verbatim are counted. ``STARTTLS``/``EHLO``/``HELO`` lines
#: are categorized by the analyzer and handled separately: pre-offer EHLO/HELO are
#: ``CAPABILITY_REQUEST`` events; post-offer EHLO/HELO become
#: ``PLAINTEXT_COMMAND_AFTER_TLS_OFFER`` events. A verb-less token (for example
#: a bare ``MAILBOX`` line) is never counted.
_PLAINTEXT_VERB_ALLOWLIST = frozenset(
    {
        "AUTH",
        "BDAT",
        "DATA",
        "ETRN",
        "EXPN",
        "HELP",
        "MAIL",
        "NOOP",
        "QUIT",
        "RCPT",
        "RSET",
        "VRFY",
    }
)

#: Stable neutral display name when no usable basename can be derived.
_NEUTRAL_FILENAME = "capture"
_NEUTRAL_TOOL = "tool"
_MAX_FILENAME_LENGTH = 100
_MAX_TOOL_LENGTH = 50

_WARNING_COLLAPSE = re.compile(r"\s+")
#: Every ASCII C0 control character and DEL is normalized to a space before
#: path detection. Deleting a separator such as a tab could concatenate safe
#: prose with a sensitive path, so control characters are replaced rather than
#: removed; the later whitespace collapse cleans the resulting spaces up.
_ASCII_CONTROLS = "".join(chr(code) for code in range(0x20)) + "\x7f"
_CONTROL_TO_SPACE = str.maketrans(_ASCII_CONTROLS, " " * len(_ASCII_CONTROLS))
# Warning sanitization is fail-closed. A filename or directory can contain
# spaces, so the end of an absolute path cannot be separated reliably from any
# trailing prose; the whole path and everything after it is therefore dropped.
# Only the earliest absolute-path *start* is detected, and only the warning
# text that precedes it is preserved. Two zero-width-lookbehind alternatives
# are used:
#   - single-slash POSIX, Windows drive and UNC starts block only a preceding
#     letter, digit, underscore or slash, so a colon is an accepted boundary
#     ("path:/secret", "path:C:\\secret", "path:\\\\server\\share") while the
#     "/" inside "a/b" stays ordinary text; the single-slash branch also
#     requires the next character not to be another slash, so the first slash
#     of "https://..." never matches;
#   - repeated-leading-slash starts (two or more slashes) additionally block a
#     preceding colon, so the "//" of "https://..." is not a local path while
#     "//server/share" still is.
# Every other preceding character (whitespace, "=", opening
# parentheses/brackets/braces, quotes, ordinary punctuation) is a boundary.
# Recognized starts, resolved in a single leftmost (earliest) scan:
#   - POSIX absolute paths, single- and repeated-leading-slash
#                                                              "/secret", "//server/share"
#   - Windows drive paths                                       "C:\secret", "C:/secret"
#   - UNC paths                                                 "\\server\share"
_PATH_START_RE = re.compile(
    r"(?<![A-Za-z0-9_/])(?:[A-Za-z]:[\\/]|\\\\|/(?=[^\s/]))"
    r"|(?<![A-Za-z0-9_/:])/{2,}(?=[^\s/])"
)
_MAX_WARNING_LENGTH = 200
_MAX_WARNINGS = 10
_WARNING_TRUNCATION = " ..."

#: Tool-stage -> chain-stage mapping. Unknown analyzer stages are rejected.
_STAGE_BY_SOURCE: dict[str, StageId] = {
    "intake": StageId.INTAKE,
    "tshark_epochs": StageId.CAPTURE_PROVENANCE,
    "tshark_observe": StageId.EVENT_RECONSTRUCTION,
    "tshark_follow": StageId.STREAM_RECONSTRUCTION,
}

#: A short, bounded summary when a transition could not complete under an
#: incomplete capture. The chain states the observed limit, never a guess.
_CAPTURE_INCOMPLETE_SUMMARY = "capture ended before one or more SMTP STARTTLS transitions completed"
_UNKNOWN_SESSION_SUMMARY = "stream content was insufficient to identify a mail transport protocol"
_INCOMPLETE_TRANSITION_SUMMARY = "insufficient evidence to determine the STARTTLS outcome"
_SECRETS_REJECTED_MESSAGE = "the passive POC adapter never receives TLS session secrets"

_SMTP_TOKEN_BY_CATEGORY: dict[str, str] = {
    "banner": "smtp:banner",
    "ehlo": "smtp:ehlo",
    "helo": "smtp:helo",
    "esmtp_response": "smtp:esmtp_response",
    "starttls_capability": "smtp:starttls_capability",
    "starttls_command": "smtp:starttls_command",
    "foreign_protocol": "smtp:foreign_protocol",
}

_EVENT_TYPE_BY_CATEGORY: dict[SmtpEventCategory, ProtocolEventType] = {
    SmtpEventCategory.BANNER: ProtocolEventType.SERVER_GREETING,
    SmtpEventCategory.EHLO: ProtocolEventType.CAPABILITY_REQUEST,
    SmtpEventCategory.HELO: ProtocolEventType.CAPABILITY_REQUEST,
    SmtpEventCategory.STARTTLS_CAPABILITY: ProtocolEventType.CAPABILITY_ADVERTISED,
    SmtpEventCategory.STARTTLS_COMMAND: ProtocolEventType.TLS_UPGRADE_REQUESTED,
}

#: TLS handshake types already observable in the analyzer output that map to a
#: chain event type. Unmapped handshake types are preserved as evidence but do
#: not produce a chain event (no guess about their meaning is made here); a
#: Certificate handshake-type observation proves message presence only.
_HANDSHAKE_EVENT_BY_TYPE: dict[int, ProtocolEventType] = {
    1: ProtocolEventType.CLIENT_HELLO,
    2: ProtocolEventType.SERVER_HELLO,
    11: ProtocolEventType.CERTIFICATE_MESSAGE,
    12: ProtocolEventType.KEY_EXCHANGE_OBSERVED,
    16: ProtocolEventType.KEY_EXCHANGE_OBSERVED,
    20: ProtocolEventType.HANDSHAKE_FINISHED,
}

_STATE_AFTER: dict[ProtocolEventType, ProtocolState] = {
    ProtocolEventType.TCP_CONNECTED: ProtocolState.CONNECTION_OPEN,
    ProtocolEventType.SERVER_GREETING: ProtocolState.GREETING,
    ProtocolEventType.CAPABILITY_REQUEST: ProtocolState.READY,
    ProtocolEventType.CAPABILITY_ADVERTISED: ProtocolState.TLS_OFFERED,
    ProtocolEventType.TLS_UPGRADE_REQUESTED: ProtocolState.TLS_REQUESTED,
    ProtocolEventType.TLS_UPGRADE_ACCEPTED: ProtocolState.TLS_NEGOTIATING,
    ProtocolEventType.TLS_UPGRADE_REJECTED: ProtocolState.TLS_FAILED,
    ProtocolEventType.CLIENT_HELLO: ProtocolState.TLS_NEGOTIATING,
    ProtocolEventType.SERVER_HELLO: ProtocolState.TLS_NEGOTIATING,
    ProtocolEventType.CERTIFICATE_MESSAGE: ProtocolState.TLS_NEGOTIATING,
    ProtocolEventType.KEY_EXCHANGE_OBSERVED: ProtocolState.TLS_NEGOTIATING,
    ProtocolEventType.HANDSHAKE_FINISHED: ProtocolState.TLS_ACTIVE,
}

_ACCEPTED_OUTCOMES: frozenset[TransitionOutcome] = frozenset(
    {TransitionOutcome.ACCEPTED_TLS, TransitionOutcome.ACCEPTED_WITHOUT_TLS}
)

#: The response status each terminal outcome must be substantiated by.
_EXPECTED_RESPONSE: dict[TransitionOutcome, str] = {
    TransitionOutcome.ACCEPTED_TLS: "accepted",
    TransitionOutcome.ACCEPTED_WITHOUT_TLS: "accepted",
    TransitionOutcome.REJECTED: "rejected",
}


class CaptureMetadata(BaseModel):
    """Capture-level metadata the analyzer does not yet surface as typed facts.

    ``link_layer_types`` comes from independent tool inspection (for example
    capinfos encapsulation lines) and is the authoritative record of the link
    layer the packets were dissected on. It is normalized to an immutable tuple
    (stripped, empty values removed, duplicates collapsed deterministically);
    ordinary list input is accepted by Pydantic and stored as a tuple so
    callers cannot mutate the boundary. ``snaplen`` is the capture snapshot
    length when known; ``truncated_packet_count`` counts explicitly truncated
    packets (``0`` means no truncation was observed, which is a value, not a
    guess).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    link_layer_types: tuple[str, ...] = Field(min_length=1)
    snaplen: int | None = Field(default=None, ge=1)
    truncated_packet_count: int = Field(ge=0)

    @field_validator("link_layer_types")
    @classmethod
    def _normalize_link_layer_types(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        cleaned: list[str] = []
        seen: set[str] = set()
        for value in values:
            item = value.strip()
            if not item or item in seen:
                continue
            seen.add(item)
            cleaned.append(item)
        if not cleaned:
            raise ValueError("link_layer_types must contain at least one non-empty value")
        return tuple(cleaned)


class PocAdapterContext(BaseModel):
    """Caller-supplied, reproducible inputs the POC adapter needs.

    ``source_configuration_digest`` is the caller's own configuration digest
    for the analysis run; the adapter folds it into the reproducible
    ``configuration_digest`` stored in the analysis manifest. ``analyzer_version``
    must be non-blank. Analysis timestamps are reported in the volatile
    execution fields (excluded from canonical content), ordered
    ``created_at <= started_at <= completed_at``.

    ``tls13_authorized_secrets`` is typed with the full :class:`Tls13SecretsStatus`
    enum so a caller that mistakenly supplies ``authorized_supplied`` gets a
    typed :class:`~securemailscope.chain.errors.ChainAdapterError` at build time;
    the passive POC adapter never accepts TLS session secrets.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    capture_metadata: CaptureMetadata
    source_configuration_digest: str
    analyzer_version: str
    created_at: AwareDatetime
    started_at: AwareDatetime
    completed_at: AwareDatetime | None = None
    tls13_authorized_secrets: Tls13SecretsStatus = Tls13SecretsStatus.NOT_SUPPLIED


@dataclass(frozen=True)
class _MappedNodes:
    """Per-stream chain output of the adapter."""

    session: Session
    protocol_events: tuple[ProtocolEvent, ...]
    evidence: tuple[EvidenceReference, ...]
    capture_incomplete: bool


@dataclass(frozen=True)
class _RawEvent:
    """A chain event before state-machine and sequence-index assignment."""

    frame: int
    occurrence: int
    rank: int
    event_type: ProtocolEventType
    direction: Direction
    timestamp: datetime
    evidence_ids: tuple[str, ...]


class _EvidenceRegistry:
    """Append-only, deduplicated evidence builder for one session.

    Evidence identity is deterministic: :func:`evidence_id` derives from the
    capture, session, source kind, source field, normalized value, frame
    numbers, direction and occurrence, so equivalent observations collapse to a
    single reference even when reached from the classification and the
    transition paths separately.

    Every referenced frame must be an observation of the owning stream, and the
    claimed evidence direction must agree with that observation's own
    ``direction``. The adapter never labels a frame ``server_to_client`` merely
    because a transition field calls it a response; the direction is always the
    observed one, and any disagreement is a typed mapping failure.
    """

    def __init__(
        self,
        *,
        capture_id: str,
        capture_sha256: str,
        session_id: str,
        stream_id: int,
        frame_epochs: dict[int, datetime],
        frames_by_number: dict[int, RawFrameObservation],
    ) -> None:
        self._capture_id = capture_id
        self._capture_sha256 = capture_sha256
        self._session_id = session_id
        self._stream_id = stream_id
        self._frame_epochs = frame_epochs
        self._frames_by_number = frames_by_number
        self._entries: dict[tuple, EvidenceReference] = {}

    def add(
        self,
        *,
        source_kind: EvidenceSourceKind,
        source_field: str,
        normalized_value: str,
        frame_numbers: list[int],
        direction: Direction,
        occurrence_index: int,
    ) -> str:
        if not frame_numbers:
            raise ChainAdapterError(
                ChainErrorCode.ADAPTER_MAPPING_FAILED,
                "adapter",
                "cannot create evidence with an empty frame list",
            )
        frames = sorted(set(frame_numbers))
        for frame in frames:
            observation = self._frames_by_number.get(frame)
            if observation is None:
                raise ChainAdapterError(
                    ChainErrorCode.ADAPTER_MAPPING_FAILED,
                    "adapter",
                    f"mapped evidence references unknown frame {frame}",
                )
            if observation.direction is not direction:
                raise ChainAdapterError(
                    ChainErrorCode.ADAPTER_MAPPING_FAILED,
                    "adapter",
                    f"evidence direction {direction.value!r} disagrees with the "
                    f"frame {frame} observation ({observation.direction.value!r})",
                )
        key = (
            source_kind,
            source_field,
            normalized_value,
            tuple(frames),
            direction,
            occurrence_index,
        )
        existing = self._entries.get(key)
        if existing is not None:
            return existing.evidence_id
        start = self._frame_epochs[frames[0]]
        end = self._frame_epochs[frames[-1]]
        if len(frames) == 1:
            display_filter = f"tcp.stream eq {self._stream_id} && frame.number == {frames[0]}"
        else:
            exact_set = ", ".join(str(frame) for frame in frames)
            display_filter = f"tcp.stream eq {self._stream_id} && frame.number in {{{exact_set}}}"
        node = EvidenceReference(
            evidence_id=evidence_id(
                self._capture_id,
                self._session_id,
                source_kind.value,
                source_field,
                normalized_value,
                frames,
                direction.value,
                occurrence_index,
            ),
            capture_id=self._capture_id,
            capture_sha256=self._capture_sha256,
            session_id=self._session_id,
            frame_numbers=frames,
            occurrence_index=occurrence_index,
            timestamp_start=start,
            timestamp_end=end,
            direction=direction,
            source_kind=source_kind,
            source_field=source_field,
            normalized_value=normalized_value,
            safe_excerpt="",
            display_filter=display_filter,
            observability=ChainObservability.OBSERVED,
            redaction=EvidenceRedaction.NONE,
            extractor_version=_EXTRACTOR_VERSION,
        )
        self._entries[key] = node
        return node.evidence_id

    def all(self) -> list[EvidenceReference]:
        return sorted(self._entries.values(), key=lambda node: node.evidence_id)


def build_chain_from_poc_analysis(
    result: AnalyzeResult,
    *,
    context: PocAdapterContext,
) -> ChainOfProof:
    """Map a verified analyzer :class:`AnalyzeResult` into a chain document.

    The mapping is deterministic and read-only. It validates the adapter
    context and analyzer provenance, maps every TCP stream to one chain
    :class:`Session`, records the observably supported SMTP and TLS handshake
    events with their evidence references, maps tool/runtime records into
    stage diagnostics, and merges the analysis/provenance warnings into the
    bounded capture-warning boundary. The returned chain is validated against
    the graph invariants before being returned.

    Raises
    ------
    ChainAdapterError
        ``adapter_input_invalid`` / ``adapter_metadata_required`` /
        ``adapter_mapping_failed`` as described in the module docstring.
    """
    _validate_context(context)
    prov = result.provenance
    _validate_provenance(prov)

    stage_diagnostics = _stage_diagnostics(result.tool_records)

    configuration_digest = stable_digest(
        context.source_configuration_digest,
        CHAIN_SCHEMA_VERSION,
        POC_ADAPTER_VERSION,
    )
    analysis_id_value = _analysis_id(
        prov.sha256,
        configuration_digest,
        context.analyzer_version,
    )
    capture_id = capture_id_from_sha256(prov.sha256)

    streams, classifications, transitions = _index_analyzer_result(result)

    sessions: list[Session] = []
    evidence_all: list[EvidenceReference] = []
    events_all: list[ProtocolEvent] = []
    capture_incomplete = False

    for stream in sorted(streams, key=lambda item: item.stream_id):
        classification = classifications.get(stream.stream_id)
        transition = transitions.get(stream.stream_id)
        _validate_stream_mapping(stream, classification, transition)
        assert classification is not None
        mapped = _map_stream(
            stream=stream,
            classification=classification,
            transition=transition,
            capture_id=capture_id,
            capture_sha256=prov.sha256,
        )
        sessions.append(mapped.session)
        evidence_all.extend(mapped.evidence)
        events_all.extend(mapped.protocol_events)
        capture_incomplete = capture_incomplete or mapped.capture_incomplete

    analysis_capture_incomplete = (
        capture_incomplete or context.capture_metadata.truncated_packet_count > 0
    )
    analysis_status, analysis_limitations = _analysis_status_and_limitations(
        analysis_capture_incomplete=analysis_capture_incomplete,
        stage_diagnostics=stage_diagnostics,
    )
    analysis_manifest = _build_analysis_manifest(
        analysis_id=analysis_id_value,
        configuration_digest=configuration_digest,
        prov=prov,
        context=context,
        analysis_status=analysis_status,
        limitations=analysis_limitations,
    )
    capture = _build_capture(
        capture_id,
        prov,
        context,
        analysis_capture_incomplete,
        result.warnings,
    )
    execution = _build_execution(prov, stage_diagnostics)

    chain = ChainOfProof(
        schema_id=SCHEMA_ID,
        chain_schema_version=CHAIN_SCHEMA_VERSION,
        analysis=analysis_manifest,
        execution=execution,
        captures=[capture],
        sessions=sessions,
        evidence=sorted(evidence_all, key=lambda node: node.evidence_id),
        protocol_events=events_all,
        crypto_observations=[],
        derived_facts=[],
        rule_evaluations=[],
        findings=[],
        policy_risk=None,
        anomaly_results=[],
        recommendations=[],
        artifacts=[],
    )
    assert_chain_valid(chain)
    return chain


# ─────────────────────────────────────────────────────────────────────────────
#  Validation
# ─────────────────────────────────────────────────────────────────────────────


def _validate_context(context: PocAdapterContext) -> None:
    """Enforce adapter-context semantics with typed, stable error codes."""
    if not context.analyzer_version or not context.analyzer_version.strip():
        raise ChainAdapterError(
            ChainErrorCode.ADAPTER_INPUT_INVALID,
            "adapter",
            "analyzer_version must be a non-blank value",
        )
    if not is_sha256_digest(context.source_configuration_digest):
        raise ChainAdapterError(
            ChainErrorCode.ADAPTER_INPUT_INVALID,
            "adapter",
            "source_configuration_digest must be a 64-lowercase-hex sha256 digest",
        )
    if context.started_at < context.created_at:
        raise ChainAdapterError(
            ChainErrorCode.ADAPTER_INPUT_INVALID,
            "adapter",
            "started_at precedes created_at",
        )
    if context.completed_at is not None:
        if context.completed_at < context.started_at:
            raise ChainAdapterError(
                ChainErrorCode.ADAPTER_INPUT_INVALID,
                "adapter",
                "completed_at precedes started_at",
            )
        if context.completed_at < context.created_at:
            raise ChainAdapterError(
                ChainErrorCode.ADAPTER_INPUT_INVALID,
                "adapter",
                "completed_at precedes created_at",
            )
    if context.tls13_authorized_secrets is Tls13SecretsStatus.AUTHORIZED_SUPPLIED:
        raise ChainAdapterError(
            ChainErrorCode.ADAPTER_INPUT_INVALID,
            "adapter",
            _SECRETS_REJECTED_MESSAGE,
        )


def _validate_provenance(prov: PocCaptureProvenance) -> None:
    if prov.status is not ProvenanceStatus.OK:
        raise ChainAdapterError(
            ChainErrorCode.ADAPTER_METADATA_REQUIRED,
            "adapter",
            "capture provenance is not usable",
            f"status={prov.status.value}",
        )
    if not is_sha256_digest(prov.sha256):
        raise ChainAdapterError(
            ChainErrorCode.ADAPTER_METADATA_REQUIRED,
            "adapter",
            "capture provenance does not carry a valid sha256 digest",
        )
    if prov.size_bytes < 0 or prov.packet_count < 0:
        raise ChainAdapterError(
            ChainErrorCode.ADAPTER_METADATA_REQUIRED,
            "adapter",
            "capture provenance carries negative size or packet count",
        )


def _index_analyzer_result(
    result: AnalyzeResult,
) -> tuple[list[TcpStream], dict[int, ProtocolClassification], dict[int, SmtpTransition]]:
    """Index analyzer collections, rejecting any structure that would force a guess."""
    streams: list[TcpStream] = []
    seen_streams: set[int] = set()
    for stream in result.streams:
        if stream.stream_id in seen_streams:
            raise ChainAdapterError(
                ChainErrorCode.ADAPTER_MAPPING_FAILED,
                "adapter",
                f"duplicate tcp.stream {stream.stream_id} in analyzer streams",
            )
        seen_streams.add(stream.stream_id)
        streams.append(stream)
    stream_ids = seen_streams

    classifications: dict[int, ProtocolClassification] = {}
    for classification in result.classifications:
        if classification.tcp_stream not in stream_ids:
            raise ChainAdapterError(
                ChainErrorCode.ADAPTER_MAPPING_FAILED,
                "adapter",
                f"classification references unknown tcp.stream {classification.tcp_stream}",
            )
        if classification.tcp_stream in classifications:
            raise ChainAdapterError(
                ChainErrorCode.ADAPTER_MAPPING_FAILED,
                "adapter",
                f"duplicate classification for tcp.stream {classification.tcp_stream}",
            )
        classifications[classification.tcp_stream] = classification

    transitions: dict[int, SmtpTransition] = {}
    for transition in result.smtp_transitions:
        if transition.tcp_stream not in stream_ids:
            raise ChainAdapterError(
                ChainErrorCode.ADAPTER_MAPPING_FAILED,
                "adapter",
                f"transition references unknown tcp.stream {transition.tcp_stream}",
            )
        if transition.tcp_stream in transitions:
            raise ChainAdapterError(
                ChainErrorCode.ADAPTER_MAPPING_FAILED,
                "adapter",
                f"duplicate transition for tcp.stream {transition.tcp_stream}",
            )
        transitions[transition.tcp_stream] = transition

    return streams, classifications, transitions


def _validate_stream_mapping(
    stream: TcpStream,
    classification: ProtocolClassification | None,
    transition: SmtpTransition | None,
) -> None:
    """Reject analyzer relationships that cannot be mapped without guessing."""
    if classification is None:
        raise ChainAdapterError(
            ChainErrorCode.ADAPTER_MAPPING_FAILED,
            "adapter",
            f"stream {stream.stream_id} has no classification",
        )
    if not stream.frames:
        raise ChainAdapterError(
            ChainErrorCode.ADAPTER_MAPPING_FAILED,
            "adapter",
            f"stream {stream.stream_id} has no frame observations",
        )
    smtp_classified = classification.protocol is Protocol.SMTP
    if transition is not None and not smtp_classified:
        raise ChainAdapterError(
            ChainErrorCode.ADAPTER_MAPPING_FAILED,
            "adapter",
            f"transition present for non-SMTP stream {stream.stream_id}",
        )
    if smtp_classified:
        if transition is None:
            raise ChainAdapterError(
                ChainErrorCode.ADAPTER_MAPPING_FAILED,
                "adapter",
                f"SMTP stream {stream.stream_id} has no STARTTLS transition",
            )
        if classification.status is not ClassificationStatus.CONFIRMED:
            raise ChainAdapterError(
                ChainErrorCode.ADAPTER_MAPPING_FAILED,
                "adapter",
                f"SMTP stream {stream.stream_id} is not confirmed by content",
            )
    if (
        transition is not None
        and transition.outcome in _ACCEPTED_OUTCOMES | {TransitionOutcome.REJECTED}
        and not transition.starttls_response_frames
    ):
        raise ChainAdapterError(
            ChainErrorCode.ADAPTER_MAPPING_FAILED,
            "adapter",
            f"stream {stream.stream_id} has outcome "
            f"{transition.outcome.value!r} without a server response frame",
        )


# ─────────────────────────────────────────────────────────────────────────────
#  Stage diagnostics / warnings / filename sanitization
# ─────────────────────────────────────────────────────────────────────────────


def _stage_diagnostics(records: list[ToolExecutionRecord]) -> list[StageDiagnostic]:
    """Map analyzer tool records into bound, deterministic stage diagnostics.

    Records are grouped by their explicit chain stage; an unknown tool stage is
    a mapping failure. Runtime seconds aggregate by sum, status is derived from
    the succeeded/failed mix, and partial/failed stages carry a typed
    ``field_unavailable`` limitation. No raw command arguments, absolute paths
    or unbounded stderr text is ever copied into the chain.
    """
    grouped: dict[StageId, list[ToolExecutionRecord]] = {}
    for record in records:
        stage = _STAGE_BY_SOURCE.get(record.stage)
        if stage is None:
            raise ChainAdapterError(
                ChainErrorCode.ADAPTER_MAPPING_FAILED,
                "adapter",
                f"unknown analyzer tool stage {record.stage!r}",
            )
        grouped.setdefault(stage, []).append(record)

    diagnostics: list[StageDiagnostic] = []
    for stage in sorted(grouped, key=lambda item: item.value):
        stage_records = grouped[stage]
        succeeded = sum(1 for record in stage_records if record.succeeded)
        total = len(stage_records)
        runtime_seconds = sum(record.runtime_seconds for record in stage_records)
        if succeeded == total:
            status = StageStatus.COMPLETE
            limitation = None
        else:
            status = StageStatus.PARTIAL if succeeded else StageStatus.FAILED
            tools = ",".join(sorted({_display_tool(record.tool) for record in stage_records}))
            limitation = AnalysisLimitation(
                code=LimitationCode.FIELD_UNAVAILABLE,
                summary=f"one or more tool invocations failed in analysis stage {stage.value}",
                detail=f"tools: {tools}",
            )
        diagnostics.append(
            StageDiagnostic(
                stage=stage,
                status=status,
                limitation=limitation,
                runtime_seconds=runtime_seconds,
            )
        )
    return diagnostics


def _sanitize_warning(message: str) -> str:
    """Bound and sanitize one warning for the capture warning boundary.

    Every ASCII control character and DEL is first normalized to a space (so a
    separator can never be deleted in a way that concatenates prose with an
    absolute path), then the earliest absolute-path start is located and the
    warning is truncated there: only the safe prose that precedes the path is
    preserved, and the path plus everything after it is dropped (fail-closed,
    because filenames may contain spaces). Warnings without an absolute path
    are unchanged. The output is whitespace-collapsed, deduplicated and bounded
    by the caller.
    """
    text = message.translate(_CONTROL_TO_SPACE)
    path_start = _PATH_START_RE.search(text)
    if path_start is not None:
        text = text[: path_start.start()]
    text = _WARNING_COLLAPSE.sub(" ", text).strip()
    if len(text) > _MAX_WARNING_LENGTH:
        keep = _MAX_WARNING_LENGTH - len(_WARNING_TRUNCATION)
        text = text[:keep] + _WARNING_TRUNCATION
    return text


def _merge_capture_warnings(
    prov: PocCaptureProvenance,
    analysis_warnings: list[str],
    analysis_capture_incomplete: bool,
) -> list[str]:
    """Merge, deduplicate, sanitize and bound the capture warning boundary.

    The canonical capture-incomplete summary is mandatory and always holds the
    reserved first slot when ``analysis_capture_incomplete`` is true, so ten
    preceding warnings can never displace it. The remaining slots are filled in
    deterministic order with the sanitized, deduplicated analyzer and
    provenance warnings, and the total count stays bounded.
    """
    merged: list[str] = []
    if analysis_capture_incomplete:
        summary = _sanitize_warning(_CAPTURE_INCOMPLETE_SUMMARY)
        if summary:
            merged.append(summary)
    for message in list(analysis_warnings) + list(prov.warnings):
        cleaned = _sanitize_warning(message)
        if not cleaned or cleaned in merged:
            continue
        merged.append(cleaned)
        if len(merged) >= _MAX_WARNINGS:
            break
    return merged


def _safe_basename(path_text: str) -> str:
    """Return the cross-platform display basename, or ``""`` when none exists."""
    posix_style = path_text.replace("\\", "/")
    candidate = posix_style.rsplit("/", 1)[-1].strip()
    cleaned = "".join(ch for ch in candidate if ch >= " " and ch != "\x7f")
    if not cleaned or set(cleaned) <= {"."}:
        return ""
    return cleaned


def _display_basename(path_text: str) -> str:
    """Return only the display basename for POSIX or Windows separators."""
    basename = _safe_basename(path_text)
    if not basename:
        return _NEUTRAL_FILENAME
    return basename[:_MAX_FILENAME_LENGTH]


def _display_tool(tool: str) -> str:
    """Sanitize a tool identity down to a bounded, parent-free basename."""
    basename = _safe_basename(tool)
    if not basename:
        return _NEUTRAL_TOOL
    return basename[:_MAX_TOOL_LENGTH]


# ─────────────────────────────────────────────────────────────────────────────
#  Capture / analysis / execution nodes
# ─────────────────────────────────────────────────────────────────────────────


def _analysis_id(
    capture_sha256: str,
    configuration_digest: str,
    analyzer_version: str,
) -> str:
    return analysis_id(
        CHAIN_SCHEMA_VERSION,
        capture_sha256,
        configuration_digest,
        analyzer_version,
    )


def _capture_incomplete_limitation() -> AnalysisLimitation:
    return AnalysisLimitation(
        code=LimitationCode.CAPTURE_INCOMPLETE,
        summary=_CAPTURE_INCOMPLETE_SUMMARY,
    )


def _analysis_status_and_limitations(
    *,
    analysis_capture_incomplete: bool,
    stage_diagnostics: list[StageDiagnostic],
) -> tuple[AnalysisStatus, list[AnalysisLimitation]]:
    limitations = [_capture_incomplete_limitation()] if analysis_capture_incomplete else []
    any_stage_problem = any(
        diagnostic.status in (StageStatus.PARTIAL, StageStatus.FAILED)
        for diagnostic in stage_diagnostics
    )
    if analysis_capture_incomplete or any_stage_problem:
        return AnalysisStatus.PARTIAL, limitations
    return AnalysisStatus.COMPLETE, limitations


def _build_analysis_manifest(
    *,
    analysis_id: str,
    configuration_digest: str,
    prov: PocCaptureProvenance,
    context: PocAdapterContext,
    analysis_status: AnalysisStatus,
    limitations: list[AnalysisLimitation],
) -> AnalysisManifest:
    return AnalysisManifest(
        analysis_id=analysis_id,
        chain_schema_version=CHAIN_SCHEMA_VERSION,
        analysis_status=analysis_status,
        created_at=context.created_at,
        started_at=context.started_at,
        completed_at=context.completed_at,
        analyzer_version=context.analyzer_version,
        tshark_version=prov.tshark_version or None,
        rule_engine_status=EngineStatus.NOT_RUN,
        rule_pack_id=None,
        rule_pack_version=None,
        ml_engine_status=EngineStatus.NOT_RUN,
        model_id=None,
        model_version=None,
        configuration_digest=configuration_digest,
        tls13_authorized_secrets=context.tls13_authorized_secrets,
        limitations=limitations,
    )


def _build_capture(
    capture_id: str,
    prov: PocCaptureProvenance,
    context: PocAdapterContext,
    analysis_capture_incomplete: bool,
    analysis_warnings: list[str],
) -> CaptureProvenance:
    warnings = _merge_capture_warnings(prov, analysis_warnings, analysis_capture_incomplete)
    captured_at_start = (
        _epoch_to_utc(prov.first_epoch_seconds) if prov.first_epoch_seconds is not None else None
    )
    captured_at_end = (
        _epoch_to_utc(prov.last_epoch_seconds) if prov.last_epoch_seconds is not None else None
    )
    return CaptureProvenance(
        capture_id=capture_id,
        original_filename_sanitized=_display_basename(prov.input_path),
        format=prov.capture_format,
        size_bytes=prov.size_bytes,
        sha256=prov.sha256,
        packet_count=prov.packet_count,
        captured_at_start=captured_at_start,
        captured_at_end=captured_at_end,
        link_layer_types=list(context.capture_metadata.link_layer_types),
        snaplen=context.capture_metadata.snaplen,
        truncated_packet_count=context.capture_metadata.truncated_packet_count,
        capture_warnings=warnings,
        ingestion_tool_versions=_tool_versions(prov),
    )


def _build_execution(
    prov: PocCaptureProvenance,
    stage_diagnostics: list[StageDiagnostic],
) -> AnalysisExecution:
    return AnalysisExecution(
        tool_versions=_tool_versions(prov),
        stage_diagnostics=stage_diagnostics,
    )


def _tool_versions(prov: PocCaptureProvenance) -> dict[str, str]:
    versions: dict[str, str] = {}
    if prov.tshark_version:
        versions["tshark"] = prov.tshark_version
    if prov.capinfos_version:
        versions["capinfos"] = prov.capinfos_version
    return versions


# ─────────────────────────────────────────────────────────────────────────────
#  Session / evidence / event mapping
# ─────────────────────────────────────────────────────────────────────────────


def _index_frames(
    stream: TcpStream,
) -> tuple[list[RawFrameObservation], dict[int, datetime], dict[int, RawFrameObservation]]:
    """Sort and index a stream's frames without ever hiding a duplicate.

    Duplicate frame numbers and frames whose ``tcp_stream`` disagrees with the
    containing stream are rejected instead of being collapsed by last-write-wins
    dictionary construction, so a referenced frame can always be traced to one
    exact observation.
    """
    ordered = sorted(stream.frames, key=lambda frame: frame.frame)
    frame_epochs: dict[int, datetime] = {}
    frames_by_number: dict[int, RawFrameObservation] = {}
    seen_numbers: set[int] = set()
    for observation in ordered:
        if observation.frame in seen_numbers:
            raise ChainAdapterError(
                ChainErrorCode.ADAPTER_MAPPING_FAILED,
                "adapter",
                f"stream {stream.stream_id} contains duplicate frame number {observation.frame}",
            )
        if observation.tcp_stream != stream.stream_id:
            raise ChainAdapterError(
                ChainErrorCode.ADAPTER_MAPPING_FAILED,
                "adapter",
                f"frame {observation.frame} belongs to tcp.stream "
                f"{observation.tcp_stream}, not its containing stream "
                f"{stream.stream_id}",
            )
        seen_numbers.add(observation.frame)
        frame_epochs[observation.frame] = _epoch_to_utc(observation.epoch_seconds)
        frames_by_number[observation.frame] = observation
    return ordered, frame_epochs, frames_by_number


def _map_stream(
    *,
    stream: TcpStream,
    classification: ProtocolClassification,
    transition: SmtpTransition | None,
    capture_id: str,
    capture_sha256: str,
) -> _MappedNodes:
    frames, frame_epochs, frames_by_number = _index_frames(stream)

    client_ip = stream.client_ip or ""
    client_port = stream.client_port
    server_ip = stream.server_ip or ""
    server_port = stream.server_port
    stable_session_key = session_stable_key(
        CHAIN_SCHEMA_VERSION,
        capture_sha256,
        stream.stream_id,
        client_ip,
        client_port,
        server_ip,
        server_port,
    )
    session_id = session_id_from_key(stable_session_key)

    is_smtp = classification.protocol is Protocol.SMTP
    protocol = Protocol.SMTP if is_smtp else Protocol.UNKNOWN
    confidence = ConfidenceLevel.HIGH if is_smtp else ConfidenceLevel.NOT_SCORED
    completeness = (
        transition.completeness if transition is not None else CompleteStatus.INSUFFICIENT
    )
    proto_limitations = _session_limitations(stream, is_smtp, classification, transition)

    registry = _EvidenceRegistry(
        capture_id=capture_id,
        capture_sha256=capture_sha256,
        session_id=session_id,
        stream_id=stream.stream_id,
        frame_epochs=frame_epochs,
        frames_by_number=frames_by_number,
    )

    classification_evidence = _collect_classification_evidence(registry, classification)
    if transition is not None:
        _collect_transition_evidence(registry, transition)

    raw_events = list(_tcp_handshake_plan(frames, registry, frame_epochs))

    if is_smtp and transition is not None:
        raw_events.extend(_smtp_event_plan(transition, registry, frame_epochs, frames_by_number))
    raw_events.extend(_handshake_event_plan(frames, registry, frame_epochs))

    ordered_events = _finalize_events(
        session_id=session_id,
        protocol=protocol,
        raw_events=sorted(
            raw_events,
            key=lambda event: (event.frame, event.occurrence, event.rank),
        ),
    )

    session = Session(
        session_id=session_id,
        stable_session_key=stable_session_key,
        capture_id=capture_id,
        tcp_stream_id=stream.stream_id,
        source_endpoint=Endpoint(ip=client_ip, port=client_port),
        destination_endpoint=Endpoint(ip=server_ip, port=server_port),
        first_frame=frames[0].frame,
        last_frame=frames[-1].frame,
        started_at=frame_epochs[frames[0].frame],
        ended_at=frame_epochs[frames[-1].frame],
        packet_count=len(frames),
        byte_count=len(stream.client_reassembled) + len(stream.server_reassembled),
        protocol=protocol,
        protocol_confidence=confidence,
        classification_evidence_ids=classification_evidence,
        capture_completeness=completeness,
        limitations=proto_limitations,
    )

    capture_incomplete = transition is not None and (
        transition.completeness is CompleteStatus.CAPTURE_INCOMPLETE
    )
    return _MappedNodes(
        session=session,
        protocol_events=tuple(ordered_events),
        evidence=tuple(registry.all()),
        capture_incomplete=capture_incomplete,
    )


def _session_limitations(
    stream: TcpStream,
    is_smtp: bool,
    classification: ProtocolClassification,
    transition: SmtpTransition | None,
) -> list[AnalysisLimitation]:
    """Typed limitations for one session's classification and transition state.

    A stream that is not SMTP-identified, or whose client/server direction
    could not be established from the TCP handshake, is honestly recorded as
    ``unknown_insufficient_evidence``. An SMTP stream whose transition is
    capture-incomplete records ``capture_incomplete``; an ``incomplete``
    outcome without capture truncation records ``unknown_insufficient_evidence``
    and never claims the capture was truncated.
    """
    if not is_smtp or stream.direction_basis is DirectionBasis.NOT_DETERMINED:
        return [
            AnalysisLimitation(
                code=LimitationCode.UNKNOWN_INSUFFICIENT_EVIDENCE,
                summary=_UNKNOWN_SESSION_SUMMARY,
                detail=classification.reason if classification.reason else "",
            )
        ]
    if transition is None:
        return []
    if transition.completeness is CompleteStatus.CAPTURE_INCOMPLETE:
        return [
            AnalysisLimitation(
                code=LimitationCode.CAPTURE_INCOMPLETE,
                summary=_CAPTURE_INCOMPLETE_SUMMARY,
            )
        ]
    if transition.outcome is TransitionOutcome.INCOMPLETE:
        return [
            AnalysisLimitation(
                code=LimitationCode.UNKNOWN_INSUFFICIENT_EVIDENCE,
                summary=_INCOMPLETE_TRANSITION_SUMMARY,
            )
        ]
    return []


def _collect_classification_evidence(
    registry: _EvidenceRegistry,
    classification: ProtocolClassification,
) -> list[str]:
    """Reference the frame-granular evidence that supports a classification."""
    bases = list(classification.positive_evidence)
    if classification.status is ClassificationStatus.CONTRADICTORY:
        bases = bases + list(classification.contradictory_evidence)
    evidence_ids: list[str] = []
    for basis in bases:
        token = _SMTP_TOKEN_BY_CATEGORY.get(basis.category)
        if token is None:
            continue
        for frame in basis.frames:
            evidence_ids.append(
                registry.add(
                    source_kind=EvidenceSourceKind.TSHARK_FIELD,
                    source_field="tcp.payload",
                    normalized_value=token,
                    frame_numbers=[frame],
                    direction=basis.direction,
                    occurrence_index=0,
                )
            )
    return sorted(set(evidence_ids))


def _collect_transition_evidence(registry: _EvidenceRegistry, transition: SmtpTransition) -> None:
    """Record the STARTTLS transition evidence reusing the classification tokens."""
    for frame in transition.banner_evidence:
        registry.add(
            source_kind=EvidenceSourceKind.TSHARK_FIELD,
            source_field="tcp.payload",
            normalized_value="smtp:banner",
            frame_numbers=[frame],
            direction=Direction.SERVER_TO_CLIENT,
            occurrence_index=0,
        )
    for frame in transition.ehlo_evidence:
        registry.add(
            source_kind=EvidenceSourceKind.TSHARK_FIELD,
            source_field="tcp.payload",
            normalized_value="smtp:ehlo",
            frame_numbers=[frame],
            direction=Direction.CLIENT_TO_SERVER,
            occurrence_index=0,
        )
    for frame in transition.starttls_capability_evidence:
        registry.add(
            source_kind=EvidenceSourceKind.TSHARK_FIELD,
            source_field="tcp.payload",
            normalized_value="smtp:starttls_capability",
            frame_numbers=[frame],
            direction=Direction.SERVER_TO_CLIENT,
            occurrence_index=0,
        )


def _command_evidence_id(
    registry: _EvidenceRegistry,
    transition: SmtpTransition,
) -> str:
    """Reference the STARTTLS-command bytes, using the follow-stream when split.

    A single-frame command is attributed through its ``tcp.payload`` row (the
    same bytes the classification path saw); a command reconstructed across
    multiple TCP segments is attributed through the TShark-native
    ``follow,tcp,raw`` byte-stream, so the evidence stays exact regardless of
    segmentation.
    """
    command_frames = list(transition.starttls_command_frames)
    if not command_frames:
        raise ChainAdapterError(
            ChainErrorCode.ADAPTER_MAPPING_FAILED,
            "adapter",
            f"stream {transition.tcp_stream} has a complete STARTTLS command "
            "without attributable frame evidence",
        )
    if len(command_frames) >= 2:
        return registry.add(
            source_kind=EvidenceSourceKind.TSHARK_FOLLOW_STREAM,
            source_field="follow,tcp,raw",
            normalized_value="smtp:starttls_command",
            frame_numbers=command_frames,
            direction=Direction.CLIENT_TO_SERVER,
            occurrence_index=0,
        )
    return registry.add(
        source_kind=EvidenceSourceKind.TSHARK_FIELD,
        source_field="tcp.payload",
        normalized_value="smtp:starttls_command",
        frame_numbers=command_frames,
        direction=Direction.CLIENT_TO_SERVER,
        occurrence_index=0,
    )


def _partial_command_frames(transition: SmtpTransition) -> frozenset[int]:
    """Return the frames that carry an incomplete STARTTLS command, if any.

    When the analyzer could not prove the complete ``STARTTLS\\r\\n`` command,
    the reconstructable prefix frames must never be read line-by-line: a
    per-frame occurrence index is not trustworthy across a split command. When
    the command is complete these frames carry the ``STARTTLS_COMMAND`` category
    instead and are never considered plaintext continuation.
    """
    if transition.starttls_command == _FULL_STARTTLS_COMMAND:
        return frozenset()
    return frozenset(transition.starttls_command_frames)


def _command_verb(line: bytes) -> str | None:
    """Return the uppercased first whitespace-delimited token of an SMTP line."""
    text = line.strip().decode("utf-8", errors="replace").upper()
    if not text:
        return None
    return text.split(None, 1)[0]


def _line_at_event(
    transition: SmtpTransition,
    event: SmtpEvent,
    frames_by_number: dict[int, RawFrameObservation],
    partial_command_frames: frozenset[int],
) -> bytes | None:
    """Return the exact payload line an ``OTHER`` event points at, or ``None``.

    The analyzer emits exactly one category per client payload line with
    ``occurrence`` equal to the line index, so the line is read from the real
    frame payload at that index. ``None`` is returned (and the line is never
    guessed) when it would fall on an incomplete-command frame, on an unknown
    frame, or outside the frame's observable lines.
    """
    if event.frame in partial_command_frames:
        return None
    observation = frames_by_number.get(event.frame)
    if observation is None:
        return None
    lines = list(_PAYLOAD_LINE_RE.findall(observation.payload))
    if event.occurrence >= len(lines):
        return None
    return lines[event.occurrence]


class _PlaintextOfferTracker:
    """Bounded state machine annotating plaintext commands after the TLS offer.

    State advances only from observable inputs: the capability gate from a
    ``STARTTLS_CAPABILITY`` server event, and the DATA/BDAT body-mode switches
    from the actual payload line verbs. A line that cannot be proven safely is
    never counted, and binary body bytes are never parsed as commands.
    """

    def __init__(self) -> None:
        self._capability_seen = False
        self._data_body_active = False
        self._absorb_after_bdat = False

    @property
    def capability_seen(self) -> bool:
        return self._capability_seen

    def observe_server_event(self, event: SmtpEvent) -> None:
        """Record the STARTTLS advertisement from a server category event."""
        if event.category is SmtpEventCategory.STARTTLS_CAPABILITY:
            self._capability_seen = True

    def classify_client_line(self, line: bytes, *, allowed: bool) -> bool:
        """Classify one client line, advancing body-mode state.

        Returns whether the line is a countable plaintext command after the
        offer. ``DATA`` switches to message-body mode (only a dot terminator
        line exits it); ``BDAT`` absorbs the remaining stream without byte
        counting because its chunk payloads are not command text. In body mode
        no line is counted.
        """
        if self._absorb_after_bdat:
            return False
        if self._data_body_active:
            if line.rstrip(b"\r\n") == b".":
                self._data_body_active = False
            return False
        verb = _command_verb(line)
        if verb is None or verb not in _PLAINTEXT_VERB_ALLOWLIST:
            return False
        if verb == "DATA":
            self._data_body_active = True
        elif verb == "BDAT":
            self._absorb_after_bdat = True
        return allowed

    def classify_client_ehlo_helo(self) -> bool:
        """Whether a client EHLO/HELO counts as plaintext after the TLS offer.

        A client EHLO/HELO that is observed strictly after the server advertised
        the STARTTLS capability is a plaintext SMTP command, so it qualifies as
        plaintext continuation (while a pre-offer EHLO/HELO stays a
        ``CAPABILITY_REQUEST``). EHLO/HELO are never DATA/BDAT operations, but
        the body/absorption guard is kept for safety so a malformed line can
        never be counted mid-body.
        """
        if self._absorb_after_bdat or self._data_body_active:
            return False
        return self._capability_seen


def _normalized_transition_events(transition: SmtpTransition) -> list[SmtpEvent]:
    """Return ``transition.events`` in deterministic wire order.

    An externally constructed :class:`SmtpTransition` may list its ``events`` in
    any caller-provided order, and that order must never influence the derived
    chain. The canonical wire order is ``(frame, occurrence, category,
    direction)``: occurrences already disambiguate multiple values on the same
    frame, and the category (then direction) deterministically orders any two
    distinct events that a caller happened to place on the same frame and
    occurrence. Every stateful consumer in :func:`_smtp_event_plan` is driven
    from this normalized list, never from the raw list order.

    Two events that share a frame and occurrence *and* the same category are
    ambiguous duplicates that the category tie-breaker cannot distinguish; they
    are rejected with a typed :class:`ChainAdapterError` rather than silently
    selecting one.
    """
    ordered = sorted(
        transition.events,
        key=lambda event: (
            event.frame,
            event.occurrence,
            event.category.value,
            event.direction.value,
        ),
    )
    seen: set[tuple[int, int, str]] = set()
    for event in ordered:
        key = (event.frame, event.occurrence, event.category.value)
        if key in seen:
            raise ChainAdapterError(
                ChainErrorCode.ADAPTER_MAPPING_FAILED,
                "adapter",
                f"stream {transition.tcp_stream} has ambiguous duplicate analyzer "
                f"events at frame {event.frame} occurrence {event.occurrence} "
                f"category {event.category.value!r} that cannot be "
                "deterministically distinguished",
            )
        seen.add(key)
    return ordered


def _plaintext_event(
    *,
    event: SmtpEvent,
    registry: _EvidenceRegistry,
    frame_epochs: dict[int, datetime],
) -> _RawEvent:
    """Build a plaintext-command-after-offer raw event for a client event."""
    evidence = registry.add(
        source_kind=EvidenceSourceKind.TSHARK_FIELD,
        source_field="tcp.payload",
        normalized_value=_PLAINTEXT_EVIDENCE_TOKEN,
        frame_numbers=[event.frame],
        direction=Direction.CLIENT_TO_SERVER,
        occurrence_index=event.occurrence,
    )
    return _RawEvent(
        frame=event.frame,
        occurrence=event.occurrence,
        rank=0,
        event_type=ProtocolEventType.PLAINTEXT_COMMAND_AFTER_TLS_OFFER,
        direction=Direction.CLIENT_TO_SERVER,
        timestamp=frame_epochs[event.frame],
        evidence_ids=(evidence,),
    )


def _smtp_event_plan(
    transition: SmtpTransition,
    registry: _EvidenceRegistry,
    frame_epochs: dict[int, datetime],
    frames_by_number: dict[int, RawFrameObservation],
) -> list[_RawEvent]:
    """Plan the SMTP and STARTTLS-transition events for one session.

    A request event is only emitted when the analyzer proved the complete
    ``STARTTLS\\r\\n`` command with attributable frames. Response events are
    derived from the actually observed response-frame payload (``220`` =
    acceptance, ``4xx/5xx`` = rejection, anything else = no synthetic event).
    All stateful processing (STARTTLS command anchor selection, capability
    tracking, plaintext detection and SMTP event emission) consumes the
    deterministic wire order from :func:`_normalized_transition_events`, never
    the raw list order of the caller-supplied transition.
    """
    plan: list[_RawEvent] = []
    ordered_events = _normalized_transition_events(transition)

    complete_command = transition.starttls_command == _FULL_STARTTLS_COMMAND
    command_evidence = None
    if complete_command:
        command_evidence = _command_evidence_id(registry, transition)
    elif transition.starttls_response_frames or transition.outcome in (
        _ACCEPTED_OUTCOMES | {TransitionOutcome.REJECTED}
    ):
        raise ChainAdapterError(
            ChainErrorCode.ADAPTER_MAPPING_FAILED,
            "adapter",
            f"stream {transition.tcp_stream} has a server response or decisive "
            "outcome without a proven complete STARTTLS command",
        )

    if command_evidence is not None:
        starttls_events = [
            event
            for event in ordered_events
            if event.category is SmtpEventCategory.STARTTLS_COMMAND
        ]
        if starttls_events:
            anchor = starttls_events[-1]
            anchor_frame = anchor.frame
            occurrence = anchor.occurrence
        else:
            anchor_frame = max(transition.starttls_command_frames)
            occurrence = 0
        if anchor_frame not in transition.starttls_command_frames:
            raise ChainAdapterError(
                ChainErrorCode.ADAPTER_MAPPING_FAILED,
                "adapter",
                f"stream {transition.tcp_stream} STARTTLS command event anchor "
                f"frame {anchor_frame} is not one of the proven command frames",
            )
        if anchor_frame not in frame_epochs:
            raise ChainAdapterError(
                ChainErrorCode.ADAPTER_MAPPING_FAILED,
                "adapter",
                f"stream {transition.tcp_stream} STARTTLS command event "
                f"references unknown frame {anchor_frame}",
            )
        plan.append(
            _RawEvent(
                frame=anchor_frame,
                occurrence=occurrence,
                rank=0,
                event_type=ProtocolEventType.TLS_UPGRADE_REQUESTED,
                direction=Direction.CLIENT_TO_SERVER,
                timestamp=frame_epochs[anchor_frame],
                evidence_ids=(command_evidence,),
            )
        )

    tracker = _PlaintextOfferTracker()
    partial_command_frames = _partial_command_frames(transition)
    for event in ordered_events:
        counted_plaintext = False
        if event.direction is Direction.SERVER_TO_CLIENT:
            tracker.observe_server_event(event)
        elif event.frame in frame_epochs and event.category is SmtpEventCategory.OTHER:
            line = _line_at_event(transition, event, frames_by_number, partial_command_frames)
            if line is not None:
                counted_plaintext = tracker.classify_client_line(
                    line, allowed=tracker.capability_seen
                )
        elif (
            event.category in (SmtpEventCategory.EHLO, SmtpEventCategory.HELO)
            and event.frame in frame_epochs
        ):
            # A client EHLO/HELO observed strictly after the STARTTLS offer is
            # a plaintext SMTP command and must remain visible in the derived
            # transition facts (counted as plaintext-after-offer), while a
            # pre-offer EHLO/HELO stays a CAPABILITY_REQUEST and is not counted.
            counted_plaintext = tracker.classify_client_ehlo_helo()
        event_type = _EVENT_TYPE_BY_CATEGORY.get(event.category)
        if counted_plaintext:
            plan.append(
                _plaintext_event(
                    event=event,
                    registry=registry,
                    frame_epochs=frame_epochs,
                )
            )
            continue
        if event_type is None:
            continue
        if event.category is SmtpEventCategory.STARTTLS_COMMAND:
            continue
        token = _SMTP_TOKEN_BY_CATEGORY.get(event.category.value)
        if token is None:
            continue
        if event.frame not in frame_epochs:
            raise ChainAdapterError(
                ChainErrorCode.ADAPTER_MAPPING_FAILED,
                "adapter",
                f"stream {transition.tcp_stream} analyzer event {event.category.value} "
                f"references unknown frame {event.frame} and was not silently skipped",
            )
        evidence = registry.add(
            source_kind=EvidenceSourceKind.TSHARK_FIELD,
            source_field="tcp.payload",
            normalized_value=token,
            frame_numbers=[event.frame],
            direction=event.direction,
            occurrence_index=0,
        )
        plan.append(
            _RawEvent(
                frame=event.frame,
                occurrence=event.occurrence,
                rank=0,
                event_type=event_type,
                direction=event.direction,
                timestamp=frame_epochs[event.frame],
                evidence_ids=(evidence,),
            )
        )

    response_event = _response_event(registry, transition, frames_by_number, frame_epochs)
    if response_event is not None:
        plan.append(response_event)

    return plan


def _response_event(
    registry: _EvidenceRegistry,
    transition: SmtpTransition,
    frames_by_number: dict[int, RawFrameObservation],
    frame_epochs: dict[int, datetime],
) -> _RawEvent | None:
    """Derive the accept/reject event from the observed response frame payload.

    An accepted/rejected event is only ever emitted after a proven complete
    STARTTLS request, and a response frame must sit strictly after every
    contributing command frame (an earlier banner containing ``220`` is never
    reused as acceptance evidence). Multiple response frames are ambiguous and
    are rejected rather than silently choosing index zero. The response event
    never implies a completed TLS handshake: handshake events remain tied to
    the actually observed handshake types. An outcome that claims
    acceptance/rejection while the observed response contradicts it is an
    unmappable analyzer shape.
    """
    if not transition.starttls_response_frames:
        return None
    if len(transition.starttls_response_frames) > 1:
        raise ChainAdapterError(
            ChainErrorCode.ADAPTER_MAPPING_FAILED,
            "adapter",
            f"stream {transition.tcp_stream} has multiple STARTTLS response "
            "frames; the mapping rejects ambiguous server responses",
        )
    response_frame = transition.starttls_response_frames[0]
    if not transition.starttls_command_frames:
        raise ChainAdapterError(
            ChainErrorCode.ADAPTER_MAPPING_FAILED,
            "adapter",
            f"stream {transition.tcp_stream} has a server response without any "
            "proven STARTTLS command frame",
        )
    command_boundary = max(transition.starttls_command_frames)
    if response_frame <= command_boundary:
        raise ChainAdapterError(
            ChainErrorCode.ADAPTER_MAPPING_FAILED,
            "adapter",
            f"stream {transition.tcp_stream} STARTTLS response frame "
            f"{response_frame} is not strictly after the command frame "
            f"{command_boundary}",
        )
    observation = frames_by_number.get(response_frame)
    if observation is None:
        raise ChainAdapterError(
            ChainErrorCode.ADAPTER_MAPPING_FAILED,
            "adapter",
            f"stream {transition.tcp_stream} response frame {response_frame} "
            "is not a session frame observation",
        )
    observed = _response_status(observation.payload)
    expected = _EXPECTED_RESPONSE.get(transition.outcome)
    if expected is not None and observed != expected:
        raise ChainAdapterError(
            ChainErrorCode.ADAPTER_MAPPING_FAILED,
            "adapter",
            f"stream {transition.tcp_stream} outcome {transition.outcome.value!r} "
            "is inconsistent with the observed server response",
        )
    if observed == "accepted":
        event_type = ProtocolEventType.TLS_UPGRADE_ACCEPTED
        token = "smtp:starttls_accept"
    elif observed == "rejected":
        event_type = ProtocolEventType.TLS_UPGRADE_REJECTED
        token = "smtp:starttls_reject"
    else:
        return None
    response_evidence = registry.add(
        source_kind=EvidenceSourceKind.TSHARK_FIELD,
        source_field="tcp.payload",
        normalized_value=token,
        frame_numbers=[response_frame],
        direction=Direction.SERVER_TO_CLIENT,
        occurrence_index=0,
    )
    return _RawEvent(
        frame=response_frame,
        occurrence=_SYNTHETIC_OCCURRENCE,
        rank=0,
        event_type=event_type,
        direction=Direction.SERVER_TO_CLIENT,
        timestamp=frame_epochs[response_frame],
        evidence_ids=(response_evidence,),
    )


def _response_status(payload: bytes) -> str:
    """Classify the observed STARTTLS response payload (reject checked first)."""
    if _STARTTLS_REJECT_RE.search(payload):
        return "rejected"
    if _STARTTLS_ACCEPT_RE.search(payload):
        return "accepted"
    return "unrecognized"


def _tcp_handshake_plan(
    frames: list[RawFrameObservation],
    registry: _EvidenceRegistry,
    frame_epochs: dict[int, datetime],
) -> list[_RawEvent]:
    """Emit ``TCP_CONNECTED`` only on proof of the ordered three-way handshake.

    A lone client SYN proves an *attempted* connection, not an established one.
    The connection-open event is emitted only when the raw observations prove,
    in strictly increasing frame order:

    1. a client SYN without ACK,
    2. a later server SYN+ACK,
    3. a later client ACK without SYN.

    The event is anchored at the final client ACK and references three exact,
    directionally-distinct evidence observations (one per leg). A handshake
    that is incomplete or out of order yields **no** ``TCP_CONNECTED`` event and
    no fabricated connection-open proof; the discovered session is retained.
    """
    ordered = sorted(frames, key=lambda frame: frame.frame)
    syn: RawFrameObservation | None = None
    syn_ack: RawFrameObservation | None = None
    final_ack: RawFrameObservation | None = None
    for observation in ordered:
        if syn is None:
            if (
                observation.direction is Direction.CLIENT_TO_SERVER
                and observation.flags_syn
                and not observation.flags_ack
            ):
                syn = observation
            continue
        if syn_ack is None:
            if (
                observation.direction is Direction.SERVER_TO_CLIENT
                and observation.flags_syn
                and observation.flags_ack
            ):
                syn_ack = observation
            continue
        if (
            observation.direction is Direction.CLIENT_TO_SERVER
            and not observation.flags_syn
            and observation.flags_ack
        ):
            final_ack = observation
            break
    if syn is None or syn_ack is None or final_ack is None:
        return []

    syn_evidence = registry.add(
        source_kind=EvidenceSourceKind.TSHARK_FIELD,
        source_field="tcp.flags.syn",
        normalized_value="tcp:syn",
        frame_numbers=[syn.frame],
        direction=Direction.CLIENT_TO_SERVER,
        occurrence_index=0,
    )
    syn_ack_evidence = registry.add(
        source_kind=EvidenceSourceKind.TSHARK_FIELD,
        source_field="tcp.flags.ack",
        normalized_value="tcp:syn_ack",
        frame_numbers=[syn_ack.frame],
        direction=Direction.SERVER_TO_CLIENT,
        occurrence_index=0,
    )
    ack_evidence = registry.add(
        source_kind=EvidenceSourceKind.TSHARK_FIELD,
        source_field="tcp.flags.ack",
        normalized_value="tcp:ack",
        frame_numbers=[final_ack.frame],
        direction=Direction.CLIENT_TO_SERVER,
        occurrence_index=0,
    )
    return [
        _RawEvent(
            frame=final_ack.frame,
            occurrence=0,
            rank=0,
            event_type=ProtocolEventType.TCP_CONNECTED,
            direction=Direction.CLIENT_TO_SERVER,
            timestamp=frame_epochs[final_ack.frame],
            evidence_ids=(syn_evidence, syn_ack_evidence, ack_evidence),
        )
    ]


def _handshake_event_plan(
    frames: list[RawFrameObservation],
    registry: _EvidenceRegistry,
    frame_epochs: dict[int, datetime],
) -> list[_RawEvent]:
    """Plan the already-observable TLS handshake-type events for one session."""
    plan: list[_RawEvent] = []
    for frame in frames:
        for occurrence, handshake_type in enumerate(frame.tls_handshake_types):
            event_type = _HANDSHAKE_EVENT_BY_TYPE.get(handshake_type)
            if event_type is None:
                continue
            evidence = registry.add(
                source_kind=EvidenceSourceKind.TSHARK_FIELD,
                source_field="tls.handshake.type",
                normalized_value=f"tls:handshake_type:{handshake_type}",
                frame_numbers=[frame.frame],
                direction=frame.direction,
                occurrence_index=occurrence,
            )
            plan.append(
                _RawEvent(
                    frame=frame.frame,
                    occurrence=occurrence,
                    rank=1,
                    event_type=event_type,
                    direction=frame.direction,
                    timestamp=frame_epochs[frame.frame],
                    evidence_ids=(evidence,),
                )
            )
    return plan


def _finalize_events(
    *,
    session_id: str,
    protocol: Protocol,
    raw_events: list[_RawEvent],
) -> list[ProtocolEvent]:
    """Assign contiguous sequence indices and deterministic state transitions."""
    events: list[ProtocolEvent] = []
    current = ProtocolState.UNKNOWN
    for sequence_index, raw in enumerate(raw_events):
        if raw.event_type is ProtocolEventType.PLAINTEXT_COMMAND_AFTER_TLS_OFFER:
            # A plaintext command continues the existing protocol state; it
            # never opens or fails the TLS transition on its own.
            state_after = current
        else:
            state_after = _STATE_AFTER[raw.event_type]
        events.append(
            ProtocolEvent(
                event_id=protocol_event_id(
                    session_id,
                    sequence_index,
                    raw.event_type.value,
                ),
                session_id=session_id,
                sequence_index=sequence_index,
                event_type=raw.event_type,
                protocol=protocol,
                state_before=current,
                state_after=state_after,
                timestamp=raw.timestamp,
                direction=raw.direction,
                evidence_ids=list(raw.evidence_ids),
                event_status=EventStatus.OBSERVED,
                observability=ChainObservability.OBSERVED,
                limitations=[],
            )
        )
        current = state_after
    return events


def _epoch_to_utc(epoch_seconds: Decimal) -> datetime:
    """Deterministic, precision-preserving Unix-epoch conversion to UTC."""
    whole = epoch_seconds.to_integral_value(rounding=ROUND_FLOOR)
    fraction_micros = int(
        ((epoch_seconds - whole) * Decimal(1_000_000)).to_integral_value(rounding=ROUND_FLOOR)
    )
    return datetime(1970, 1, 1, tzinfo=UTC) + timedelta(
        seconds=int(whole),
        microseconds=fraction_micros,
    )
