"""Typed boundary models for the deterministic prerequisite doctor and the
E2/E3A offline capture analysis path.

The doctor models (top of file) are unchanged. Below are the typed models for
capture provenance, tool execution records, raw TCP/stream observations, SMTP
classification, and the SMTP STARTTLS transition state machine.
"""

from __future__ import annotations

from decimal import Decimal
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_serializer


class CheckStatus(StrEnum):
    """Terminal status of a single doctor check."""

    PASS = "pass"
    FAIL = "fail"


class DoctorCheck(BaseModel):
    """One deterministic prerequisite check result."""

    model_config = ConfigDict(extra="forbid")

    id: str
    requirement: str
    status: CheckStatus
    observed: str
    required: bool


class DoctorReport(BaseModel):
    """Stable machine-readable structure emitted by `securemailscope doctor`."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str
    command: str
    ready: bool
    checks: list[DoctorCheck]


# ─────────────────────────────────────────────────────────────────────────────
#  E2/E3A offline analysis path models
# ─────────────────────────────────────────────────────────────────────────────


class Direction(StrEnum):
    """Inferred direction of a frame relative to the analysed TCP stream."""

    CLIENT_TO_SERVER = "client_to_server"
    SERVER_TO_CLIENT = "server_to_client"
    UNKNOWN = "unknown"


class DirectionBasis(StrEnum):
    """How the client/server direction was inferred."""

    TCP_SYN = "tcp_syn"
    NOT_DETERMINED = "not_determined"


class Protocol(StrEnum):
    """Content-classified mail transport protocol (SMTP only in E2/E3A)."""

    SMTP = "smtp"
    IMAP = "imap"
    POP3 = "pop3"
    UNKNOWN = "unknown"


class ClassificationStatus(StrEnum):
    """Confidence category for a protocol classification decision."""

    CONFIRMED = "confirmed"
    INSUFFICIENT = "insufficient"
    CONTRADICTORY = "contradictory"


class TransitionOutcome(StrEnum):
    """Deterministic SMTP STARTTLS transition outcome."""

    ACCEPTED_TLS = "accepted_tls"
    REJECTED = "rejected"
    ACCEPTED_WITHOUT_TLS = "accepted_without_tls"
    TRUNCATED = "truncated"
    INCOMPLETE = "incomplete"


class CompleteStatus(StrEnum):
    """Completeness/observability of a reconstructed analysis result."""

    COMPLETE = "complete"
    CAPTURE_INCOMPLETE = "capture_incomplete"
    INSUFFICIENT = "insufficient"


class CaptureFormat(StrEnum):
    """Capture container format recognised from actual tool inspection."""

    PCAP = "pcap"
    PCAPNG = "pcapng"
    UNKNOWN = "unknown"


class ProvenanceStatus(StrEnum):
    """Validation status of the capture provenance pipeline."""

    OK = "ok"
    FAILED = "failed"


class EvidenceRef(BaseModel):
    """A precise stream/frame/occurrence reference for one observation.

    ``occurrence`` disambiguates multiple values of the same field inside one
    frame (0-based), never flattened into an ambiguous comma string.
    """

    model_config = ConfigDict(extra="forbid")

    tcp_stream: int
    frame: int
    occurrence: int
    direction: Direction
    field: str
    raw_value: str
    normalized_value: str


class SmtpEventCategory(StrEnum):
    """Category of a reconstructed plaintext SMTP event."""

    BANNER = "banner"
    EHLO = "ehlo"
    HELO = "helo"
    ESMTP_RESPONSE = "esmtp_response"
    STARTTLS_CAPABILITY = "starttls_capability"
    STARTTLS_COMMAND = "starttls_command"
    STARTTLS_ACCEPTANCE = "starttls_acceptance"
    STARTTLS_REJECTION = "starttls_rejection"
    TLS_CLIENT_HELLO = "tls_client_hello"
    OTHER = "other"


class SmtpEvent(BaseModel):
    """One ordered plaintext-SMTP or TLS-handshake event on a stream.

    ``occurrence`` is the 0-based index of this event *within its own frame*
    (multiple events may share a frame, e.g. a multi-line response), so the
    canonical ordering of events is ``(frame, occurrence)``.
    """

    model_config = ConfigDict(extra="forbid")

    category: SmtpEventCategory
    direction: Direction
    frame: int
    occurrence: int
    text: str


# ─────────────────────────────────────────────────────────────────────────────
#  Raw observations / provenance / tool records
# ─────────────────────────────────────────────────────────────────────────────


class RawFrameObservation(BaseModel):
    """One raw, typed TCP/TLS frame observation for a stream.

    Repeated ``tls.handshake.type`` occurrences are preserved in order in
    ``tls_handshake_types``, never flattened into an ambiguous comma string.
    ``has_client_hello`` is derived from those preserved values. A missing field
    ``()`` is distinct from an observed empty value.
    """

    model_config = ConfigDict(extra="forbid")

    frame: int
    epoch_seconds: Decimal
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    direction: Direction
    direction_basis: DirectionBasis
    tcp_stream: int
    payload: bytes = b""
    seq: Decimal = Decimal("0")
    has_payload: bool = False
    has_client_hello: bool = False
    tls_handshake_types: tuple[int, ...] = ()
    flags_syn: bool = False
    flags_ack: bool = False
    flags_fin: bool = False
    flags_rst: bool = False

    @field_serializer("payload")
    def _payload_as_hex(self, value: bytes, _info) -> str:
        return value.hex()


class TcpStream(BaseModel):
    """One discovered TCP stream with endpoints, direction, and lifecycle."""

    model_config = ConfigDict(extra="forbid")

    stream_id: int
    client_ip: str = ""
    client_port: int = 0
    server_ip: str = ""
    server_port: int = 0
    direction_basis: DirectionBasis = DirectionBasis.NOT_DETERMINED
    client_syn: bool = False
    server_syn_ack: bool = False
    fin_from_client: bool = False
    fin_from_server: bool = False
    reset_count: int = 0
    client_plaintext: bytes = b""
    server_plaintext: bytes = b""
    client_reassembled: bytes = b""
    server_reassembled: bytes = b""
    client_hello_frame: int | None = None
    frame_epochs: list[tuple[int, Decimal]] = Field(default_factory=list)
    frames: list[RawFrameObservation] = Field(default_factory=list)

    @field_serializer("client_plaintext")
    def _client_plaintext_as_hex(self, value: bytes, _info) -> str:
        return value.hex()

    @field_serializer("server_plaintext")
    def _server_plaintext_as_hex(self, value: bytes, _info) -> str:
        return value.hex()

    @field_serializer("client_reassembled")
    def _client_reassembled_as_hex(self, value: bytes, _info) -> str:
        return value.hex()

    @field_serializer("server_reassembled")
    def _server_reassembled_as_hex(self, value: bytes, _info) -> str:
        return value.hex()


class CaptureProvenance(BaseModel):
    """Immutable capture provenance computed by the intake stage."""

    model_config = ConfigDict(extra="forbid")

    input_path: str
    sha256: str
    size_bytes: int
    capture_format: CaptureFormat
    packet_count: int
    first_epoch_seconds: Decimal | None = None
    last_epoch_seconds: Decimal | None = None
    link_layer_types: list[str] = Field(default_factory=list)
    snaplen: int | None = Field(default=None, ge=1)
    truncated_packet_count: int | None = Field(default=None, ge=0)
    tshark_version: str = ""
    capinfos_version: str = ""
    status: ProvenanceStatus
    warnings: list[str] = Field(default_factory=list)


class ToolExecutionRecord(BaseModel):
    """Bounded, typed outcome of one external-tool invocation."""

    model_config = ConfigDict(extra="forbid")

    tool: str
    argument_summary: str
    stage: str
    timeout_seconds: float
    runtime_seconds: float
    exit_code: int
    succeeded: bool
    stderr_diagnostic: str = ""
    output_char_count: int = 0


# ─────────────────────────────────────────────────────────────────────────────
#  Classification / transition results
# ─────────────────────────────────────────────────────────────────────────────


class ClassificationBasis(BaseModel):
    """One matched SMTP evidence category for classification."""

    model_config = ConfigDict(extra="forbid")

    category: str
    direction: Direction
    frames: list[int] = Field(default_factory=list)
    text: str = ""


class ProtocolClassification(BaseModel):
    """Content-based protocol classification of one stream (SMTP only here)."""

    model_config = ConfigDict(extra="forbid")

    tcp_stream: int
    protocol: Protocol
    status: ClassificationStatus
    positive_evidence: list[ClassificationBasis] = Field(default_factory=list)
    contradictory_evidence: list[ClassificationBasis] = Field(default_factory=list)
    port_hints: list[int] = Field(default_factory=list)
    reason: str = ""


class SmtpTransition(BaseModel):
    """Reconstructed SMTP STARTTLS transition and its outcome."""

    model_config = ConfigDict(extra="forbid")

    tcp_stream: int
    events: list[SmtpEvent] = Field(default_factory=list)
    banner_evidence: list[int] = Field(default_factory=list)
    ehlo_evidence: list[int] = Field(default_factory=list)
    starttls_capability_evidence: list[int] = Field(default_factory=list)
    starttls_command: str = ""
    starttls_command_frames: list[int] = Field(default_factory=list)
    starttls_response_frames: list[int] = Field(default_factory=list)
    client_hello_frame: int | None = None
    client_hello_same_stream: bool = False
    outcome: TransitionOutcome = TransitionOutcome.INCOMPLETE
    completeness: CompleteStatus = CompleteStatus.INSUFFICIENT
    reasons: list[str] = Field(default_factory=list)


class AnalyzeResult(BaseModel):
    """Top-level result of the E2/E3A offline analysis path."""

    model_config = ConfigDict(extra="forbid")

    provenance: CaptureProvenance
    tool_records: list[ToolExecutionRecord] = Field(default_factory=list)
    streams: list[TcpStream] = Field(default_factory=list)
    classifications: list[ProtocolClassification] = Field(default_factory=list)
    smtp_transitions: list[SmtpTransition] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
