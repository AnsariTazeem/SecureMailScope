"""Versioned enums for the Chain-of-Proof graph contract (spec schema 1.0.0).

These enums are the stable vocabulary of the chain graph itself. Stable POC
enums that already exist (``Direction``, ``Protocol``, ``CaptureFormat``,
``CompleteStatus``) are reused from :mod:`securemailscope.models` and are not
re-declared here.

The ``Observability`` vocabulary deliberately follows the Chain of Proof
specification (§6.1) rather than the earlier POC observation vocabulary. The
legacy analyzer-to-chain observability mapping belongs to the Commit 2 adapter
and is intentionally not declared or frozen in this contract package.
"""

from __future__ import annotations

from enum import StrEnum


class ChainObservability(StrEnum):
    """Observability of a chain node, exactly as defined by spec §6.1.

    ``session_secrets_required`` describes protected TLS evidence (for example
    the encrypted TLS 1.3 certificate) that requires authorized session secrets
    to interpret. It is a valid result, never a value to be guessed.
    """

    OBSERVED = "observed"
    DERIVED = "derived"
    POLICY_INFERRED = "policy_inferred"
    NOT_OBSERVABLE = "not_observable"
    INCOMPLETE_CAPTURE = "incomplete_capture"
    SESSION_SECRETS_REQUIRED = "session_secrets_required"
    NOT_APPLICABLE = "not_applicable"


class ConfidenceLevel(StrEnum):
    """Confidence with an explicit basis (spec §6.2)."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NOT_SCORED = "not_scored"


class AnalysisStatus(StrEnum):
    """Overall status of a reproducible analysis execution."""

    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"


class StageStatus(StrEnum):
    """Status of one analysis stage inside the execution envelope."""

    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"
    NOT_RUN = "not_run"
    SKIPPED = "skipped"


class StageId(StrEnum):
    """Short identifiers for analysis stages used in typed diagnostics."""

    INTAKE = "intake"
    CAPTURE_PROVENANCE = "capture_provenance"
    STREAM_RECONSTRUCTION = "stream_reconstruction"
    EVENT_RECONSTRUCTION = "event_reconstruction"
    TLS_EXTRACTION = "tls_extraction"
    FACT_DERIVATION = "fact_derivation"
    POLICY_EVALUATION = "policy_evaluation"
    ANOMALY_SCORING = "anomaly_scoring"
    REPORT_GENERATION = "report_generation"
    ARTIFACT_MANIFEST = "artifact_manifest"


class EngineStatus(StrEnum):
    """Believability of a versioned sub-engine output.

    ``not_run`` is used when no rule pack or model was evaluated. A typed
    status is used instead of magic-string "-none" sentinel values.
    """

    NOT_RUN = "not_run"
    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"
    UNAVAILABLE = "unavailable"


class Tls13SecretsStatus(StrEnum):
    """Whether authorized TLS 1.3 session secrets were supplied for a capture.

    The contract records only *that* authorized secrets were supplied, never the
    secret material itself. ``not_supplied`` forces TLS 1.3 certificate details
    to ``session_secrets_required``/``not_observable``; ``authorized_supplied``
    permits observed certificate details that reference actual evidence.
    """

    NOT_SUPPLIED = "not_supplied"
    AUTHORIZED_SUPPLIED = "authorized_supplied"


class EvidenceSourceKind(StrEnum):
    """Provenance kind of an evidence extraction (spec §4.4)."""

    CAPINFOS = "capinfos"
    TSHARK_FIELD = "tshark_field"
    TSHARK_FOLLOW_STREAM = "tshark_follow_stream"
    TSHARK_EXPERT = "tshark_expert"
    CRYPTOGRAPHY_LIBRARY = "cryptography_library"
    DERIVED_STATE_MACHINE = "derived_state_machine"


class EvidenceRedaction(StrEnum):
    """Redaction applied to a safe excerpt or normalized value.

    ``none`` means the value contains no sensitive material by construction.
    """

    NONE = "none"
    REDACTED_LOCAL_PART = "redacted_local_part"
    REDACTED_CREDENTIAL = "redacted_credential"
    HASHED = "hashed"
    EXCERPT_ONLY = "excerpt_only"


class ProtocolEventType(StrEnum):
    """Ordered protocol or TLS transition event types (spec §4.5)."""

    TCP_CONNECTED = "tcp_connected"
    SERVER_GREETING = "server_greeting"
    CAPABILITY_REQUEST = "capability_request"
    CAPABILITY_ADVERTISED = "capability_advertised"
    TLS_UPGRADE_REQUESTED = "tls_upgrade_requested"
    TLS_UPGRADE_ACCEPTED = "tls_upgrade_accepted"
    TLS_UPGRADE_REJECTED = "tls_upgrade_rejected"
    CLIENT_HELLO = "client_hello"
    SERVER_HELLO = "server_hello"
    CERTIFICATE_MESSAGE = "certificate_message"
    KEY_EXCHANGE_OBSERVED = "key_exchange_observed"
    HANDSHAKE_FINISHED = "handshake_finished"
    ENCRYPTED_APPLICATION_DATA = "encrypted_application_data"
    PLAINTEXT_COMMAND_AFTER_TLS_OFFER = "plaintext_command_after_tls_offer"
    SESSION_CLOSED = "session_closed"
    CAPTURE_BOUNDARY_REACHED = "capture_boundary_reached"


class ProtocolState(StrEnum):
    """Reconstructed protocol state used for transition before/after values."""

    CONNECTION_OPEN = "connection_open"
    GREETING = "greeting"
    READY = "ready"
    TLS_OFFERED = "tls_offered"
    TLS_REQUESTED = "tls_requested"
    TLS_NEGOTIATING = "tls_negotiating"
    TLS_ACTIVE = "tls_active"
    TLS_FAILED = "tls_failed"
    CLOSED = "closed"
    UNKNOWN = "unknown"


class EventStatus(StrEnum):
    """How an event relates to directly observed evidence."""

    OBSERVED = "observed"
    INFERRED = "inferred"
    INCOMPLETE_CAPTURE = "incomplete_capture"
    NOT_OBSERVABLE = "not_observable"


class ObservationKind(StrEnum):
    """Observable TLS/X.509 fact kinds (spec §4.6), plus the explicit
    unobservable-certificate kind for passive TLS 1.3 captures."""

    TLS_NEGOTIATED_VERSION = "tls_negotiated_version"
    SELECTED_CIPHER_SUITE = "selected_cipher_suite"
    RECORD_LAYER_LEGACY_VERSION = "record_layer_legacy_version"
    SUPPORTED_VERSIONS = "supported_versions"
    KEY_SHARE_GROUP = "key_share_group"
    PSK_KEY_EXCHANGE_MODE = "psk_key_exchange_mode"
    SIGNATURE_ALGORITHM = "signature_algorithm"
    PUBLIC_KEY_ALGORITHM = "public_key_algorithm"
    PUBLIC_KEY_LENGTH = "public_key_length"
    CERTIFICATE_SUBJECT = "certificate_subject"
    CERTIFICATE_ISSUER = "certificate_issuer"
    CERTIFICATE_SAN = "certificate_san"
    CERTIFICATE_VALIDITY_WINDOW = "certificate_validity_window"
    CERTIFICATE_FINGERPRINT = "certificate_fingerprint"
    CERTIFICATE_CHAIN_STRUCTURE = "certificate_chain_structure"
    CERTIFICATE_SERIAL_NUMBER = "certificate_serial_number"
    CERTIFICATE_BASIC_CONSTRAINTS = "certificate_basic_constraints"
    CERTIFICATE_KEY_USAGE = "certificate_key_usage"
    CERTIFICATE_STRUCTURE_PARSED = "certificate_structure_parsed"
    CERTIFICATE_SIGNATURE_CHAIN_CHECKED = "certificate_signature_chain_checked"
    CERTIFICATE_TRUSTED_PATH_VALIDATED = "certificate_trusted_path_validated"
    CERTIFICATE_SERVICE_IDENTITY_VALIDATED = "certificate_service_identity_validated"
    CERTIFICATE_REVOCATION_CHECKED = "certificate_revocation_checked"
    SESSION_RESUMPTION_INDICATOR = "session_resumption_indicator"
    TLS13_CERTIFICATE_UNAVAILABLE = "tls13_certificate_unavailable"


class RuleOutcome(StrEnum):
    """Policy-rule evaluation outcomes (spec §4.8)."""

    MATCHED = "matched"
    NOT_MATCHED = "not_matched"
    NOT_APPLICABLE = "not_applicable"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    SUPPRESSED_BY_PROFILE = "suppressed_by_profile"


class RuleReasonCode(StrEnum):
    """Machine-readable reason for a rule evaluation outcome."""

    RULE_MATCHED = "rule_matched"
    RULE_NOT_MATCHED = "rule_not_matched"
    NOT_APPLICABLE_PROTOCOL = "not_applicable_protocol"
    FACTS_MISSING = "facts_missing"
    EVIDENCE_INCOMPLETE = "evidence_incomplete"
    PROFILE_SUPPRESSED = "profile_suppressed"


class SeverityLevel(StrEnum):
    """Finding severity (policy-risk points derived deterministically)."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingCategory(StrEnum):
    """Stable finding categories used by the v1 rule surface."""

    ENCRYPTION_TRANSITION = "encryption_transition"
    TLS_VERSION = "tls_version"
    KEY_EXCHANGE = "key_exchange"
    CERTIFICATE_VALIDITY = "certificate_validity"
    CERTIFICATE_IDENTITY = "certificate_identity"
    AUTHENTICATION = "authentication"
    SENSITIVE_DATA = "sensitive_data"
    CONFIGURATION = "configuration"
    NOT_CLASSIFIED = "not_classified"


class AnomalyBand(StrEnum):
    """Calibrated ML anomaly bands, separate from policy risk."""

    NORMAL = "normal"
    ATTENTION = "attention"
    ELEVATED = "elevated"
    ANOMALOUS = "anomalous"


class RecommendationPriority(StrEnum):
    """Recommendation priority tiers."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class RecommendationScope(StrEnum):
    """Scope a recommendation applies to."""

    SESSION = "session"
    CAPTURE = "capture"
    SERVICE = "service"
    DEPLOYMENT = "deployment"


class AutomationStatus(StrEnum):
    """What SecureMailScope may do automatically.

    For v1 this is always ``advisory_only``; the tool never alters
    infrastructure.
    """

    ADVISORY_ONLY = "advisory_only"


class LimitationCode(StrEnum):
    """Stable reason codes for limitations on evidence and conclusions.

    The codes preserve the exact vocabulary used by the earlier analyzer
    output plus the explicit TLS 1.3 and capture-boundary reasons.
    """

    DERIVED_FROM_OBSERVED = "derived_from_observed"
    NOT_OBSERVABLE_ENCRYPTED_TLS13 = "not_observable_encrypted_tls13"
    NOT_PRESENT = "not_present"
    CAPTURE_INCOMPLETE = "capture_incomplete"
    UNKNOWN_INSUFFICIENT_EVIDENCE = "unknown_insufficient_evidence"
    SESSION_SECRETS_REQUIRED = "session_secrets_required"
    FIELD_UNAVAILABLE = "field_unavailable"
    NOT_ASSESSED = "not_assessed"
    NOT_APPLICABLE = "not_applicable"


class EdgeType(StrEnum):
    """Canonical graph edge semantics (spec §5).

    The serialized chain stores these relationships as direct reference fields
    rather than a separate edge table; this enum documents the fixed semantics.
    """

    ANALYZED_FROM = "analyzed_from"
    CONTAINS_SESSION = "contains_session"
    HAS_EVENT = "has_event"
    SUPPORTED_BY = "supported_by"
    OBSERVED_AS = "observed_as"
    DERIVED_FROM = "derived_from"
    EVALUATED_BY = "evaluated_by"
    PRODUCED = "produced"
    PRIORITIZED_WITH = "prioritized_with"
    REMEDIATED_BY = "remediated_by"
    REPRESENTED_IN = "represented_in"
    SUPERSEDES = "supersedes"
