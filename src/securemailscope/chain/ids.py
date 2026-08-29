"""Semantic and compact stable identifiers for chain nodes (spec §4, §12).

Compact IDs never depend on UUIDs, database identifiers, display text, or
execution timestamps. Stable ``sha256:`` keys are namespace/version separated
so a schema-version change automatically produces a different key for the same
content.

Component joining uses a canonical JSON array (unambiguous, cannot collide on
component boundaries) rather than a bare delimiter.

ID shapes:
    raw digest  ``<64 lowercase hex>``           (capture/artifact SHA-256)
    stable key  ``sha256:<64 lowercase hex>``    (semantic stable keys)
    compact     ``<prefix>_<16 lowercase hex>``
"""

from __future__ import annotations

import hashlib
import json
import re

PREFIX_ANALYSIS = "ana"
PREFIX_CAPTURE = "cap"
PREFIX_SESSION = "ses"
PREFIX_EVIDENCE = "ev"
PREFIX_PROTOCOL_EVENT = "eve"
PREFIX_CRYPTO_OBSERVATION = "obs"
PREFIX_FACT = "fact"
PREFIX_RULE_EVALUATION = "eval"
PREFIX_FINDING = "fnd"
PREFIX_ANOMALY = "anm"
PREFIX_ARTIFACT = "art"
PREFIX_POLICY_RISK = "polr"
PREFIX_POLICY_CONTRIBUTION = "plc"

#: Raw SHA-256 digest: exactly 64 lowercase hex characters.
SHA256_DIGEST_PATTERN = r"^[0-9a-f]{64}$"
#: Tagged stable semantic key: ``sha256:<64 lowercase hex>``.
SHA256_KEY_PATTERN = r"^sha256:[0-9a-f]{64}$"
SEMVER_PATTERN = r"^\d+\.\d+\.\d+$"
RECOMMENDATION_PATTERN = r"^REC-[A-Z0-9]+(-[A-Z0-9]+)*$"
COMPACT_ID_PATTERN: dict[str, str] = {
    prefix: rf"^{prefix}_[0-9a-f]{{16}}$"
    for prefix in (
        PREFIX_ANALYSIS,
        PREFIX_CAPTURE,
        PREFIX_SESSION,
        PREFIX_EVIDENCE,
        PREFIX_PROTOCOL_EVENT,
        PREFIX_CRYPTO_OBSERVATION,
        PREFIX_FACT,
        PREFIX_RULE_EVALUATION,
        PREFIX_FINDING,
        PREFIX_ANOMALY,
        PREFIX_ARTIFACT,
        PREFIX_POLICY_RISK,
        PREFIX_POLICY_CONTRIBUTION,
    )
}


def _join(*parts: str) -> str:
    """Unambiguous component encoding: canonical JSON array.

    A bare delimiter can collide when one component contains the separator
    (``["a", "b\\x1fc"]`` vs ``["a\\x1fb", "c"]``). A JSON array cannot, because
    the component boundaries are structural.
    """
    return json.dumps(
        list(parts),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def stable_digest(*parts: str) -> str:
    """SHA-256 hex digest over canonically joined string parts."""
    return hashlib.sha256(_join(*parts).encode("utf-8")).hexdigest()


def stable_sha256_key(*parts: str) -> str:
    """``sha256:<hex>`` stable key over canonically joined parts."""
    return "sha256:" + stable_digest(*parts)


def short_id(prefix: str, digest: str, length: int = 16) -> str:
    """Compact ``<prefix>_<first-16-hex>`` identifier from a digest."""
    return f"{prefix}_{digest[:length]}"


def compact_id(prefix: str, *parts: str) -> str:
    """Compact identifier over deterministic parts (16-hex prefix default)."""
    return short_id(prefix, stable_digest(prefix, *parts))


def is_sha256_digest(value: str) -> bool:
    return re.fullmatch(SHA256_DIGEST_PATTERN, value) is not None


def is_sha256_key(value: str) -> bool:
    return re.fullmatch(SHA256_KEY_PATTERN, value) is not None


def is_semver(value: str) -> bool:
    return re.fullmatch(SEMVER_PATTERN, value) is not None


def is_recommendation_id(value: str) -> bool:
    return re.fullmatch(RECOMMENDATION_PATTERN, value) is not None


def is_compact_id(prefix: str, value: str) -> bool:
    pattern = COMPACT_ID_PATTERN.get(prefix)
    return pattern is not None and re.fullmatch(pattern, value) is not None


# ─────────────────────────────────────────────────────────────────────────────
#  Structural node identities (deterministic semantic helpers)
# ─────────────────────────────────────────────────────────────────────────────


def analysis_id(
    chain_schema_version: str,
    capture_sha256: str,
    configuration_digest: str,
    analyzer_version: str,
    rule_pack_id: str | None = None,
    rule_pack_version: str | None = None,
    model_id: str | None = None,
    model_version: str | None = None,
) -> str:
    """Reproducible analysis identity from capture + versioned engine inputs.

    The same capture, analyzer, rule pack and model configuration produce the
    same analysis identity regardless of execution timestamps.
    """
    return compact_id(
        PREFIX_ANALYSIS,
        "analysis",
        chain_schema_version,
        capture_sha256,
        configuration_digest,
        analyzer_version,
        rule_pack_id or "",
        rule_pack_version or "",
        model_id or "",
        model_version or "",
    )


def session_stable_key(
    chain_schema_version: str,
    capture_sha256: str,
    tcp_stream_id: int,
    client_ip: str,
    client_port: int,
    server_ip: str,
    server_port: int,
) -> str:
    """Reproducible session key from schema version, capture, stream and
    both transport endpoints. The ``tcp_stream_id`` disambiguates two streams
    that share the same four-tuple within one capture."""
    return stable_sha256_key(
        "session",
        chain_schema_version,
        capture_sha256,
        str(tcp_stream_id),
        client_ip,
        str(client_port),
        server_ip,
        str(server_port),
    )


def session_id_from_key(stable_session_key: str) -> str:
    return compact_id(PREFIX_SESSION, "identity", stable_session_key)


def capture_id_from_sha256(capture_sha256: str) -> str:
    return compact_id(PREFIX_CAPTURE, "sha256", capture_sha256)


def artifact_manifest_id(analysis_id: str, canonical_json_sha256: str) -> str:
    return compact_id(PREFIX_ARTIFACT, analysis_id, canonical_json_sha256)


def policy_risk_id(analysis_id: str, profile_id: str) -> str:
    return compact_id(PREFIX_POLICY_RISK, analysis_id, profile_id)


def policy_contribution_id(finding_id: str, rule_id: str, rule_version: str) -> str:
    return compact_id(PREFIX_POLICY_CONTRIBUTION, finding_id, rule_id, rule_version)


def evidence_id(
    capture_id: str,
    session_id: str,
    source_kind: str,
    source_field: str,
    normalized_value: str,
    frame_numbers: list[int] | tuple[int, ...] = (),
    direction: str = "",
    occurrence_index: int = 0,
) -> str:
    """Reproducible evidence identity including its packet occurrence."""
    return compact_id(
        PREFIX_EVIDENCE,
        "evidence",
        capture_id,
        session_id,
        source_kind,
        source_field,
        normalized_value,
        *[str(frame) for frame in frame_numbers],
        direction,
        str(occurrence_index),
    )


def protocol_event_id(
    session_id: str,
    sequence_index: int,
    event_type: str,
) -> str:
    """Reproducible protocol-event identity from session and ordered position."""
    return compact_id(
        PREFIX_PROTOCOL_EVENT,
        "event",
        session_id,
        str(sequence_index),
        event_type,
    )


def crypto_observation_id(
    session_id: str,
    kind: str,
    normalized_value: str,
) -> str:
    """Reproducible crypto-observation identity from session, kind and value."""
    return compact_id(
        PREFIX_CRYPTO_OBSERVATION,
        "observation",
        session_id,
        kind,
        normalized_value,
    )


def fact_stable_key(
    chain_schema_version: str,
    stable_session_key: str,
    fact_type: str,
    normalized_value: str,
    source_event_ids: list[str] = (),
    source_observation_ids: list[str] = (),
    source_fact_ids: list[str] = (),
) -> str:
    """Reproducible fact key from its session, type, value, and sorted sources."""
    return stable_sha256_key(
        "fact",
        chain_schema_version,
        stable_session_key,
        fact_type,
        normalized_value,
        *sorted(source_event_ids),
        *sorted(source_observation_ids),
        *sorted(source_fact_ids),
    )


def fact_id_from_key(stable_fact_key: str) -> str:
    return compact_id(PREFIX_FACT, "identity", stable_fact_key)


def rule_evaluation_id(
    session_id: str,
    rule_id: str,
    rule_version: str,
    profile_id: str,
) -> str:
    """Reproducible rule-evaluation identity from session and versioned rule."""
    return compact_id(
        PREFIX_RULE_EVALUATION,
        "evaluation",
        session_id,
        rule_id,
        rule_version,
        profile_id,
    )


def finding_stable_key(
    chain_schema_version: str,
    stable_session_key: str,
    rule_id: str,
    rule_version: str,
    fact_ids: list[str],
) -> str:
    """Reproducible finding key from session, rule version, and sorted facts."""
    return stable_sha256_key(
        "finding",
        chain_schema_version,
        stable_session_key,
        rule_id,
        rule_version,
        *sorted(fact_ids),
    )


def finding_id_from_key(stable_finding_key: str) -> str:
    return compact_id(PREFIX_FINDING, "identity", stable_finding_key)


def anomaly_result_id(
    session_id: str,
    model_id: str,
    model_version: str,
    feature_schema_version: str,
) -> str:
    """Reproducible anomaly-result identity from session and versioned model."""
    return compact_id(
        PREFIX_ANOMALY,
        "anomaly",
        session_id,
        model_id,
        model_version,
        feature_schema_version,
    )
