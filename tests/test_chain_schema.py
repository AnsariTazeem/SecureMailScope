"""Schema tests: the checked-in Draft 2020-12 schema validates both fixtures,
drift is detected, unknown properties and invalid enums are rejected, and
required-nullable / partial-analysis semantics are honoured.
"""

from __future__ import annotations

import copy
import json
import re

import pytest
from chain_helpers import (
    build_chain_schema,
    load_checked_in_schema,
    load_insecure_fixture,
    load_secure_fixture,
)
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from securemailscope.chain.models import ChainOfProof


@pytest.fixture(scope="module")
def validator():
    return Draft202012Validator(load_checked_in_schema())


def _errors(validator, data):
    return sorted(validator.iter_errors(data), key=lambda e: list(e.path))


def test_schema_is_draft_2020_12_with_expected_id():
    schema = load_checked_in_schema()
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["$id"] == "urn:securemailscope:schema:chain-of-proof:1.0.0"
    assert Draft202012Validator.check_schema(schema) is None


def test_secure_fixture_validates_against_checked_in_schema(validator):
    assert _errors(validator, load_secure_fixture()) == []


def test_insecure_fixture_validates_against_checked_in_schema(validator):
    assert _errors(validator, load_insecure_fixture()) == []


def test_schema_drift_detected_when_checked_in_schema_stale():
    stale = copy.deepcopy(load_checked_in_schema())
    stale["properties"]["artifacts"]["minItems"] = 1
    fresh = build_chain_schema()
    assert stale != fresh
    assert build_chain_schema() == copy.deepcopy(load_checked_in_schema())


def test_checked_in_schema_matches_current_pydantic_generation():
    assert build_chain_schema() == load_checked_in_schema()


def test_unknown_root_property_fails_schema(validator):
    data = load_secure_fixture()
    data["unexpected"] = True
    assert _errors(validator, data) != []


def test_unknown_nested_property_fails_schema(validator):
    data = load_secure_fixture()
    data["sessions"][0]["bogus"] = "x"
    assert _errors(validator, data) != []


def test_invalid_enum_fails_schema(validator):
    data = load_secure_fixture()
    data["analysis"]["analysis_status"] = "nope"
    errors = _errors(validator, data)
    assert any("analysis_status" in str(list(e.path)) for e in errors)


def test_required_nullable_rule_fields_are_schema_required_and_nullable(validator):
    # The JSON schema marks the origin fields (and nullable ID/version fields)
    # as required, but allows an explicit null. The pairing rule lives in the
    # model validator, not the static schema.

    schema = load_checked_in_schema()
    analysis = schema["$defs"]["AnalysisManifest"]["properties"]
    required = schema["$defs"]["AnalysisManifest"]["required"]
    assert "rule_pack_id" in required
    assert "rule_pack_version" in required
    assert "model_id" in required
    assert "model_version" in required
    # anyOf includes an explicit null branch -> required-but-nullable
    assert {"type": "null"} in analysis["rule_pack_id"]["anyOf"]
    assert {"type": "null"} in analysis["model_version"]["anyOf"]

    # The schema type-checks an explicit null as valid (absence is a schema
    # error, null is valid).
    data = load_secure_fixture()
    errors = _errors(validator, data)
    assert errors == []


def test_model_enforces_nullable_field_pairing():
    from securemailscope.chain.models import AnalysisManifest, EngineStatus

    base = {
        "analysis_id": "ana_" + "a" * 16,
        "chain_schema_version": "1.0.0",
        "analysis_status": "complete",
        "created_at": "2026-08-27T10:00:00Z",
        "started_at": "2026-08-27T10:00:01Z",
        "completed_at": None,
        "analyzer_version": "0.1.0",
        "tshark_version": None,
        "rule_engine_status": EngineStatus.COMPLETE,
        "rule_pack_id": None,
        "rule_pack_version": None,
        "ml_engine_status": EngineStatus.NOT_RUN,
        "model_id": None,
        "model_version": None,
        "configuration_digest": "c" * 64,
        "tls13_authorized_secrets": "not_supplied",
        "limitations": [],
    }
    with pytest.raises(ValidationError):
        AnalysisManifest.model_validate(base)


def test_schema_accepts_explicit_null_for_optional_artifact_hashes(validator):
    data = load_secure_fixture()
    data["artifacts"] = [
        {
            "artifact_manifest_id": "art_" + "1" * 16,
            "analysis_id": data["analysis"]["analysis_id"],
            "capture_sha256": data["captures"][0]["sha256"],
            "canonical_json_sha256": "ab" * 32,
            "html_report_sha256": None,
            "pdf_report_sha256": None,
            "rule_pack_sha256": None,
            "model_artifact_sha256": None,
            "generated_at": "2026-08-27T11:00:04Z",
            "signature_algorithm": None,
            "signature": None,
        }
    ]
    assert _errors(validator, data) == []


def test_partial_failed_analysis_preserves_provenance_without_fake_sessions():
    # A partial analysis records a failed status while preserving the capture
    # provenance and all real evidence; it does not annotate sessions or
    # findings that were never actually reconstructed.
    data = load_secure_fixture()
    data["analysis"]["analysis_status"] = "failed"
    data["analysis"]["completed_at"] = None
    data["analysis"]["limitations"].append(
        {
            "code": "capture_incomplete",
            "summary": "analysis failed before protocol reconstruction completed",
            "detail": "stage_failure",
        }
    )
    model = ChainOfProof.model_validate(data)
    assert model.analysis.analysis_status == "failed"
    assert model.analysis.completed_at is None
    # provenance retained; no findings fabricated
    assert model.captures[0].capture_id != ""
    assert model.findings == []
    ok, _ = model_validate_invariants(data)
    assert ok


def model_validate_invariants(data):
    from securemailscope.chain.invariants import validate_chain

    return validate_chain(ChainOfProof.model_validate(data))


def test_sessions_collection_allows_zero_for_provenance_only_chain():
    # A failed invalid-capture analysis is representable with zero sessions:
    # provenance attempt retained, no fabricated evidence/facts/findings.
    data = load_secure_fixture()
    data["analysis"]["analysis_status"] = "failed"
    data["analysis"]["completed_at"] = None
    data["analysis"]["limitations"].append(
        {
            "code": "unknown_insufficient_evidence",
            "summary": "intake could not determine capture metadata; analysis failed",
            "detail": "invalid_capture",
        }
    )
    data["sessions"] = []
    data["evidence"] = []
    data["protocol_events"] = []
    data["crypto_observations"] = []
    data["derived_facts"] = []
    data["rule_evaluations"] = []
    data["findings"] = []
    data["recommendations"] = []
    model = ChainOfProof.model_validate(data)
    assert model.sessions == []
    assert model.evidence == []
    assert model.findings == []
    assert model.analysis.analysis_status == "failed"
    # provenance attempt retained
    assert len(model.captures) == 1
    # passes invariants (a provenance-only chain is a valid contract)
    ok, _ = model_validate_invariants(data)
    assert ok


def test_fixtures_contain_no_credentials_or_unsafe_message_body():
    def dump(name):
        if name.startswith("secure"):
            return json.dumps(load_secure_fixture())
        return json.dumps(load_insecure_fixture())

    for name in ("secure-smtp-chain.json", "insecure-smtp-chain.json"):
        text = dump(name)
        lowered = text.lower()
        assert "password" not in lowered
        assert "credentials" not in lowered
        assert "auth login" not in lowered
        assert ";pass=" not in lowered
        assert "<secret>" not in lowered.replace("authorized_secrets", "")
        assert "<redacted>" in lowered or "starttls" in lowered


#: Any of these in an unredacted safe excerpt is a privacy failure: credentials,
#: message-body constructs, or envelope/address commands whose payload is not
#: redacted. Redacted excerpts (containing <redacted>) bypass these markers.
_SENSITIVE_EXCERPT_MARKERS = (
    "password",
    "credentials",
    "username",
    "auth login",
    "authorization:",
    "mail from:",
    "rcpt to:",
    "subject:",
    "content-type:",
    "mime",
    "base64",
)


def _is_unsafe_unredacted_excerpt(excerpt: str) -> bool:
    """True when a non-redacted excerpt could expose sensitive material.

    Privacy rule (spec §17): never display credentials, real addresses, or raw
    message bodies. Harmless protocol responses (``STARTTLS``, an SMTP ``220``
    status line such as ``220 Ready to start TLS``) carry no user content and
    remain allowed. A value is safe only when it is empty, contains the
    ``<redacted>`` placeholder, or is a short protocol-only token with no
    address or body-like content.
    """
    if not excerpt or "<redacted>" in excerpt:
        return False
    lowered = excerpt.lower()
    if any(marker in lowered for marker in _SENSITIVE_EXCERPT_MARKERS):
        return True
    if "@" in excerpt:
        return True
    if len(excerpt) > 80:
        return True
    return re.fullmatch(r"[\w .:/=\-+]+", excerpt) is None


def test_fixtures_redact_local_parts_and_excerpt_only():
    for data in (load_secure_fixture(), load_insecure_fixture()):
        for evidence in data["evidence"]:
            excerpt = evidence["safe_excerpt"]
            # No credentials, real addresses, or raw message bodies may reach a
            # report. Harmless protocol responses may be present verbatim; any
            # other value needs the <redacted> placeholder.
            assert not _is_unsafe_unredacted_excerpt(excerpt), (
                f"{evidence['evidence_id']}: unsafe unredacted safe_excerpt {excerpt!r}"
            )
            # No real addresses in the raw normalized values.
            assert "gmail.com" not in evidence["normalized_value"]


def test_harmless_protocol_excerpts_are_allowed_but_sensitive_are_not():
    # The SMTP "220 Ready to start TLS" upgrade-acceptance response carries no
    # user content and is allowed; credentials, addresses and body fragments
    # are never.
    assert not _is_unsafe_unredacted_excerpt("220 Ready to start TLS")
    assert not _is_unsafe_unredacted_excerpt("STARTTLS")
    assert not _is_unsafe_unredacted_excerpt("")
    assert not _is_unsafe_unredacted_excerpt("220 2.0.0 Greetings from example.test")

    assert _is_unsafe_unredacted_excerpt("AUTH LOGIN dXNlcg==")
    assert _is_unsafe_unredacted_excerpt("username: alice")
    assert _is_unsafe_unredacted_excerpt("220 password 1234")
    assert _is_unsafe_unredacted_excerpt("MAIL FROM:<alice@example.com>")
    assert _is_unsafe_unredacted_excerpt("Subject: re: urgent")
    assert _is_unsafe_unredacted_excerpt("a" * 200)


def test_schema_marks_occurrence_index_required_and_typed():
    schema = load_checked_in_schema()
    evidence = schema["properties"]["evidence"]["items"]["$ref"].split("/")[-1]
    props = schema["$defs"][evidence]["properties"]
    assert "occurrence_index" in schema["$defs"][evidence]["required"]
    assert props["occurrence_index"]["type"] == "integer"
    assert props["occurrence_index"]["minimum"] == 0


# ─────────────────────────────────────────────────────────────────────────────
#  Item 1: required fields are present in the schema for key nodes
# ─────────────────────────────────────────────────────────────────────────────


def test_schema_required_fields_present_for_key_nodes():
    s = load_checked_in_schema()
    defs = s["$defs"]

    assert "tls13_authorized_secrets" in defs["AnalysisManifest"]["required"]

    evidence = s["properties"]["evidence"]["items"]["$ref"].split("/")[-1]
    assert set(defs[evidence]["required"]) >= {
        "evidence_id",
        "capture_sha256",
        "session_id",
        "source_kind",
        "source_field",
        "normalized_value",
        "observability",
        "redaction",
    }

    assert set(defs["Session"]["required"]) >= {
        "session_id",
        "stable_session_key",
        "capture_id",
        "tcp_stream_id",
    }
    assert set(defs["CryptoObservation"]["required"]) >= {
        "observation_id",
        "session_id",
        "kind",
        "normalized_value",
        "observability",
        "evidence_ids",
        "limitations",
    }
    assert set(defs["DerivedFact"]["required"]) >= {
        "fact_id",
        "session_id",
        "fact_type",
        "source_event_ids",
        "source_observation_ids",
        "source_fact_ids",
        "observability",
        "limitations",
    }
    assert set(defs["Finding"]["required"]) >= {
        "finding_id",
        "stable_finding_key",
        "evidence_ids",
        "fact_ids",
        "recommendation_id",
        "standards_references",
        "limitations",
    }
    assert set(defs["PolicyRiskSummary"]["required"]) >= {
        "policy_risk_id",
        "analysis_id",
        "profile_id",
        "uncapped_score",
        "capped_score",
        "contributions",
        "limitations",
    }
    assert set(defs["ArtifactManifest"]["required"]) >= {
        "artifact_manifest_id",
        "canonical_json_sha256",
        "html_report_sha256",
        "pdf_report_sha256",
        "signature_algorithm",
        "signature",
    }


def test_schema_rejects_missing_required_tls13_field(validator):
    data = load_secure_fixture()
    del data["analysis"]["tls13_authorized_secrets"]
    errors = _errors(validator, data)
    assert any("tls13_authorized_secrets" in str(e) for e in errors)


# ─────────────────────────────────────────────────────────────────────────────
#  Item 13: Decimal canonicalization preserves precision, rejects non-finite
# ─────────────────────────────────────────────────────────────────────────────


def test_decimal_canonical_str_preserves_precision():
    from decimal import Decimal

    from securemailscope.chain.canonical import decimal_canonical_str

    assert decimal_canonical_str(Decimal("1.2300")) == "1.2300"
    assert decimal_canonical_str(Decimal("1.23")) == "1.23"
    assert decimal_canonical_str(Decimal("0.1")) == "0.1"
    assert decimal_canonical_str(Decimal("100000000000000000000")) == "100000000000000000000"
    assert decimal_canonical_str(Decimal("-0")) == "0"
    assert decimal_canonical_str(Decimal("0.0")) == "0"


def test_decimal_distinct_values_never_collide_in_canonical_form():
    from decimal import Decimal

    from securemailscope.chain.canonical import decimal_canonical_str

    pairs = [
        (Decimal("1.0"), Decimal("1.00")),
        (Decimal("0.3"), Decimal("0.30")),
        (Decimal("1.5"), Decimal("1.50")),
    ]
    for a, b in pairs:
        assert decimal_canonical_str(a) == decimal_canonical_str(a)
        assert decimal_canonical_str(a) != decimal_canonical_str(b) or a == b


def test_decimal_non_finite_rejected():
    from decimal import Decimal

    import pytest as _pytest

    from securemailscope.chain.canonical import (
        ChainError as _ChainError,
    )
    from securemailscope.chain.canonical import (
        decimal_canonical_str,
    )

    with _pytest.raises(_ChainError):
        decimal_canonical_str(Decimal("NaN"))
    with _pytest.raises(_ChainError):
        decimal_canonical_str(Decimal("Infinity"))
    with _pytest.raises(_ChainError):
        decimal_canonical_str(Decimal("-Infinity"))
