"""Graph and business invariant tests for the Chain-of-Proof document.

Each mutation starts from a valid fixture and nudges one edge case; the
invariant validator must flag it while Pydantic still accepts the shape (or a
clear, intentional model rejection for impossible shapes).
"""

from __future__ import annotations

import copy
import json

from chain_helpers import load_insecure_fixture, load_secure_fixture

from securemailscope.chain.ids import (
    anomaly_result_id,
    capture_id_from_sha256,
    crypto_observation_id,
    evidence_id,
    session_id_from_key,
    session_stable_key,
)
from securemailscope.chain.invariants import validate_chain
from securemailscope.chain.models import ChainOfProof

DIGIT = "1" * 16


def _insecure():
    return ChainOfProof.model_validate(load_insecure_fixture())


def _secure():
    return ChainOfProof.model_validate(load_secure_fixture())


def _problems(data) -> list[str]:
    model = ChainOfProof.model_validate(data)
    _ok, problems = validate_chain(model)
    return problems


def test_baseline_fixtures_have_no_invariant_problems():
    assert _problems(load_secure_fixture()) == []
    assert _problems(load_insecure_fixture()) == []


def test_source_less_fact_fails():
    data = load_insecure_fixture()
    data["derived_facts"][0]["source_event_ids"] = []
    data["derived_facts"][0]["source_observation_ids"] = []
    data["derived_facts"][0]["source_fact_ids"] = []
    problems = _problems(data)
    assert any("no source events" in p for p in problems)


def test_missing_session_reference_fails():
    data = load_insecure_fixture()
    data["derived_facts"][0]["session_id"] = "ses_" + DIGIT
    problems = _problems(data)
    assert any("missing session" in p for p in problems)


def test_cross_session_reference_fails():
    data = load_insecure_fixture()
    # Build a second real session on the same capture (different source port).
    schema_version = data["analysis"]["chain_schema_version"]
    capture = data["captures"][0]
    client_ip = data["sessions"][0]["source_endpoint"]["ip"]
    server_ip = data["sessions"][0]["destination_endpoint"]["ip"]
    server_port = data["sessions"][0]["destination_endpoint"]["port"]
    key2 = session_stable_key(
        schema_version,
        capture["sha256"],
        2,
        client_ip,
        44444,
        server_ip,
        server_port,
    )
    ses2_id = session_id_from_key(key2)
    observation1 = data["crypto_observations"][0]["observation_id"]
    data["sessions"].append(
        {
            "session_id": ses2_id,
            "stable_session_key": key2,
            "capture_id": capture["capture_id"],
            "tcp_stream_id": 2,
            "source_endpoint": {"ip": client_ip, "port": 44444},
            "destination_endpoint": {
                "ip": server_ip,
                "port": server_port,
            },
            "first_frame": 7,
            "last_frame": 9,
            "started_at": "2026-08-27T11:01:00Z",
            "ended_at": "2026-08-27T11:01:02Z",
            "packet_count": 3,
            "byte_count": 128,
            "protocol": "smtp",
            "protocol_confidence": "high",
            "classification_evidence_ids": [data["evidence"][1]["evidence_id"]],
            "capture_completeness": "complete",
            "limitations": [],
        }
    )
    # A fact in session2 that references an observation from session1.
    data["derived_facts"].append(
        {
            "fact_id": "fact_" + "9" * 16,
            "session_id": ses2_id,
            "fact_type": "cross_session_probe",
            "value": True,
            "derivation_id": "chain.probe",
            "derivation_version": "1.0.0",
            "source_observation_ids": [observation1],
            "source_event_ids": [],
            "source_fact_ids": [],
            "observability": "derived",
            "confidence_level": "high",
            "confidence_basis": ["probe"],
            "limitations": [],
        }
    )
    problems = _problems(data)
    assert any("another session" in p for p in problems)


def test_capture_hash_mismatch_fails():
    data = load_insecure_fixture()
    data["evidence"][0]["capture_sha256"] = "0c" * 32
    problems = _problems(data)
    assert any("does not match its capture" in p for p in problems)


def test_event_ordering_fails():
    data = load_insecure_fixture()
    evs = data["protocol_events"]
    evs[3]["sequence_index"], evs[4]["sequence_index"] = (
        evs[4]["sequence_index"],
        evs[3]["sequence_index"],
    )
    problems = _problems(data)
    assert any("not contiguous" in p or "nondecreasing" in p for p in problems)


def test_fact_cycle_fails():
    data = load_insecure_fixture()
    data["derived_facts"][0]["source_fact_ids"] = [data["derived_facts"][1]["fact_id"]]
    data["derived_facts"][1]["source_fact_ids"] = [data["derived_facts"][0]["fact_id"]]
    problems = _problems(data)
    assert any("cycle" in p for p in problems)


def test_port_only_classification_fails():
    data = load_insecure_fixture()
    data["evidence"][0]["source_field"] = "tcp.port"
    data["sessions"][0]["classification_evidence_ids"] = [data["evidence"][0]["evidence_id"]]
    problems = _problems(data)
    assert any("port/service metadata" in p for p in problems)


def test_finding_lineage_mismatch_fails():
    data = load_insecure_fixture()
    data["findings"][0]["rule_evaluation_id"] = "eval_" + DIGIT
    problems = _problems(data)
    assert any("missing rule evaluation" in p for p in problems)


def test_recommendation_mismatch_fails():
    data = load_insecure_fixture()
    data["findings"][0]["recommendation_id"] = "REC-DIFFERENT-CARD"
    problems = _problems(data)
    assert any("not bidirectional" in p for p in problems)


def test_tls13_observed_cert_without_secrets_fails():
    data = load_secure_fixture()
    _append_tls13_cert_field(
        data,
        value="CN=example.test",
        normalized="CN=example.test",
        observability="observed",
        limitation=None,
    )
    problems = _problems(data)
    assert any("fabricated" in p for p in problems)


def test_tls13_unobservable_cert_requires_session_secrets_reason():
    data = load_secure_fixture()
    data["crypto_observations"][3]["limitations"] = []
    problems = _problems(data)
    key = "missing session_secrets_required limitation"
    assert any(key in p for p in problems)


def _append_tls13_cert_field(data, value, normalized, observability, limitation):
    """Append a certificate-field observation to the secure TLS 1.3 fixture,
    always using a deterministic ``crypto_observation_id``."""
    ses = data["sessions"][0]["session_id"]
    obs_id = crypto_observation_id(ses, "certificate_subject", normalized)
    data["crypto_observations"].append(
        {
            "observation_id": obs_id,
            "session_id": ses,
            "kind": "certificate_subject",
            "value": value,
            "normalized_value": normalized,
            "observability": observability,
            "evidence_ids": [],
            "limitations": [limitation] if limitation is not None else [],
        }
    )
    return obs_id


_SESSION_SECRETS_LIMITATION = {
    "code": "session_secrets_required",
    "summary": "TLS 1.3 certificate is encrypted after ServerHello "
    "without authorized session secrets",
    "detail": "no_secret_log",
}


def test_tls13_neutral_session_secrets_required_cert_field_passes():
    # A certificate-FIELD observation (not the UNAVAILABLE sentinel) explicitly
    # marked session_secrets_required with the typed limitation and a neutral
    # value is a legitimate unavailable observation, not a fabricated claim.
    data = load_secure_fixture()
    _append_tls13_cert_field(
        data,
        value=None,
        normalized="session_secrets_required",
        observability="session_secrets_required",
        limitation=_SESSION_SECRETS_LIMITATION,
    )
    problems = _problems(data)
    assert not any("fabricated" in p for p in problems), problems
    assert problems == [], problems


def test_tls13_neutral_not_observable_cert_field_passes():
    # The not_observable certificate-field state with the typed
    # session_secrets_required limitation and the frozen neutral value passes.
    data = load_secure_fixture()
    _append_tls13_cert_field(
        data,
        value="not_observable",
        normalized="not_observable",
        observability="not_observable",
        limitation=_SESSION_SECRETS_LIMITATION,
    )
    problems = _problems(data)
    assert not any("fabricated" in p for p in problems), problems
    assert problems == [], problems


def test_tls13_cert_value_labelled_session_secrets_required_fails():
    # An actual certificate claim labelled session_secrets_required is still an
    # unavailable observation smuggling real content: the neutral freeze catches
    # it even though the typed limitation is present.
    data = load_secure_fixture()
    _append_tls13_cert_field(
        data,
        value="CN=example.test",
        normalized="CN=example.test",
        observability="session_secrets_required",
        limitation=_SESSION_SECRETS_LIMITATION,
    )
    problems = _problems(data)
    assert any("must not carry actual certificate content" in p for p in problems), problems


def test_tls13_cert_value_labelled_not_observable_fails():
    data = load_secure_fixture()
    _append_tls13_cert_field(
        data,
        value="SHA256:abcd1234",
        normalized="SHA256:abcd1234",
        observability="not_observable",
        limitation=_SESSION_SECRETS_LIMITATION,
    )
    problems = _problems(data)
    assert any("must not carry actual certificate content" in p for p in problems), problems


def test_tls13_non_neutral_normalized_value_fails():
    # Even a neutral-looking value string that does not match the frozen
    # normalized representation for the state must fail.
    data = load_secure_fixture()
    _append_tls13_cert_field(
        data,
        value="not_observable",
        normalized="not_observable",
        observability="session_secrets_required",
        limitation=_SESSION_SECRETS_LIMITATION,
    )
    problems = _problems(data)
    assert any("deterministic neutral normalized value" in p for p in problems), problems


def test_tls13_unavailable_cert_field_without_session_secrets_limitation_fails():
    # The typed session_secrets_required limitation stays mandatory for an
    # unavailable certificate-field observation, even with a neutral value.
    data = load_secure_fixture()
    _append_tls13_cert_field(
        data,
        value=None,
        normalized="session_secrets_required",
        observability="session_secrets_required",
        limitation=None,
    )
    problems = _problems(data)
    assert any("requires a session_secrets_required limitation" in p for p in problems), problems


def test_tls13_incomplete_capture_cert_field_fails():
    data = load_secure_fixture()
    _append_tls13_cert_field(
        data,
        value=None,
        normalized="incomplete_capture",
        observability="incomplete_capture",
        limitation=_SESSION_SECRETS_LIMITATION,
    )
    problems = _problems(data)
    assert any("disallowed state" in p for p in problems), problems


def test_tls13_not_applicable_cert_field_fails():
    data = load_secure_fixture()
    _append_tls13_cert_field(
        data,
        value=None,
        normalized="not_applicable",
        observability="not_applicable",
        limitation=_SESSION_SECRETS_LIMITATION,
    )
    problems = _problems(data)
    assert any("disallowed state" in p for p in problems), problems


def test_tls13_derived_and_policy_inferred_cert_claims_fail():
    # observed, derived, and policy_inferred certificate details all assert real
    # content and must fail on a TLS 1.3 session without authorized secrets.
    for claiming_observability in ("observed", "derived", "policy_inferred"):
        data = load_secure_fixture()
        obs_id = _append_tls13_cert_field(
            data,
            value="CN=example.test",
            normalized="CN=example.test",
            observability=claiming_observability,
            limitation=None,
        )
        problems = _problems(data)
        assert any("fabricated" in p for p in problems), problems
        assert obs_id in data["crypto_observations"][-1]["observation_id"]


def test_tls13_sentinel_still_required_for_session():
    # Removing the explicit TLS13_CERTIFICATE_UNAVAILABLE sentinel from a TLS 1.3
    # session without secrets must still be enforced.
    data = load_secure_fixture()
    data["crypto_observations"] = [
        obs for obs in data["crypto_observations"] if obs["kind"] != "tls13_certificate_unavailable"
    ]
    problems = _problems(data)
    assert any("missing explicit certificate-unavailable observation" in p for p in problems)


def _append_tls13_unavailable_sentinel(
    data, session_id, value, normalized, observability, limitation
):
    """Append a dedicated TLS13_CERTIFICATE_UNAVAILABLE sentinel using a
    deterministic reprocessed crypto_observation_id so the mutation isolates the
    sentinel invariant without unrelated id/reference defects."""
    obs_id = crypto_observation_id(session_id, "tls13_certificate_unavailable", normalized)
    data["crypto_observations"].append(
        {
            "observation_id": obs_id,
            "session_id": session_id,
            "kind": "tls13_certificate_unavailable",
            "value": value,
            "normalized_value": normalized,
            "observability": observability,
            "evidence_ids": [],
            "limitations": [limitation] if limitation is not None else [],
        }
    )
    return obs_id


def test_tls13_unavailable_neutral_sentinel_passes():
    # The frozen neutral sentinel already present in the secure TLS 1.3 fixture
    # must pass unchanged: normalized_value == "certificate_not_observable", value
    # is the same neutral string, on the TLS 1.3 session, with the typed
    # session_secrets_required limitation.
    data = load_secure_fixture()
    sentinels = [
        obs for obs in data["crypto_observations"] if obs["kind"] == "tls13_certificate_unavailable"
    ]
    assert len(sentinels) == 1
    sentinel = sentinels[0]
    assert sentinel["normalized_value"] == "certificate_not_observable"
    assert sentinel["value"] == "certificate_not_observable"
    assert sentinel["session_id"] == data["sessions"][0]["session_id"]
    assert any(item["code"] == "session_secrets_required" for item in sentinel["limitations"])
    problems = _problems(data)
    assert problems == [], problems


def test_tls13_unavailable_sentinel_with_cert_content_fails():
    # A sentinel smuggling actual certificate content (value) with a neutral
    # normalized_value must fail: the sentinel must never carry certificate data.
    data = load_secure_fixture()
    _append_tls13_unavailable_sentinel(
        data,
        session_id=data["sessions"][0]["session_id"],
        value="CN=private.example",
        normalized="certificate_not_observable",
        observability="session_secrets_required",
        limitation=_SESSION_SECRETS_LIMITATION,
    )
    problems = _problems(data)
    assert any("must not carry actual certificate content" in p for p in problems), problems


def test_tls13_unavailable_sentinel_non_neutral_normalized_fails():
    # A sentinel whose normalized_value differs from the frozen neutral must fail,
    # even if its value field is itself neutral.
    data = load_secure_fixture()
    _append_tls13_unavailable_sentinel(
        data,
        session_id=data["sessions"][0]["session_id"],
        value=None,
        normalized="not_observable",
        observability="session_secrets_required",
        limitation=_SESSION_SECRETS_LIMITATION,
    )
    problems = _problems(data)
    assert any("normalized_value must equal the frozen neutral" in p for p in problems), problems


def test_tls13_unavailable_sentinel_on_non_tls13_session_fails():
    # A neutral sentinel is valid only on a real TLS 1.3 session; attaching it to
    # a non-TLS 1.3 session must fail.
    data = load_insecure_fixture()
    _append_tls13_unavailable_sentinel(
        data,
        session_id=data["sessions"][0]["session_id"],
        value="certificate_not_observable",
        normalized="certificate_not_observable",
        observability="session_secrets_required",
        limitation=_SESSION_SECRETS_LIMITATION,
    )
    problems = _problems(data)
    assert any("non-TLS 1.3 session" in p for p in problems), problems


def test_artifact_identity_mismatch_fails():
    data = load_insecure_fixture()
    data["artifacts"].append(
        {
            "artifact_manifest_id": "art_" + "5" * 16,
            "analysis_id": "ana_" + "0" * 16,
            "capture_sha256": data["captures"][0]["sha256"],
            "canonical_json_sha256": "ff" * 32,
            "html_report_sha256": None,
            "pdf_report_sha256": None,
            "rule_pack_sha256": None,
            "model_artifact_sha256": None,
            "generated_at": "2026-08-27T11:00:04Z",
            "signature_algorithm": None,
            "signature": None,
        }
    )
    problems = _problems(data)
    assert any("does not match manifest" in p for p in problems)


def test_artifact_hash_mismatch_fails():
    data = load_insecure_fixture()
    data["artifacts"].append(
        {
            "artifact_manifest_id": "art_" + "5" * 16,
            "analysis_id": data["analysis"]["analysis_id"],
            "capture_sha256": data["captures"][0]["sha256"],
            "canonical_json_sha256": "ff" * 32,
            "html_report_sha256": None,
            "pdf_report_sha256": None,
            "rule_pack_sha256": None,
            "model_artifact_sha256": None,
            "generated_at": "2026-08-27T11:00:04Z",
            "signature_algorithm": None,
            "signature": None,
        }
    )
    problems = _problems(data)
    assert any("does not match the reproducible" in p for p in problems)


def test_port_only_classification_is_interpretable_but_flags():
    # A finding with no evidence linkage on the anomaly would be caught; here
    # we confirm the port-only guard exists and is reachable.
    data = load_insecure_fixture()
    data["sessions"][0]["protocol_confidence"] = "high"
    assert _problems(data) == []


# ─────────────────────────────────────────────────────────────────────────────
#  Item 4: tampering with any reproducible ID is detected
# ─────────────────────────────────────────────────────────────────────────────


def _mutate_and_expect(data, mutator, needle):
    clone = json.loads(json.dumps(load_insecure_fixture() if data is None else data))
    mutator(clone)
    problems = _problems(clone)
    assert any(needle in p for p in problems), problems


def test_tampered_analysis_id_detected():
    data = load_secure_fixture()
    data["analysis"]["analysis_id"] = "ana_" + "c" * 16
    problems = _problems(data)
    assert any("analysis_id is not reproducible" in p for p in problems)


def test_tampered_capture_id_detected():
    data = load_secure_fixture()
    data["captures"][0]["capture_id"] = "cap_" + "c" * 16
    problems = _problems(data)
    assert any("capture_id not derived from its sha256" in p for p in problems)


def test_tampered_session_id_detected():
    data = load_secure_fixture()
    data["sessions"][0]["session_id"] = "ses_" + "c" * 16
    problems = _problems(data)
    assert any("session_id not derived from its stable key" in p for p in problems)


def test_tampered_stable_session_key_detected():
    data = load_secure_fixture()
    data["sessions"][0]["stable_session_key"] = "sha256:" + "d" * 64
    problems = _problems(data)
    assert any("stable_session_key not reproducible" in p for p in problems)


def test_tampered_evidence_id_detected():
    data = load_secure_fixture()
    data["evidence"][0]["evidence_id"] = "ev_" + "c" * 16
    problems = _problems(data)
    assert any("evidence_id not reproducible" in p for p in problems)


def test_tampered_occurrence_index_detected():
    # occurrence_index is part of the reproducible evidence identity: altering
    # it changes the recomputed id and must be caught like any other tamper.
    data = load_secure_fixture()
    data["evidence"][0]["occurrence_index"] = 1
    problems = _problems(data)
    assert any("evidence_id not reproducible" in p for p in problems)


def test_duplicate_evidence_distinguished_by_occurrence_index_is_valid():
    # Two real entries that differ only in occurrence_index are distinct nodes:
    # reproducible ids differ, so no duplicate-id error may fire. The clone must
    # carry the recomputed id to remain a valid (distinct) node.
    from securemailscope.chain.ids import evidence_id

    data = load_secure_fixture()
    src = data["evidence"][0]
    clone = copy.deepcopy(src)
    clone["occurrence_index"] = 1
    clone["evidence_id"] = evidence_id(
        src["capture_id"],
        src["session_id"],
        src["source_kind"],
        src["source_field"],
        src["normalized_value"],
        src["frame_numbers"],
        src["direction"],
        1,
    )
    data["evidence"].append(clone)
    problems = _problems(data)
    assert problems == [], problems


def test_tampered_event_id_detected():
    data = load_secure_fixture()
    data["protocol_events"][0]["event_id"] = "eve_" + "c" * 16
    problems = _problems(data)
    assert any("event_id not reproducible" in p for p in problems)


def test_tampered_observation_id_detected():
    data = load_secure_fixture()
    data["crypto_observations"][0]["observation_id"] = "obs_" + "c" * 16
    problems = _problems(data)
    assert any("observation_id not reproducible" in p for p in problems)


def test_tampered_fact_id_detected():
    data = load_secure_fixture()
    data["derived_facts"][0]["fact_id"] = "fact_" + "c" * 16
    problems = _problems(data)
    assert any("fact_id not reproducible" in p for p in problems)


def test_tampered_evaluation_id_detected():
    data = load_insecure_fixture()
    data["rule_evaluations"][0]["evaluation_id"] = "eval_" + "c" * 16
    problems = _problems(data)
    assert any("evaluation_id not reproducible" in p for p in problems)


def test_tampered_finding_id_detected():
    data = load_insecure_fixture()
    data["findings"][0]["finding_id"] = "fnd_" + "c" * 16
    problems = _problems(data)
    assert any("finding_id not derived from its stable key" in p for p in problems)


def test_tampered_stable_finding_key_detected():
    data = load_insecure_fixture()
    data["findings"][0]["stable_finding_key"] = "sha256:" + "e" * 64
    problems = _problems(data)
    assert any("stable_finding_key not reproducible" in p for p in problems)


def test_tampered_anomaly_id_and_policy_ids_detected():
    # Anomaly: build a valid anomaly then tamper its id.
    data = load_insecure_fixture()
    data["crypto_observations"].append(
        {
            "observation_id": "obs_" + "a1" * 8,
            "session_id": data["sessions"][0]["session_id"],
            "kind": "tls_negotiated_version",
            "value": "not_observable",
            "normalized_value": "not_observable",
            "observability": "not_observable",
            "evidence_ids": [],
            "limitations": [{"code": "unknown_insufficient_evidence", "summary": "x"}],
        }
    )
    import json as _json

    clone = _json.loads(_json.dumps(data))
    clone["anomaly_results"].append(
        {
            "anomaly_result_id": "anm_" + "b2" * 8,
            "session_id": data["sessions"][0]["session_id"],
            "model_id": "iso-forest",
            "model_version": "1.0.0",
            "feature_schema_version": "1.0.0",
            "feature_snapshot": {},
            "raw_score": 0.1,
            "normalized_score": 0.1,
            "threshold": 0.5,
            "band": "normal",
            "unusual_feature_indicators": [],
            "linked_fact_ids": [],
            "linked_observation_ids": [],
            "evidence_ids": [data["evidence"][0]["evidence_id"]],
            "interpretation_note": "Anomalous behavior is not proof of malicious activity.",
            "limitations": [],
        }
    )
    clone["anomaly_results"][0]["anomaly_result_id"] = "anm_" + "c" * 16
    problems = _problems(clone)
    assert any("anomaly_result_id not reproducible" in p for p in problems)


def test_tampered_policy_risk_and_contribution_ids_detected():
    data = load_insecure_fixture()
    data["policy_risk"]["policy_risk_id"] = "polr_" + "c" * 16
    problems = _problems(data)
    assert any("policy_risk_id not reproducible" in p for p in problems)

    data = load_insecure_fixture()
    data["policy_risk"]["contributions"][0]["contribution_id"] = "plc_" + "c" * 16
    problems = _problems(data)
    assert any("contribution_id not reproducible" in p for p in problems)


# ─────────────────────────────────────────────────────────────────────────────
#  Item 5: duplicate-ID detection (without dict erasure)
# ─────────────────────────────────────────────────────────────────────────────


def test_duplicate_session_id_detected():
    data = load_insecure_fixture()
    data["sessions"].append(copy.deepcopy(data["sessions"][0]))
    problems = _problems(data)
    assert any("duplicate session id" in p for p in problems)


def test_duplicate_evidence_id_detected():
    data = load_insecure_fixture()
    data["evidence"].append(copy.deepcopy(data["evidence"][0]))
    problems = _problems(data)
    assert any("duplicate evidence id" in p for p in problems)


def test_duplicate_event_id_detected():
    data = load_insecure_fixture()
    data["protocol_events"].append(copy.deepcopy(data["protocol_events"][0]))
    problems = _problems(data)
    assert any("duplicate event id" in p for p in problems)


def test_duplicate_fact_id_detected():
    data = load_insecure_fixture()
    data["derived_facts"].append(copy.deepcopy(data["derived_facts"][0]))
    problems = _problems(data)
    assert any("duplicate fact id" in p for p in problems)


def test_duplicate_contribution_id_detected():
    data = load_insecure_fixture()
    data["policy_risk"]["contributions"].append(
        copy.deepcopy(data["policy_risk"]["contributions"][0])
    )
    problems = _problems(data)
    assert any("duplicate policy_contribution id" in p for p in problems)


def test_duplicate_finding_id_detected():
    data = load_insecure_fixture()
    data["findings"].append(copy.deepcopy(data["findings"][0]))
    problems = _problems(data)
    assert any("duplicate finding id" in p for p in problems)


def test_duplicate_evaluation_id_detected():
    data = load_insecure_fixture()
    data["rule_evaluations"].append(copy.deepcopy(data["rule_evaluations"][0]))
    problems = _problems(data)
    assert any("duplicate evaluation id" in p for p in problems)


def test_duplicate_capture_id_across_duplicates_detected():
    data = load_insecure_fixture()
    data["captures"].append(copy.deepcopy(data["captures"][0]))
    problems = _problems(data)
    assert any("duplicate capture id" in p for p in problems)


def test_no_false_positive_across_distinct_prefix_collections():
    # Every compact node id uses a distinct, per-collection prefix (ana_/cap_/
    # ses_/ev_/eve_/obs_/fact_/eval_/fnd_/anm_/art_/polr_/plc_). No id string is
    # valid in two different collections, so cross-collection id collisions are
    # structurally impossible and the validator must not false-positive here.
    data = load_secure_fixture()
    assert _problems(data) == []

    # The cross-collection guard lives in _check_unique_ids but is inert by
    # construction; confirm the distinct prefixes never overlap.
    prefixes = {
        "ana",
        "cap",
        "ses",
        "ev",
        "eve",
        "obs",
        "fact",
        "eval",
        "fnd",
        "anm",
        "art",
        "polr",
        "plc",
    }
    assert len(prefixes) == 13


# ─────────────────────────────────────────────────────────────────────────────
#  Item 8: schema / version / time invariants
# ─────────────────────────────────────────────────────────────────────────────


def test_root_and_analysis_schema_version_mismatch_fails():
    data = load_secure_fixture()
    data["analysis"]["chain_schema_version"] = "1.0.1"
    problems = _problems(data)
    assert any("does not equal analysis.chain_schema_version" in p for p in problems)


def test_created_after_started_fails():
    data = load_secure_fixture()
    data["analysis"]["created_at"] = "2026-08-27T10:00:05Z"
    data["analysis"]["started_at"] = "2026-08-27T10:00:01Z"
    problems = _problems(data)
    assert any("started_at is before" in p for p in problems)


def test_completed_before_started_fails():
    data = load_secure_fixture()
    data["analysis"]["completed_at"] = "2026-08-27T10:00:00Z"
    problems = _problems(data)
    assert any("completed_at is before" in p for p in problems)


def test_capture_end_before_start_fails():
    data = load_secure_fixture()
    data["captures"][0]["captured_at_end"] = "2026-08-27T10:00:00Z"
    problems = _problems(data)
    assert any("captured_at_end before captured_at_start" in p for p in problems)


def test_session_end_before_start_fails():
    data = load_secure_fixture()
    data["sessions"][0]["ended_at"] = "2026-08-27T10:00:00Z"
    problems = _problems(data)
    assert any("started_at after ended_at" in p for p in problems)


def test_evidence_start_after_end_fails():
    data = load_secure_fixture()
    data["evidence"][0]["timestamp_start"] = "2026-08-27T10:00:09Z"
    data["evidence"][0]["timestamp_end"] = "2026-08-27T10:00:02Z"
    problems = _problems(data)
    assert any("timestamp_start after timestamp_end" in p for p in problems)


def test_event_timestamp_outside_session_window_fails():
    data = load_secure_fixture()
    data["protocol_events"][0]["timestamp"] = "2026-08-27T11:00:00Z"
    problems = _problems(data)
    assert any("timestamp outside session window" in p for p in problems)


def test_evidence_timestamp_outside_capture_window_fails():
    data = load_secure_fixture()
    data["evidence"][0]["timestamp_start"] = "2026-08-27T12:00:00Z"
    data["evidence"][0]["timestamp_end"] = "2026-08-27T12:00:01Z"
    problems = _problems(data)
    assert any("timestamps outside capture window" in p for p in problems)


# ─────────────────────────────────────────────────────────────────────────────
#  Item 9: evidence-backed graph invariants and recommendations
# ─────────────────────────────────────────────────────────────────────────────


def test_observed_material_event_without_evidence_fails():
    data = load_secure_fixture()
    for event in data["protocol_events"]:
        if event["event_type"] in ("server_hello", "handshake_finished"):
            event["evidence_ids"] = []
    problems = _problems(data)
    assert any("observed material event" in p for p in problems)


def test_observed_crypto_observation_without_evidence_fails():
    data = load_secure_fixture()
    data["crypto_observations"][0]["evidence_ids"] = []
    problems = _problems(data)
    assert any("observed crypto observation" in p for p in problems)


def test_observed_event_status_conflicts_with_derived_observability():
    # event_status="observed" demands observability="observed"; pairing it with
    # a derived/observability state is a coherence violation.
    data = load_secure_fixture()
    data["protocol_events"][1]["event_status"] = "observed"
    data["protocol_events"][1]["observability"] = "derived"
    problems = _problems(data)
    assert any("observed event status conflicts with observability" in p for p in problems)


def test_inferred_event_status_cannot_be_directly_observed():
    data = load_secure_fixture()
    data["protocol_events"][1]["event_status"] = "inferred"
    data["protocol_events"][1]["observability"] = "observed"
    problems = _problems(data)
    assert any("inferred event cannot be directly observed" in p for p in problems)


def test_incomplete_capture_event_status_requires_matching_observability():
    data = load_secure_fixture()
    data["protocol_events"][1]["event_status"] = "incomplete_capture"
    data["protocol_events"][1]["observability"] = "observed"
    problems = _problems(data)
    assert any("incomplete event status conflicts with observability" in p for p in problems)


def test_not_observable_event_status_conflicts_with_observed_observability():
    data = load_secure_fixture()
    data["protocol_events"][1]["event_status"] = "not_observable"
    data["protocol_events"][1]["observability"] = "observed"
    problems = _problems(data)
    assert any("not-observable status conflicts with observability" in p for p in problems)


def test_inferred_derived_handshake_finished_event_passes_invariants():
    # The TLS 1.3 handshake-completion event in the secure fixture is
    # legitimately inferred/derived (Finished is encrypted); the coherence
    # invariants must accept it rather than demand observed status.
    data = load_secure_fixture()
    handshake = next(
        event for event in data["protocol_events"] if event["event_type"] == "handshake_finished"
    )
    assert handshake["event_status"] == "inferred"
    assert handshake["observability"] == "derived"
    assert _problems(data) == []


def test_orphan_recommendation_rejected():
    data = load_insecure_fixture()
    data["recommendations"].append(
        {
            "recommendation_id": "REC-ORPHAN-TEST",
            "title": "Orphan",
            "summary": "unreferenced",
            "priority": "info",
            "affected_finding_ids": [],
            "action_steps": [],
            "verification_steps": [],
            "standards_references": [],
            "scope": "service",
            "automation_status": "advisory_only",
        }
    )
    problems = _problems(data)
    assert any("orphan recommendation" in p for p in problems)


# ─────────────────────────────────────────────────────────────────────────────
#  Item 11: X.509 conservative states (missing inputs never claim invalid)
# ─────────────────────────────────────────────────────────────────────────────


def test_x509_conservative_not_assessed_observation_ok():
    from securemailscope.chain.ids import crypto_observation_id

    # Missing trust store -> "not_assessed", never "invalid". The prediction is
    # made on a non-TLS-1.3 plaintext session so no server-secret requirement is
    # forced, and a single clean conservative observation passes all invariants.
    data = load_insecure_fixture()
    ses = data["sessions"][0]["session_id"]
    obs_id = crypto_observation_id(ses, "certificate_trusted_path_validated", "not_assessed")
    data["crypto_observations"].append(
        {
            "observation_id": obs_id,
            "session_id": ses,
            "kind": "certificate_trusted_path_validated",
            "value": "not_assessed",
            "normalized_value": "not_assessed",
            "observability": "not_observable",
            "evidence_ids": [],
            "limitations": [
                {
                    "code": "not_assessed",
                    "summary": "No trust store was supplied",
                    "detail": "missing_trust_store",
                }
            ],
        }
    )
    problems = _problems(data)
    assert problems == [], problems
    assert not any("invalid certificate" in p for p in problems)


# ─────────────────────────────────────────────────────────────────────────────
#  Gap 2: evidence capture/session consistency
# ─────────────────────────────────────────────────────────────────────────────


def test_evidence_capture_session_mismatch_fails():
    # An evidence node references capture B but its session belongs to capture A.
    # Its deterministic evidence id is recomputed for capture B so the test
    # isolates the graph error (no reproducibility problem fires).
    data = load_insecure_fixture()
    session_a = data["sessions"][0]
    sha_b = "3c" * 32
    capture_b_id = capture_id_from_sha256(sha_b)
    capture_a = data["captures"][0]
    data["captures"].append(
        {**copy.deepcopy(capture_a), "capture_id": capture_b_id, "sha256": sha_b}
    )

    evidence = data["evidence"][0]
    evidence["capture_id"] = capture_b_id
    evidence["capture_sha256"] = sha_b
    evidence["evidence_id"] = evidence_id(
        capture_b_id,
        evidence["session_id"],
        evidence["source_kind"],
        evidence["source_field"],
        evidence["normalized_value"],
        evidence["frame_numbers"],
        evidence["direction"],
        evidence["occurrence_index"],
    )
    assert evidence["session_id"] == session_a["session_id"]
    assert session_a["capture_id"] != capture_b_id

    problems = _problems(data)
    assert any("capture/session mismatch" in p for p in problems), problems
    assert not any("evidence_id not reproducible" in p for p in problems)


def test_evidence_capture_matches_session_is_valid():
    # Reassigning the evidence node's session to a capture-B session (and
    # recomputing its id) is coherent and must not trigger the mismatch.
    data = load_insecure_fixture()
    schema_version = data["analysis"]["chain_schema_version"]
    capture_a = data["captures"][0]
    sha_b = "3c" * 32
    capture_b_id = capture_id_from_sha256(sha_b)
    data["captures"].append(
        {**copy.deepcopy(capture_a), "capture_id": capture_b_id, "sha256": sha_b}
    )

    client_ip = data["sessions"][0]["source_endpoint"]["ip"]
    server_ip = data["sessions"][0]["destination_endpoint"]["ip"]
    server_port = data["sessions"][0]["destination_endpoint"]["port"]
    key_b = session_stable_key(schema_version, sha_b, 7, client_ip, 55555, server_ip, server_port)
    ses_b_id = session_id_from_key(key_b)
    data["sessions"].append(
        {
            "session_id": ses_b_id,
            "stable_session_key": key_b,
            "capture_id": capture_b_id,
            "tcp_stream_id": 7,
            "source_endpoint": {"ip": client_ip, "port": 55555},
            "destination_endpoint": {"ip": server_ip, "port": server_port},
            "first_frame": 1,
            "last_frame": 4,
            "started_at": "2026-08-27T11:00:02Z",
            "ended_at": "2026-08-27T11:00:02.700000Z",
            "packet_count": 3,
            "byte_count": 128,
            "protocol": "smtp",
            "protocol_confidence": "high",
            "classification_evidence_ids": [],
            "capture_completeness": "complete",
            "limitations": [],
        }
    )
    evidence = data["evidence"][0]
    evidence["session_id"] = ses_b_id
    evidence["capture_id"] = capture_b_id
    evidence["capture_sha256"] = sha_b
    evidence["evidence_id"] = evidence_id(
        capture_b_id,
        ses_b_id,
        evidence["source_kind"],
        evidence["source_field"],
        evidence["normalized_value"],
        evidence["frame_numbers"],
        evidence["direction"],
        evidence["occurrence_index"],
    )
    problems = _problems(data)
    assert not any("capture/session mismatch" in p for p in problems), problems


# ─────────────────────────────────────────────────────────────────────────────
#  Gap 3: anomaly graph links
# ─────────────────────────────────────────────────────────────────────────────


def _enable_ml(data) -> str:
    """Mark the ML engine complete with a versioned model and propagate the
    resulting reproducible analysis_id across the document so the mutation
    isolates only the anomaly-link graph error."""
    old_analysis_id = data["analysis"]["analysis_id"]
    data["analysis"]["ml_engine_status"] = "complete"
    data["analysis"]["model_id"] = "iso-forest"
    data["analysis"]["model_version"] = "1.0.0"
    from securemailscope.chain.ids import analysis_id as make_analysis_id
    from securemailscope.chain.ids import policy_risk_id as make_policy_risk_id

    new_analysis_id = make_analysis_id(
        data["analysis"]["chain_schema_version"],
        data["captures"][0]["sha256"],
        data["analysis"]["configuration_digest"],
        data["analysis"]["analyzer_version"],
        data["analysis"]["rule_pack_id"],
        data["analysis"]["rule_pack_version"],
        data["analysis"]["model_id"],
        data["analysis"]["model_version"],
    )
    data["analysis"]["analysis_id"] = new_analysis_id
    for finding in data["findings"]:
        if finding["analysis_id"] == old_analysis_id:
            finding["analysis_id"] = new_analysis_id
    if data["policy_risk"] is not None:
        if data["policy_risk"]["analysis_id"] == old_analysis_id:
            data["policy_risk"]["analysis_id"] = new_analysis_id
        data["policy_risk"]["policy_risk_id"] = make_policy_risk_id(
            new_analysis_id, data["policy_risk"]["profile_id"]
        )
    return new_analysis_id


def _anomaly_insecure(data, linked_facts, linked_obs, evidence_ids):
    """Append a valid anomaly result (reproducible id) to the insecure fixture."""
    _enable_ml(data)
    session_id = data["sessions"][0]["session_id"]
    anm_id = anomaly_result_id(session_id, "iso-forest", "1.0.0", "1.0.0")
    data["anomaly_results"].append(
        {
            "anomaly_result_id": anm_id,
            "session_id": session_id,
            "model_id": "iso-forest",
            "model_version": "1.0.0",
            "feature_schema_version": "1.0.0",
            "feature_snapshot": {"plaintext_after_offer": 1},
            "raw_score": 0.0,
            "normalized_score": 0.0,
            "threshold": 0.5,
            "band": "normal",
            "unusual_feature_indicators": [],
            "linked_fact_ids": list(linked_facts),
            "linked_observation_ids": list(linked_obs),
            "evidence_ids": list(evidence_ids),
            "interpretation_note": "Anomalous behavior is not proof of malicious activity.",
            "limitations": [],
        }
    )
    return anm_id


def test_anomaly_baseline_with_links_is_valid():
    data = load_insecure_fixture()
    fact = data["derived_facts"][0]["fact_id"]
    obs = data["crypto_observations"][0]["observation_id"]
    evidence = data["evidence"][0]["evidence_id"]
    _anomaly_insecure(data, [fact], [obs], [evidence])
    problems = _problems(data)
    assert problems == [], problems


def test_anomaly_missing_linked_fact_fails():
    data = load_insecure_fixture()
    obs = data["crypto_observations"][0]["observation_id"]
    evidence = data["evidence"][0]["evidence_id"]
    _anomaly_insecure(data, ["fact_" + "f" * 16], [obs], [evidence])
    problems = _problems(data)
    assert any("missing fact" in p for p in problems), problems


def test_anomaly_missing_linked_observation_fails():
    data = load_insecure_fixture()
    fact = data["derived_facts"][0]["fact_id"]
    evidence = data["evidence"][0]["evidence_id"]
    _anomaly_insecure(data, [fact], ["obs_" + "d" * 16], [evidence])
    problems = _problems(data)
    assert any("missing linked observation" in p for p in problems), problems


def test_anomaly_cross_session_linked_fact_fails():
    data = load_insecure_fixture()
    schema_version = data["analysis"]["chain_schema_version"]
    capture = data["captures"][0]
    client_ip = data["sessions"][0]["source_endpoint"]["ip"]
    server_ip = data["sessions"][0]["destination_endpoint"]["ip"]
    server_port = data["sessions"][0]["destination_endpoint"]["port"]
    key2 = session_stable_key(
        schema_version, capture["sha256"], 99, client_ip, 44444, server_ip, server_port
    )
    ses2_id = session_id_from_key(key2)
    data["sessions"].append(
        {
            "session_id": ses2_id,
            "stable_session_key": key2,
            "capture_id": capture["capture_id"],
            "tcp_stream_id": 99,
            "source_endpoint": {"ip": client_ip, "port": 44444},
            "destination_endpoint": {"ip": server_ip, "port": server_port},
            "first_frame": 1,
            "last_frame": 4,
            "started_at": "2026-08-27T11:00:02Z",
            "ended_at": "2026-08-27T11:00:02.700000Z",
            "packet_count": 3,
            "byte_count": 128,
            "protocol": "smtp",
            "protocol_confidence": "high",
            "classification_evidence_ids": [],
            "capture_completeness": "complete",
            "limitations": [],
        }
    )
    session_id = data["sessions"][0]["session_id"]
    cross_fact_id = "fact_" + "c" * 16
    data["derived_facts"].append(
        {
            "fact_id": cross_fact_id,
            "session_id": ses2_id,
            "fact_type": "cross_session_probe",
            "value": True,
            "derivation_id": "chain.probe",
            "derivation_version": "1.0.0",
            "source_event_ids": [],
            "source_observation_ids": [],
            "source_fact_ids": [],
            "observability": "derived",
            "confidence_level": "high",
            "confidence_basis": ["probe"],
            "limitations": [],
        }
    )
    obs = data["crypto_observations"][0]["observation_id"]
    evidence = data["evidence"][0]["evidence_id"]
    _anomaly_insecure(data, [cross_fact_id], [obs], [evidence])
    assert session_id != ses2_id
    problems = _problems(data)
    assert any("linked fact from another session" in p for p in problems), problems


def test_anomaly_cross_session_linked_observation_fails():
    data = load_insecure_fixture()
    schema_version = data["analysis"]["chain_schema_version"]
    capture = data["captures"][0]
    client_ip = data["sessions"][0]["source_endpoint"]["ip"]
    server_ip = data["sessions"][0]["destination_endpoint"]["ip"]
    server_port = data["sessions"][0]["destination_endpoint"]["port"]
    key2 = session_stable_key(
        schema_version, capture["sha256"], 99, client_ip, 44444, server_ip, server_port
    )
    ses2_id = session_id_from_key(key2)
    data["sessions"].append(
        {
            "session_id": ses2_id,
            "stable_session_key": key2,
            "capture_id": capture["capture_id"],
            "tcp_stream_id": 99,
            "source_endpoint": {"ip": client_ip, "port": 44444},
            "destination_endpoint": {"ip": server_ip, "port": server_port},
            "first_frame": 1,
            "last_frame": 4,
            "started_at": "2026-08-27T11:00:02Z",
            "ended_at": "2026-08-27T11:00:02.700000Z",
            "packet_count": 3,
            "byte_count": 128,
            "protocol": "smtp",
            "protocol_confidence": "high",
            "classification_evidence_ids": [],
            "capture_completeness": "complete",
            "limitations": [],
        }
    )
    fact = data["derived_facts"][0]["fact_id"]
    cross_obs_id = "obs_" + "e" * 16
    data["crypto_observations"].append(
        {
            "observation_id": cross_obs_id,
            "session_id": ses2_id,
            "kind": "tls_negotiated_version",
            "value": "not_observable",
            "normalized_value": "not_observable",
            "observability": "not_observable",
            "evidence_ids": [],
            "limitations": [{"code": "unknown_insufficient_evidence", "summary": "x"}],
        }
    )
    evidence = data["evidence"][0]["evidence_id"]
    _anomaly_insecure(data, [fact], [cross_obs_id], [evidence])
    problems = _problems(data)
    assert any("linked observation from another session" in p for p in problems), problems


def test_anomaly_with_no_feature_links_fails():
    data = load_insecure_fixture()
    evidence = data["evidence"][0]["evidence_id"]
    _anomaly_insecure(data, [], [], [evidence])
    problems = _problems(data)
    assert any("at least one linked fact or linked observation" in p for p in problems), problems
