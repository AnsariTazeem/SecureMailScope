"""Reproducibility tests: stable IDs and canonical hashes.

Proves that stable identifiers and canonical content hashes are reproducible
across builds and that volatile execution timestamps do not enter the
reproducible hash.
"""

from __future__ import annotations

from chain_helpers import (
    load_insecure_fixture,
    load_secure_fixture,
)

from securemailscope.chain.canonical import (
    canonical_content_hash,
    canonical_content_json,
)
from securemailscope.chain.ids import (
    capture_id_from_sha256,
    compact_id,
    is_compact_id,
    is_recommendation_id,
    is_semver,
    is_sha256_digest,
    is_sha256_key,
    session_id_from_key,
    session_stable_key,
)
from securemailscope.chain.models import ChainOfProof


def test_stable_ids_are_deterministic_and_reproducible():
    a = compact_id("ses", "stream", "abc")
    b = compact_id("ses", "stream", "abc")
    assert a == b
    assert is_compact_id("ses", a)


def test_capture_id_derived_from_sha256():
    sha = "sha256:" + "ab" * 32
    cid = capture_id_from_sha256(sha)
    assert is_compact_id("cap", cid)
    assert cid == capture_id_from_sha256(sha)


def test_session_id_derived_from_stable_key():
    data = load_secure_fixture()
    session = data["sessions"][0]
    expect = session_id_from_key(session["stable_session_key"])
    assert session["session_id"] == expect


def test_evidence_occurrence_index_disambiguates_repeated_packet_fields():
    from securemailscope.chain.ids import evidence_id

    # Two evidence entries may share the same capture/session/source field and
    # frame when a packet repeats a field (e.g. multiple SMTP response lines or
    # repeated TLS handshake types). occurrence_index is the typed per-packet
    # disambiguation and must produce distinct, deterministic IDs.
    base = {
        "capture_id": "cap_" + "1" * 16,
        "session_id": "ses_" + "2" * 16,
        "source_kind": "tshark_field",
        "source_field": "smtp.response",
        "normalized_value": "220 Ready to start TLS",
        "frame_numbers": [4],
        "direction": "server_to_client",
    }
    first = evidence_id(**base, occurrence_index=0)
    second = evidence_id(**base, occurrence_index=1)
    assert first != second
    # Deterministic: identical inputs reproduce the identical id.
    assert evidence_id(**base, occurrence_index=0) == first
    assert evidence_id(**base, occurrence_index=1) == second
    assert is_compact_id("ev", first)
    assert is_compact_id("ev", second)


def test_fixture_evidence_ids_use_occurrence_index_zero():
    # Both fixtures encode evidence reproducibility including occurrence_index
    # (frame/field repetition), defaulting to the first occurrence of a packet
    # field; the invariant validator recomputes the same ids.
    data = load_secure_fixture()
    assert all(evidence["occurrence_index"] == 0 for evidence in data["evidence"])
    data = load_insecure_fixture()
    assert all(evidence["occurrence_index"] == 0 for evidence in data["evidence"])


def test_canonical_hash_reproducible_across_model_round_trip():
    data = load_secure_fixture()
    m1 = ChainOfProof.model_validate(data)
    json_text = canonical_content_json(m1)
    m2 = ChainOfProof.model_validate(data)
    assert canonical_content_hash(m1) == canonical_content_hash(m2)
    assert canonical_content_json(m2) == json_text


def test_canonical_hash_same_for_both_fixture_loads():
    h1 = canonical_content_hash(ChainOfProof.model_validate(load_secure_fixture()))
    h2 = canonical_content_hash(ChainOfProof.model_validate(load_secure_fixture()))
    assert h1 == h2
    assert is_sha256_digest(h1)


def test_volatile_execution_timestamps_do_not_change_reproducible_hash():
    data = load_insecure_fixture()
    base = ChainOfProof.model_validate(data)
    base_hash = canonical_content_hash(base)

    clone = load_insecure_fixture()
    clone["analysis"]["created_at"] = "2026-08-28T00:00:00Z"
    clone["analysis"]["started_at"] = "2026-08-28T00:00:10Z"
    clone["analysis"]["completed_at"] = "2026-08-28T00:00:50Z"
    clone["findings"][0]["created_at"] = "2026-08-28T00:00:20Z"
    clone["rule_evaluations"][0]["evaluated_at"] = "2026-08-28T00:00:20Z"
    clone["execution"]["stage_diagnostics"][0]["runtime_seconds"] = 9.99
    varied = ChainOfProof.model_validate(clone)

    assert canonical_content_hash(varied) == base_hash


def test_evidence_timestamp_does_change_reproducible_hash():
    def hash_of(ev_start):
        clone = load_secure_fixture()
        clone["evidence"][0]["timestamp_start"] = ev_start
        return canonical_content_hash(ChainOfProof.model_validate(clone))

    assert hash_of("2026-08-27T10:00:02.1Z") == hash_of("2026-08-27T10:00:02.1Z")
    assert hash_of("2026-08-27T10:00:02.1Z") != hash_of("2026-08-27T10:00:09.9Z")


def test_id_shape_helpers():
    assert is_sha256_key("sha256:" + "a" * 64)
    assert not is_sha256_key("sha256:xyz")
    assert is_semver("1.2.3")
    assert not is_semver("1.2")
    assert is_recommendation_id("REC-EMAIL-REQUIRE-TLS")
    assert not is_recommendation_id("REC bad")


# ─────────────────────────────────────────────────────────────────────────────
#  Item 3: raw digests vs tagged stable keys; frozen PCAP hash format
# ─────────────────────────────────────────────────────────────────────────────


def test_raw_digest_and_tagged_key_are_separate_patterns():
    raw = "a" * 64
    tagged = "sha256:" + raw
    # raw digest is exactly 64 lowercase hex
    assert is_sha256_digest(raw)
    assert not is_sha256_key(raw)
    # tagged stable key carries the sha256: prefix
    assert is_sha256_key(tagged)
    assert not is_sha256_digest(tagged)
    # helpers reject wrong forms
    assert not is_sha256_digest("a" * 63)
    assert not is_sha256_digest("A" * 64)
    assert not is_sha256_key("sha256:" + "A" * 64)


def test_frozen_raw_pcap_digest_is_valid_raw_format():
    # Frozen T01 PCAP SHA-256 (progress tracker / evidence record). The contract
    # stores capture/artifact digests as raw 64-lowercase-hex, not a tagged key.
    frozen = "772d166b5e2b32516c76833357ff309af0d99d7bc962cf4c685279fc662ab086"
    assert is_sha256_digest(frozen)
    assert not is_sha256_key(frozen)
    assert len(frozen) == 64
    assert frozen == frozen.lower()


# ─────────────────────────────────────────────────────────────────────────────
#  Item 4: deterministic, unambiguous stable identities
# ─────────────────────────────────────────────────────────────────────────────


def test_four_tuple_with_different_stream_id_do_not_collide():
    schema = "1.0.0"
    sha = "aa" * 32
    # Same four-tuple, different tcp_stream_id -> distinct keys and ids
    k1 = session_stable_key(schema, sha, 0, "192.0.2.1", 35210, "192.0.2.2", 2525)
    k2 = session_stable_key(schema, sha, 1, "192.0.2.1", 35210, "192.0.2.2", 2525)
    assert k1 != k2
    assert session_id_from_key(k1) != session_id_from_key(k2)
    # Recomputing produces identical results (reproducibility)
    assert k1 == session_stable_key(schema, sha, 0, "192.0.2.1", 35210, "192.0.2.2", 2525)


def test_component_boundary_separator_values_do_not_collide():
    # A delimiter-only encoding could collide when one component contains the
    # separator. The canonical-array encoding must not collide on any split.
    from securemailscope.chain.ids import stable_digest

    # "a|b|c" split as ["a|b", "c"] and ["a", "b|c"] must differ
    assert stable_digest("a|b", "c") != stable_digest("a", "b|c")
    # Same reasoning for a control separator
    assert stable_digest("a\x1fb", "c") != stable_digest("a", "b\x1fc")
    # And equal inputs still produce equal digests
    assert stable_digest("a", "b", "c") == stable_digest("a", "b", "c")


def test_equivalent_input_produces_identical_ids():
    # Same capture + session + rule inputs -> identical IDs across calls
    schema = "1.0.0"
    sha = "bb" * 32
    cfg = "c" * 64
    a1 = compact_id("ana", "analysis", schema, sha, cfg, "0.1.0", "PACK", "1.0.0", "", "")
    a2 = compact_id("ana", "analysis", schema, sha, cfg, "0.1.0", "PACK", "1.0.0", "", "")
    assert a1 == a2
    assert is_compact_id("ana", a1)


def test_all_node_id_helpers_are_deterministic():
    from securemailscope.chain.ids import (
        analysis_id,
        anomaly_result_id,
        artifact_manifest_id,
        capture_id_from_sha256,
        crypto_observation_id,
        evidence_id,
        fact_id_from_key,
        fact_stable_key,
        finding_id_from_key,
        finding_stable_key,
        policy_contribution_id,
        policy_risk_id,
        protocol_event_id,
        rule_evaluation_id,
        session_id_from_key,
        session_stable_key,
    )

    sha = "cc" * 32
    cfg = "c" * 64
    ana = analysis_id("1.0.0", sha, cfg, "0.1.0")
    cap = capture_id_from_sha256(sha)
    ses_key = session_stable_key("1.0.0", sha, 1, "10.0.0.1", 1, "10.0.0.2", 25)
    ses = session_id_from_key(ses_key)
    ev = evidence_id(cap, ses, "tshark_field", "tls.handshake.type", "2")
    eve = protocol_event_id(ses, 3, "server_hello")
    obs = crypto_observation_id(ses, "selected_cipher_suite", "TLS_AES_128_GCM_SHA256")
    fact_key = fact_stable_key("1.0.0", ses_key, "negotiated_tls_version", '"TLS_1_2"')
    fact = fact_id_from_key(fact_key)
    evals = rule_evaluation_id(ses, "R", "1.0.0", "prof")
    fnd_key = finding_stable_key("1.0.0", ses_key, "R", "1.0.0", [fact])
    fnd = finding_id_from_key(fnd_key)
    anm = anomaly_result_id(ses, "m", "1.0.0", "1.0.0")
    polr = policy_risk_id(ana, "prof")
    plc = policy_contribution_id(fnd, "R", "1.0.0")
    art = artifact_manifest_id(ana, "dd" * 32)

    generated = [ana, cap, ses, ev, eve, obs, fact, evals, fnd, anm, polr, plc, art]
    # All compact node ids are distinct and shaped correctly
    prefixes = {
        "ana": ana,
        "cap": cap,
        "ses": ses,
        "ev": ev,
        "eve": eve,
        "obs": obs,
        "fact": fact,
        "eval": evals,
        "fnd": fnd,
        "anm": anm,
        "polr": polr,
        "plc": plc,
        "art": art,
    }
    for prefix, node_id in prefixes.items():
        assert is_compact_id(prefix, node_id), (prefix, node_id)
    assert len(set(generated)) == len(generated)
    assert is_sha256_key(ses_key)
    assert is_sha256_key(fact_key)
    assert is_sha256_key(fnd_key)
