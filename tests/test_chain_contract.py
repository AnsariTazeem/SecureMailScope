"""Contract tests: Pydantic boundary validation of the Chain-of-Proof models.

Proves the strict, frozen contract behavior: both fixtures validate, extra
fields and invalid enums fail, and required-but-nullable fields behave
correctly without magic-string "-none" sentinels.
"""

from __future__ import annotations

import pytest
from chain_helpers import (
    load_insecure_fixture,
    load_secure_fixture,
)
from pydantic import ValidationError

from securemailscope.chain.enums import EngineStatus
from securemailscope.chain.invariants import validate_chain
from securemailscope.chain.models import (
    AnalysisManifest,
    ChainOfProof,
    PolicyRiskSummary,
)


def test_secure_fixture_validates_and_passes_invariants():
    model = ChainOfProof.model_validate(load_secure_fixture())
    ok, problems = validate_chain(model)
    assert ok, problems
    assert model.artifacts == []  # partial analysis, no generated reports
    assert model.analysis.rule_engine_status is EngineStatus.NOT_RUN
    assert model.policy_risk is None
    assert model.anomaly_results == []


def test_insecure_fixture_validates_and_passes_invariants():
    model = ChainOfProof.model_validate(load_insecure_fixture())
    ok, problems = validate_chain(model)
    assert ok, problems
    assert model.policy_risk is not None
    assert model.anomaly_results == []
    assert len(model.findings) == 1


def test_root_artifacts_collection_allowed_empty():
    secure = load_secure_fixture()
    assert secure["artifacts"] == []
    ChainOfProof.model_validate(secure)


def test_extra_fields_rejected():
    data = load_secure_fixture()
    data["unexpected_root_field"] = "boom"
    with pytest.raises(ValidationError) as exc:
        ChainOfProof.model_validate(data)
    assert "extra_forbidden" in str(exc.value) or "unexpected_root_field" in str(exc.value)


def test_nested_extra_fields_rejected():
    data = load_secure_fixture()
    data["sessions"][0]["bogus"] = True
    with pytest.raises(ValidationError) as exc:
        ChainOfProof.model_validate(data)
    assert "extra_forbidden" in str(exc.value) or "bogus" in str(exc.value)


def test_invalid_enum_rejected():
    data = load_secure_fixture()
    data["analysis"]["analysis_status"] = "definitely_not_a_status"
    with pytest.raises(ValidationError):
        ChainOfProof.model_validate(data)


def test_invalid_observation_kind_rejected():
    data = load_secure_fixture()
    data["crypto_observations"][0]["kind"] = "not_a_real_kind"
    with pytest.raises(ValidationError):
        ChainOfProof.model_validate(data)


def test_invalid_severity_rejected():
    data = load_insecure_fixture()
    data["findings"][0]["severity"] = "ultra"
    with pytest.raises(ValidationError):
        ChainOfProof.model_validate(data)


def test_naive_datetime_rejected():
    data = load_secure_fixture()
    data["analysis"]["created_at"] = "2026-08-27T10:00:00"
    with pytest.raises(ValidationError):
        ChainOfProof.model_validate(data)


def test_required_nullable_rule_fields_must_be_null_when_not_run():
    payload = {
        "analysis_id": "ana_" + "a" * 16,
        "chain_schema_version": "1.0.0",
        "analysis_status": "failed",
        "created_at": "2026-08-27T10:00:00Z",
        "started_at": "2026-08-27T10:00:01Z",
        "completed_at": None,
        "analyzer_version": "0.1.0",
        "tshark_version": None,
        "rule_engine_status": EngineStatus.NOT_RUN,
        "rule_pack_id": None,
        "rule_pack_version": None,
        "ml_engine_status": EngineStatus.NOT_RUN,
        "model_id": None,
        "model_version": None,
        "configuration_digest": "c" * 64,
        "tls13_authorized_secrets": "not_supplied",
        "limitations": [],
    }
    AnalysisManifest.model_validate(payload)


def test_required_nullable_rule_fields_must_be_present_when_engine_ran():
    payload = {
        "analysis_id": "ana_" + "a" * 16,
        "chain_schema_version": "1.0.0",
        "analysis_status": "complete",
        "created_at": "2026-08-27T10:00:00Z",
        "started_at": "2026-08-27T10:00:01Z",
        "completed_at": None,
        "analyzer_version": "0.1.0",
        "tshark_version": None,
        "rule_engine_status": EngineStatus.COMPLETE,
        "rule_pack_id": None,  # must be set when engine ran -> should fail
        "rule_pack_version": None,
        "ml_engine_status": EngineStatus.NOT_RUN,
        "model_id": None,
        "model_version": None,
        "configuration_digest": "c" * 64,
        "tls13_authorized_secrets": "not_supplied",
        "limitations": [],
    }
    with pytest.raises(ValidationError):
        AnalysisManifest.model_validate(payload)


def test_rule_fields_both_null_or_both_set():
    payload = {
        "analysis_id": "ana_" + "a" * 16,
        "chain_schema_version": "1.0.0",
        "analysis_status": "complete",
        "created_at": "2026-08-27T10:00:00Z",
        "started_at": "2026-08-27T10:00:01Z",
        "completed_at": None,
        "analyzer_version": "0.1.0",
        "tshark_version": None,
        "rule_engine_status": EngineStatus.COMPLETE,
        "rule_pack_id": "SMS-EMAIL",
        "rule_pack_version": None,  # must be both null or both set
        "ml_engine_status": EngineStatus.NOT_RUN,
        "model_id": None,
        "model_version": None,
        "configuration_digest": "c" * 64,
        "tls13_authorized_secrets": "not_supplied",
        "limitations": [],
    }
    with pytest.raises(ValidationError):
        AnalysisManifest.model_validate(payload)


def test_model_fields_both_null_or_both_set():
    payload = {
        "analysis_id": "ana_" + "a" * 16,
        "chain_schema_version": "1.0.0",
        "analysis_status": "complete",
        "created_at": "2026-08-27T10:00:00Z",
        "started_at": "2026-08-27T10:00:01Z",
        "completed_at": None,
        "analyzer_version": "0.1.0",
        "tshark_version": None,
        "rule_engine_status": EngineStatus.NOT_RUN,
        "rule_pack_id": None,
        "rule_pack_version": None,
        "ml_engine_status": EngineStatus.COMPLETE,
        "model_id": None,
        "model_version": "1.0.0",
        "configuration_digest": "c" * 64,
        "tls13_authorized_secrets": "not_supplied",
        "limitations": [],
    }
    with pytest.raises(ValidationError):
        AnalysisManifest.model_validate(payload)


def test_absence_uses_typed_status_not_dash_none_sentinel():
    data = load_secure_fixture()
    # Verify the contract never serializes magic "-none" values.
    import json

    rendered = json.dumps(data)
    assert 'rule_pack_id": "-none"' not in rendered
    assert 'model_id": "-none"' not in rendered
    assert data["analysis"]["rule_engine_status"] == "not_run"
    assert data["analysis"]["ml_engine_status"] == "not_run"


def test_policy_risk_and_anomaly_are_separate_outputs():
    insecure = load_insecure_fixture()
    assert insecure["policy_risk"] is not None
    assert insecure["anomaly_results"] == []
    secure = load_secure_fixture()
    assert secure["policy_risk"] is None
    assert secure["anomaly_results"] == []


def test_policy_risk_present_only_when_rule_engine_ran():
    model = ChainOfProof.model_validate(load_insecure_fixture())
    ok, problems = validate_chain(model)
    assert ok, problems
    assert isinstance(model.policy_risk, PolicyRiskSummary)


# ─────────────────────────────────────────────────────────────────────────────
#  Item 1: strict required-fields contract at the model boundary
# ─────────────────────────────────────────────────────────────────────────────


def test_root_policy_risk_required_but_nullable():
    from securemailscope.chain.models import ChainOfProof as C

    secure = load_secure_fixture()
    # policy_risk is a required key but may be an object or explicit null
    assert "policy_risk" in C.model_fields

    # Explicit null is allowed (provenance-only / engine-not-run chain)
    C.model_validate(secure)

    # Omitting the required-nullable key is a validation error (no default)
    without = {k: v for k, v in secure.items() if k != "policy_risk"}
    with pytest.raises(ValidationError):
        C.model_validate(without)


def test_root_collections_required_but_allow_empty():
    from securemailscope.chain.models import ChainOfProof as C

    secure = load_secure_fixture()
    for key in ("evidence", "sessions", "findings", "artifacts", "recommendations"):
        assert key in C.model_fields
        missing = {k: v for k, v in secure.items() if k != key}
        with pytest.raises(ValidationError):
            C.model_validate(missing)


# ─────────────────────────────────────────────────────────────────────────────
#  Item 6: no observability state raises AttributeError
# ─────────────────────────────────────────────────────────────────────────────


def test_every_observability_state_is_handled_without_attribute_error():
    from securemailscope.chain.enums import ChainObservability
    from securemailscope.chain.models import ChainOfProof as C

    # Evidence observability is fixed to "observed"; the broader enum applies to
    # events, observations, facts and findings. For every enum state the
    # invariant walk must never raise AttributeError (it returns typed problems).
    for obs in ChainObservability:
        data = load_secure_fixture()
        data["protocol_events"][0]["observability"] = obs.value
        data["crypto_observations"][0]["observability"] = obs.value
        data["derived_facts"][0]["observability"] = obs.value
        model = C.model_validate(data)
        try:
            ok, problems = validate_chain(model)
        except AttributeError:
            pytest.fail(f"AttributeError raised for observability={obs.value}")
        assert isinstance(ok, bool)


def test_invariants_never_raise_attribute_error_on_partial_data():
    from securemailscope.chain.models import ChainOfProof as C

    # A provenance-only chain (no sessions) must not crash invariant walking.
    data = load_secure_fixture()
    data["sessions"] = []
    data["protocol_events"] = []
    data["crypto_observations"] = []
    data["derived_facts"] = []
    data["rule_evaluations"] = []
    data["findings"] = []
    data["anomaly_results"] = []
    data["recommendations"] = []
    data["policy_risk"] = None
    model = C.model_validate(data)
    ok, problems = validate_chain(model)
    assert isinstance(ok, bool)


# ─────────────────────────────────────────────────────────────────────────────
#  Item 7: engine-failure semantics are explicit, never silently dropped
# ─────────────────────────────────────────────────────────────────────────────


def test_engine_failure_is_represented_explicitly_and_valid():
    from securemailscope.chain.enums import EngineStatus
    from securemailscope.chain.models import ChainOfProof as C

    assert EngineStatus.FAILED.value == "failed"

    data = load_secure_fixture()
    data["analysis"]["analysis_status"] = "failed"
    data["analysis"]["rule_engine_status"] = "failed"
    data["analysis"]["ml_engine_status"] = "failed"
    data["analysis"]["limitations"] = [
        {"code": "field_unavailable", "summary": "rule engine could not complete"}
    ]
    data["rule_evaluations"] = []
    data["findings"] = []
    data["policy_risk"] = None
    data["anomaly_results"] = []
    data["recommendations"] = []
    model = C.model_validate(data)
    ok, problems = validate_chain(model)
    assert ok, problems
    assert model.analysis.analysis_status.value == "failed"


def test_invalid_engine_failure_status_rejected():
    from securemailscope.chain.enums import EngineStatus

    assert not hasattr(EngineStatus, "CRASHED")
    data = load_secure_fixture()
    data["analysis"]["rule_engine_status"] = "crashed"
    with pytest.raises(ValidationError):
        AnalysisManifest.model_validate(data["analysis"])


# ─────────────────────────────────────────────────────────────────────────────
#  Item 10: TLS 1.3 authorized-secret semantics
# ─────────────────────────────────────────────────────────────────────────────


def test_tls13_authorized_secrets_enum_has_only_two_states():
    from securemailscope.chain.enums import Tls13SecretsStatus

    states = {s.value for s in Tls13SecretsStatus}
    assert states == {"not_supplied", "authorized_supplied"}
    # The contract records only that secrets were authorized, never the material


def test_tls13_not_supplied_forces_session_secrets_required():
    from securemailscope.chain.enums import (
        ChainObservability,
        ObservationKind,
        Tls13SecretsStatus,
    )

    data = load_secure_fixture()
    data["analysis"]["tls13_authorized_secrets"] = Tls13SecretsStatus.NOT_SUPPLIED.value
    # Fabricate an observed TLS 1.3 certificate claim while not_supplied.
    data["crypto_observations"].append(
        {
            "observation_id": "obs_" + "ab" * 8,
            "session_id": data["sessions"][0]["session_id"],
            "kind": ObservationKind.CERTIFICATE_TRUSTED_PATH_VALIDATED.value,
            "value": "valid",
            "normalized_value": "valid",
            "observability": ChainObservability.OBSERVED.value,
            "evidence_ids": [data["evidence"][0]["evidence_id"]],
            "limitations": [],
        }
    )
    model = ChainOfProof.model_validate(data)
    ok, problems = validate_chain(model)
    assert not ok
    assert any("fabricated" in p for p in problems)
    assert any(
        "authorized session secrets" in p and "authorized session secrets" in p for p in problems
    )


def test_tls13_valid_distinct_secrets_status_is_accepted():
    from securemailscope.chain.enums import Tls13SecretsStatus

    data = load_secure_fixture()
    data["analysis"]["tls13_authorized_secrets"] = Tls13SecretsStatus.AUTHORIZED_SUPPLIED.value
    model = ChainOfProof.model_validate(data)
    ok, problems = validate_chain(model)
    assert ok, problems


# ─────────────────────────────────────────────────────────────────────────────
#  Item 12: anomaly interpretation note is a stable Literal, not free-form
# ─────────────────────────────────────────────────────────────────────────────


def test_anomaly_interpretation_note_is_stable_literal():
    from securemailscope.chain.models import ANOMALY_INTERPRETATION_NOTE, AnomalyResult

    assert ANOMALY_INTERPRETATION_NOTE == ("Anomalous behavior is not proof of malicious activity.")

    base = {
        "anomaly_result_id": "anm_" + "ab" * 8,
        "session_id": "ses_" + "c" * 16,
        "model_id": "iso-forest",
        "model_version": "1.0.0",
        "feature_schema_version": "1.0.0",
        "feature_snapshot": {"cpu_wait": 0.0},
        "raw_score": 0.1,
        "normalized_score": 0.1,
        "threshold": 0.5,
        "band": "normal",
        "unusual_feature_indicators": [],
        "linked_fact_ids": [],
        "linked_observation_ids": [],
        "evidence_ids": [],
        "limitations": [],
    }
    # Free-form interpretation text is rejected by the strict Literal.
    with pytest.raises(ValidationError):
        AnomalyResult.model_validate({**base, "interpretation_note": "custom text"})
    # The exact frozen literal is accepted.
    model = AnomalyResult.model_validate(
        {**base, "interpretation_note": ANOMALY_INTERPRETATION_NOTE}
    )
    assert model.interpretation_note == ANOMALY_INTERPRETATION_NOTE
