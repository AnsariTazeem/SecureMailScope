"""Backend V2 Milestone V2-1 Slice 1 identity-contract tests."""

from __future__ import annotations

import json

import pytest
from pydantic import BaseModel, ValidationError

from securemailscope.chain.ids import is_sha256_digest
from securemailscope.identity import (
    ANALYSIS_FINGERPRINT_SCHEMA_VERSION,
    AnalysisFingerprintInput,
    MlExecutionIdentity,
    PacketToolchainIdentity,
    ProtocolPluginIdentity,
    canonical_analysis_fingerprint_bytes,
    compute_analysis_fingerprint,
    is_job_id,
    new_job_id,
)


def _plugin(plugin_id: str = "smtp", version: str = "1.0.0") -> ProtocolPluginIdentity:
    return ProtocolPluginIdentity(plugin_id=plugin_id, plugin_version=version)


def _ml_identity() -> MlExecutionIdentity:
    return MlExecutionIdentity(
        feature_schema_id="email-session-features",
        feature_schema_version="1.0.0",
        feature_schema_digest="5" * 64,
        model_id="smtp-isolation-forest",
        model_version="1.0.0",
        model_digest="6" * 64,
        inference_runtime_id="scikit-learn",
        inference_runtime_version="1.9.0",
    )


def _packet_toolchain() -> PacketToolchainIdentity:
    return PacketToolchainIdentity(tshark_version="4.2.5", capinfos_version="4.2.5")


def _fingerprint_input(**updates: object) -> AnalysisFingerprintInput:
    values: dict[str, object] = {
        "fingerprint_schema_version": ANALYSIS_FINGERPRINT_SCHEMA_VERSION,
        "capture_sha256": "1" * 64,
        "analyzer_version": "securemailscope/0.1.0",
        "chain_schema_version": "1.0.0",
        "packet_toolchain": _packet_toolchain(),
        "analysis_configuration_digest": "2" * 64,
        "policy_pack_id": "smtp-starttls",
        "policy_pack_digest": "3" * 64,
        "profile_id": "sms-liberal",
        "protocol_plugins": (_plugin("smtp"), _plugin("imap", "2.0.0")),
        "ml_identity": _ml_identity(),
    }
    values.update(updates)
    return AnalysisFingerprintInput.model_validate(values)


def test_job_id_is_opaque_public_safe_and_distinct_from_other_identities() -> None:
    first = new_job_id()
    second = new_job_id()

    assert first != second
    assert is_job_id(first)
    assert not first.startswith("ana_")
    assert "capture" not in first
    assert len(first) == 36


@pytest.mark.parametrize("value", [None, 7, b"job_" + b"a" * 32, object()])
def test_job_id_validation_returns_false_for_non_strings(value: object) -> None:
    assert is_job_id(value) is False


def test_identical_complete_input_has_deterministic_fingerprint() -> None:
    first = _fingerprint_input()
    second = AnalysisFingerprintInput.model_validate(first.model_dump(mode="python"))

    assert compute_analysis_fingerprint(first) == compute_analysis_fingerprint(second)
    assert is_sha256_digest(compute_analysis_fingerprint(first))
    assert canonical_analysis_fingerprint_bytes(first) == canonical_analysis_fingerprint_bytes(
        second
    )


def test_plugin_order_does_not_affect_fingerprint_or_payload() -> None:
    forward = _fingerprint_input(protocol_plugins=(_plugin("smtp"), _plugin("imap", "2.0.0")))
    reverse = _fingerprint_input(protocol_plugins=(_plugin("imap", "2.0.0"), _plugin("smtp")))

    assert compute_analysis_fingerprint(forward) == compute_analysis_fingerprint(reverse)
    assert canonical_analysis_fingerprint_bytes(forward) == canonical_analysis_fingerprint_bytes(
        reverse
    )
    assert [plugin.plugin_id for plugin in reverse.protocol_plugins] == ["imap", "smtp"]


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("capture_sha256", "a" * 64),
        ("analyzer_version", "securemailscope/0.2.0"),
        ("chain_schema_version", "2.0.0"),
        (
            "packet_toolchain",
            PacketToolchainIdentity(tshark_version="4.4.0", capinfos_version="4.2.5"),
        ),
        ("analysis_configuration_digest", "b" * 64),
        ("policy_pack_id", "enterprise-email"),
        ("policy_pack_digest", "c" * 64),
        ("profile_id", "sms-strict"),
        ("protocol_plugins", (_plugin("smtp", "1.1.0"), _plugin("imap", "2.0.0"))),
        (
            "ml_identity",
            _ml_identity().model_copy(update={"model_digest": "d" * 64}),
        ),
    ],
)
def test_each_top_level_output_affecting_field_changes_fingerprint(
    field: str, replacement: object
) -> None:
    assert compute_analysis_fingerprint(_fingerprint_input()) != compute_analysis_fingerprint(
        _fingerprint_input(**{field: replacement})
    )


@pytest.mark.parametrize(
    ("field", "replacement"),
    [("plugin_id", "pop3"), ("plugin_version", "1.1.0")],
)
def test_each_protocol_plugin_identity_field_changes_fingerprint(
    field: str, replacement: str
) -> None:
    values = _plugin("smtp").model_dump(mode="python")
    values[field] = replacement
    changed_plugin = ProtocolPluginIdentity.model_validate(values)

    assert compute_analysis_fingerprint(_fingerprint_input()) != compute_analysis_fingerprint(
        _fingerprint_input(protocol_plugins=(changed_plugin, _plugin("imap", "2.0.0")))
    )


@pytest.mark.parametrize(
    ("field", "replacement"),
    [("tshark_version", "4.4.0"), ("capinfos_version", "4.4.0")],
)
def test_each_packet_tool_version_changes_fingerprint(field: str, replacement: str) -> None:
    values = _packet_toolchain().model_dump(mode="python")
    values[field] = replacement
    changed_toolchain = PacketToolchainIdentity.model_validate(values)

    assert compute_analysis_fingerprint(_fingerprint_input()) != compute_analysis_fingerprint(
        _fingerprint_input(packet_toolchain=changed_toolchain)
    )


@pytest.mark.parametrize("field", ["tshark_version", "capinfos_version"])
@pytest.mark.parametrize(
    "malformed",
    ["", "invalid", "4.2.5-dev", " 4.2.5", "4.2.5 ", "4.2.5\nextra", "4.2.٥", "v" * 257],
)
def test_malformed_packet_tool_versions_are_rejected(field: str, malformed: str) -> None:
    values = _packet_toolchain().model_dump(mode="python")
    values[field] = malformed

    with pytest.raises(ValidationError, match=field):
        PacketToolchainIdentity.model_validate(values)


def test_packet_toolchain_accepts_exact_repository_version_banner_shape() -> None:
    toolchain = PacketToolchainIdentity(
        tshark_version="TShark (Wireshark) 4.2.2 (Git v4.2.2 packaged as 4.2.2-1.1build3).",
        capinfos_version="Capinfos (Wireshark) 4.2.2 (Git v4.2.2 packaged as 4.2.2-1.1build3).",
    )

    assert toolchain.tshark_version.startswith("TShark (Wireshark) 4.2.2")
    assert toolchain.capinfos_version.startswith("Capinfos (Wireshark) 4.2.2")


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("feature_schema_id", "flow-features"),
        ("feature_schema_version", "1.1.0"),
        ("feature_schema_digest", "a" * 64),
        ("model_id", "mail-isolation-forest"),
        ("model_version", "1.1.0"),
        ("model_digest", "b" * 64),
        ("inference_runtime_id", "onnxruntime"),
        ("inference_runtime_version", "1.10.0"),
    ],
)
def test_each_ml_identity_field_changes_fingerprint(field: str, replacement: str) -> None:
    changed_ml = _ml_identity().model_copy(update={field: replacement})
    assert compute_analysis_fingerprint(_fingerprint_input()) != compute_analysis_fingerprint(
        _fingerprint_input(ml_identity=changed_ml)
    )


@pytest.mark.parametrize(
    "excluded_field",
    [
        "job_id",
        "created_at",
        "original_filename",
        "capture_path",
        "request_id",
        "capture_bytes",
    ],
)
def test_execution_and_file_metadata_are_not_fingerprint_inputs(excluded_field: str) -> None:
    values = _fingerprint_input().model_dump(mode="python")
    values[excluded_field] = "sensitive-or-volatile-value"

    with pytest.raises(ValidationError, match=excluded_field):
        AnalysisFingerprintInput.model_validate(values)


@pytest.mark.parametrize(
    "field",
    ["capture_sha256", "analysis_configuration_digest", "policy_pack_digest"],
)
@pytest.mark.parametrize("malformed", ["a" * 63, "A" * 64, "sha256:" + "a" * 64, "xyz"])
def test_malformed_top_level_sha256_values_are_rejected(field: str, malformed: str) -> None:
    with pytest.raises(ValidationError, match=field):
        _fingerprint_input(**{field: malformed})


@pytest.mark.parametrize("field", ["feature_schema_digest", "model_digest"])
def test_malformed_ml_sha256_values_are_rejected(field: str) -> None:
    values = _ml_identity().model_dump(mode="python")
    values[field] = "not-a-digest"
    with pytest.raises(ValidationError, match=field):
        MlExecutionIdentity.model_validate(values)


def test_duplicate_plugin_ids_are_rejected_even_with_different_versions() -> None:
    with pytest.raises(ValidationError, match="duplicate protocol plugin IDs"):
        _fingerprint_input(protocol_plugins=(_plugin("smtp"), _plugin("smtp", "2.0.0")))


def test_zero_protocol_plugins_are_rejected() -> None:
    with pytest.raises(ValidationError, match="protocol_plugins"):
        _fingerprint_input(protocol_plugins=())


def test_more_than_32_protocol_plugins_are_rejected() -> None:
    plugins = tuple(_plugin(f"plugin-{index}") for index in range(33))
    with pytest.raises(ValidationError, match="protocol_plugins"):
        _fingerprint_input(protocol_plugins=plugins)


@pytest.mark.parametrize(
    ("model_type", "field"),
    [
        (ProtocolPluginIdentity, "plugin_version"),
        (MlExecutionIdentity, "feature_schema_version"),
        (MlExecutionIdentity, "model_version"),
        (MlExecutionIdentity, "inference_runtime_version"),
        (PacketToolchainIdentity, "tshark_version"),
        (PacketToolchainIdentity, "capinfos_version"),
        (AnalysisFingerprintInput, "chain_schema_version"),
    ],
)
def test_empty_versions_are_rejected(model_type: type[BaseModel], field: str) -> None:
    if model_type is ProtocolPluginIdentity:
        values = _plugin().model_dump(mode="python")
    elif model_type is MlExecutionIdentity:
        values = _ml_identity().model_dump(mode="python")
    elif model_type is PacketToolchainIdentity:
        values = _packet_toolchain().model_dump(mode="python")
    else:
        values = _fingerprint_input().model_dump(mode="python")
    values[field] = ""

    with pytest.raises(ValidationError, match=field):
        model_type.model_validate(values)


def test_ml_absent_and_ml_present_inputs_are_distinct() -> None:
    without_ml = _fingerprint_input(ml_identity=None)
    with_ml = _fingerprint_input()

    assert compute_analysis_fingerprint(without_ml) != compute_analysis_fingerprint(with_ml)
    assert "ml_identity" not in json.loads(canonical_analysis_fingerprint_bytes(without_ml))


def test_canonical_payload_is_versioned_and_contains_only_safe_identity_fields() -> None:
    payload = canonical_analysis_fingerprint_bytes(_fingerprint_input())
    decoded = json.loads(payload)

    assert decoded["fingerprint_schema_version"] == ANALYSIS_FINGERPRINT_SCHEMA_VERSION
    assert set(decoded) == {
        "analysis_configuration_digest",
        "analyzer_version",
        "capture_sha256",
        "chain_schema_version",
        "fingerprint_schema_version",
        "ml_identity",
        "packet_toolchain",
        "policy_pack_digest",
        "policy_pack_id",
        "profile_id",
        "protocol_plugins",
    }
    assert b"capture bytes" not in payload
    assert b"customer-secrets.pcapng" not in payload
    assert b"/private/tmp/customer-secrets.pcapng" not in payload


@pytest.mark.parametrize(
    ("model_type", "field"),
    [
        (ProtocolPluginIdentity, "plugin_id"),
        (MlExecutionIdentity, "model_id"),
        (AnalysisFingerprintInput, "analyzer_version"),
        (AnalysisFingerprintInput, "policy_pack_id"),
        (AnalysisFingerprintInput, "profile_id"),
    ],
)
def test_blank_identifiers_are_rejected(model_type: type[BaseModel], field: str) -> None:
    if model_type is ProtocolPluginIdentity:
        values = _plugin().model_dump(mode="python")
    elif model_type is MlExecutionIdentity:
        values = _ml_identity().model_dump(mode="python")
    else:
        values = _fingerprint_input().model_dump(mode="python")
    values[field] = "   "

    with pytest.raises(ValidationError, match=field):
        model_type.model_validate(values)


@pytest.mark.parametrize(
    "plugin_id",
    ["SMTP", "smtp plugin", "smtp\nplugin", "smтp", "smtp/plugin", "smtp:plugin", "smtp@plugin"],
)
def test_plugin_id_rejects_noncanonical_values(plugin_id: str) -> None:
    with pytest.raises(ValidationError, match="plugin_id"):
        _plugin(plugin_id)


@pytest.mark.parametrize("plugin_id", ["smtp", "smtp.starttls", "smtp_v2", "smtp-plugin-2"])
def test_plugin_id_accepts_canonical_lowercase_ascii_values(plugin_id: str) -> None:
    assert _plugin(plugin_id).plugin_id == plugin_id


@pytest.mark.parametrize(
    ("target", "field", "invalid_value"),
    [
        ("fingerprint", "policy_pack_id", "SMTP-PACK"),
        ("fingerprint", "profile_id", "sms liberal"),
        ("ml", "feature_schema_id", "feature\nschema"),
        ("ml", "model_id", "mоdel"),
        ("ml", "inference_runtime_id", "Scikit-Learn"),
        ("ml", "inference_runtime_id", "scikit/learn"),
    ],
)
def test_all_identity_fields_share_canonical_safe_format(
    target: str, field: str, invalid_value: str
) -> None:
    if target == "ml":
        values = _ml_identity().model_dump(mode="python")
        values[field] = invalid_value
        with pytest.raises(ValidationError, match=field):
            MlExecutionIdentity.model_validate(values)
    else:
        values = _fingerprint_input().model_dump(mode="python")
        values[field] = invalid_value
        with pytest.raises(ValidationError, match=field):
            AnalysisFingerprintInput.model_validate(values)


@pytest.mark.parametrize(
    "analyzer_version",
    ["SecureMailScope/0.1.0", "securemailscope 0.1.0", "securemailscope/٠.1.0"],
)
def test_analyzer_version_rejects_noncanonical_ascii_values(analyzer_version: str) -> None:
    with pytest.raises(ValidationError, match="analyzer_version"):
        _fingerprint_input(analyzer_version=analyzer_version)


def test_existing_slash_delimited_analyzer_version_is_accepted() -> None:
    assert _fingerprint_input().analyzer_version == "securemailscope/0.1.0"


def test_malformed_ml_runtime_version_is_rejected() -> None:
    values = _ml_identity().model_dump(mode="python")
    values["inference_runtime_version"] = "1.9"

    with pytest.raises(ValidationError, match="inference_runtime_version"):
        MlExecutionIdentity.model_validate(values)


@pytest.mark.parametrize(
    "runtime_id",
    ["Scikit-Learn", "scikit learn", "scikit\nlearn", "scikit-ℓearn", "scikit/learn"],
)
def test_malformed_ml_runtime_id_is_rejected(runtime_id: str) -> None:
    values = _ml_identity().model_dump(mode="python")
    values["inference_runtime_id"] = runtime_id

    with pytest.raises(ValidationError, match="inference_runtime_id"):
        MlExecutionIdentity.model_validate(values)


def test_unsupported_fingerprint_schema_version_is_rejected() -> None:
    with pytest.raises(ValidationError, match="fingerprint_schema_version"):
        _fingerprint_input(fingerprint_schema_version="2.0.0")


def test_identity_models_are_strict_immutable_and_forbid_extras() -> None:
    inputs = _fingerprint_input()
    with pytest.raises(ValidationError):
        inputs.profile_id = "changed"
    with pytest.raises(ValidationError, match="unexpected"):
        ProtocolPluginIdentity.model_validate(
            {"plugin_id": "smtp", "plugin_version": "1.0.0", "unexpected": True}
        )


def test_fingerprint_bytes_require_validated_contract() -> None:
    with pytest.raises(TypeError, match="AnalysisFingerprintInput"):
        canonical_analysis_fingerprint_bytes({})  # type: ignore[arg-type]


def test_canonical_boundary_revalidates_copied_invalid_capture_digest() -> None:
    invalid = _fingerprint_input().model_copy(update={"capture_sha256": "invalid"})

    with pytest.raises(ValidationError, match="capture_sha256"):
        canonical_analysis_fingerprint_bytes(invalid)
    with pytest.raises(ValidationError, match="capture_sha256"):
        compute_analysis_fingerprint(invalid)


def test_canonical_boundary_revalidates_copied_invalid_nested_plugin_version() -> None:
    valid = _fingerprint_input()
    invalid_plugin = valid.protocol_plugins[0].model_copy(update={"plugin_version": "invalid"})
    invalid = valid.model_copy(
        update={"protocol_plugins": (invalid_plugin, *valid.protocol_plugins[1:])}
    )

    with pytest.raises(ValidationError, match="plugin_version"):
        canonical_analysis_fingerprint_bytes(invalid)
    with pytest.raises(ValidationError, match="plugin_version"):
        compute_analysis_fingerprint(invalid)


def test_canonical_boundary_revalidates_copied_invalid_nested_ml_digest() -> None:
    valid = _fingerprint_input()
    assert valid.ml_identity is not None
    invalid_ml = valid.ml_identity.model_copy(update={"model_digest": "invalid"})
    invalid = valid.model_copy(update={"ml_identity": invalid_ml})

    with pytest.raises(ValidationError, match="model_digest"):
        canonical_analysis_fingerprint_bytes(invalid)
    with pytest.raises(ValidationError, match="model_digest"):
        compute_analysis_fingerprint(invalid)


def test_canonical_boundary_revalidates_copied_invalid_nested_toolchain() -> None:
    valid = _fingerprint_input()
    invalid_toolchain = valid.packet_toolchain.model_copy(update={"tshark_version": "invalid"})
    invalid = valid.model_copy(update={"packet_toolchain": invalid_toolchain})

    with pytest.raises(ValidationError, match="tshark_version"):
        canonical_analysis_fingerprint_bytes(invalid)
    with pytest.raises(ValidationError, match="tshark_version"):
        compute_analysis_fingerprint(invalid)


def test_analysis_fingerprint_golden_compatibility_vector() -> None:
    inputs = AnalysisFingerprintInput(
        fingerprint_schema_version="1.0.0",
        capture_sha256="01" * 32,
        analyzer_version="securemailscope/0.1.0",
        chain_schema_version="1.0.0",
        packet_toolchain=PacketToolchainIdentity(
            tshark_version="4.2.5",
            capinfos_version="4.2.5",
        ),
        analysis_configuration_digest="23" * 32,
        policy_pack_id="smtp-starttls",
        policy_pack_digest="45" * 32,
        profile_id="sms-liberal",
        protocol_plugins=(
            ProtocolPluginIdentity(plugin_id="smtp", plugin_version="1.2.3"),
            ProtocolPluginIdentity(plugin_id="imap", plugin_version="2.0.0"),
        ),
        ml_identity=MlExecutionIdentity(
            feature_schema_id="email-session-features",
            feature_schema_version="1.1.0",
            feature_schema_digest="67" * 32,
            model_id="smtp-isolation-forest",
            model_version="3.2.1",
            model_digest="89" * 32,
            inference_runtime_id="scikit-learn",
            inference_runtime_version="1.9.0",
        ),
    )
    expected_bytes = (
        b'{"analysis_configuration_digest":"2323232323232323232323232323232323232323232323'
        b'232323232323232323","analyzer_version":"securemailscope/0.1.0","capture_sha256":'
        b'"0101010101010101010101010101010101010101010101010101010101010101","chain_schema'
        b'_version":"1.0.0","fingerprint_schema_version":"1.0.0","ml_identity":{"feature_s'
        b'chema_digest":"6767676767676767676767676767676767676767676767676767676767676767"'
        b',"feature_schema_id":"email-session-features","feature_schema_version":"1.1.0","'
        b'inference_runtime_id":"scikit-learn","inference_runtime_version":"1.9.0","model_'
        b'digest":"8989898989898989898989898989898989898989898989898989898989898989","mode'
        b'l_id":"smtp-isolation-forest","model_version":"3.2.1"},"packet_toolchain":{"capi'
        b'nfos_version":"4.2.5","tshark_version":"4.2.5"},"policy_pack_digest":"4545454545'
        b'454545454545454545454545454545454545454545454545454545","policy_pack_id":"smtp-s'
        b'tarttls","profile_id":"sms-liberal","protocol_plugins":[{"plugin_id":"imap","plu'
        b'gin_version":"2.0.0"},{"plugin_id":"smtp","plugin_version":"1.2.3"}]}'
    )

    assert canonical_analysis_fingerprint_bytes(inputs) == expected_bytes
    assert (
        compute_analysis_fingerprint(inputs)
        == "2089fc099537f9a30c81f6157e335594220ecf24e3d92a4a77019964db4b3f8e"
    )
