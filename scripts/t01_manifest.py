"""Ground-truth manifest construction and strict validation for fixture T01.

Truth sources are limited to generator configuration, endpoint negotiation
results, certificate inspection, independent tool results (openssl verify),
capture time, and artifact hashes. The manifest never references private key
paths/contents/hashes and never contains a self-hash.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import Any

from _fixture_common import (
    EPOCH_TEXT_PATTERN,
    FileIntegrity,
    FixtureError,
    decimal_epoch_to_utc_iso,
    iso_utc,
    parse_validated_epoch,
    run_bounded,
    utc_now,
)
from t01_capture import CAPTURE_BPF_FILTER, CAPTURE_INTERFACE, PCAP_FILENAME
from t01_endpoint import (
    BIND_IP,
    CIPHER_IANA_NAME,
    CIPHER_ID_HEX,
    CIPHER_OPENSSL_NAME,
    EC_GROUP_ID,
    EC_GROUP_NAME,
    EHLO_CLIENT_NAME,
    SERVER_PORT,
    STARTTLS_WRITE_PARTS,
    TLS_VERSION_LABEL,
    TLS_WIRE_VERSION_HEX,
)
from t01_pki import FIXTURE_HOSTNAME, CertificateFacts, load_crypto_version

MANIFEST_SCHEMA_VERSION = "1.0"
GENERATOR_NAME = "generate_t01_fixture"
GENERATOR_VERSION = "1.0"
FIXTURE_ID = "T01"
SCENARIO = "SMTP non-standard port, split STARTTLS, TLS 1.2 ECDHE, valid chain"
KEY_EXCHANGE_MECHANISM = "ECDHE"

MANIFEST_RELATIVE_PATH = Path("fixtures/manifests/t01_ground_truth.json")
PCAP_RELATIVE_PATH = Path("fixtures/pcaps") / PCAP_FILENAME
ENDPOINT_LOG_RELATIVE_PATH = Path("fixtures/endpoint_logs/t01_endpoint_log.jsonl")
EVIDENCE_RELATIVE_PATH = Path("fixtures/evidence/t01_manual_evidence.json")
CAPTURE_LOG_ARTIFACT_ROLE = "capture_log"

_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_HEX16_PATTERN = re.compile(r"^0x[0-9a-fA-F]{4}$")
_EPOCH_PATTERN = EPOCH_TEXT_PATTERN
_FORBIDDEN_KEY_PATTERN = re.compile(
    r"private|secret|key_material|self_hash|manifest_sha256", re.IGNORECASE
)

_REQUIRED_TOP_KEYS = frozenset(
    {
        "schema_version",
        "generator",
        "fixture_id",
        "scenario",
        "generated_at_utc",
        "endpoint",
        "smtp",
        "tls",
        "certificate",
        "chain_validation",
        "capture",
        "artifacts",
        "provenance",
    }
)


class ManifestValidationError(FixtureError):
    """The manifest structure violates the frozen ground-truth contract."""


def build_manifest(
    *,
    endpoint_log_relative_path: str,
    capture_log_relative_path: str,
    pcap_integrity: FileIntegrity,
    root_cert_integrity: FileIntegrity,
    leaf_cert_integrity: FileIntegrity,
    chain_integrity: FileIntegrity,
    endpoint_log_integrity: FileIntegrity,
    capture_log_integrity: FileIntegrity,
    leaf_facts: CertificateFacts,
    attime_epoch: int,
    first_packet_epoch: str,
    last_packet_epoch: str,
    first_packet_utc: str,
    last_packet_utc: str,
    runtime_versions: dict[str, str],
) -> dict[str, object]:
    """Assemble the ordered T01 ground-truth manifest dictionary."""
    return {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "generator": {"name": GENERATOR_NAME, "version": GENERATOR_VERSION},
        "fixture_id": FIXTURE_ID,
        "scenario": SCENARIO,
        "generated_at_utc": iso_utc(utc_now()),
        "endpoint": {
            "hostname": FIXTURE_HOSTNAME,
            "ip": BIND_IP,
            "port": SERVER_PORT,
            "interface": CAPTURE_INTERFACE,
        },
        "smtp": {
            "expected_sequence": expected_smtp_sequence(),
            "split_writes": split_writes_block(),
        },
        "tls": tls_truth_block(),
        "certificate": certificate_truth_block(leaf_facts),
        "chain_validation": {
            "method": "openssl verify -CAfile -attime -verify_hostname",
            "cafile_artifact_role": "root_ca_cert",
            "target_artifact_role": "server_leaf_cert",
            "verify_hostname": FIXTURE_HOSTNAME,
            "attime_epoch": attime_epoch,
            "expected_result": "ok",
        },
        "capture": {
            "filename": PCAP_FILENAME,
            "interface": CAPTURE_INTERFACE,
            "bpf_filter": CAPTURE_BPF_FILTER,
            "first_packet_epoch": first_packet_epoch,
            "last_packet_epoch": last_packet_epoch,
            "first_packet_utc": first_packet_utc,
            "last_packet_utc": last_packet_utc,
        },
        "artifacts": [
            _artifact("pcap", PCAP_RELATIVE_PATH.as_posix(), pcap_integrity),
            _artifact("root_ca_cert", "fixtures/pki/root-ca.pem", root_cert_integrity),
            _artifact("server_leaf_cert", "fixtures/pki/smtp-server-cert.pem", leaf_cert_integrity),
            _artifact("server_chain", "fixtures/pki/server-chain.pem", chain_integrity),
            _artifact("endpoint_log", endpoint_log_relative_path, endpoint_log_integrity),
            _artifact("capture_log", capture_log_relative_path, capture_log_integrity),
        ],
        "provenance": {
            "generator": {"name": GENERATOR_NAME, "version": GENERATOR_VERSION},
            "runtime": runtime_versions,
        },
    }


def expected_smtp_sequence() -> list[dict[str, object]]:
    part_one, part_two = STARTTLS_WRITE_PARTS
    return [
        {"actor": "server", "event": "banner"},
        {"actor": "client", "event": "ehlo", "value": f"EHLO {EHLO_CLIENT_NAME}"},
        {"actor": "server", "event": "ehlo_capabilities", "requires": ["STARTTLS"]},
        {"actor": "client", "event": "starttls_part", "index": 1, "value": part_one},
        {"actor": "client", "event": "starttls_part", "index": 2, "value": part_two.rstrip("\r\n")},
        {"actor": "server", "event": "starttls_accepted_220"},
        {"actor": "client", "event": "tls_client_hello"},
        {
            "actor": "server",
            "event": "tls_server_hello",
            "wire_version": TLS_WIRE_VERSION_HEX,
            "cipher_id_hex": CIPHER_ID_HEX,
        },
        {"actor": "client", "event": "ehlo_post_tls"},
        {"actor": "server", "event": "ehlo_post_tls_response"},
        {"actor": "client", "event": "quit"},
        {"actor": "server", "event": "bye_221"},
        {"actor": "both", "event": "clean_close_fin"},
    ]


def split_writes_block() -> dict[str, object]:
    reconstructed = "".join(part for part in STARTTLS_WRITE_PARTS)
    visible_parts = [part for part in STARTTLS_WRITE_PARTS if part != "\r\n"]
    return {
        "minimum_frames_required": 2,
        "writes": visible_parts,
        "reconstructed_command": reconstructed,
    }


def tls_truth_block() -> dict[str, object]:
    return {
        "version": TLS_VERSION_LABEL,
        "wire_version": TLS_WIRE_VERSION_HEX,
        "cipher_openssl_name": CIPHER_OPENSSL_NAME,
        "cipher_iana_name": CIPHER_IANA_NAME,
        "cipher_id_hex": CIPHER_ID_HEX,
        "key_exchange": KEY_EXCHANGE_MECHANISM,
        "ecdh_group_name": EC_GROUP_NAME,
        "ecdh_group_id": EC_GROUP_ID,
        "forward_secrecy_expected": True,
    }


def certificate_truth_block(facts: CertificateFacts) -> dict[str, object]:
    return {
        "role_paths": {
            "leaf_cert": "fixtures/pki/smtp-server-cert.pem",
            "chain": "fixtures/pki/server-chain.pem",
            "root_cert": "fixtures/pki/root-ca.pem",
        },
        "subject": facts.subject_rfc4514,
        "issuer": facts.issuer_rfc4514,
        "san_dns_names": list(facts.san_dns_names),
        "serial_hex": facts.serial_hex,
        "not_before_utc": facts.not_before_utc,
        "not_after_utc": facts.not_after_utc,
        "public_key_algorithm": facts.public_key_algorithm,
        "public_key_bits": facts.public_key_bits,
        "signature_algorithm": facts.signature_algorithm_name,
        "sha256_fingerprint": facts.sha256_fingerprint_hex,
    }


def collect_runtime_versions() -> dict[str, str]:
    from platform import python_version

    versions = {"python": python_version(), "cryptography": load_crypto_version()}
    for tool, argv in (
        ("openssl", ("openssl", "version")),
        ("dumpcap", ("dumpcap", "--version")),
        ("capinfos", ("capinfos", "--version")),
        ("tshark", ("tshark", "--version")),
    ):
        versions[tool] = _first_version_line(argv)
    return versions


def skeleton_manifest() -> dict[str, Any]:
    """A minimal structurally valid manifest used by validation unit tests."""
    return {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "generator": {"name": GENERATOR_NAME, "version": GENERATOR_VERSION},
        "fixture_id": FIXTURE_ID,
        "scenario": SCENARIO,
        "generated_at_utc": "1970-01-01T00:00:00.000Z",
        "endpoint": {
            "hostname": "example.test",
            "ip": "127.0.0.1",
            "port": 2525,
            "interface": "lo",
        },
        "smtp": {
            "expected_sequence": [
                {"actor": "server", "event": "banner"},
                {"actor": "client", "event": "starttls_part", "index": 1, "value": "START"},
                {"actor": "client", "event": "starttls_part", "index": 2, "value": "TLS"},
            ],
            "split_writes": {
                "minimum_frames_required": 2,
                "writes": ["START", "TLS"],
                "reconstructed_command": "STARTTLS\r\n",
            },
        },
        "tls": {
            "version": TLS_VERSION_LABEL,
            "wire_version": TLS_WIRE_VERSION_HEX,
            "cipher_openssl_name": CIPHER_OPENSSL_NAME,
            "cipher_iana_name": CIPHER_IANA_NAME,
            "cipher_id_hex": CIPHER_ID_HEX,
            "key_exchange": KEY_EXCHANGE_MECHANISM,
            "ecdh_group_name": EC_GROUP_NAME,
            "ecdh_group_id": EC_GROUP_ID,
            "forward_secrecy_expected": True,
        },
        "certificate": {
            "role_paths": {
                "leaf_cert": "fixtures/pki/leaf.pem",
                "chain": "fixtures/pki/chain.pem",
                "root_cert": "fixtures/pki/root.pem",
            },
            "subject": "CN=example.test",
            "issuer": "CN=Example Root",
            "san_dns_names": ["example.test"],
            "serial_hex": "0x1F",
            "not_before_utc": "1970-01-01T00:00:00.000Z",
            "not_after_utc": "3999-01-01T00:00:00.000Z",
            "public_key_algorithm": "RSA",
            "public_key_bits": 2048,
            "signature_algorithm": "sha256WithRSAEncryption",
            "sha256_fingerprint": "0" * 64,
        },
        "chain_validation": {
            "method": "openssl verify -CAfile -attime -verify_hostname",
            "cafile_artifact_role": "root_ca_cert",
            "target_artifact_role": "server_leaf_cert",
            "verify_hostname": "example.test",
            "attime_epoch": 1800000000,
            "expected_result": "ok",
        },
        "capture": {
            "filename": "fixture.pcapng",
            "interface": "lo",
            "bpf_filter": "tcp port 2525",
            "first_packet_epoch": "1800000000.100000123",
            "last_packet_epoch": "1800000000.900000987",
            "first_packet_utc": "2027-01-15T08:00:00.100000123Z",
            "last_packet_utc": "2027-01-15T08:00:00.900000987Z",
        },
        "artifacts": [
            {
                "role": "pcap",
                "path": "fixtures/pcaps/fixture.pcapng",
                "sha256": "0" * 64,
                "size_bytes": 128,
            }
        ],
        "provenance": {
            "generator": {"name": GENERATOR_NAME, "version": GENERATOR_VERSION},
            "runtime": {"python": "3.12.3"},
        },
    }


def validate_manifest(manifest: Mapping[str, Any]) -> None:
    """Enforce the full structural contract with precise failure messages."""
    _reject_forbidden_keys(manifest, "$")
    _require_exact_keys("$", dict(manifest), _REQUIRED_TOP_KEYS)
    if manifest["schema_version"] != MANIFEST_SCHEMA_VERSION:
        raise ManifestValidationError(
            "$.schema_version: expected "
            f"'{MANIFEST_SCHEMA_VERSION}', got '{manifest['schema_version']}'"
        )
    if manifest["fixture_id"] != FIXTURE_ID:
        raise ManifestValidationError(
            f"$.fixture_id: expected '{FIXTURE_ID}', got '{manifest['fixture_id']}'"
        )
    for key in ("scenario", "generated_at_utc"):
        if not isinstance(manifest[key], str) or not manifest[key]:
            raise ManifestValidationError(f"$.{key}: must be a non-empty string")
    _validate_generator(manifest["generator"])
    _validate_endpoint(manifest["endpoint"])
    _validate_smtp(manifest["smtp"])
    _validate_tls(manifest["tls"])
    _validate_certificate(manifest["certificate"])
    _validate_chain_validation(manifest["chain_validation"])
    first_epoch, _last_epoch = _validate_capture(manifest["capture"])
    chain_validation = manifest["chain_validation"]
    attime_epoch = chain_validation.get("attime_epoch")
    if attime_epoch != int(first_epoch):
        raise ManifestValidationError(
            f"$.chain_validation.attime_epoch: must equal int(first_packet_epoch) "
            f"({int(first_epoch)}), got {attime_epoch}"
        )
    _validate_artifacts(manifest["artifacts"])
    _validate_provenance(manifest["provenance"])


def validate_artifact_path(relative_path: str) -> None:
    path = PurePosixPath(relative_path)
    if path.is_absolute() or ".." in path.parts:
        raise ManifestValidationError(
            f"artifact path '{relative_path}' must stay inside the repository"
        )


def _artifact(role: str, relative_path: str, integrity: FileIntegrity) -> dict[str, object]:
    return {
        "role": role,
        "path": relative_path,
        "sha256": integrity.sha256_hex,
        "size_bytes": integrity.size_bytes,
    }


def _first_version_line(argv: tuple[str, ...]) -> str:
    try:
        result = run_bounded(list(argv), error_stage="provenance version probe")
    except FixtureError:
        return "unavailable"
    first_line = result.stdout_text.splitlines()[0] if result.stdout_text.splitlines() else ""
    return first_line or "unavailable"


def _require_exact_keys(section: str, obj: Mapping[str, Any], required: frozenset[str]) -> None:
    actual = set(obj)
    missing = sorted(required - actual)
    extra = sorted(actual - required)
    if missing:
        raise ManifestValidationError(f"{section}: missing required key(s): {', '.join(missing)}")
    if extra:
        raise ManifestValidationError(f"{section}: unexpected extra key(s): {', '.join(extra)}")


def _reject_forbidden_keys(node: Any, path: str) -> None:
    if isinstance(node, Mapping):
        for key, value in node.items():
            key_text = str(key)
            if _FORBIDDEN_KEY_PATTERN.search(key_text):
                raise ManifestValidationError(f"{path}.{key_text}: forbidden manifest key")
            _reject_forbidden_keys(value, f"{path}.{key_text}")
    elif isinstance(node, Sequence) and not isinstance(node, (str, bytes)):
        for index, item in enumerate(node):
            _reject_forbidden_keys(item, f"{path}[{index}]")


def _str_section(section: str, obj: Any, keys: tuple[str, ...]) -> None:
    mapping = _as_mapping(section, obj)
    for key in keys:
        value = mapping.get(key)
        if not isinstance(value, str) or not value:
            raise ManifestValidationError(f"{section}.{key}: must be a non-empty string")


def _as_mapping(section: str, obj: Any) -> Mapping[str, Any]:
    if not isinstance(obj, Mapping):
        raise ManifestValidationError(f"{section}: must be an object")
    return obj


def _validate_generator(section: Any) -> None:
    _str_section("$.generator", section, ("name", "version"))


def _validate_endpoint(section: Any) -> None:
    mapping = _as_mapping("$.endpoint", section)
    _require_exact_keys("$.endpoint", mapping, frozenset({"hostname", "ip", "port", "interface"}))
    _str_section("$.endpoint", mapping, ("hostname", "ip", "interface"))
    port = mapping.get("port")
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise ManifestValidationError("$.endpoint.port: must be an integer in [1, 65535]")


def _validate_smtp(section: Any) -> None:
    mapping = _as_mapping("$.smtp", section)
    _require_exact_keys("$.smtp", mapping, frozenset({"expected_sequence", "split_writes"}))
    sequence = mapping.get("expected_sequence")
    if not isinstance(sequence, list) or not sequence:
        raise ManifestValidationError("$.smtp.expected_sequence: must be a non-empty list")
    for index, step in enumerate(sequence):
        step_mapping = _as_mapping(f"$.smtp.expected_sequence[{index}]", step)
        for key in ("actor", "event"):
            if not isinstance(step_mapping.get(key), str) or not step_mapping.get(key):
                raise ManifestValidationError(
                    f"$.smtp.expected_sequence[{index}].{key}: must be a non-empty string"
                )
    writes_section = _as_mapping("$.smtp.split_writes", mapping.get("split_writes"))
    _require_exact_keys(
        "$.smtp.split_writes",
        writes_section,
        frozenset({"minimum_frames_required", "writes", "reconstructed_command"}),
    )
    minimum = writes_section.get("minimum_frames_required")
    if not isinstance(minimum, int) or isinstance(minimum, bool) or minimum < 2:
        raise ManifestValidationError("$.smtp.split_writes.minimum_frames_required: must be >= 2")
    writes = writes_section.get("writes")
    if (
        not isinstance(writes, list)
        or len(writes) < 2
        or not all(isinstance(item, str) and item for item in writes)
    ):
        raise ManifestValidationError("$.smtp.split_writes.writes: must be >= 2 non-empty strings")
    reconstructed = writes_section.get("reconstructed_command")
    if not isinstance(reconstructed, str) or not reconstructed.endswith("\r\n"):
        raise ManifestValidationError(
            "$.smtp.split_writes.reconstructed_command: must be a CRLF-terminated command"
        )


def _validate_tls(section: Any) -> None:
    mapping = _as_mapping("$.tls", section)
    required = frozenset(
        {
            "version",
            "wire_version",
            "cipher_openssl_name",
            "cipher_iana_name",
            "cipher_id_hex",
            "key_exchange",
            "ecdh_group_name",
            "ecdh_group_id",
            "forward_secrecy_expected",
        }
    )
    _require_exact_keys("$.tls", mapping, required)
    for key in (
        "version",
        "wire_version",
        "cipher_openssl_name",
        "cipher_iana_name",
        "cipher_id_hex",
        "key_exchange",
        "ecdh_group_name",
    ):
        value = mapping.get(key)
        if not isinstance(value, str) or not value:
            raise ManifestValidationError(f"$.tls.{key}: must be a non-empty string")
    for key in ("wire_version", "cipher_id_hex"):
        value = mapping.get(key)
        if isinstance(value, str) and not _HEX16_PATTERN.match(value):
            raise ManifestValidationError(f"$.tls.{key}: must match {value!r} pattern '0xHHHH'")
    group_id = mapping.get("ecdh_group_id")
    if not isinstance(group_id, int) or isinstance(group_id, bool) or group_id <= 0:
        raise ManifestValidationError("$.tls.ecdh_group_id: must be a positive integer")
    forward_secrecy = mapping.get("forward_secrecy_expected")
    if not isinstance(forward_secrecy, bool):
        raise ManifestValidationError("$.tls.forward_secrecy_expected: must be a boolean")


def _validate_certificate(section: Any) -> None:
    mapping = _as_mapping("$.certificate", section)
    required = frozenset(
        {
            "role_paths",
            "subject",
            "issuer",
            "san_dns_names",
            "serial_hex",
            "not_before_utc",
            "not_after_utc",
            "public_key_algorithm",
            "public_key_bits",
            "signature_algorithm",
            "sha256_fingerprint",
        }
    )
    _require_exact_keys("$.certificate", mapping, required)
    role_paths = _as_mapping("$.certificate.role_paths", mapping.get("role_paths"))
    _require_exact_keys(
        "$.certificate.role_paths",
        role_paths,
        frozenset({"leaf_cert", "chain", "root_cert"}),
    )
    for role, relative_path in role_paths.items():
        if not isinstance(relative_path, str) or not relative_path:
            raise ManifestValidationError(f"$.certificate.role_paths.{role}: must be a path string")
        validate_artifact_path(relative_path)
    for key in (
        "subject",
        "issuer",
        "serial_hex",
        "not_before_utc",
        "not_after_utc",
        "public_key_algorithm",
        "signature_algorithm",
    ):
        value = mapping.get(key)
        if not isinstance(value, str) or not value:
            raise ManifestValidationError(f"$.certificate.{key}: must be a non-empty string")
    san = mapping.get("san_dns_names")
    if (
        not isinstance(san, list)
        or not san
        or not all(isinstance(item, str) and item for item in san)
    ):
        raise ManifestValidationError("$.certificate.san_dns_names: must be non-empty DNS strings")
    bits = mapping.get("public_key_bits")
    if not isinstance(bits, int) or isinstance(bits, bool) or bits <= 0:
        raise ManifestValidationError("$.certificate.public_key_bits: must be a positive integer")
    fingerprint = mapping.get("sha256_fingerprint")
    if not isinstance(fingerprint, str) or not _SHA256_PATTERN.match(fingerprint):
        raise ManifestValidationError(
            "$.certificate.sha256_fingerprint: must be lowercase sha256 hex"
        )


def _validate_chain_validation(section: Any) -> None:
    mapping = _as_mapping("$.chain_validation", section)
    required = frozenset(
        {
            "method",
            "cafile_artifact_role",
            "target_artifact_role",
            "verify_hostname",
            "attime_epoch",
            "expected_result",
        }
    )
    _require_exact_keys("$.chain_validation", mapping, required)
    for key in ("method", "cafile_artifact_role", "target_artifact_role", "verify_hostname"):
        value = mapping.get(key)
        if not isinstance(value, str) or not value:
            raise ManifestValidationError(f"$.chain_validation.{key}: must be a non-empty string")
    epoch = mapping.get("attime_epoch")
    if not isinstance(epoch, int) or isinstance(epoch, bool) or epoch < 0:
        raise ManifestValidationError(
            "$.chain_validation.attime_epoch: must be a non-negative integer"
        )
    if mapping.get("expected_result") != "ok":
        raise ManifestValidationError("$.chain_validation.expected_result: T01 expects 'ok'")
    if mapping.get("cafile_artifact_role") != "root_ca_cert":
        raise ManifestValidationError(
            "$.chain_validation.cafile_artifact_role: T01 verifies against 'root_ca_cert'"
        )
    if mapping.get("target_artifact_role") != "server_leaf_cert":
        raise ManifestValidationError(
            "$.chain_validation.target_artifact_role: T01 verifies the leaf certificate"
        )


def _validate_capture(section: Any) -> None:
    mapping = _as_mapping("$.capture", section)
    _require_exact_keys(
        "$.capture",
        mapping,
        frozenset(
            {
                "filename",
                "interface",
                "bpf_filter",
                "first_packet_epoch",
                "last_packet_epoch",
                "first_packet_utc",
                "last_packet_utc",
            }
        ),
    )
    _str_section(
        "$.capture",
        mapping,
        (
            "filename",
            "interface",
            "bpf_filter",
            "first_packet_epoch",
            "last_packet_epoch",
            "first_packet_utc",
            "last_packet_utc",
        ),
    )
    for key in ("first_packet_epoch", "last_packet_epoch"):
        value = mapping.get(key)
        if isinstance(value, str) and not _EPOCH_PATTERN.match(value):
            raise ManifestValidationError(
                "$.capture."
                f"{key}: must be decimal seconds with 1-9 fractional digits like "
                "'1800000000.100000123'"
            )
    first_epoch = parse_validated_epoch(str(mapping.get("first_packet_epoch")))
    last_epoch = parse_validated_epoch(str(mapping.get("last_packet_epoch")))
    if first_epoch is None:
        raise ManifestValidationError(
            "$.capture.first_packet_epoch: malformed, negative, or non-finite epoch"
        )
    if last_epoch is None:
        raise ManifestValidationError(
            "$.capture.last_packet_epoch: malformed, negative, or non-finite epoch"
        )
    if first_epoch > last_epoch:
        raise ManifestValidationError(
            "$.capture: reversed timestamp interval (first_packet_epoch > last_packet_epoch)"
        )
    expected_first_utc = decimal_epoch_to_utc_iso(first_epoch)
    if str(mapping.get("first_packet_utc")) != expected_first_utc:
        raise ManifestValidationError(
            f"$.capture.first_packet_utc: '{mapping.get('first_packet_utc')}' does not match "
            f"canonical rendering {expected_first_utc} of first_packet_epoch"
        )
    expected_last_utc = decimal_epoch_to_utc_iso(last_epoch)
    if str(mapping.get("last_packet_utc")) != expected_last_utc:
        raise ManifestValidationError(
            f"$.capture.last_packet_utc: '{mapping.get('last_packet_utc')}' does not match "
            f"canonical rendering {expected_last_utc} of last_packet_epoch"
        )
    return first_epoch, last_epoch


def _validate_artifacts(section: Any) -> None:
    if not isinstance(section, list) or not section:
        raise ManifestValidationError("$.artifacts: must be a non-empty list")
    for index, entry in enumerate(section):
        entry_mapping = _as_mapping(f"$.artifacts[{index}]", entry)
        _require_exact_keys(
            f"$.artifacts[{index}]",
            entry_mapping,
            frozenset({"role", "path", "sha256", "size_bytes"}),
        )
        role = entry_mapping.get("role")
        path_value = entry_mapping.get("path")
        digest = entry_mapping.get("sha256")
        size = entry_mapping.get("size_bytes")
        if not isinstance(role, str) or not role:
            raise ManifestValidationError(f"$.artifacts[{index}].role: must be a non-empty string")
        if not isinstance(path_value, str):
            raise ManifestValidationError(f"$.artifacts[{index}].path: must be a string")
        validate_artifact_path(path_value)
        if not isinstance(digest, str) or not _SHA256_PATTERN.match(digest):
            raise ManifestValidationError(
                f"$.artifacts[{index}].sha256: must be lowercase 64-hex sha256"
            )
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise ManifestValidationError(
                f"$.artifacts[{index}].size_bytes: must be a non-negative integer"
            )


def _validate_provenance(section: Any) -> None:
    mapping = _as_mapping("$.provenance", section)
    generator = _as_mapping("$.provenance.generator", mapping.get("generator"))
    _str_section("$.provenance.generator", generator, ("name", "version"))
    runtime = mapping.get("runtime")
    if not isinstance(runtime, dict) or not runtime:
        raise ManifestValidationError("$.provenance.runtime: must be a non-empty version map")
