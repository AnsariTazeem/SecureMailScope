"""Unit tests for T01 fixture tooling.

Covers hashing, bounded subprocesses, manifest validation, wire-row parsing/
normalization, endpoint constants/log/SAN handling, negotiated-facts contract,
PKI cryptographic properties, capture-log parsing, PCAP interval parsing,
verifier comparators, Forward-Secrecy derivation independence, and connection
lifecycle evidence.

No test performs live capture, network access, or depends on a generated PCAP.
"""

from __future__ import annotations

import json
import os
import re
import stat
import sys
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

import pytest
from _fixture_common import (
    DETAIL_TEXT_LIMIT,
    CommandWindow,
    FixtureToolError,
    PayloadFrame,
    bound_text,
    capture_interval,
    decimal_epoch_to_utc_iso,
    locate_command_window,
    normalize_argv,
    parse_frame_epoch_rows,
    parse_packet_count,
    parse_payload_rows,
    parse_validated_epoch,
    run_bounded,
    sha256_file,
    truncate_log_text,
    write_json_file,
)
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import ExtensionOID
from t01_capture import CAPTURE_DRAIN_SECONDS, DumpcapSummary, parse_dumpcap_summary
from t01_endpoint import (
    CIPHER_IANA_NAME,
    CIPHER_OPENSSL_NAME,
    EC_GROUP_ID,
    INTER_WRITE_DELAY_SECONDS,
    SERVER_PORT,
    STARTTLS_WRITE_PARTS,
    TLS_WIRE_VERSION_HEX,
    EndpointEventLog,
    SessionFacts,
    SmtpSessionError,
    dns_names_from_peercert,
    validate_negotiated_facts,
)
from t01_manifest import (
    FIXTURE_ID,
    MANIFEST_SCHEMA_VERSION,
    ManifestValidationError,
    skeleton_manifest,
    validate_manifest,
)
from t01_pki import FIXTURE_HOSTNAME, generate_pki, inspect_certificate
from verify_t01_manual import (
    EXPECTED_CIPHER_ID_INT,
    SECP256R1_GROUP_ID,
    TLS_12_WIRE_VERSION_INT,
    TLS_13_WIRE_VERSION_INT,
    HandshakeFrameView,
    build_tshark_argv,
    classify_direction,
    connection_lifecycle_summary,
    csv_hex_ints,
    derive_forward_secrecy,
    first_type_positions,
    forward_secrecy_check,
    handshake_order_result,
    named_curve_result,
    negotiated_version_result,
    parse_certificate_rows,
    parse_flag_rows,
    parse_handshake_rows,
)


def _frame(
    number: int, payload: bytes, src_port: int = 41000, dst_port: int = SERVER_PORT
) -> PayloadFrame:
    return PayloadFrame(
        frame_number=number,
        source_ip="127.0.0.1",
        source_port=src_port,
        destination_port=dst_port,
        payload=payload,
    )


def _view(
    frame_number: int, types: tuple[int, ...], **extra: tuple[int, ...]
) -> HandshakeFrameView:
    defaults: dict[str, tuple[int, ...]] = {
        "versions": (),
        "cipher_suites": (),
        "named_curves": (),
        "advertised_versions": (),
    }
    defaults.update(extra)
    return HandshakeFrameView(
        frame_number=frame_number,
        handshake_types=types,
        versions=defaults["versions"],
        cipher_suites=defaults["cipher_suites"],
        named_curves=defaults["named_curves"],
        advertised_versions=defaults["advertised_versions"],
    )


def _flag_line(frame: int, port: int, raw_flags: int) -> str:
    return f"{frame}\t127.0.0.1\t{port}\t{raw_flags}"


def test_sha256_and_size_roundtrip(tmp_path: Path) -> None:
    target = tmp_path / "blob.bin"
    target.write_bytes(b"controlled fixture bytes")
    integrity = sha256_file(target)
    assert len(integrity.sha256_hex) == 64
    assert integrity.size_bytes == target.stat().st_size


def test_run_bounded_success_nonzero_timeout_missing_and_shell_rejection() -> None:
    ok = run_bounded([sys.executable, "-c", "print('bounded-ok')"], error_stage="probe")
    assert ok.ok and "bounded-ok" in ok.stdout_text

    failed = run_bounded([sys.executable, "-c", "raise SystemExit(7)"], error_stage="probe")
    assert not failed.ok and failed.returncode == 7

    with pytest.raises(FixtureToolError, match="timed out"):
        run_bounded(["sleep", "3"], error_stage="probe", timeout_seconds=0.3)

    with pytest.raises(FixtureToolError, match="not found"):
        run_bounded(["sms-no-such-tool-xyz"], error_stage="probe")

    with pytest.raises(FixtureToolError):
        normalize_argv("echo hi && rm -rf /")
    with pytest.raises(FixtureToolError):
        normalize_argv(["echo", ""])


def test_bound_text_truncates_with_ellipsis() -> None:
    bounded = bound_text("x" * (DETAIL_TEXT_LIMIT + 50))
    assert len(bounded) <= DETAIL_TEXT_LIMIT and bounded.endswith("...")


def test_write_json_file_creates_parents_and_newline(tmp_path: Path) -> None:
    target = tmp_path / "nested" / "out.json"
    write_json_file(target, {"a": 1})
    content = target.read_text(encoding="utf-8")
    assert content.endswith("\n") and '"a": 1' in content


def test_parse_packet_count_accepts_colon_equals_and_rejects_bad_values() -> None:
    assert parse_packet_count("Number of packets: 10\n") == 10
    assert parse_packet_count("Number of packets = 10\n") == 10
    assert parse_packet_count("File type = Wireshark - pcapng\nNumber of packets: 42\n") == 42
    assert parse_packet_count("Number of packets: 0\n") == 0
    assert parse_packet_count("Number of packets: abc\n") is None
    assert parse_packet_count("Packets: 12\n") is None
    assert parse_packet_count("") is None


def test_parse_frame_epoch_rows_and_capture_interval() -> None:
    raw = "40\t1800000000.900000987\n3\t1800000000.100000123\nnot-a-row\n"
    rows = parse_frame_epoch_rows(raw)
    assert len(rows) == 2
    interval = capture_interval(rows)
    assert interval == ("1800000000.100000123", "1800000000.900000987")
    assert capture_interval([]) is None


def test_parse_validated_epoch_accepts_nine_digits_and_rejects_bad_values() -> None:
    nine_digits = parse_validated_epoch("1800000000.100000123")
    assert nine_digits == Decimal("1800000000.100000123")
    assert parse_validated_epoch("1800000000.1") == Decimal("1800000000.1")
    assert parse_validated_epoch(" 1800000000.5 ") == Decimal("1800000000.5")
    for bad in ("-1.5", "NaN", "-Infinity", "Infinity", "abc", "1800000000.", "5", "1.1234567890"):
        assert parse_validated_epoch(bad) is None, bad


def test_decimal_epoch_utc_canonical_rendering_is_exact() -> None:
    assert decimal_epoch_to_utc_iso(Decimal("0.000000001")) == "1970-01-01T00:00:00.000000001Z"
    assert (
        decimal_epoch_to_utc_iso(Decimal("1800000000.100000123"))
        == "2027-01-15T08:00:00.100000123Z"
    )
    assert (
        decimal_epoch_to_utc_iso(Decimal("1800000000.900000987"))
        == "2027-01-15T08:00:00.900000987Z"
    )
    assert decimal_epoch_to_utc_iso(parse_validated_epoch("1800000000.100000123")) == (
        "2027-01-15T08:00:00.100000123Z"
    )


def test_truncate_log_text_preserves_lines_and_bounds() -> None:
    text = "\n".join(f"line {i}" for i in range(2000))
    truncated = truncate_log_text(text, limit=500)
    assert len(truncated) <= 520
    assert truncated.startswith("line 0")
    assert "[truncated]" in truncated
    short = truncate_log_text("a\nb\n", limit=500)
    assert short == "a\nb\n"


def test_parse_payload_rows_parses_and_skips_malformed() -> None:
    raw = (
        f"10\t127.0.0.1\t41000\t{SERVER_PORT}\t{b'START'.hex()}\n"
        f"11\t127.0.0.1\t41000\t{SERVER_PORT}\t{b'TLS\r\n'.hex()}\n"
        "12\t127.0.0.1\t41000\t2525\t\n"
        "not-a-row\n"
    )
    frames = parse_payload_rows(raw)
    assert [frame.payload for frame in frames] == [b"START", b"TLS\r\n"]


def test_locate_command_window_requires_two_frames() -> None:
    split_frames = [_frame(1, b"EHLO x\r\n"), _frame(2, b"START"), _frame(3, b"TLS\r\n")]
    window = locate_command_window(split_frames, b"STARTTLS\r\n", minimum_frames=2)
    assert isinstance(window, CommandWindow)
    assert [frame.frame_number for frame in window.frames] == [2, 3]
    buffer = b"".join(frame.payload for frame in split_frames)
    assert buffer[window.start_offset : window.end_offset] == b"STARTTLS\r\n"
    assert (
        locate_command_window([_frame(1, b"STARTTLS\r\n")], b"STARTTLS\r\n", minimum_frames=2)
        is None
    )
    assert locate_command_window([_frame(1, b"NOPE")], b"STARTTLS\r\n", minimum_frames=2) is None


def test_starttls_parts_join_to_expected_command() -> None:
    joined = b"".join(part.encode(encoding="ascii") for part in STARTTLS_WRITE_PARTS)
    assert joined == b"STARTTLS\r\n"
    assert len(STARTTLS_WRITE_PARTS) >= 2
    assert 0 < INTER_WRITE_DELAY_SECONDS <= 1.0
    assert CIPHER_OPENSSL_NAME == "ECDHE-RSA-AES128-GCM-SHA256"
    assert CIPHER_IANA_NAME == "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
    assert EC_GROUP_ID == 23
    assert TLS_WIRE_VERSION_HEX == "0x0303"


def test_dns_names_from_peercert_reads_dns_label_not_dnsname() -> None:
    peer_cert = {"subjectAltName": (("DNS", "mail.securemailscope.test"),)}
    assert dns_names_from_peercert(peer_cert) == ("mail.securemailscope.test",)

    mixed = {"subjectAltName": (("DNS", "a.test"), ("IP Address", "127.0.0.1"), ("DNS", "b.test"))}
    assert dns_names_from_peercert(mixed) == ("a.test", "b.test")
    assert dns_names_from_peercert({}) == ()
    assert dns_names_from_peercert({"subjectAltName": "unexpected"}) == ()


def _facts(
    *,
    version: str = "TLSv1.2",
    cipher: str = CIPHER_OPENSSL_NAME,
    bits: int = 128,
    san: tuple[str, ...] = (FIXTURE_HOSTNAME,),
) -> SessionFacts:
    return SessionFacts(
        tls_protocol_version=version,
        cipher_openssl_name=cipher,
        cipher_bits=bits,
        peer_san_dns_names=san,
    )


def test_negotiated_facts_validation_accepts_contract_session() -> None:
    validate_negotiated_facts(_facts())


@pytest.mark.parametrize(
    "kwargs",
    [
        {"version": "TLSv1.3"},
        {"cipher": "AES128-GCM-SHA256"},
        {"bits": 256},
        {"san": ("other.example.test",)},
    ],
)
def test_negotiated_facts_validation_rejects_each_mismatch(kwargs: dict[str, object]) -> None:
    with pytest.raises(SmtpSessionError):
        validate_negotiated_facts(_facts(**kwargs))  # type: ignore[arg-type]


def test_endpoint_event_log_bounds_entries_and_details() -> None:
    log = EndpointEventLog(max_events=3)
    log.add("client", "one", detail="y" * 500)
    log.add("server", "two")
    log.add("client", "three")
    with pytest.raises(SmtpSessionError):
        log.add("server", "overflow")
    lines = log.to_jsonl().strip().splitlines()
    assert len(lines) == 3
    parsed = json.loads(lines[0])
    assert set(parsed) == {"seq", "ts_utc", "actor", "event", "details"}
    assert len(parsed["details"]["detail"]) <= DETAIL_TEXT_LIMIT


def test_manifest_skeleton_validates_and_pins_identity() -> None:
    skeleton = skeleton_manifest()
    validate_manifest(skeleton)
    assert skeleton["fixture_id"] == FIXTURE_ID
    assert skeleton["schema_version"] == MANIFEST_SCHEMA_VERSION
    assert skeleton["chain_validation"]["target_artifact_role"] == "server_leaf_cert"


@pytest.mark.parametrize(
    "mutation",
    [
        lambda m: m.pop("fixture_id"),
        lambda m: m.update(fixture_id="T99"),
        lambda m: m.update(schema_version="9.9"),
        lambda m: m["certificate"].update(private_key_path="fixtures/pki/private/x.key"),
        lambda m: m.update(manifest_sha256="0" * 64),
        lambda m: m["endpoint"].update(port="2525"),
        lambda m: m["smtp"]["split_writes"].update(minimum_frames_required=1),
        lambda m: m["smtp"]["split_writes"].update(reconstructed_command="STARTTLS"),
        lambda m: m["tls"].update(cipher_id_hex="C02F"),
        lambda m: m["certificate"].update(sha256_fingerprint="ZZ"),
        lambda m: m["artifacts"][0].update(size_bytes=-1),
        lambda m: m["artifacts"][0].update(path="../outside.pcapng"),
        lambda m: m["capture"].update(first_packet_epoch="abc"),
        lambda m: m["capture"].pop("last_packet_utc"),
        lambda m: m["capture"].update(captured_at_utc="1970-01-01T00:00:00Z"),
        lambda m: m["capture"].update(first_packet_epoch="1800000000.900000987"),
        lambda m: m["capture"].update(last_packet_epoch="1800000000.100000123"),
        lambda m: m["capture"].update(first_packet_epoch="-1.5"),
        lambda m: m["capture"].update(first_packet_epoch="1800000000.1000001234"),
        lambda m: m["capture"].update(first_packet_utc="2027-01-15T08:00:00.100000124Z"),
        lambda m: m["capture"].update(last_packet_utc="2027-01-15T08:00:00.900000988Z"),
        lambda m: m["chain_validation"].update(attime_epoch=1800000001),
    ],
)
def test_manifest_validation_rejects_mutations(mutation) -> None:
    manifest = skeleton_manifest()
    mutation(manifest)
    with pytest.raises(ManifestValidationError):
        validate_manifest(manifest)


def test_generate_pki_writes_restricted_files_and_correct_facts(tmp_path: Path) -> None:
    pki_dir = tmp_path / "pki"
    pki = generate_pki(pki_dir, now=datetime.now(UTC))

    private_dir = pki_dir / "private"
    assert stat.S_IMODE(private_dir.stat().st_mode) == 0o700
    for key_path in (pki.root_key_path, pki.leaf_key_path):
        assert key_path.is_file()
        assert stat.S_IMODE(key_path.stat().st_mode) == 0o600
    for public_path in (pki.root_cert_path, pki.leaf_cert_path, pki.chain_path):
        assert stat.S_IMODE(public_path.stat().st_mode) == 0o644

    leaf = pki.leaf_facts
    assert leaf.public_key_algorithm == "RSA" and leaf.public_key_bits == 2048
    assert leaf.signature_algorithm_name == "sha256WithRSAEncryption"
    assert leaf.san_dns_names == (FIXTURE_HOSTNAME,)
    assert pki.root_facts.issuer_rfc4514 == pki.root_facts.subject_rfc4514
    reloaded = inspect_certificate(pki.leaf_cert_path)
    assert reloaded == leaf


def test_leaf_certificate_is_cryptographically_signed_by_root(tmp_path: Path) -> None:
    pki = generate_pki(tmp_path / "pki", now=datetime.now(UTC))
    root = x509.load_pem_x509_certificate(pki.root_cert_path.read_bytes())
    leaf = x509.load_pem_x509_certificate(pki.leaf_cert_path.read_bytes())

    root.public_key().verify(
        leaf.signature,
        leaf.tbs_certificate_bytes,
        padding.PKCS1v15(),
        leaf.signature_hash_algorithm,
    )

    assert leaf.issuer == root.subject

    leaf_public_key = leaf.public_key()
    assert isinstance(leaf_public_key, rsa.RSAPublicKey)
    assert leaf_public_key.key_size == 2048

    assert isinstance(root.signature_hash_algorithm, hashes.SHA256)
    assert isinstance(leaf.signature_hash_algorithm, hashes.SHA256)

    san = leaf.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
    assert san.get_values_for_type(x509.DNSName) == ["mail.securemailscope.test"]

    chain_blocks = re.findall(
        r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
        pki.chain_path.read_text(encoding="utf-8"),
        flags=re.DOTALL,
    )
    assert len(chain_blocks) == 2
    chain_first = x509.load_pem_x509_certificate(chain_blocks[0].encode())
    chain_second = x509.load_pem_x509_certificate(chain_blocks[1].encode())
    assert chain_first.fingerprint(hashes.SHA256()) == leaf.fingerprint(hashes.SHA256())
    assert chain_second.fingerprint(hashes.SHA256()) == root.fingerprint(hashes.SHA256())


def _installed_dumpcap_line(captured: int, received: int, dropped: int) -> str:
    return (
        "Packets received/dropped on interface 'Loopback: lo': "
        f"{received}/{dropped} (pcap:0/dumpcap:0/flushed:0/ps_ifdrop:0) (100.0%)"
    )


def test_parse_dumpcap_summary_exact_installed_one_line_form() -> None:
    sample = "Packets captured: 10\n" + _installed_dumpcap_line(10, 10, 0) + "\n"
    summary = parse_dumpcap_summary(sample)
    assert summary == DumpcapSummary(captured=10, received=10, dropped=0)


def test_parse_dumpcap_summary_captured_positive_and_dropped_zero() -> None:
    sample = "Packets captured: 12\n" + _installed_dumpcap_line(12, 12, 0) + "\n"
    summary = parse_dumpcap_summary(sample)
    assert summary is not None
    assert summary.captured > 0 and summary.dropped == 0


def test_parse_dumpcap_summary_split_line_compatibility() -> None:
    sample = (
        "Packets captured: 10\n"
        "Packets received/dropped on interface 'Loopback: lo': 10/0\n"
        "(pcap:0/dumpcap:0/flushed:0/ps_ifdrop:0) (100.0%)\n"
    )
    summary = parse_dumpcap_summary(sample)
    assert summary == DumpcapSummary(captured=10, received=10, dropped=0)


def test_parse_dumpcap_summary_nonzero_dropped_malformed_missing() -> None:
    dropped = parse_dumpcap_summary(
        "Packets captured: 7\n" + _installed_dumpcap_line(7, 7, 3) + "\n"
    )
    assert dropped == DumpcapSummary(captured=7, received=7, dropped=3)

    assert parse_dumpcap_summary("Packets captured: ten\n") is None
    assert parse_dumpcap_summary("Packets captured: 5\n") is None
    assert (
        parse_dumpcap_summary(
            "Packets captured: 5\nPackets received/dropped on interface 'lo': x/y\n"
        )
        is None
    )
    assert parse_dumpcap_summary("") is None


def test_csv_hex_ints_handles_decimal_and_hex_tokens() -> None:
    assert csv_hex_ints("23") == (23,)
    assert csv_hex_ints("0xc02f") == (0xC02F,)
    assert csv_hex_ints("0x0303,49199") == (0x0303, 49199)
    assert csv_hex_ints("") == ()
    assert csv_hex_ints("junk,5") == (5,)


def test_parse_handshake_rows_normalizes_columns() -> None:
    views = parse_handshake_rows("\t".join(["7", "2", "0x0303", "0xc02f", "23", ""]))
    assert len(views) == 1
    view = views[0]
    assert view.frame_number == 7
    assert view.handshake_types == (2,)
    assert view.versions == (771,)
    assert view.cipher_suites == (49199,)
    assert view.named_curves == (23,)


def test_classify_direction_uses_server_ip_and_port() -> None:
    assert (
        classify_direction("127.0.0.1", SERVER_PORT, "127.0.0.1", SERVER_PORT) == "server_to_client"
    )
    assert classify_direction("127.0.0.1", 41000, "127.0.0.1", SERVER_PORT) == "client_to_server"
    assert classify_direction("127.0.0.1", SERVER_PORT, "10.0.0.9", SERVER_PORT) == "unknown"


def test_first_type_positions_returns_earliest_frame_per_type() -> None:
    views = [_view(5, (11,)), _view(3, (1,)), _view(4, (2,))]
    positions = first_type_positions(views, (1, 2, 11))
    assert {kind: positions[kind].frame_number for kind in positions} == {1: 3, 2: 4, 11: 5}


def test_handshake_order_accepts_canonical_ecdhe_flow() -> None:
    views = [
        _view(8, (1,)),
        _view(9, (2,), versions=(TLS_12_WIRE_VERSION_INT,)),
        _view(10, (11, 12)),
        _view(11, (14,)),
        _view(12, (16,)),
    ]
    ok, reason = handshake_order_result(views)
    assert ok, reason


def test_handshake_order_accepts_observed_same_frame_coalesced_types() -> None:
    """Exact observed layout: frame 15: (1,), frame 16: (2,11,12,14),
    frame 18: (16,), frame 19: (4,).
    """
    views = [
        _view(15, (1,)),
        _view(16, (2, 11, 12, 14)),
        _view(18, (16,)),
        _view(19, (4,)),
    ]
    ok, reason = handshake_order_result(views)
    assert ok, reason


def test_handshake_order_rejects_same_frame_reorder_ske_before_cert() -> None:
    """Within the same frame, Certificate must precede ServerKeyExchange."""
    views = [
        _view(15, (1,)),
        _view(16, (2, 12, 11, 14)),
        _view(18, (16,)),
    ]
    ok, reason = handshake_order_result(views)
    assert not ok and "order violated" in reason


def test_handshake_order_rejects_same_frame_reorder_hello_done_before_ske() -> None:
    """Within the same frame, ServerKeyExchange must precede ServerHelloDone."""
    views = [
        _view(15, (1,)),
        _view(16, (2, 11, 14, 12)),
        _view(18, (16,)),
    ]
    ok, reason = handshake_order_result(views)
    assert not ok and "did not follow" in reason


def test_handshake_order_rejects_cke_before_ske_in_same_frame() -> None:
    """ClientKeyExchange must not appear before ServerKeyExchange."""
    views = [
        _view(15, (1,)),
        _view(16, (2, 11, 16, 12)),
    ]
    ok, reason = handshake_order_result(views)
    assert not ok and "did not follow" in reason


@pytest.mark.parametrize(
    "views",
    [
        [_view(8, (2,)), _view(9, (1,)), _view(10, (11,)), _view(11, (12,))],
        [_view(8, (1,)), _view(9, (11,)), _view(10, (2,)), _view(11, (12,))],
        [_view(8, (1,)), _view(9, (2,))],
    ],
)
def test_handshake_order_rejects_wrong_sequences(views: list[HandshakeFrameView]) -> None:
    assert not handshake_order_result(views)[0]


def test_negotiated_version_requires_tls12_without_tls13_advertisement() -> None:
    good = _view(9, (2,), versions=(TLS_12_WIRE_VERSION_INT,))
    ok, actual = negotiated_version_result(good)
    assert ok and "0x0303" in actual
    assert not negotiated_version_result(_view(9, (2,), versions=(0x0301,)))[0]
    hidden_tls13 = _view(
        9,
        (2,),
        versions=(TLS_12_WIRE_VERSION_INT,),
        advertised_versions=(TLS_13_WIRE_VERSION_INT,),
    )
    assert not negotiated_version_result(hidden_tls13)[0]


def test_named_curve_result_identifies_group_23() -> None:
    ok, detail, group = named_curve_result(
        [_view(10, (12,), named_curves=(SECP256R1_GROUP_ID,))], SECP256R1_GROUP_ID
    )
    assert ok and group == 23 and "frame(s) [10]" in detail
    wrong = [_view(10, (12,), named_curves=(24,))]
    ok_w, _detail, group_w = named_curve_result(wrong, SECP256R1_GROUP_ID)
    assert not ok_w and group_w is None
    assert not named_curve_result([_view(10, (2,))], SECP256R1_GROUP_ID)[0]


def test_cipher_expectation_constant_matches_frozen_fact() -> None:
    assert EXPECTED_CIPHER_ID_INT == 0xC02F


def _lifecycle_rows() -> str:
    return "\n".join(
        [
            _flag_line(1, 41000, 0x0002),
            _flag_line(2, SERVER_PORT, 0x0012),
            _flag_line(30, 41000, 0x0001),
            _flag_line(31, SERVER_PORT, 0x0001),
            "",
        ]
    )


def test_connection_lifecycle_complete_handshake_and_clean_close() -> None:
    lifecycle = connection_lifecycle_summary(parse_flag_rows(_lifecycle_rows()), SERVER_PORT)
    assert lifecycle.client_syn
    assert lifecycle.server_syn_ack
    assert lifecycle.reset_count == 0
    assert lifecycle.fin_from_client and lifecycle.fin_from_server
    assert lifecycle.complete_and_clean


@pytest.mark.parametrize(
    "rows",
    [
        _flag_line(2, SERVER_PORT, 0x0012)
        + "\n"
        + _flag_line(30, 41000, 0x0001)
        + "\n"
        + _flag_line(31, SERVER_PORT, 0x0001),
        _flag_line(1, 41000, 0x0002)
        + "\n"
        + _flag_line(30, 41000, 0x0001)
        + "\n"
        + _flag_line(31, SERVER_PORT, 0x0001),
        _flag_line(1, 41000, 0x0002)
        + "\n"
        + _flag_line(2, SERVER_PORT, 0x0012)
        + "\n"
        + _flag_line(31, SERVER_PORT, 0x0001),
        _flag_line(1, 41000, 0x0002)
        + "\n"
        + _flag_line(2, SERVER_PORT, 0x0012)
        + "\n"
        + _flag_line(30, 41000, 0x0001),
        _flag_line(1, 41000, 0x0002)
        + "\n"
        + _flag_line(2, SERVER_PORT, 0x0012)
        + "\n"
        + _flag_line(30, 41000, 0x0001)
        + "\n"
        + _flag_line(31, SERVER_PORT, 0x0001)
        + "\n"
        + _flag_line(32, 41000, 0x0004),
        _flag_line(1, SERVER_PORT, 0x0002)
        + "\n"
        + _flag_line(2, SERVER_PORT, 0x0012)
        + "\n"
        + _flag_line(30, 41000, 0x0001)
        + "\n"
        + _flag_line(31, SERVER_PORT, 0x0001),
    ],
)
def test_connection_lifecycle_rejects_incomplete_or_dirty_flows(rows: str) -> None:
    lifecycle = connection_lifecycle_summary(parse_flag_rows(rows), SERVER_PORT)
    assert not lifecycle.complete_and_clean


def test_syn_carrying_rst_is_counted_as_reset() -> None:
    rows = _lifecycle_rows() + _flag_line(32, 41000, 0x0006) + "\n"
    lifecycle = connection_lifecycle_summary(parse_flag_rows(rows), SERVER_PORT)
    assert lifecycle.reset_count == 1
    assert not lifecycle.complete_and_clean


DIAGNOSIS_14_ROWS = "\n".join(
    [
        "1\t127.0.0.1\t43768\t0x0002",
        "2\t127.0.0.1\t2525\t0x0012",
        "3\t127.0.0.1\t43768\t0x0010",
        "4\t127.0.0.1\t2525\t0x0018",
        "5\t127.0.0.1\t43768\t0x0010",
        "6\t127.0.0.1\t43768\t0x0018",
        "7\t127.0.0.1\t2525\t0x0010",
        "8\t127.0.0.1\t2525\t0x0018",
        "9\t127.0.0.1\t43768\t0x0018",
        "10\t127.0.0.1\t2525\t0x0010",
        "11\t127.0.0.1\t43768\t0x0018",
        "12\t127.0.0.1\t2525\t0x0010",
        "13\t127.0.0.1\t2525\t0x0018",
        "14\t127.0.0.1\t43768\t0x0010",
        "",
    ]
)


def test_diagnosis_14_rows_detects_syn_and_synack_but_not_fin() -> None:
    rows = parse_flag_rows(DIAGNOSIS_14_ROWS)
    assert len(rows) == 14
    lifecycle = connection_lifecycle_summary(rows, 2525)
    assert lifecycle.client_syn is True
    assert lifecycle.server_syn_ack is True
    assert lifecycle.fin_from_client is False
    assert lifecycle.fin_from_server is False
    assert lifecycle.reset_count == 0
    assert not lifecycle.complete_and_clean


def test_diagnosis_14_rows_no_rst_detected() -> None:
    rows = parse_flag_rows(DIAGNOSIS_14_ROWS)
    lifecycle = connection_lifecycle_summary(rows, 2525)
    assert lifecycle.reset_count == 0


def test_capture_drain_constant_is_positive() -> None:
    assert CAPTURE_DRAIN_SECONDS > 0


_COMPLETE_HANDSHAKE_VIEWS = [
    _view(8, (1,)),
    _view(9, (2,), versions=(TLS_12_WIRE_VERSION_INT,), cipher_suites=(EXPECTED_CIPHER_ID_INT,)),
    _view(10, (12,), named_curves=(SECP256R1_GROUP_ID,)),
]

_INCOMPLETE_EVIDENCE_VIEWS = [
    _view(8, (1,)),
    _view(9, (2,), versions=(TLS_12_WIRE_VERSION_INT,), cipher_suites=(EXPECTED_CIPHER_ID_INT,)),
]


def test_forward_secrecy_derives_yes_only_from_full_packet_evidence() -> None:
    derived, reason = derive_forward_secrecy(_COMPLETE_HANDSHAKE_VIEWS)
    assert derived, reason


def test_changing_manifest_expectations_cannot_rescue_incomplete_evidence() -> None:
    derived, _reason = derive_forward_secrecy(_INCOMPLETE_EVIDENCE_VIEWS)
    assert derived is False

    _derived, passed, detail = forward_secrecy_check(
        _INCOMPLETE_EVIDENCE_VIEWS, expected_forward_secrecy=True
    )
    assert passed is False
    assert "derived=False" in detail
    assert "expected=True (manifest)" in detail


def test_parse_certificate_rows_extracts_der_blobs() -> None:
    der_hex = bytes(range(6)).hex(":")
    rows = f"15\t{der_hex},{bytes([9, 9]).hex(':')}\njunk-line\t\n16\t\n"
    ders = parse_certificate_rows(rows)
    assert ders[0] == bytes(range(6))
    assert ders[1] == b"\x09\x09"


def test_build_tshark_argv_is_two_pass_decode_as_and_list_based() -> None:
    argv = build_tshark_argv(
        "fixtures/pcaps/x.pcapng", "tcp.stream==3", ("tcp.stream",), smtp_server_port=2599
    )
    assert isinstance(argv, list)
    assert all(isinstance(part, str) and part for part in argv)
    assert argv[0] == "tshark"
    assert "-2" in argv
    decode_as_position = argv.index("-d")
    assert argv[decode_as_position + 1] == "tcp.port==2599,smtp"
    fields_positions = [i for i, part in enumerate(argv) if part == "-e"]
    assert argv[fields_positions[0] + 1] == "tcp.stream"


def test_os_umask_does_not_weaken_private_key_permissions(tmp_path: Path) -> None:
    os.umask(0)
    try:
        pki = generate_pki(tmp_path / "pki", now=datetime.now(UTC))
        assert stat.S_IMODE(pki.leaf_key_path.stat().st_mode) == 0o600
    finally:
        os.umask(0o022)
