"""Mocked-command flow tests for the independent T01 manual verifier.

Every external tool call is intercepted; nothing invokes tshark, capinfos,
openssl, dumpcap, sockets, or live capture. The tests prove:
- every TShark read uses two-pass analysis (-2);
- the SMTP decode-as argument is derived from the validated manifest port;
- commands are argument lists of plain strings (never shell strings/shell=True);
- tool failures are rejected with typed bounded errors;
- a fully consistent observation set passes every comparison;
- an OpenSSL verification failure records a precise failed comparison.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
from _fixture_common import (
    BoundedRun,
    FileIntegrity,
    decimal_epoch_to_utc_iso,
    sha256_file,
    write_json_file,
)
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from t01_endpoint import FIXTURE_HOSTNAME as HOSTNAME
from t01_manifest import MANIFEST_RELATIVE_PATH, build_manifest
from t01_pki import generate_pki
from verify_t01_manual import (
    FixtureToolError,
    ManualVerifier,
)

CLIENT_PORT = 41000
SERVER_PORT_MANIFEST = 2525
FIRST_EPOCH = "1800000000.100000123"
LAST_EPOCH = "1800000000.900000987"


def _bounded(stdout: str = "", stderr: str = "", returncode: int = 0) -> BoundedRun:
    return BoundedRun(
        argv_head="mock",
        returncode=returncode,
        stdout_text=stdout,
        stderr_text=stderr,
    )


def _payload_hex(payload: bytes) -> str:
    return payload.hex()


def _canned_outputs(server_port: int) -> dict[str, str]:
    sp = server_port
    cp = CLIENT_PORT
    banner_hex = _payload_hex(b"220 " + HOSTNAME.encode() + b" ESMTP ready\r\n")
    payloads = "\n".join(
        [
            f"3\t127.0.0.1\t{sp}\t{cp}\t{banner_hex}",
            f"4\t127.0.0.1\t{cp}\t{sp}\t{_payload_hex(b'EHLO client.securemailscope.test\r\n')}",
            f"5\t127.0.0.1\t{sp}\t{cp}\t{_payload_hex(b'250-mail.test\r\n250 STARTTLS\r\n')}",
            f"6\t127.0.0.1\t{cp}\t{sp}\t{_payload_hex(b'START')}",
            f"7\t127.0.0.1\t{cp}\t{sp}\t{_payload_hex(b'TLS\r\n')}",
            f"8\t127.0.0.1\t{sp}\t{cp}\t{_payload_hex(b'220 Ready to start TLS\r\n')}",
        ]
    )
    handshakes = "\n".join(
        [
            "9\t1\t\t\t\t",
            "10\t2\t0x0303\t0xc02f\t\t",
            "11\t11,12\t\t\t23\t",
        ]
    )
    flags = "\n".join(
        [
            f"1\t127.0.0.1\t{cp}\t0x0002",
            f"2\t127.0.0.1\t{sp}\t0x0012",
            f"30\t127.0.0.1\t{cp}\t0x0001",
            f"31\t127.0.0.1\t{sp}\t0x0001",
        ]
    )
    epochs = f"1\t{FIRST_EPOCH}\n31\t{LAST_EPOCH}\n"
    streams = "5\n"
    capinfos = (
        "File name = fixture.pcapng\n"
        "File type = Wireshark/tcpdump/... - pcapng\n"
        "Number of packets: 42\n"
    )
    return {
        "payloads": payloads,
        "handshakes": handshakes,
        "flags": flags,
        "epochs": epochs,
        "streams": streams,
        "capinfos": capinfos,
    }


def _fake_env(
    tmp_path: Path, *, server_port: int = SERVER_PORT_MANIFEST
) -> tuple[Path, Path, bytes, bytes]:
    repo = tmp_path / "repo"
    pki_dir = repo / "fixtures" / "pki"
    pki = generate_pki(pki_dir, now=datetime.now(UTC))

    pcap_path = repo / "fixtures" / "pcaps" / "smtp_tls12_valid.pcapng"
    pcap_path.parent.mkdir(parents=True, exist_ok=True)
    pcap_path.write_bytes(b"dummy-pcapng-bytes")

    endpoint_log = repo / "fixtures" / "endpoint_logs" / "t01_endpoint_log.jsonl"
    endpoint_log.parent.mkdir(parents=True, exist_ok=True)
    endpoint_log.write_text('{"seq":1}\n', encoding="utf-8")

    capture_log = repo / "fixtures" / "capture_logs" / "t01_dumpcap.log"
    capture_log.parent.mkdir(parents=True, exist_ok=True)
    capture_log.write_text(
        "command: dumpcap -i lo -f tcp port 2525 -w out.pcapng -a duration:120\n\n"
        "Packets captured: 12\n"
        "Packets received/dropped on interface 'Loopback: lo': 12/0\n"
        "(pcap:0/dumpcap:0/flushed:0/ps_ifdrop:0) (100.0%)\n",
        encoding="utf-8",
    )

    leaf_cert = x509.load_pem_x509_certificate(pki.leaf_cert_path.read_bytes())
    root_cert = x509.load_pem_x509_certificate(pki.root_cert_path.read_bytes())
    leaf_der = leaf_cert.public_bytes(Encoding.DER)
    root_der = root_cert.public_bytes(Encoding.DER)

    manifest = build_manifest(
        endpoint_log_relative_path="fixtures/endpoint_logs/t01_endpoint_log.jsonl",
        capture_log_relative_path="fixtures/capture_logs/t01_dumpcap.log",
        pcap_integrity=sha256_file(pcap_path),
        root_cert_integrity=FileIntegrity(**_integrity_fields(pki.root_cert_path)),
        leaf_cert_integrity=FileIntegrity(**_integrity_fields(pki.leaf_cert_path)),
        chain_integrity=FileIntegrity(**_integrity_fields(pki.chain_path)),
        endpoint_log_integrity=FileIntegrity(**_integrity_fields(endpoint_log)),
        capture_log_integrity=FileIntegrity(**_integrity_fields(capture_log)),
        leaf_facts=pki.leaf_facts,
        attime_epoch=int(Decimal(FIRST_EPOCH)),
        first_packet_epoch=FIRST_EPOCH,
        last_packet_epoch=LAST_EPOCH,
        first_packet_utc=_utc(FIRST_EPOCH),
        last_packet_utc=_utc(LAST_EPOCH),
        runtime_versions={"python": "3.12"},
    )
    # Exercise manifest-derived configuration instead of constants.
    endpoint = manifest["endpoint"]
    assert isinstance(endpoint, dict)
    endpoint["port"] = server_port

    manifest_path = repo / MANIFEST_RELATIVE_PATH
    write_json_file(manifest_path, manifest)
    return repo, manifest_path, leaf_der, root_der


def _integrity_fields(path: Path) -> dict[str, Any]:
    integrity = sha256_file(path)
    return {"sha256_hex": integrity.sha256_hex, "size_bytes": integrity.size_bytes}


def _utc(epoch_seconds: str) -> str:
    return decimal_epoch_to_utc_iso(Decimal(epoch_seconds))


def _install_recorder(
    monkeypatch: pytest.MonkeyPatch,
    *,
    server_port: int,
    leaf_der_hex: str,
    root_der_hex: str,
    tshark_returncode: int = 0,
    capinfos_returncode: int = 0,
    openssl_returncode: int = 0,
) -> list[list[str]]:
    import verify_t01_manual as vtm

    canned = _canned_outputs(server_port)
    calls: list[list[str]] = []

    def fake_run(
        argv: list[str],
        *,
        error_stage: str,
        timeout_seconds: float = 20.0,
    ) -> BoundedRun:
        assert isinstance(argv, list), "commands must stay argument lists"
        assert all(isinstance(part, str) and part for part in argv)
        assert "shell" not in error_stage
        calls.append(list(argv))
        head = argv[0]
        if head == "capinfos":
            return _bounded(canned["capinfos"], returncode=capinfos_returncode)
        if head == "openssl":
            body = (
                ": OK\n"
                if openssl_returncode == 0
                else "Error 20 at depth 0: unable to get local issuer certificate\n"
            )
            return _bounded(body, returncode=openssl_returncode)
        if head == "tshark":
            if tshark_returncode != 0:
                return _bounded(stderr="tshark synthetic failure\n", returncode=tshark_returncode)
            fields = {argv[i + 1] for i, part in enumerate(argv) if part == "-e"}
            if "frame.time_epoch" in fields:
                return _bounded(canned["epochs"])
            if fields == {"tcp.stream"}:
                return _bounded(canned["streams"])
            if "tcp.payload" in fields:
                return _bounded(canned["payloads"])
            if "tls.handshake.certificate" in fields:
                return _bounded(f"11\t{leaf_der_hex},{root_der_hex}\n")
            if "tls.handshake.type" in fields:
                return _bounded(canned["handshakes"])
            if "tcp.flags" in fields:
                return _bounded(canned["flags"])
        raise AssertionError(f"unexpected mocked command probed: {argv}")

    monkeypatch.setattr(vtm, "run_bounded", fake_run)
    return calls


def test_full_verification_passes_with_two_pass_and_manifest_derived_decode_as(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, manifest_path, leaf_hex, root_hex = _prepare_env(tmp_path)
    leaf_der_hex = leaf_hex.hex()
    root_der_hex = root_hex.hex()
    calls = _install_recorder(
        monkeypatch,
        server_port=SERVER_PORT_MANIFEST,
        leaf_der_hex=leaf_der_hex,
        root_der_hex=root_der_hex,
    )

    verifier = ManualVerifier(manifest_path, repo_root=repo)
    comparisons = verifier.run()

    failed = [comparison.identifier for comparison in comparisons if not comparison.passed]
    assert failed == [], f"unexpected failures: {[c.actual for c in comparisons if not c.passed]}"

    tshark_calls = [argv for argv in calls if argv[0] == "tshark"]
    assert len(tshark_calls) >= 5
    for argv in tshark_calls:
        assert "-2" in argv
        decode_as_index = argv.index("-d")
        assert argv[decode_as_index + 1] == f"tcp.port=={SERVER_PORT_MANIFEST},smtp"

    capinfos_calls = [argv for argv in calls if argv[0] == "capinfos"]
    assert len(capinfos_calls) == 1

    openssl_call = next(argv for argv in calls if argv[0] == "openssl")
    cafile_index = openssl_call.index("-CAfile")
    attime_index = openssl_call.index("-attime")
    hostname_index = openssl_call.index("-verify_hostname")
    assert openssl_call[cafile_index + 1].endswith("root-ca.pem")
    assert openssl_call[attime_index + 1] == str(int(Decimal(FIRST_EPOCH)))
    assert openssl_call[hostname_index + 1] == HOSTNAME
    assert openssl_call[-1].endswith("smtp-server-cert.pem")

    identifiers = [comparison.identifier for comparison in comparisons]
    assert "pcap_interval_matches_manifest" in identifiers
    assert "connection_lifecycle_syn_synack_fin_no_rst" in identifiers
    assert "wire_root_certificate_fingerprint_matches_controlled_root" in identifiers
    assert "forward_secrecy_derived_from_packets_only" in identifiers


def test_decode_as_port_is_taken_from_manifest_not_constant(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    alternate_port = 2599
    repo, manifest_path, leaf_hex, root_hex = _prepare_env(tmp_path, server_port=alternate_port)
    calls = _install_recorder(
        monkeypatch,
        server_port=alternate_port,
        leaf_der_hex=leaf_hex.hex(),
        root_der_hex=root_hex.hex(),
    )

    comparisons = ManualVerifier(manifest_path, repo_root=repo).run()

    assert all(comparison.passed for comparison in comparisons)
    decode_as_args = {
        argv[argv.index("-d") + 1] for argv in calls if argv[0] == "tshark" and "-d" in argv
    }
    assert decode_as_args == {f"tcp.port=={alternate_port},smtp"}
    assert (
        json.loads(manifest_path.read_text(encoding="utf-8"))["endpoint"]["port"] == alternate_port
    )


def test_nonzero_tshark_raises_typed_tool_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, manifest_path, leaf_hex, root_hex = _prepare_env(tmp_path)
    _install_recorder(
        monkeypatch,
        server_port=SERVER_PORT_MANIFEST,
        leaf_der_hex=leaf_hex.hex(),
        root_der_hex=root_hex.hex(),
        tshark_returncode=2,
    )

    with pytest.raises(FixtureToolError, match="tshark synthetic failure"):
        ManualVerifier(manifest_path, repo_root=repo).run()


def test_nonzero_capinfos_raises_typed_tool_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, manifest_path, leaf_hex, root_hex = _prepare_env(tmp_path)
    _install_recorder(
        monkeypatch,
        server_port=SERVER_PORT_MANIFEST,
        leaf_der_hex=leaf_hex.hex(),
        root_der_hex=root_hex.hex(),
        capinfos_returncode=1,
    )

    with pytest.raises(FixtureToolError, match="capinfos failed"):
        ManualVerifier(manifest_path, repo_root=repo).run()


def test_failed_openssl_verification_records_precise_comparison_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, manifest_path, leaf_hex, root_hex = _prepare_env(tmp_path)
    _install_recorder(
        monkeypatch,
        server_port=SERVER_PORT_MANIFEST,
        leaf_der_hex=leaf_hex.hex(),
        root_der_hex=root_hex.hex(),
        openssl_returncode=2,
    )

    comparisons = ManualVerifier(manifest_path, repo_root=repo).run()

    openssl_comparisons = [
        comparison
        for comparison in comparisons
        if comparison.identifier == "openssl_chain_verify_ok_at_capture_time"
    ]
    assert len(openssl_comparisons) == 1
    assert openssl_comparisons[0].passed is False
    assert "rc=2" in openssl_comparisons[0].actual


def _prepare_env(tmp_path: Path, **kwargs: Any) -> tuple[Path, Path, bytes, bytes]:
    repo, manifest_path, leaf_der, root_der = _fake_env(tmp_path, **kwargs)
    return repo, manifest_path, leaf_der, root_der


def test_missing_pcap_epochs_fails_openssl_without_manifest_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import verify_t01_manual as vtm

    repo, manifest_path, leaf_hex, root_hex = _prepare_env(tmp_path)
    calls = _install_recorder(
        monkeypatch,
        server_port=SERVER_PORT_MANIFEST,
        leaf_der_hex=leaf_hex.hex(),
        root_der_hex=root_hex.hex(),
    )

    monkeypatch.setattr(vtm, "parse_frame_epoch_rows", lambda *_args, **_kwargs: ())

    comparisons = ManualVerifier(manifest_path, repo_root=repo).run()
    by_id = {comparison.identifier: comparison for comparison in comparisons}

    assert by_id["pcap_interval_matches_manifest"].passed is False
    assert by_id["attime_epoch_matches_first_pcap_epoch"].passed is False
    openssl_comparison = by_id["openssl_chain_verify_ok_at_capture_time"]
    assert openssl_comparison.passed is False
    assert "not executable" in openssl_comparison.actual
    assert all(argv[0] != "openssl" for argv in calls)
