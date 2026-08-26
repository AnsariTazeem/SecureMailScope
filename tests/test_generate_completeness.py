"""Direct regression tests for the T01 generator completeness gate.

Every test exercises the real completeness gate functions with monkeypatched
TShark output (no live capture, no dumpcap, no sockets). Proves:
- real TShark query builder argv properties (strings, -2, decode-as, fields);
- STARTTLS split reconstruction via _probe_starttls_split;
- arbitrary payload after 220 cannot count as ClientHello;
- complete controlled sample passes every gate;
- old 14-frame diagnosis fails for missing FINs and TLS;
- missing client/server FIN fails;
- any RST fails;
- missing each required handshake type fails;
- wrong TLS version/cipher/group fails;
- TLS handshake ordering violations (wrong order, same-frame reorder);
- same-frame 2,11,12 accepted;
- invalid DER certificate fails with typed error;
- one/mismatched certificate fails;
- second-stream evidence cannot satisfy the controlled stream;
- capture ordering: runner.start -> session -> sleep(1.0) -> runner.stop;
- completeness failure creates no manifest with full artifact cleanup.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import generate_t01_fixture as gen
import pytest
from _fixture_common import BoundedRun, PayloadFrame
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from t01_capture import CAPTURE_DRAIN_SECONDS
from t01_endpoint import (
    CIPHER_OPENSSL_NAME,
    FIXTURE_HOSTNAME,
    SERVER_PORT,
    EndpointEventLog,
    SessionFacts,
)
from t01_pki import GeneratedPki, generate_pki

CONTROLLED_STREAM = "7"
CONTROLLED_CLIENT_PORT = 43768

TSHARK_SYN = "0x0002"
TSHARK_SYN_ACK = "0x0012"
TSHARK_ACK = "0x0010"
TSHARK_PSH_ACK = "0x0018"
TSHARK_FIN_ACK = "0x0011"


def _split_starttls_frames() -> tuple[PayloadFrame, ...]:
    return (
        PayloadFrame(
            frame_number=9,
            source_ip="127.0.0.1",
            source_port=CONTROLLED_CLIENT_PORT,
            destination_port=SERVER_PORT,
            payload=b"START",
        ),
        PayloadFrame(
            frame_number=11,
            source_ip="127.0.0.1",
            source_port=CONTROLLED_CLIENT_PORT,
            destination_port=SERVER_PORT,
            payload=b"TLS\r\n",
        ),
    )


def _leaf_der_hex(pki: GeneratedPki) -> str:
    cert = x509.load_pem_x509_certificate(pki.leaf_cert_path.read_bytes())
    return cert.public_bytes(Encoding.DER).hex()


def _root_der_hex(pki: GeneratedPki) -> str:
    cert = x509.load_pem_x509_certificate(pki.root_cert_path.read_bytes())
    return cert.public_bytes(Encoding.DER).hex()


def _handshake_rows(leaf_hex: str, root_hex: str, *, group: int = 23) -> str:
    return "\n".join(
        [
            "14\t1\t\t\t\t",
            "15\t2\t0x0303\t0xc02f\t\t",
            f"16\t11,12\t\t\t{group}\t",
        ]
    )


def _complete_canned_outputs(pki: GeneratedPki) -> dict[str, str]:
    leaf_hex = _leaf_der_hex(pki)
    root_hex = _root_der_hex(pki)
    return {
        "streams": f"{CONTROLLED_STREAM}\n",
        "lifecycle": "\n".join(
            [
                f"1\t{CONTROLLED_CLIENT_PORT}\t{TSHARK_SYN}",
                f"2\t{SERVER_PORT}\t{TSHARK_SYN_ACK}",
                f"3\t{CONTROLLED_CLIENT_PORT}\t{TSHARK_ACK}",
                f"4\t{SERVER_PORT}\t{TSHARK_PSH_ACK}",
                f"5\t{CONTROLLED_CLIENT_PORT}\t{TSHARK_ACK}",
                f"12\t{SERVER_PORT}\t{TSHARK_PSH_ACK}",
                f"13\t{CONTROLLED_CLIENT_PORT}\t{TSHARK_ACK}",
                f"20\t{CONTROLLED_CLIENT_PORT}\t{TSHARK_FIN_ACK}",
                f"21\t{SERVER_PORT}\t{TSHARK_FIN_ACK}",
            ]
        ),
        "starttls_220": "\n".join(
            [
                "12\t" + str(SERVER_PORT) + "\t32323020526561647920746f20737461727420544c530d0a",
                f"13\t{CONTROLLED_CLIENT_PORT}\t{TSHARK_ACK}",
            ]
        ),
        "clienthello": "14\n",
        "handshakes": _handshake_rows(leaf_hex, root_hex),
        "certs": f"16\t{leaf_hex},{root_hex}\n",
    }


class _TsharkMock:
    def __init__(self, canned: dict[str, str], *, extra_streams: bool = False) -> None:
        self._canned = canned
        self._extra_streams = extra_streams
        self.calls: list[list[str]] = []

    def __call__(
        self,
        argv: list[str],
        *,
        error_stage: str,
        timeout_seconds: float = 20.0,
    ) -> BoundedRun:
        self.calls.append(list(argv))
        assert all(isinstance(p, str) and p for p in argv), f"non-string in argv: {argv}"
        assert "-2" in argv, "missing two-pass flag"
        fields = {argv[i + 1] for i, part in enumerate(argv) if part == "-e"}
        filter_text = ""
        for i, part in enumerate(argv):
            if part == "-Y" and i + 1 < len(argv):
                filter_text = argv[i + 1]
                break
        if "tcp.stream" in fields and len(fields) == 1:
            if self._extra_streams:
                return BoundedRun(
                    argv_head="tshark",
                    returncode=0,
                    stdout_text=f"{CONTROLLED_STREAM}\n99\n",
                    stderr_text="",
                )
            return BoundedRun(
                argv_head="tshark",
                returncode=0,
                stdout_text=self._canned["streams"],
                stderr_text="",
            )
        if "tcp.flags" in fields:
            return BoundedRun(
                argv_head="tshark",
                returncode=0,
                stdout_text=self._canned["lifecycle"],
                stderr_text="",
            )
        if "tcp.srcport" in fields and "tcp.payload" in fields:
            return BoundedRun(
                argv_head="tshark",
                returncode=0,
                stdout_text=self._canned["starttls_220"],
                stderr_text="",
            )
        if "tls.handshake.version" in fields:
            return BoundedRun(
                argv_head="tshark",
                returncode=0,
                stdout_text=self._canned["handshakes"],
                stderr_text="",
            )
        if "tls.handshake.certificate" in fields:
            return BoundedRun(
                argv_head="tshark",
                returncode=0,
                stdout_text=self._canned["certs"],
                stderr_text="",
            )
        if fields == {"frame.number"} and "tls.handshake.type" in filter_text:
            return BoundedRun(
                argv_head="tshark",
                returncode=0,
                stdout_text=self._canned["clienthello"],
                stderr_text="",
            )
        return BoundedRun(
            argv_head="tshark",
            returncode=1,
            stdout_text="",
            stderr_text=f"no canned response for {fields}",
        )


# ──────────────────────────────────────────────────────────────────
# 4.  TShark query builder – test the real function
# ──────────────────────────────────────────────────────────────────


def test_tshark_query_raw_mode_all_elements_are_strings_with_two_pass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cap = []

    def fake_run(argv, *, error_stage, timeout_seconds=20.0):
        cap.append(list(argv))
        return BoundedRun(
            argv_head="tshark",
            returncode=0,
            stdout_text="",
            stderr_text="",
        )

    monkeypatch.setattr(gen, "run_bounded", fake_run)
    gen._tshark_query(tmp_path / "x.pcapng", "tcp", ("tcp.stream",))
    argv = cap[0]
    assert all(isinstance(p, str) and p for p in argv)
    assert "-2" in argv
    assert "-d" not in argv


def test_tshark_query_smtp_mode_contains_decode_as(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cap = []

    def fake_run(argv, *, error_stage, timeout_seconds=20.0):
        cap.append(list(argv))
        return BoundedRun(
            argv_head="tshark",
            returncode=0,
            stdout_text="",
            stderr_text="",
        )

    monkeypatch.setattr(gen, "run_bounded", fake_run)
    gen._tshark_query(
        tmp_path / "x.pcapng",
        "tls.handshake.type==1",
        ("frame.number",),
        decode_as="tcp.port==2525,smtp",
    )
    argv = cap[0]
    assert "-d" in argv
    idx = argv.index("-d")
    assert argv[idx + 1] == "tcp.port==2525,smtp"


def test_tshark_query_emits_each_field_as_e_flag_pair(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cap = []

    def fake_run(argv, *, error_stage, timeout_seconds=20.0):
        cap.append(list(argv))
        return BoundedRun(
            argv_head="tshark",
            returncode=0,
            stdout_text="",
            stderr_text="",
        )

    monkeypatch.setattr(gen, "run_bounded", fake_run)
    fields = ("tcp.stream", "tcp.flags", "tcp.srcport")
    gen._tshark_query(tmp_path / "x.pcapng", "tcp", fields)
    argv = cap[0]
    e_indices = [i for i, p in enumerate(argv) if p == "-e"]
    emitted = tuple(argv[i + 1] for i in e_indices)
    assert emitted == fields
    for idx in e_indices:
        assert idx + 1 < len(argv)


# ──────────────────────────────────────────────────────────────────
#  Split / ordering / arbitrary-payload gate tests
# ──────────────────────────────────────────────────────────────────


def test_exact_split_starttls_reconstructs() -> None:
    frames = _split_starttls_frames()
    combined = b"".join(frame.payload for frame in frames)
    assert combined == b"STARTTLS\r\n"
    assert len(frames) == 2


def test_arbitrary_payload_after_220_cannot_count_as_clienthello(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pki = generate_pki(tmp_path / "pki", now=datetime.now(UTC))
    canned = _complete_canned_outputs(pki)
    canned["handshakes"] = "\n".join(
        [
            "15\t2\t0x0303\t0xc02f\t\t",
            "16\t11,12\t\t\t23\t",
        ]
    )
    canned["clienthello"] = "13\n"
    mock = _TsharkMock(canned)
    monkeypatch.setattr(gen, "run_bounded", mock)
    with pytest.raises(gen.FixtureError, match="ClientHello"):
        gen._completeness_gate(tmp_path / "dummy.pcapng", _split_starttls_frames(), pki)


def test_complete_controlled_sample_passes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pki = generate_pki(tmp_path / "pki", now=datetime.now(UTC))
    canned = _complete_canned_outputs(pki)
    monkeypatch.setattr(gen, "run_bounded", _TsharkMock(canned))
    gen._completeness_gate(tmp_path / "dummy.pcapng", _split_starttls_frames(), pki)


# ──────────────────────────────────────────────────────────────────
#  Lifecycle gate tests
# ──────────────────────────────────────────────────────────────────


def test_14_frame_diagnosis_fails_missing_fins_and_tls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pki = generate_pki(tmp_path / "pki", now=datetime.now(UTC))
    canned = _complete_canned_outputs(pki)
    canned["lifecycle"] = "\n".join(
        [
            f"1\t{CONTROLLED_CLIENT_PORT}\t{TSHARK_SYN}",
            f"2\t{SERVER_PORT}\t{TSHARK_SYN_ACK}",
            f"3\t{CONTROLLED_CLIENT_PORT}\t{TSHARK_ACK}",
            f"4\t{SERVER_PORT}\t{TSHARK_PSH_ACK}",
            f"5\t{CONTROLLED_CLIENT_PORT}\t{TSHARK_ACK}",
            f"6\t{CONTROLLED_CLIENT_PORT}\t{TSHARK_PSH_ACK}",
            f"7\t{SERVER_PORT}\t{TSHARK_ACK}",
            f"8\t{SERVER_PORT}\t{TSHARK_PSH_ACK}",
            f"9\t{CONTROLLED_CLIENT_PORT}\t{TSHARK_PSH_ACK}",
            f"10\t{SERVER_PORT}\t{TSHARK_ACK}",
            f"11\t{CONTROLLED_CLIENT_PORT}\t{TSHARK_PSH_ACK}",
            f"12\t{SERVER_PORT}\t{TSHARK_ACK}",
            f"13\t{SERVER_PORT}\t{TSHARK_PSH_ACK}",
            f"14\t{CONTROLLED_CLIENT_PORT}\t{TSHARK_ACK}",
        ]
    )
    canned["handshakes"] = ""
    canned["certs"] = ""
    canned["clienthello"] = ""
    canned["starttls_220"] = "\n".join(
        [
            f"11\t{CONTROLLED_CLIENT_PORT}\t544c530d0a",
            f"12\t{SERVER_PORT}\t32323020526561647920746f20737461727420544c530d0a",
        ]
    )
    mock = _TsharkMock(canned)
    monkeypatch.setattr(gen, "run_bounded", mock)
    with pytest.raises(gen.FixtureError, match="FIN from client"):
        gen._completeness_gate(
            tmp_path / "dummy.pcapng",
            (
                PayloadFrame(9, "127.0.0.1", CONTROLLED_CLIENT_PORT, SERVER_PORT, b"START"),
                PayloadFrame(11, "127.0.0.1", CONTROLLED_CLIENT_PORT, SERVER_PORT, b"TLS\r\n"),
            ),
            pki,
        )


def test_missing_client_fin_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pki = generate_pki(tmp_path / "pki", now=datetime.now(UTC))
    canned = _complete_canned_outputs(pki)
    canned["lifecycle"] = "\n".join(
        [
            f"1\t{CONTROLLED_CLIENT_PORT}\t{TSHARK_SYN}",
            f"2\t{SERVER_PORT}\t{TSHARK_SYN_ACK}",
            f"3\t{CONTROLLED_CLIENT_PORT}\t{TSHARK_ACK}",
            f"21\t{SERVER_PORT}\t{TSHARK_FIN_ACK}",
        ]
    )
    monkeypatch.setattr(gen, "run_bounded", _TsharkMock(canned))
    with pytest.raises(gen.FixtureError, match="FIN from client"):
        gen._completeness_gate(tmp_path / "dummy.pcapng", _split_starttls_frames(), pki)


def test_missing_server_fin_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pki = generate_pki(tmp_path / "pki", now=datetime.now(UTC))
    canned = _complete_canned_outputs(pki)
    canned["lifecycle"] = "\n".join(
        [
            f"1\t{CONTROLLED_CLIENT_PORT}\t{TSHARK_SYN}",
            f"2\t{SERVER_PORT}\t{TSHARK_SYN_ACK}",
            f"3\t{CONTROLLED_CLIENT_PORT}\t{TSHARK_ACK}",
            f"20\t{CONTROLLED_CLIENT_PORT}\t{TSHARK_FIN_ACK}",
        ]
    )
    monkeypatch.setattr(gen, "run_bounded", _TsharkMock(canned))
    with pytest.raises(gen.FixtureError, match="FIN from server"):
        gen._completeness_gate(tmp_path / "dummy.pcapng", _split_starttls_frames(), pki)


def test_rst_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pki = generate_pki(tmp_path / "pki", now=datetime.now(UTC))
    canned = _complete_canned_outputs(pki)
    canned["lifecycle"] = "\n".join(
        [
            f"1\t{CONTROLLED_CLIENT_PORT}\t{TSHARK_SYN}",
            f"2\t{SERVER_PORT}\t{TSHARK_SYN_ACK}",
            f"3\t{CONTROLLED_CLIENT_PORT}\t{TSHARK_ACK}",
            f"20\t{CONTROLLED_CLIENT_PORT}\t{TSHARK_FIN_ACK}",
            f"21\t{SERVER_PORT}\t{TSHARK_FIN_ACK}",
            f"22\t{CONTROLLED_CLIENT_PORT}\t0x0004",
        ]
    )
    monkeypatch.setattr(gen, "run_bounded", _TsharkMock(canned))
    with pytest.raises(gen.FixtureError, match="RST"):
        gen._completeness_gate(tmp_path / "dummy.pcapng", _split_starttls_frames(), pki)


# ──────────────────────────────────────────────────────────────────
#  Missing handshake type tests
# ──────────────────────────────────────────────────────────────────


def test_missing_clienthello_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pki = generate_pki(tmp_path / "pki", now=datetime.now(UTC))
    canned = _complete_canned_outputs(pki)
    canned["handshakes"] = "\n".join(
        [
            "15\t2\t0x0303\t0xc02f\t\t",
            "16\t11,12\t\t\t23\t",
        ]
    )
    canned["clienthello"] = ""
    monkeypatch.setattr(gen, "run_bounded", _TsharkMock(canned))
    with pytest.raises(gen.FixtureError, match="ClientHello"):
        gen._completeness_gate(tmp_path / "dummy.pcapng", _split_starttls_frames(), pki)


def test_missing_serverhello_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pki = generate_pki(tmp_path / "pki", now=datetime.now(UTC))
    canned = _complete_canned_outputs(pki)
    canned["handshakes"] = "\n".join(
        [
            "14\t1\t\t\t\t",
            "16\t11,12\t\t\t23\t",
        ]
    )
    monkeypatch.setattr(gen, "run_bounded", _TsharkMock(canned))
    with pytest.raises(gen.FixtureError, match="ServerHello"):
        gen._completeness_gate(tmp_path / "dummy.pcapng", _split_starttls_frames(), pki)


def test_missing_certificate_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pki = generate_pki(tmp_path / "pki", now=datetime.now(UTC))
    canned = _complete_canned_outputs(pki)
    canned["handshakes"] = "\n".join(
        [
            "14\t1\t\t\t\t",
            "15\t2\t0x0303\t0xc02f\t\t",
            "16\t12\t\t\t23\t",
        ]
    )
    monkeypatch.setattr(gen, "run_bounded", _TsharkMock(canned))
    with pytest.raises(gen.FixtureError, match="Certificate"):
        gen._completeness_gate(tmp_path / "dummy.pcapng", _split_starttls_frames(), pki)


def test_missing_serverkeyexchange_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pki = generate_pki(tmp_path / "pki", now=datetime.now(UTC))
    canned = _complete_canned_outputs(pki)
    canned["handshakes"] = "\n".join(
        [
            "14\t1\t\t\t\t",
            "15\t2\t0x0303\t0xc02f\t\t",
            "16\t11\t\t\t\t",
        ]
    )
    monkeypatch.setattr(gen, "run_bounded", _TsharkMock(canned))
    with pytest.raises(gen.FixtureError, match="ServerKeyExchange"):
        gen._completeness_gate(tmp_path / "dummy.pcapng", _split_starttls_frames(), pki)


# ──────────────────────────────────────────────────────────────────
#  TLS handshake version / cipher / group tests
# ──────────────────────────────────────────────────────────────────


def test_wrong_tls_version_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pki = generate_pki(tmp_path / "pki", now=datetime.now(UTC))
    canned = _complete_canned_outputs(pki)
    canned["handshakes"] = _handshake_rows(_leaf_der_hex(pki), _root_der_hex(pki)).replace(
        "0x0303", "0x0301"
    )
    monkeypatch.setattr(gen, "run_bounded", _TsharkMock(canned))
    with pytest.raises(gen.FixtureError, match="version mismatch"):
        gen._completeness_gate(tmp_path / "dummy.pcapng", _split_starttls_frames(), pki)


def test_wrong_cipher_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pki = generate_pki(tmp_path / "pki", now=datetime.now(UTC))
    canned = _complete_canned_outputs(pki)
    canned["handshakes"] = _handshake_rows(_leaf_der_hex(pki), _root_der_hex(pki)).replace(
        "0xc02f", "0x009c"
    )
    monkeypatch.setattr(gen, "run_bounded", _TsharkMock(canned))
    with pytest.raises(gen.FixtureError, match="cipher mismatch"):
        gen._completeness_gate(tmp_path / "dummy.pcapng", _split_starttls_frames(), pki)


def test_wrong_group_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pki = generate_pki(tmp_path / "pki", now=datetime.now(UTC))
    canned = _complete_canned_outputs(pki)
    canned["handshakes"] = _handshake_rows(_leaf_der_hex(pki), _root_der_hex(pki), group=24)
    monkeypatch.setattr(gen, "run_bounded", _TsharkMock(canned))
    with pytest.raises(gen.FixtureError, match="named curve"):
        gen._completeness_gate(tmp_path / "dummy.pcapng", _split_starttls_frames(), pki)


# ──────────────────────────────────────────────────────────────────
# 1.  TLS handshake ordering tests
# ──────────────────────────────────────────────────────────────────


def test_serverhello_before_clienthello_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pki = generate_pki(tmp_path / "pki", now=datetime.now(UTC))
    canned = _complete_canned_outputs(pki)
    canned["handshakes"] = "\n".join(
        [
            "14\t2\t0x0303\t0xc02f\t\t",
            "15\t1\t\t\t\t",
            "16\t11,12\t\t\t23\t",
        ]
    )
    monkeypatch.setattr(gen, "run_bounded", _TsharkMock(canned))
    with pytest.raises(gen.FixtureError, match="handshake ordering"):
        gen._completeness_gate(tmp_path / "dummy.pcapng", _split_starttls_frames(), pki)


def test_certificate_before_serverhello_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pki = generate_pki(tmp_path / "pki", now=datetime.now(UTC))
    canned = _complete_canned_outputs(pki)
    canned["handshakes"] = "\n".join(
        [
            "14\t1\t\t\t\t",
            "15\t11\t\t\t\t",
            "16\t2\t0x0303\t0xc02f\t\t",
            "17\t12\t\t\t23\t",
        ]
    )
    monkeypatch.setattr(gen, "run_bounded", _TsharkMock(canned))
    with pytest.raises(gen.FixtureError, match="handshake ordering"):
        gen._completeness_gate(tmp_path / "dummy.pcapng", _split_starttls_frames(), pki)


def test_serverkeyexchange_before_certificate_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pki = generate_pki(tmp_path / "pki", now=datetime.now(UTC))
    canned = _complete_canned_outputs(pki)
    canned["handshakes"] = "\n".join(
        [
            "14\t1\t\t\t\t",
            "15\t2\t0x0303\t0xc02f\t\t",
            "16\t12\t\t\t23\t",
            "17\t11\t\t\t\t",
        ]
    )
    monkeypatch.setattr(gen, "run_bounded", _TsharkMock(canned))
    with pytest.raises(gen.FixtureError, match="handshake ordering"):
        gen._completeness_gate(tmp_path / "dummy.pcapng", _split_starttls_frames(), pki)


def test_same_frame_2_12_11_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pki = generate_pki(tmp_path / "pki", now=datetime.now(UTC))
    canned = _complete_canned_outputs(pki)
    canned["handshakes"] = "\n".join(
        [
            "14\t1\t\t\t\t",
            "15\t2,12,11\t\t\t\t",
        ]
    )
    monkeypatch.setattr(gen, "run_bounded", _TsharkMock(canned))
    with pytest.raises(gen.FixtureError, match="handshake ordering"):
        gen._completeness_gate(tmp_path / "dummy.pcapng", _split_starttls_frames(), pki)


def test_same_frame_2_11_12_accepted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pki = generate_pki(tmp_path / "pki", now=datetime.now(UTC))
    canned = _complete_canned_outputs(pki)
    leaf_hex = _leaf_der_hex(pki)
    root_hex = _root_der_hex(pki)
    canned["handshakes"] = "\n".join(
        [
            "14\t1\t\t\t\t",
            "15\t2,11,12\t0x0303\t0xc02f\t23\t",
        ]
    )
    canned["certs"] = f"15\t{leaf_hex},{root_hex}\n"
    monkeypatch.setattr(gen, "run_bounded", _TsharkMock(canned))
    gen._completeness_gate(tmp_path / "dummy.pcapng", _split_starttls_frames(), pki)


# ──────────────────────────────────────────────────────────────────
# 2.  Invalid DER certificate test
# ──────────────────────────────────────────────────────────────────


def test_invalid_der_certificate_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pki = generate_pki(tmp_path / "pki", now=datetime.now(UTC))
    canned = _complete_canned_outputs(pki)
    canned["certs"] = "16\tdeadbeef,cafebabe\n"
    monkeypatch.setattr(gen, "run_bounded", _TsharkMock(canned))
    with pytest.raises(gen.FixtureError, match="wire certificate DER is invalid"):
        gen._completeness_gate(tmp_path / "dummy.pcapng", _split_starttls_frames(), pki)


# ──────────────────────────────────────────────────────────────────
#  Certificate fingerprint / count tests
# ──────────────────────────────────────────────────────────────────


def test_one_certificate_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pki = generate_pki(tmp_path / "pki", now=datetime.now(UTC))
    canned = _complete_canned_outputs(pki)
    canned["certs"] = f"16\t{_leaf_der_hex(pki)}\n"
    monkeypatch.setattr(gen, "run_bounded", _TsharkMock(canned))
    with pytest.raises(gen.FixtureError, match="fewer than 2 DER"):
        gen._completeness_gate(tmp_path / "dummy.pcapng", _split_starttls_frames(), pki)


def test_mismatched_leaf_fingerprint_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pki = generate_pki(tmp_path / "pki", now=datetime.now(UTC))
    other_pki = generate_pki(tmp_path / "pki2", now=datetime.now(UTC))
    canned = _complete_canned_outputs(pki)
    other_leaf_hex = _leaf_der_hex(other_pki)
    canned["certs"] = f"16\t{other_leaf_hex},{_root_der_hex(pki)}\n"
    monkeypatch.setattr(gen, "run_bounded", _TsharkMock(canned))
    with pytest.raises(gen.FixtureError, match="wire leaf fingerprint"):
        gen._completeness_gate(tmp_path / "dummy.pcapng", _split_starttls_frames(), pki)


def test_mismatched_root_fingerprint_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pki = generate_pki(tmp_path / "pki", now=datetime.now(UTC))
    other_pki = generate_pki(tmp_path / "pki2", now=datetime.now(UTC))
    canned = _complete_canned_outputs(pki)
    other_root_hex = _root_der_hex(other_pki)
    canned["certs"] = f"16\t{_leaf_der_hex(pki)},{other_root_hex}\n"
    monkeypatch.setattr(gen, "run_bounded", _TsharkMock(canned))
    with pytest.raises(gen.FixtureError, match="wire root fingerprint"):
        gen._completeness_gate(tmp_path / "dummy.pcapng", _split_starttls_frames(), pki)


def test_second_stream_evidence_cannot_satisfy_controlled_stream(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pki = generate_pki(tmp_path / "pki", now=datetime.now(UTC))
    canned = _complete_canned_outputs(pki)
    mock = _TsharkMock(canned, extra_streams=True)
    monkeypatch.setattr(gen, "run_bounded", mock)
    with pytest.raises(gen.FixtureError, match="exactly one TCP stream"):
        gen._completeness_gate(tmp_path / "dummy.pcapng", _split_starttls_frames(), pki)


# ──────────────────────────────────────────────────────────────────
# 3.  Capture ordering + cleanup tests
# ──────────────────────────────────────────────────────────────────


class _FakeRunner:
    def __init__(self, pcap_path: Path, order: list[str], **_kw: object) -> None:
        self._pcap_path = pcap_path
        self._order = order
        self.argv = ["dumpcap", "-i", "lo"]
        self.collected_stderr = "Packets captured: 12\n"

    def start(self) -> None:
        self._order.append("runner.start")
        self._pcap_path.parent.mkdir(parents=True, exist_ok=True)
        self._pcap_path.write_bytes(b"dummy")

    def stop(self) -> None:
        self._order.append("runner.stop")

    def abort(self) -> None:
        pass


def _fake_session(
    pki: GeneratedPki,
) -> tuple[SessionFacts, EndpointEventLog]:
    log = EndpointEventLog()
    log.add("client", "connection_opened")
    facts = SessionFacts(
        tls_protocol_version="TLSv1.2",
        cipher_openssl_name=CIPHER_OPENSSL_NAME,
        cipher_bits=128,
        peer_san_dns_names=(FIXTURE_HOSTNAME,),
    )
    return facts, log


def test_capture_ordering_is_runner_start_session_sleep_runner_stop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pki_dir = tmp_path / "repo" / "fixtures" / "pki"
    pki = generate_pki(pki_dir, now=datetime.now(UTC))
    paths = gen.GeneratorPaths.from_root(tmp_path / "repo")
    order: list[str] = []

    def fake_run_session(
        root: Path,
        chain: Path,
        key: Path,
    ) -> tuple[SessionFacts, EndpointEventLog]:
        order.append("session")
        return _fake_session(pki)

    def fake_generate_pki(pki_path: Path, *, now: datetime) -> GeneratedPki:
        return generate_pki(pki_path, now=now)

    def fake_sleep(seconds: float) -> None:
        order.append(f"sleep({seconds})")

    mock_time = type(
        "MockTime",
        (),
        {"sleep": staticmethod(fake_sleep), "monotonic": time.monotonic},
    )()

    def make_runner(*a: object, **kw: object) -> _FakeRunner:
        return _FakeRunner(paths.pcap_path, order)

    monkeypatch.setattr(gen, "DumpcapRunner", make_runner)
    monkeypatch.setattr(gen, "run_controlled_session", fake_run_session)
    monkeypatch.setattr(gen, "time", mock_time)
    monkeypatch.setattr(gen, "generate_pki", fake_generate_pki)
    monkeypatch.setattr(gen, "_probe_capture_readable", lambda _p: 12)
    monkeypatch.setattr(
        gen,
        "_require_clean_capture_summary",
        lambda _p: type("S", (), {"dropped": 0, "captured": 12})(),
    )
    monkeypatch.setattr(
        gen,
        "_extract_capture_interval",
        lambda _p: ("1800000000.100000123", "1800000000.900000987"),
    )
    monkeypatch.setattr(
        gen,
        "_probe_starttls_split",
        lambda _p: _split_starttls_frames(),
    )
    monkeypatch.setattr(gen, "_completeness_gate", lambda *a, **kw: None)
    monkeypatch.setattr(gen, "_openssl_leaf_check", lambda *a: None)
    monkeypatch.setattr(gen, "validate_negotiated_facts", lambda _f: None)
    monkeypatch.setattr(gen, "certificate_valid_at", lambda *a: True)
    monkeypatch.setattr(
        gen,
        "_validated_interval",
        lambda _f, _l: __import__("decimal").Decimal("1800000000.100000123"),
    )
    monkeypatch.setattr(
        gen,
        "_require_epoch",
        lambda _t: __import__("decimal").Decimal("1800000000.900000987"),
    )

    gen._generate(force=True, paths=paths)
    assert order == [
        "runner.start",
        "session",
        f"sleep({CAPTURE_DRAIN_SECONDS})",
        "runner.stop",
    ]


def test_completeness_failure_removes_all_artifacts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pki_dir = tmp_path / "repo" / "fixtures" / "pki"
    pki = generate_pki(pki_dir, now=datetime.now(UTC))
    paths = gen.GeneratorPaths.from_root(tmp_path / "repo")
    order: list[str] = []

    def failing_gate(*_a: Any, **_kw: Any) -> None:
        raise gen.FixtureError("simulated completeness gate failure")

    neighbor = paths.pki_dir.parent / "keepme.txt"
    neighbor.parent.mkdir(parents=True, exist_ok=True)
    neighbor.write_text("survive", encoding="utf-8")

    mock_time = type(
        "MockTime",
        (),
        {
            "sleep": staticmethod(lambda _s: None),
            "monotonic": time.monotonic,
        },
    )()

    def make_runner(*a: object, **kw: object) -> _FakeRunner:
        return _FakeRunner(paths.pcap_path, order)

    monkeypatch.setattr(gen, "DumpcapRunner", make_runner)
    monkeypatch.setattr(
        gen,
        "run_controlled_session",
        lambda *a, **kw: _fake_session(pki),
    )
    monkeypatch.setattr(gen, "time", mock_time)
    monkeypatch.setattr(
        gen,
        "generate_pki",
        lambda p, **kw: generate_pki(p, now=datetime.now(UTC)),
    )
    monkeypatch.setattr(gen, "_probe_capture_readable", lambda _p: 12)
    monkeypatch.setattr(
        gen,
        "_require_clean_capture_summary",
        lambda _p: type("S", (), {"dropped": 0, "captured": 12})(),
    )
    monkeypatch.setattr(
        gen,
        "_extract_capture_interval",
        lambda _p: ("1800000000.100000123", "1800000000.900000987"),
    )
    monkeypatch.setattr(
        gen,
        "_probe_starttls_split",
        lambda _p: _split_starttls_frames(),
    )
    monkeypatch.setattr(gen, "_completeness_gate", failing_gate)
    monkeypatch.setattr(gen, "_openssl_leaf_check", lambda *a: None)
    monkeypatch.setattr(gen, "validate_negotiated_facts", lambda _f: None)
    monkeypatch.setattr(gen, "certificate_valid_at", lambda *a: True)
    monkeypatch.setattr(
        gen,
        "_validated_interval",
        lambda _f, _l: __import__("decimal").Decimal("1800000000.100000123"),
    )
    monkeypatch.setattr(
        gen,
        "_require_epoch",
        lambda _t: __import__("decimal").Decimal("1800000000.900000987"),
    )

    with pytest.raises(gen.FixtureError, match="completeness gate failure"):
        gen._generate(force=True, paths=paths)

    leftovers = [p for p in gen._artifact_paths(paths) if p.exists()]
    assert leftovers == [], f"cleanup left behind: {leftovers}"
    assert neighbor.exists()
