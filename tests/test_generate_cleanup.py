"""Isolated failure-cleanup and overwrite-refusal tests for the T01 generator.

Every collaborator (PKI generation, dumpcap runner, controlled session, PCAP
probes, OpenSSL check, manifest write) is monkeypatched; no listener is
started, dumpcap never runs, and no live capture occurs. All artifact paths
are redirected into a temporary root via GeneratorPaths.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

import generate_t01_fixture as gen
import pytest
from t01_capture import CaptureRunnerError
from t01_endpoint import (
    CIPHER_OPENSSL_NAME,
    FIXTURE_HOSTNAME,
    EndpointEventLog,
    SessionFacts,
    SmtpSessionError,
)


def _paths(tmp_path: Path) -> gen.GeneratorPaths:
    return gen.GeneratorPaths.from_root(tmp_path / "repo")


def _neighbor(paths: gen.GeneratorPaths) -> Path:
    neighbor = paths.pki_dir.parent / "keepme.txt"
    neighbor.parent.mkdir(parents=True, exist_ok=True)
    neighbor.write_text("unrelated file that must survive cleanup", encoding="utf-8")
    return neighbor


def _assert_all_artifacts_removed(paths: gen.GeneratorPaths) -> None:
    leftovers = [path for path in gen._artifact_paths(paths) if path.exists()]
    assert leftovers == [], f"cleanup left behind: {leftovers}"


def _valid_facts() -> SessionFacts:
    return SessionFacts(
        tls_protocol_version="TLSv1.2",
        cipher_openssl_name=CIPHER_OPENSSL_NAME,
        cipher_bits=128,
        peer_san_dns_names=(FIXTURE_HOSTNAME,),
    )


class FakeOkRunner:
    def __init__(self, pcap_path: Path, **_kwargs: object) -> None:
        self._pcap_path = pcap_path
        self.argv = ["dumpcap", "-i", "lo", "-f", "tcp port 2525", "-w", str(pcap_path)]
        self.collected_stderr = "Packets captured: 12\n"

    def start(self) -> None:
        self._pcap_path.parent.mkdir(parents=True, exist_ok=True)
        self._pcap_path.write_bytes(b"dummy-pcapng-bytes")

    def stop(self) -> None:
        pass

    def abort(self) -> None:
        pass

    def join(self, timeout: float) -> None:
        pass


class FakeReadyFailureRunner(FakeOkRunner):
    def start(self) -> None:
        super().start()
        raise CaptureRunnerError("dumpcap produced no readable capture file within 15s")


class FakeSession:
    def __init__(self, facts: SessionFacts, log: EndpointEventLog) -> None:
        self.facts = facts
        self.log = log

    def __call__(
        self, _root_cert: Path, _chain: Path, _leaf_key: Path
    ) -> tuple[SessionFacts, EndpointEventLog]:
        return self.facts, self.log


def test_overwrite_refusal_without_force_leaves_existing_artifacts_untouched(
    tmp_path: Path,
) -> None:
    paths = _paths(tmp_path)
    for artifact in gen._artifact_paths(paths):
        artifact.parent.mkdir(parents=True, exist_ok=True)
        artifact.write_bytes(b"pre-existing")
    neighbor = _neighbor(paths)
    before = {artifact.stat().st_mtime_ns for artifact in gen._artifact_paths(paths)}

    with pytest.raises(gen.OverwriteRefused):
        gen._generate(force=False, paths=paths)

    for artifact in gen._artifact_paths(paths):
        assert artifact.read_bytes() == b"pre-existing"
    assert neighbor.exists()
    after = {artifact.stat().st_mtime_ns for artifact in gen._artifact_paths(paths)}
    assert before == after


def test_partial_pki_failure_removes_every_enumerated_artifact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _paths(tmp_path)
    neighbor = _neighbor(paths)

    def failing_generate_pki(pki_dir: Path, *, now: datetime) -> None:
        pki_dir.mkdir(parents=True, exist_ok=True)
        (pki_dir / "root-ca.pem").write_bytes(b"partial")
        private = pki_dir / "private"
        private.mkdir(exist_ok=True)
        (private / "root-ca.key").write_bytes(b"partial-key")
        raise RuntimeError("simulated key generation crash")

    monkeypatch.setattr(gen, "generate_pki", failing_generate_pki)

    with pytest.raises(RuntimeError, match="simulated key generation crash"):
        gen._generate(force=True, paths=paths)

    _assert_all_artifacts_removed(paths)
    assert neighbor.exists()


def test_dumpcap_readiness_failure_after_pcap_creation_removes_everything(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _paths(tmp_path)
    neighbor = _neighbor(paths)
    monkeypatch.setattr(gen, "DumpcapRunner", FakeReadyFailureRunner)

    with pytest.raises(CaptureRunnerError):
        gen._generate(force=True, paths=paths)

    _assert_all_artifacts_removed(paths)
    assert neighbor.exists()


def test_session_contract_failure_after_log_writes_removes_logs_and_pki(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _paths(tmp_path)
    neighbor = _neighbor(paths)
    log = EndpointEventLog()
    log.add("client", "connection_opened")
    monkeypatch.setattr(gen, "DumpcapRunner", FakeOkRunner)
    monkeypatch.setattr(
        gen,
        "run_controlled_session",
        FakeSession(
            SessionFacts(
                tls_protocol_version="TLSv1.3",
                cipher_openssl_name=CIPHER_OPENSSL_NAME,
                cipher_bits=128,
                peer_san_dns_names=(FIXTURE_HOSTNAME,),
            ),
            log,
        ),
    )

    with pytest.raises(SmtpSessionError):
        gen._generate(force=True, paths=paths)

    _assert_all_artifacts_removed(paths)
    assert neighbor.exists()


def test_manifest_write_failure_removes_every_enumerated_artifact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _paths(tmp_path)
    neighbor = _neighbor(paths)
    monkeypatch.setattr(gen, "DumpcapRunner", FakeOkRunner)
    monkeypatch.setattr(
        gen, "run_controlled_session", FakeSession(_valid_facts(), EndpointEventLog())
    )
    monkeypatch.setattr(gen, "_probe_capture_readable", lambda _pcap: 42)
    monkeypatch.setattr(
        gen,
        "_require_clean_capture_summary",
        lambda _log: CaptureRunnerSummaryStub(),
    )
    monkeypatch.setattr(
        gen,
        "_extract_capture_interval",
        lambda _pcap: ("1800000000.100000123", "1800000000.900000987"),
    )
    monkeypatch.setattr(
        gen, "_probe_starttls_split", lambda _pcap: (_frame_stub(6), _frame_stub(7))
    )
    monkeypatch.setattr(gen, "_completeness_gate", lambda _pcap, _frames, _pki: None)
    monkeypatch.setattr(gen, "_openssl_leaf_check", lambda *_args: None)

    def failing_write_json(path: Path, payload: object) -> None:
        raise OSError("simulated disk failure while writing manifest")

    monkeypatch.setattr(gen, "write_json_file", failing_write_json)

    with pytest.raises(OSError, match="simulated disk failure"):
        gen._generate(force=True, paths=paths)

    _assert_all_artifacts_removed(paths)
    assert neighbor.exists()


class CaptureRunnerSummaryStub:
    captured = 12
    received = 12
    dropped = 0

    def __repr__(self) -> str:
        return (
            f"DumpcapSummary(captured={self.captured}, "
            f"received={self.received}, dropped={self.dropped})"
        )


def _frame_stub(frame_number: int) -> object:
    class _Frame:
        pass

    frame = _Frame()
    frame.frame_number = frame_number
    return frame
