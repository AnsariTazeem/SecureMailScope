"""Generate the controlled T01 SMTP STARTTLS evidence fixture end to end.

Pipeline: refuse-overwrite guard -> controlled PKI -> dumpcap loopback capture
-> SMTP session with deliberately split STARTTLS -> negotiated-facts contract
check -> PCAP sanity probes (packet count, dumpcap drop counters, STARTTLS
split, capture interval) -> openssl verify of the LEAF at a real packet epoch
-> hashed ground-truth manifest.

Exit codes:
 0 success
 1 unexpected internal failure
 2 artifact overwrite refused (use --force)
 3 external tool failure
 4 controlled session/capture/ground-truth inconsistency

The overwrite-refusal guard runs before any mutation. After that guard, every
generation step runs inside a failure-cleanup scope that unlinks each exact
path returned by `_artifact_paths()`; removal is per-file only. This script
never imports analyzer code and never prints private key material.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

from _fixture_common import (
    REPO_ROOT,
    FixtureError,
    FixtureToolError,
    PayloadFrame,
    bound_text,
    capture_interval,
    decimal_epoch_to_utc_iso,
    locate_command_window,
    parse_frame_epoch_rows,
    parse_packet_count,
    parse_payload_rows,
    parse_validated_epoch,
    run_bounded,
    sha256_file,
    truncate_log_text,
    utc_now,
    write_json_file,
)
from t01_capture import (
    CAPTURE_DRAIN_SECONDS,
    CAPTURE_LOG_DIRNAME,
    CAPTURE_LOG_FILENAME,
    CaptureRunnerError,
    DumpcapRunner,
    DumpcapSummary,
    parse_dumpcap_summary,
)
from t01_endpoint import (
    CIPHER_IANA_NAME,
    CIPHER_ID_HEX,
    CIPHER_OPENSSL_NAME,
    EC_GROUP_ID,
    EC_GROUP_NAME,
    FIXTURE_HOSTNAME,
    SERVER_PORT,
    TLS_VERSION_LABEL,
    TLS_WIRE_VERSION_HEX,
    SmtpSessionError,
    run_controlled_session,
    validate_negotiated_facts,
)
from t01_manifest import (
    ENDPOINT_LOG_RELATIVE_PATH,
    MANIFEST_RELATIVE_PATH,
    PCAP_RELATIVE_PATH,
    build_manifest,
    collect_runtime_versions,
    validate_manifest,
)
from t01_pki import (
    CHAIN_FILENAME,
    LEAF_CERT_FILENAME,
    LEAF_KEY_FILENAME,
    PRIVATE_DIRNAME,
    ROOT_CERT_FILENAME,
    ROOT_KEY_FILENAME,
    GeneratedPki,
    certificate_valid_at,
    generate_pki,
)

EXIT_OK = 0
EXIT_UNEXPECTED = 1
EXIT_REFUSED = 2
EXIT_TOOL_FAILURE = 3
EXIT_SESSION_FAILURE = 4


@dataclass(frozen=True)
class GeneratorPaths:
    """Explicitly enumerated T01 artifact locations rooted at one base."""

    root: Path
    pki_dir: Path
    pcap_path: Path
    endpoint_log_path: Path
    capture_log_path: Path
    manifest_path: Path

    @classmethod
    def from_root(cls, root: Path) -> GeneratorPaths:
        return cls(
            root=root,
            pki_dir=root / "fixtures" / "pki",
            pcap_path=root / PCAP_RELATIVE_PATH,
            endpoint_log_path=root / ENDPOINT_LOG_RELATIVE_PATH,
            capture_log_path=root / CAPTURE_LOG_DIRNAME / CAPTURE_LOG_FILENAME,
            manifest_path=root / MANIFEST_RELATIVE_PATH,
        )


PATHS = GeneratorPaths.from_root(REPO_ROOT)


class OverwriteRefused(FixtureError):
    """Existing T01 artifacts were found without --force."""


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="generate_t01_fixture",
        description="Generate the controlled T01 SMTP STARTTLS evidence fixture.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="overwrite previously generated T01 artifact files individually",
    )
    return parser.parse_args(argv)


def _artifact_paths(paths: GeneratorPaths) -> tuple[Path, ...]:
    private_dir = paths.pki_dir / PRIVATE_DIRNAME
    return (
        paths.pcap_path,
        paths.endpoint_log_path,
        paths.capture_log_path,
        paths.manifest_path,
        paths.pki_dir / ROOT_CERT_FILENAME,
        paths.pki_dir / LEAF_CERT_FILENAME,
        paths.pki_dir / CHAIN_FILENAME,
        private_dir / ROOT_KEY_FILENAME,
        private_dir / LEAF_KEY_FILENAME,
    )


def _generate(*, force: bool, paths: GeneratorPaths = PATHS) -> None:
    existing = [path for path in _artifact_paths(paths) if path.exists()]
    if existing and not force:
        listing = "\n  ".join(str(path) for path in existing)
        raise OverwriteRefused(f"{len(existing)} T01 artifact(s) already exist:\n  {listing}")

    try:
        for path in existing:
            path.unlink(missing_ok=True)

        pki = generate_pki(paths.pki_dir, now=utc_now())

        runner = DumpcapRunner(paths.pcap_path)
        runner.start()
        try:
            facts, log = run_controlled_session(
                pki.root_cert_path, pki.chain_path, pki.leaf_key_path
            )
        except BaseException:
            runner.abort()
            raise
        time.sleep(CAPTURE_DRAIN_SECONDS)
        runner.stop()

        _write_capture_log(runner, paths.capture_log_path)

        paths.endpoint_log_path.parent.mkdir(parents=True, exist_ok=True)
        paths.endpoint_log_path.write_text(log.to_jsonl(), encoding="utf-8")

        validate_negotiated_facts(facts)

        _probe_capture_readable(paths.pcap_path)
        summary = _require_clean_capture_summary(paths.capture_log_path)
        first_epoch_text, last_epoch_text = _extract_capture_interval(paths.pcap_path)
        first_epoch = _validated_interval(first_epoch_text, last_epoch_text)
        attime_epoch = int(first_epoch)
        first_utc = decimal_epoch_to_utc_iso(first_epoch)
        last_utc = decimal_epoch_to_utc_iso(_require_epoch(last_epoch_text))
        if not certificate_valid_at(pki.leaf_cert_path, _epoch_datetime(attime_epoch)):
            raise FixtureError("leaf certificate is not valid at the captured packet time")

        split_frames = _probe_starttls_split(paths.pcap_path)
        _completeness_gate(paths.pcap_path, split_frames, pki)
        _openssl_leaf_check(pki.leaf_cert_path, pki.root_cert_path, attime_epoch)

        manifest = build_manifest(
            endpoint_log_relative_path=_relative_to(paths.endpoint_log_path, paths.root),
            capture_log_relative_path=_relative_to(paths.capture_log_path, paths.root),
            pcap_integrity=sha256_file(paths.pcap_path),
            root_cert_integrity=sha256_file(pki.root_cert_path),
            leaf_cert_integrity=sha256_file(pki.leaf_cert_path),
            chain_integrity=sha256_file(pki.chain_path),
            endpoint_log_integrity=sha256_file(paths.endpoint_log_path),
            capture_log_integrity=sha256_file(paths.capture_log_path),
            leaf_facts=pki.leaf_facts,
            attime_epoch=attime_epoch,
            first_packet_epoch=first_epoch_text,
            last_packet_epoch=last_epoch_text,
            first_packet_utc=first_utc,
            last_packet_utc=last_utc,
            runtime_versions=collect_runtime_versions(),
        )
        validate_manifest(manifest)
        write_json_file(paths.manifest_path, manifest)
    except BaseException:
        for artifact in _artifact_paths(paths):
            try:
                artifact.unlink(missing_ok=True)
            except OSError:
                pass
        raise

    artifact_rows = manifest["artifacts"]
    assert isinstance(artifact_rows, list)
    print("T01 fixture generated.")
    print(f"  negotiated: {facts.tls_protocol_version} {facts.cipher_openssl_name}")
    print(f"  expected:   {TLS_VERSION_LABEL} ({TLS_WIRE_VERSION_HEX})")
    print(f"              {CIPHER_OPENSSL_NAME} / {CIPHER_IANA_NAME} ({CIPHER_ID_HEX})")
    print(f"              key exchange ECDHE group {EC_GROUP_NAME} ({EC_GROUP_ID})")
    print(f"  starttls split across frames: {[f.frame_number for f in split_frames]}")
    print(
        "  capture interval: "
        f"{first_epoch_text} .. {last_epoch_text} "
        f"(dropped={summary.dropped}, captured={summary.captured})"
    )
    for entry in artifact_rows:
        assert isinstance(entry, dict)
        print(
            f"  {entry['role']:<17} sha256={entry['sha256']} "
            f"bytes={entry['size_bytes']} {entry['path']}"
        )
    print(f"  manifest: {_relative_to(paths.manifest_path, paths.root)}")


def _relative_to(path: Path, base: Path) -> str:
    try:
        return path.relative_to(base).as_posix()
    except ValueError:
        return os.path.relpath(path, base)


def _write_capture_log(runner: DumpcapRunner, capture_log_path: Path) -> None:
    argv_text = " ".join(runner.argv)
    body = f"command: {argv_text}\n\n{runner.collected_stderr}"
    capture_log_path.parent.mkdir(parents=True, exist_ok=True)
    capture_log_path.write_text(truncate_log_text(body), encoding="utf-8")


def _probe_capture_readable(pcap_path: Path) -> int:
    result = run_bounded(
        ["capinfos", "-c", "-M", str(pcap_path)],
        error_stage="capture readability probe",
    )
    if not result.ok:
        raise CaptureRunnerError(f"capinfos failed: {bound_text(result.stderr_text)}")
    count = parse_packet_count(result.stdout_text)
    if count is None or count <= 0:
        raise CaptureRunnerError("captured PCAP reports no parseable packet count or zero packets")
    return count


def _require_clean_capture_summary(capture_log_path: Path) -> DumpcapSummary:
    log_text = capture_log_path.read_text(encoding="utf-8", errors="replace")
    summary = parse_dumpcap_summary(log_text)
    if summary is None:
        raise CaptureRunnerError(
            "dumpcap stop summary missing from the capture log; cannot prove clean capture"
        )
    if summary.captured <= 0:
        raise CaptureRunnerError(f"dumpcap reports zero packets captured: {summary}")
    if summary.dropped != 0:
        raise CaptureRunnerError(f"dumpcap reports dropped packets: {summary}")
    return summary


def _extract_capture_interval(pcap_path: Path) -> tuple[str, str]:
    result = run_bounded(
        [
            "tshark",
            "-2",
            "-r",
            str(pcap_path),
            "-Y",
            "frame",
            "-T",
            "fields",
            "-e",
            "frame.number",
            "-e",
            "frame.time_epoch",
        ],
        error_stage="capture interval extraction",
    )
    if not result.ok:
        raise CaptureRunnerError(
            f"tshark interval extraction failed: {bound_text(result.stderr_text)}"
        )
    interval = capture_interval(parse_frame_epoch_rows(result.stdout_text))
    if interval is None:
        raise CaptureRunnerError("captured PCAP contains no frame epochs")
    return interval


def _validated_interval(first_text: str, last_text: str) -> Decimal:
    first_epoch = parse_validated_epoch(first_text)
    last_epoch = parse_validated_epoch(last_text)
    if first_epoch is None or last_epoch is None or first_epoch > last_epoch:
        raise FixtureError(
            f"PCAP capture interval invalid or reversed: [{first_text}, {last_text}]"
        )
    return first_epoch


def _require_epoch(text: str) -> Decimal:
    epoch = parse_validated_epoch(text)
    if epoch is None:
        raise FixtureError(f"malformed PCAP frame epoch: {text!r}")
    return epoch


def _epoch_datetime(attime_epoch: int) -> datetime:
    return datetime.fromtimestamp(attime_epoch, tz=UTC)


def _probe_starttls_split(pcap_path: Path) -> tuple[PayloadFrame, ...]:
    result = run_bounded(
        [
            "tshark",
            "-2",
            "-r",
            str(pcap_path),
            "-Y",
            "tcp.len>0",
            "-T",
            "fields",
            "-e",
            "frame.number",
            "-e",
            "ip.src",
            "-e",
            "tcp.srcport",
            "-e",
            "tcp.dstport",
            "-e",
            "tcp.payload",
        ],
        error_stage="STARTTLS split probe",
    )
    if not result.ok:
        raise CaptureRunnerError(f"tshark split probe failed: {bound_text(result.stderr_text)}")
    frames = parse_payload_rows(result.stdout_text)
    client_frames = [frame for frame in frames if frame.destination_port == SERVER_PORT]
    window = locate_command_window(client_frames, b"STARTTLS\r\n", minimum_frames=2)
    if window is None:
        raise SmtpSessionError(
            "STARTTLS was not captured across >=2 TCP payload frames; "
            "re-run the generator (segment splitting is timing dependent)"
        )
    return window.frames


def _tshark_query(
    pcap_path: Path,
    display_filter: str,
    fields: tuple[str, ...],
    *,
    decode_as: str | None = None,
) -> str:
    argv: list[str] = [
        "tshark",
        "-2",
        "-r",
        str(pcap_path),
        "-Y",
        display_filter,
    ]
    if decode_as is not None:
        argv.extend(["-d", decode_as])
    argv.append("-T")
    argv.append("fields")
    for field_name in fields:
        argv.extend(["-e", field_name])
    result = run_bounded(argv, error_stage=f"completeness gate tshark ({display_filter})")
    if not result.ok:
        raise CaptureRunnerError(
            f"tshark completeness gate failed: {bound_text(result.stderr_text)}"
        )
    return result.stdout_text


def _select_single_stream(pcap_path: Path, server_port: int) -> str:
    lines = _tshark_query(
        pcap_path,
        f"tcp.port=={server_port}",
        ("tcp.stream",),
    ).splitlines()
    streams: set[str] = set()
    for line in lines:
        token = line.strip()
        if token:
            streams.add(token)
    if len(streams) != 1:
        raise FixtureError(
            f"expected exactly one TCP stream for port {server_port}; "
            f"found {len(streams)}: {sorted(streams)[:5]}"
        )
    return streams.pop()


TCP_FIN_FLAG = 0x0001
TCP_SYN_FLAG = 0x0002
TCP_RST_FLAG = 0x0004
TCP_ACK_FLAG = 0x0010

TCP_FLAGS_DECODE_AS = None


def _check_lifecycle(pcap_path: Path, stream_id: str, server_port: int) -> None:
    stream_filter = f"tcp.stream=={stream_id}"
    lines = _tshark_query(
        pcap_path,
        stream_filter,
        ("frame.number", "tcp.srcport", "tcp.flags"),
    ).splitlines()
    client_syn = False
    server_syn_ack = False
    fin_client = False
    fin_server = False
    resets = 0
    for line in lines:
        cols = line.split("\t")
        if len(cols) < 3:
            continue
        try:
            srcport = int(cols[1])
            flags = int(cols[2], 0)
        except (ValueError, IndexError):
            continue
        from_server = srcport == server_port
        if (flags & TCP_SYN_FLAG) and not (flags & TCP_ACK_FLAG) and not from_server:
            client_syn = True
        if (flags & TCP_SYN_FLAG) and (flags & TCP_ACK_FLAG) and from_server:
            server_syn_ack = True
        if flags & TCP_FIN_FLAG:
            if from_server:
                fin_server = True
            else:
                fin_client = True
        if flags & TCP_RST_FLAG:
            resets += 1
    if not client_syn:
        raise FixtureError("capture lacks client SYN; cannot prove lifecycle")
    if not server_syn_ack:
        raise FixtureError("capture lacks server SYN/ACK; cannot prove lifecycle")
    if not fin_client:
        raise FixtureError("capture lacks FIN from client; cannot prove lifecycle")
    if not fin_server:
        raise FixtureError("capture lacks FIN from server; cannot prove lifecycle")
    if resets != 0:
        raise FixtureError(
            f"capture contains RST frame(s) ({resets}); cannot prove clean lifecycle"
        )


def _check_starttls_ordering(
    pcap_path: Path,
    stream_id: str,
    server_port: int,
    starttls_frames: tuple[PayloadFrame, ...],
) -> None:
    last_starttls_frame = starttls_frames[-1].frame_number
    stream_filter = f"tcp.stream=={stream_id}"
    server_after = _tshark_query(
        pcap_path,
        f"{stream_filter} && tcp.len>0 && frame.number>{last_starttls_frame}",
        ("frame.number", "tcp.srcport", "tcp.payload"),
    ).splitlines()
    accept_frame = None
    for line in server_after:
        cols = line.split("\t")
        if len(cols) < 3 or not cols[2]:
            continue
        try:
            frame_num = int(cols[0])
            srcport = int(cols[1])
        except (ValueError, IndexError):
            continue
        if srcport != server_port:
            continue
        try:
            payload = bytes.fromhex(cols[2].replace(":", ""))
        except ValueError:
            continue
        if payload.startswith(b"220 "):
            accept_frame = frame_num
            break
    if accept_frame is None:
        raise FixtureError("capture lacks 220 acceptance after STARTTLS; cannot prove ordering")
    hello_lines = _tshark_query(
        pcap_path,
        f"{stream_filter} && tls.handshake.type==1 && frame.number>{accept_frame}",
        ("frame.number",),
        decode_as=f"tcp.port=={server_port},smtp",
    ).splitlines()
    client_hello_frame = None
    for line in hello_lines:
        cols = line.split("\t")
        if cols and cols[0]:
            try:
                client_hello_frame = int(cols[0])
                break
            except ValueError:
                continue
    if client_hello_frame is None:
        raise FixtureError("capture lacks ClientHello after 220 acceptance; cannot prove ordering")
    if not (last_starttls_frame < accept_frame < client_hello_frame):
        raise FixtureError(
            f"STARTTLS ordering violated: starttls={last_starttls_frame}, "
            f"220={accept_frame}, clienthello={client_hello_frame}"
        )


def _check_tls_handshake(
    pcap_path: Path,
    stream_id: str,
    server_port: int,
) -> None:
    stream_filter = f"tcp.stream=={stream_id}"
    decode_as = f"tcp.port=={server_port},smtp"
    rows = _tshark_query(
        pcap_path,
        f"{stream_filter} && tls.handshake.type",
        (
            "frame.number",
            "tls.handshake.type",
            "tls.handshake.version",
            "tls.handshake.ciphersuite",
            "tls.handshake.server_named_curve",
        ),
        decode_as=decode_as,
    ).splitlines()
    HandshakeRow = tuple[int, tuple[int, ...], tuple[int, ...], tuple[int, ...]]
    frames_by_type: dict[int, list[HandshakeRow]] = {}
    first_position: dict[int, tuple[int, int]] = {}
    for line in rows:
        cols = line.split("\t")
        while len(cols) < 5:
            cols.append("")
        try:
            frame_number = int(cols[0])
        except ValueError:
            continue
        types = _csv_hex_ints(cols[1])
        versions = _csv_hex_ints(cols[2])
        ciphers = _csv_hex_ints(cols[3])
        curves = _csv_hex_ints(cols[4])
        for occurrence_idx, htype in enumerate(types):
            frames_by_type.setdefault(htype, []).append((frame_number, versions, ciphers, curves))
            if htype not in first_position:
                first_position[htype] = (frame_number, occurrence_idx)
    for required_type, label in (
        (1, "ClientHello"),
        (2, "ServerHello"),
        (11, "Certificate"),
        (12, "ServerKeyExchange"),
    ):
        if required_type not in frames_by_type:
            raise FixtureError(f"capture lacks TLS {label} (type {required_type})")
    required = (1, 2, 11, 12)
    labels = {1: "ClientHello", 2: "ServerHello", 11: "Certificate", 12: "ServerKeyExchange"}
    for idx in range(len(required) - 1):
        a = required[idx]
        b = required[idx + 1]
        pos_a = first_position[a]
        pos_b = first_position[b]
        if not (pos_a < pos_b):
            pos_str = ", ".join(
                f"type={labels[t]} frame={first_position[t][0]} occurrence={first_position[t][1]}"
                for t in required
            )
            raise FixtureError(f"TLS handshake ordering violated: {pos_str}")
    server_hellos = frames_by_type.get(2, [])
    sh_versions = server_hellos[0][1] if server_hellos else ()
    if 0x0303 not in sh_versions:
        raise FixtureError(f"ServerHello version mismatch: {[f'0x{v:04x}' for v in sh_versions]}")
    sh_ciphers = server_hellos[0][2] if server_hellos else ()
    if 0xC02F not in sh_ciphers:
        raise FixtureError(f"ServerHello cipher mismatch: {[f'0x{c:04x}' for c in sh_ciphers]}")
    ske_rows = frames_by_type.get(12, [])
    all_curves = [curve for _, _, _, curves in ske_rows for curve in curves]
    if 23 not in all_curves:
        raise FixtureError(f"ServerKeyExchange named curve mismatch: {all_curves}")


def _csv_hex_ints(column: str) -> tuple[int, ...]:
    values: list[int] = []
    for part in column.split(","):
        token = part.strip()
        if not token:
            continue
        base = 16 if token.lower().startswith("0x") else 10
        try:
            values.append(int(token, base))
        except ValueError:
            continue
    return tuple(values)


def _check_wire_certificates(
    pcap_path: Path,
    stream_id: str,
    server_port: int,
    pki: GeneratedPki,
) -> None:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes

    stream_filter = f"tcp.stream=={stream_id}"
    decode_as = f"tcp.port=={server_port},smtp"
    cert_rows = _tshark_query(
        pcap_path,
        f"{stream_filter} && tls.handshake.type==11",
        ("frame.number", "tls.handshake.certificate"),
        decode_as=decode_as,
    ).splitlines()
    ders: list[bytes] = []
    for line in cert_rows:
        cols = line.split("\t")
        if len(cols) < 2 or not cols[1]:
            continue
        for blob in cols[1].split(","):
            hex_text = blob.strip().replace(":", "")
            if not hex_text:
                continue
            try:
                ders.append(bytes.fromhex(hex_text))
            except ValueError:
                continue
    if len(ders) < 2:
        raise FixtureError(
            f"capture carries fewer than 2 DER certificates ({len(ders)}); "
            "cannot prove wire certificate truth"
        )
    leaf_der = ders[0]
    root_der = ders[1]
    try:
        wire_leaf_fp = x509.load_der_x509_certificate(leaf_der).fingerprint(hashes.SHA256()).hex()
    except ValueError as exc:
        raise FixtureError(f"wire certificate DER is invalid (leaf): {exc}") from exc
    try:
        wire_root_fp = x509.load_der_x509_certificate(root_der).fingerprint(hashes.SHA256()).hex()
    except ValueError as exc:
        raise FixtureError(f"wire certificate DER is invalid (root): {exc}") from exc
    if wire_leaf_fp != pki.leaf_facts.sha256_fingerprint_hex:
        raise FixtureError(
            f"wire leaf fingerprint {wire_leaf_fp} != "
            f"controlled {pki.leaf_facts.sha256_fingerprint_hex}"
        )
    if wire_root_fp != pki.root_facts.sha256_fingerprint_hex:
        raise FixtureError(
            f"wire root fingerprint {wire_root_fp} != "
            f"controlled {pki.root_facts.sha256_fingerprint_hex}"
        )


def _completeness_gate(
    pcap_path: Path,
    starttls_frames: tuple[PayloadFrame, ...],
    pki: GeneratedPki,
) -> None:
    stream_id = _select_single_stream(pcap_path, SERVER_PORT)
    _check_lifecycle(pcap_path, stream_id, SERVER_PORT)
    _check_starttls_ordering(pcap_path, stream_id, SERVER_PORT, starttls_frames)
    _check_tls_handshake(pcap_path, stream_id, SERVER_PORT)
    _check_wire_certificates(pcap_path, stream_id, SERVER_PORT, pki)


def _openssl_leaf_check(leaf_path: Path, root_path: Path, attime_epoch: int) -> None:
    result = run_bounded(
        [
            "openssl",
            "verify",
            "-CAfile",
            str(root_path),
            "-attime",
            str(attime_epoch),
            "-verify_hostname",
            FIXTURE_HOSTNAME,
            str(leaf_path),
        ],
        error_stage="openssl capture-time leaf verification",
    )
    if not result.ok or ": OK" not in result.stdout_text:
        raise FixtureToolError(
            f"openssl verify did not report OK: {result.stdout_text or result.stderr_text}"
        )


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        _generate(force=args.force)
    except OverwriteRefused as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        print("Re-run with --force to overwrite these exact files.", file=sys.stderr)
        return EXIT_REFUSED
    except FixtureToolError as exc:
        print(f"TOOL FAILURE: {exc}", file=sys.stderr)
        return EXIT_TOOL_FAILURE
    except FixtureError as exc:
        print(f"SESSION FAILURE: {exc}", file=sys.stderr)
        return EXIT_SESSION_FAILURE
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
