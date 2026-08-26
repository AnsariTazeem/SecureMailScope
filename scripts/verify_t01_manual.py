"""Independent manual verification of the T01 fixture against its manifest.

This verifier re-observes everything directly from the PCAP using TShark
(two-pass analysis plus manifest-derived SMTP decode-as), capinfos, and
OpenSSL plus raw certificate parsing. It reads the ground-truth manifest as
the expectation source but never trusts generator claims and never imports
analyzer code. Bounded evidence is written separately from any analyzer
output.

Exit codes:
 0 every T01 comparison passed
 1 one or more comparisons failed (precise list printed and written)
 2 invalid input/manifest
 3 external tool failure

Usage:
  uv run python scripts/verify_t01_manual.py [MANIFEST_PATH] [--evidence-out PATH]
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from _fixture_common import (
    REPO_ROOT,
    CommandWindow,
    FixtureError,
    FixtureToolError,
    PayloadFrame,
    bound_text,
    capture_interval,
    decimal_epoch_to_utc_iso,
    iso_utc,
    locate_command_window,
    parse_frame_epoch_rows,
    parse_packet_count,
    parse_payload_rows,
    parse_validated_epoch,
    run_bounded,
    sha256_file,
    utc_now,
    write_json_file,
)
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from t01_capture import parse_dumpcap_summary
from t01_manifest import (
    CAPTURE_LOG_ARTIFACT_ROLE,
    EVIDENCE_RELATIVE_PATH,
    MANIFEST_RELATIVE_PATH,
    ManifestValidationError,
    validate_manifest,
)
from t01_pki import CertificateFacts, facts_from_certificate

VERIFIER_NAME = "verify_t01_manual"
VERIFIER_VERSION = "1.0"
DEFAULT_MANIFEST_PATH = MANIFEST_RELATIVE_PATH
PCAP_ARTIFACT_ROLE = "pcap"
ROOT_CERT_ARTIFACT_ROLE = "root_ca_cert"
LEAF_CERT_ARTIFACT_ROLE = "server_leaf_cert"
SECP256R1_GROUP_NAME = "secp256r1"

EXIT_OK = 0
EXIT_COMPARISONS_FAILED = 1
EXIT_USAGE = 2
EXIT_TOOL_FAILURE = 3

SECP256R1_GROUP_ID = 23
TLS_12_WIRE_VERSION_INT = 0x0303
TLS_13_WIRE_VERSION_INT = 0x0304
EXPECTED_CIPHER_ID_INT = 0xC02F

HANDSHAKE_TYPE_CLIENT_HELLO = 1
HANDSHAKE_TYPE_SERVER_HELLO = 2
HANDSHAKE_TYPE_CERTIFICATE = 11
HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE = 12
HANDSHAKE_TYPE_SERVER_HELLO_DONE = 14
HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE = 16

REQUIRED_HANDSHAKE_ORDER = (
    HANDSHAKE_TYPE_CLIENT_HELLO,
    HANDSHAKE_TYPE_SERVER_HELLO,
    HANDSHAKE_TYPE_CERTIFICATE,
    HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE,
)


class VerificationInputError(FixtureError):
    """The verifier inputs were missing or unusable."""


def build_tshark_argv(
    pcap_path: Path | str,
    display_filter: str,
    fields: Sequence[str],
    *,
    smtp_server_port: int,
) -> list[str]:
    """Deterministic two-pass TShark command with manifest-derived decode-as."""
    argv = [
        "tshark",
        "-2",
        "-r",
        str(pcap_path),
        "-Y",
        display_filter,
        "-d",
        f"tcp.port=={smtp_server_port},smtp",
        "-T",
        "fields",
    ]
    for field_name in fields:
        argv.extend(["-e", field_name])
    return argv


@dataclass(frozen=True)
class Comparison:
    """One recorded expectation-versus-observation outcome."""

    identifier: str
    passed: bool
    expected: str
    actual: str
    detail: str = ""


@dataclass(frozen=True)
class HandshakeFrameView:
    """Normalized TShark TLS handshake row for one frame."""

    frame_number: int
    handshake_types: tuple[int, ...]
    versions: tuple[int, ...]
    cipher_suites: tuple[int, ...]
    named_curves: tuple[int, ...]
    advertised_versions: tuple[int, ...]


@dataclass(frozen=True)
class FlagRow:
    frame_number: int
    source_port: int
    raw_flags: int


@dataclass(frozen=True)
class ConnectionLifecycle:
    client_syn: bool
    server_syn_ack: bool
    reset_count: int
    fin_from_client: bool
    fin_from_server: bool

    @property
    def complete_and_clean(self) -> bool:
        return (
            self.client_syn
            and self.server_syn_ack
            and self.reset_count == 0
            and self.fin_from_client
            and self.fin_from_server
        )


@dataclass
class VerifierState:
    stream_id: str | None = None
    payload_frames: tuple[PayloadFrame, ...] = ()
    handshake_views: tuple[HandshakeFrameView, ...] = ()
    client_hello_frame: int | None = None
    starttls_window: CommandWindow | None = None
    wire_certificates: tuple[bytes, ...] = ()
    first_packet_epoch: str | None = None


def csv_hex_ints(column: str) -> tuple[int, ...]:
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


def classify_direction(source_ip: str, source_port: int, server_ip: str, server_port: int) -> str:
    if source_ip == server_ip and source_port == server_port:
        return "server_to_client"
    if source_port != server_port:
        return "client_to_server"
    return "unknown"


def parse_handshake_rows(stdout_text: str) -> tuple[HandshakeFrameView, ...]:
    views: list[HandshakeFrameView] = []
    for line in stdout_text.splitlines():
        columns = line.split("\t")
        while len(columns) < 6:
            columns.append("")
        try:
            frame_number = int(columns[0])
        except ValueError:
            continue
        views.append(
            HandshakeFrameView(
                frame_number=frame_number,
                handshake_types=csv_hex_ints(columns[1]),
                versions=csv_hex_ints(columns[2]),
                cipher_suites=csv_hex_ints(columns[3]),
                named_curves=csv_hex_ints(columns[4]),
                advertised_versions=csv_hex_ints(columns[5]),
            )
        )
    return tuple(views)


def parse_flag_rows(stdout_text: str) -> tuple[FlagRow, ...]:
    rows: list[FlagRow] = []
    for line in stdout_text.splitlines():
        columns = line.split("\t")
        if len(columns) < 4:
            continue
        try:
            frame_number = int(columns[0])
            source_port = int(columns[2])
            raw_flags = int(columns[3], 0)
        except (ValueError, IndexError):
            continue
        rows.append(
            FlagRow(
                frame_number=frame_number,
                source_port=source_port,
                raw_flags=raw_flags,
            )
        )
    return tuple(rows)


def connection_lifecycle_summary(rows: Sequence[FlagRow], server_port: int) -> ConnectionLifecycle:
    client_syn = False
    server_syn_ack = False
    resets = 0
    fin_client = False
    fin_server = False
    for row in rows:
        from_server = row.source_port == server_port
        syn = bool(row.raw_flags & 0x0002)
        ack = bool(row.raw_flags & 0x0010)
        fin = bool(row.raw_flags & 0x0001)
        rst = bool(row.raw_flags & 0x0004)
        if syn and not ack and not from_server:
            client_syn = True
        if syn and ack and from_server:
            server_syn_ack = True
        if fin:
            if from_server:
                fin_server = True
            else:
                fin_client = True
        if rst:
            resets += 1
    return ConnectionLifecycle(
        client_syn=client_syn,
        server_syn_ack=server_syn_ack,
        reset_count=resets,
        fin_from_client=fin_client,
        fin_from_server=fin_server,
    )


def first_type_positions(
    views: Sequence[HandshakeFrameView], wanted_types: Sequence[int]
) -> dict[int, HandshakeFrameView]:
    positions: dict[int, HandshakeFrameView] = {}
    for view in sorted(views, key=lambda item: item.frame_number):
        for handshake_type in view.handshake_types:
            if handshake_type in wanted_types and handshake_type not in positions:
                positions[handshake_type] = view
    return positions


def _position_of(
    views: Sequence[HandshakeFrameView], wanted_types: Sequence[int]
) -> dict[int, tuple[int, int]]:
    """Map each wanted type to (frame_number, occurrence_index) of its first appearance.

    The occurrence index is the position of the type within the view's
    handshake_types tuple at which the first match was found.
    """
    positions: dict[int, tuple[int, int]] = {}
    for view in sorted(views, key=lambda item: item.frame_number):
        for idx, handshake_type in enumerate(view.handshake_types):
            if handshake_type in wanted_types and handshake_type not in positions:
                positions[handshake_type] = (view.frame_number, idx)
    return positions


def handshake_order_result(views: Sequence[HandshakeFrameView]) -> tuple[bool, str]:
    positions = first_type_positions(views, REQUIRED_HANDSHAKE_ORDER)
    missing = [str(t) for t in REQUIRED_HANDSHAKE_ORDER if t not in positions]
    if missing:
        return False, f"missing handshake message type(s): {', '.join(missing)}"
    frame_positions = _position_of(views, REQUIRED_HANDSHAKE_ORDER)
    ordered = sorted(REQUIRED_HANDSHAKE_ORDER, key=lambda t: frame_positions[t])
    if ordered != list(REQUIRED_HANDSHAKE_ORDER):
        sequence = " -> ".join(
            f"{t}@({frame_positions[t][0]}, {frame_positions[t][1]})"
            for t in REQUIRED_HANDSHAKE_ORDER
        )
        return False, f"handshake order violated: {sequence}"
    ske_position = frame_positions[HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE]
    for later_type in (HANDSHAKE_TYPE_SERVER_HELLO_DONE, HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE):
        later_all = _position_of(views, (later_type,))
        if later_type in later_all and later_all[later_type] <= ske_position:
            return False, f"handshake type {later_type} did not follow the ServerKeyExchange"
    return True, "order ok"


def negotiated_version_result(view: HandshakeFrameView) -> tuple[bool, str]:
    has_tls12 = TLS_12_WIRE_VERSION_INT in view.versions
    advertises_tls13 = TLS_13_WIRE_VERSION_INT in view.advertised_versions
    actual = ", ".join(f"0x{value:04x}" for value in view.versions) or "none"
    if not has_tls12:
        return False, f"ServerHello versions: [{actual}]"
    if advertises_tls13:
        return False, "ServerHello advertises 0x0304 via supported_versions"
    return True, f"ServerHello version 0x{TLS_12_WIRE_VERSION_INT:04x}"


def observed_version_is_tls12(views: Sequence[HandshakeFrameView]) -> bool:
    server_hello = first_type_positions(views, (HANDSHAKE_TYPE_SERVER_HELLO,)).get(
        HANDSHAKE_TYPE_SERVER_HELLO
    )
    if server_hello is None:
        return False
    version_ok, _detail = negotiated_version_result(server_hello)
    return version_ok


def observed_cipher_is_expected(views: Sequence[HandshakeFrameView]) -> bool:
    server_hello = first_type_positions(views, (HANDSHAKE_TYPE_SERVER_HELLO,)).get(
        HANDSHAKE_TYPE_SERVER_HELLO
    )
    return server_hello is not None and EXPECTED_CIPHER_ID_INT in server_hello.cipher_suites


def observed_server_key_exchange_exists(views: Sequence[HandshakeFrameView]) -> bool:
    return HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE in first_type_positions(
        views, (HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE,)
    )


def named_curve_result(
    views: Sequence[HandshakeFrameView], expected_group_id: int
) -> tuple[bool, str, int | None]:
    observed: list[tuple[int, int]] = []
    for view in views:
        for curve_id in view.named_curves:
            observed.append((view.frame_number, curve_id))
    if not observed:
        return False, "no tls.handshake.server_named_curve observation found", None
    matching = [frame for frame, curve_id in observed if curve_id == expected_group_id]
    rendered = ", ".join(f"frame {frame}: group {curve}" for frame, curve in observed[:8])
    if not matching:
        return False, f"expected group {expected_group_id}; observed: {rendered}", None
    return True, f"group {expected_group_id} in frame(s) {sorted(set(matching))}", expected_group_id


def derive_forward_secrecy(views: Sequence[HandshakeFrameView]) -> tuple[bool, str]:
    """Derive FS only from packet observations; manifest values are never input."""
    reasons: list[str] = []
    version_ok = observed_version_is_tls12(views)
    cipher_ok = observed_cipher_is_expected(views)
    ske_ok = observed_server_key_exchange_exists(views)
    curve_ok, curve_detail, _group = named_curve_result(views, SECP256R1_GROUP_ID)
    if not version_ok:
        reasons.append("TLS 1.2 ServerHello version not observed")
    if not cipher_ok:
        reasons.append(f"ciphersuite {EXPECTED_CIPHER_ID_INT:#06x} not selected")
    if not ske_ok:
        reasons.append("no ServerKeyExchange observed")
    if not curve_ok:
        reasons.append(f"ephemeral group evidence missing ({curve_detail})")
    if reasons:
        return False, "; ".join(reasons)
    return True, (
        f"ECDHE proven by SKE + {SECP256R1_GROUP_NAME} named curve under "
        f"{EXPECTED_CIPHER_ID_INT:#06x}"
    )


SECP256R1_GROUP_NAME = "secp256r1"


def forward_secrecy_check(
    views: Sequence[HandshakeFrameView], expected_forward_secrecy: bool
) -> tuple[bool, bool, str]:
    """Return (derived_fs, comparison_passed, reason); expectations used last."""
    derived, derivation_reason = derive_forward_secrecy(views)
    passed = derived == expected_forward_secrecy
    detail = (
        f"derived={derived}; {derivation_reason}; expected={expected_forward_secrecy} (manifest)"
    )
    return derived, passed, detail


def parse_certificate_rows(stdout_text: str) -> tuple[bytes, ...]:
    ders: list[bytes] = []
    for line in stdout_text.splitlines():
        columns = line.split("\t")
        if len(columns) < 2 or not columns[1]:
            continue
        for blob in columns[1].split(","):
            hex_text = blob.strip().replace(":", "")
            if not hex_text:
                continue
            try:
                ders.append(bytes.fromhex(hex_text))
            except ValueError:
                continue
    return tuple(ders)


class ManualVerifier:
    def __init__(
        self,
        manifest_path: Path,
        *,
        repo_root: Path = REPO_ROOT,
    ) -> None:
        self._repo_root = repo_root
        self._manifest_path = manifest_path
        self._manifest = self._load_manifest()
        self._comparisons: list[Comparison] = []
        self._state = VerifierState()
        self._server_ip = str(self._endpoint().get("ip"))
        self._server_port = int(self._endpoint().get("port"))
        pcap_relative = self._path_by_role(PCAP_ARTIFACT_ROLE)
        if pcap_relative is None:
            raise VerificationInputError("manifest lists no artifact with role 'pcap'")
        self._pcap_path = self._resolve(pcap_relative)

    @property
    def comparisons(self) -> tuple[Comparison, ...]:
        return tuple(self._comparisons)

    def _resolve(self, relative: str) -> Path:
        candidate = (self._repo_root / relative).resolve()
        repo_root_resolved = self._repo_root.resolve()
        if candidate != repo_root_resolved and repo_root_resolved not in candidate.parents:
            raise VerificationInputError(f"path escapes repository root: {relative}")
        return candidate

    def _load_manifest(self) -> Mapping[str, Any]:
        if not self._manifest_path.is_file():
            raise VerificationInputError(f"manifest not found: {self._manifest_path}")
        try:
            manifest = json.loads(self._manifest_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise VerificationInputError(f"manifest unreadable: {bound_text(str(exc))}") from exc
        validate_manifest(manifest)
        return manifest

    def _section(self, name: str) -> Mapping[str, Any]:
        section = self._manifest.get(name)
        if not isinstance(section, Mapping):
            raise VerificationInputError(f"manifest section '{name}' missing")
        return section

    def _record(
        self,
        identifier: str,
        passed: bool,
        expected: str,
        actual: str,
        detail: str = "",
    ) -> bool:
        self._comparisons.append(
            Comparison(
                identifier, passed, bound_text(expected), bound_text(actual), bound_text(detail)
            )
        )
        return passed

    def run(self) -> tuple[Comparison, ...]:
        self._check_artifact_hashes()
        self._check_pcap_metadata()
        self._check_dumpcap_evidence_log()
        self._check_capture_interval()
        self._check_single_stream()
        self._check_smtp_content_and_direction()
        self._check_starttls_split_and_reconstruction()
        self._check_starttls_ordering()
        self._check_tls_negotiation()
        self._check_forward_secrecy()
        self._check_wire_certificates()
        self._check_openssl_chain_verification()
        self._check_connection_lifecycle()
        return self.comparisons

    def _artifact_rows(self) -> list[Mapping[str, Any]]:
        artifacts = self._manifest.get("artifacts")
        if not isinstance(artifacts, list):
            raise VerificationInputError("manifest artifacts section missing")
        return [entry for entry in artifacts if isinstance(entry, Mapping)]

    def _path_by_role(self, role: str) -> str | None:
        for entry in self._artifact_rows():
            if str(entry.get("role")) == role:
                return str(entry.get("path"))
        return None

    def _endpoint(self) -> Mapping[str, Any]:
        return self._section("endpoint")

    def _tshark(self, display_filter: str, fields: Sequence[str]) -> str:
        argv = build_tshark_argv(
            self._pcap_path,
            display_filter,
            fields,
            smtp_server_port=self._server_port,
        )
        result = run_bounded(argv, error_stage=f"tshark query ({display_filter})")
        if not result.ok:
            raise FixtureToolError(
                f"tshark failed rc={result.returncode}: {bound_text(result.stderr_text)}"
            )
        return result.stdout_text

    def _capinfos(self, arguments: Sequence[str]) -> str:
        argv = ["capinfos", *arguments, str(self._pcap_path)]
        result = run_bounded(argv, error_stage="capinfos query")
        if not result.ok:
            raise FixtureToolError(
                f"capinfos failed rc={result.returncode}: {bound_text(result.stderr_text)}"
            )
        return result.stdout_text

    def _check_artifact_hashes(self) -> None:
        rows = self._artifact_rows()
        problems: list[str] = []
        roles: list[str] = []
        for entry in rows:
            role = str(entry.get("role", ""))
            relative_path = str(entry.get("path", ""))
            expected_sha = str(entry.get("sha256", ""))
            expected_size = int(entry.get("size_bytes", -1))
            roles.append(role)
            artifact_path = self._resolve(relative_path)
            if not artifact_path.is_file():
                problems.append(f"{role}: missing file '{relative_path}'")
                continue
            integrity = sha256_file(artifact_path)
            if integrity.sha256_hex != expected_sha or integrity.size_bytes != expected_size:
                problems.append(
                    f"{role}: hash/size mismatch ({integrity.sha256_hex}/{integrity.size_bytes})"
                )
        self._record(
            "artifact_hashes_match_manifest",
            not problems,
            f"all {len(rows)} listed artifacts match manifest hash and size",
            "; ".join(problems) if problems else "all match",
            ", ".join(roles),
        )

    def _check_pcap_metadata(self) -> None:
        output = self._capinfos(("-t", "-c"))
        combined_lower = output.lower()
        is_pcapng = "pcapng" in combined_lower
        count = parse_packet_count(output)
        passed = is_pcapng and count is not None and count > 0
        self._record(
            "pcap_metadata_pcapng_with_packets",
            passed,
            "pcapng container with >0 packets",
            f"pcapng={is_pcapng}, packets={count}",
            bound_text(output, 200),
        )

    def _check_dumpcap_evidence_log(self) -> None:
        log_relative = self._path_by_role(CAPTURE_LOG_ARTIFACT_ROLE)
        if log_relative is None:
            self._record(
                "dumpcap_evidence_clean_capture",
                False,
                "capture log reports captured>0 and dropped==0",
                f"no artifact with role '{CAPTURE_LOG_ARTIFACT_ROLE}'",
            )
            return
        log_text = self._resolve(log_relative).read_text(encoding="utf-8", errors="replace")
        summary = parse_dumpcap_summary(log_text)
        passed = summary is not None and summary.captured > 0 and summary.dropped == 0
        actual = "unparseable or missing dumpcap summary" if summary is None else repr(summary)
        self._record(
            "dumpcap_evidence_clean_capture",
            passed,
            "capture log reports captured>0 and dropped==0",
            actual,
        )

    def _check_capture_interval(self) -> None:
        rows = parse_frame_epoch_rows(self._tshark("frame", ("frame.number", "frame.time_epoch")))
        interval = capture_interval(rows)
        capture = self._section("capture")
        manifest_first_text = str(capture.get("first_packet_epoch"))
        manifest_last_text = str(capture.get("last_packet_epoch"))
        if interval is None:
            self._state.first_packet_epoch = None
            self._record(
                "pcap_interval_matches_manifest",
                False,
                f"epochs [{manifest_first_text}, {manifest_last_text}] with canonical UTC pair",
                "PCAP contains no frame epochs",
            )
            self._record(
                "attime_epoch_matches_first_pcap_epoch",
                False,
                "attime equals int(first PCAP epoch)",
                "no PCAP first epoch available",
            )
            return
        first_text, last_text = interval
        actual_first = parse_validated_epoch(first_text)
        actual_last = parse_validated_epoch(last_text)
        if actual_first is None or actual_last is None or actual_first > actual_last:
            self._state.first_packet_epoch = None
            self._record(
                "pcap_interval_matches_manifest",
                False,
                f"epochs [{manifest_first_text}, {manifest_last_text}] with canonical UTC pair",
                f"extracted interval invalid: [{first_text}, {last_text}]",
            )
            self._record(
                "attime_epoch_matches_first_pcap_epoch",
                False,
                "attime equals int(first PCAP epoch)",
                "no valid PCAP first epoch",
            )
            return
        self._state.first_packet_epoch = first_text
        manifest_first = parse_validated_epoch(manifest_first_text)
        manifest_last = parse_validated_epoch(manifest_last_text)
        epochs_match = (
            manifest_first is not None
            and manifest_last is not None
            and actual_first == manifest_first
            and actual_last == manifest_last
        )
        derived_first_utc = decimal_epoch_to_utc_iso(actual_first)
        derived_last_utc = decimal_epoch_to_utc_iso(actual_last)
        utc_match = (
            str(capture.get("first_packet_utc")) == derived_first_utc
            and str(capture.get("last_packet_utc")) == derived_last_utc
        )
        self._record(
            "pcap_interval_matches_manifest",
            epochs_match and utc_match,
            f"exact Decimal epochs [{manifest_first_text}, {manifest_last_text}] "
            "plus matching canonical UTC fields",
            f"extracted [{first_text}, {last_text}]; utc {derived_first_utc} .. {derived_last_utc}",
        )
        chain_validation = self._section("chain_validation")
        manifest_attime = int(chain_validation.get("attime_epoch", -1))
        expected_attime = int(actual_first)
        self._record(
            "attime_epoch_matches_first_pcap_epoch",
            manifest_attime == expected_attime,
            f"attime_epoch == {expected_attime} (int of first PCAP epoch)",
            f"manifest attime_epoch={manifest_attime}",
        )

    def _check_single_stream(self) -> None:
        streams = {
            token.strip()
            for token in self._tshark("tcp", ("tcp.stream",)).splitlines()
            if token.strip()
        }
        passed = len(streams) == 1
        self._state.stream_id = next(iter(streams)) if passed else None
        self._record(
            "single_relevant_tcp_stream",
            passed,
            "exactly one TCP stream present in the controlled single-session fixture",
            f"{len(streams)} distinct stream(s): {sorted(streams)[:5]}",
        )

    def _stream_filter(self) -> str:
        if self._state.stream_id is None:
            raise VerificationInputError("no relevant TCP stream identified")
        return f"tcp.stream=={self._state.stream_id}"

    def _collect_stream_observations(self) -> None:
        payload_text = self._tshark(
            f"{self._stream_filter()} && tcp.len>0",
            ("frame.number", "ip.src", "tcp.srcport", "tcp.dstport", "tcp.payload"),
        )
        self._state.payload_frames = parse_payload_rows(payload_text)
        self._state.handshake_views = parse_handshake_rows(
            self._tshark(
                f"{self._stream_filter()} && tls.handshake.type",
                (
                    "frame.number",
                    "tls.handshake.type",
                    "tls.handshake.version",
                    "tls.handshake.ciphersuite",
                    "tls.handshake.server_named_curve",
                    "tls.handshake.extensions.supported_version",
                ),
            )
        )
        hello_positions = first_type_positions(
            self._state.handshake_views, (HANDSHAKE_TYPE_CLIENT_HELLO,)
        )
        client_hello = hello_positions.get(HANDSHAKE_TYPE_CLIENT_HELLO)
        self._state.client_hello_frame = (
            client_hello.frame_number if client_hello is not None else None
        )
        self._state.wire_certificates = parse_certificate_rows(
            self._tshark(
                f"{self._stream_filter()} && tls.handshake.type==11",
                ("frame.number", "tls.handshake.certificate"),
            )
        )

    def _directed_frames(self, direction: str) -> list[PayloadFrame]:
        classified = [
            (
                frame,
                classify_direction(
                    frame.source_ip, frame.source_port, self._server_ip, self._server_port
                ),
            )
            for frame in self._state.payload_frames
        ]
        unknown_frames = [
            frame.frame_number for frame, verdict in classified if verdict == "unknown"
        ]
        if unknown_frames:
            self._record(
                "payload_directions_determined",
                False,
                "every payload frame maps to a direction via manifest endpoint",
                f"{len(unknown_frames)} unclassifiable frame(s): {unknown_frames[:5]}",
            )
        return [
            frame
            for frame, verdict in classified
            if verdict == direction and frame.frame_number not in unknown_frames
        ]

    def _check_smtp_content_and_direction(self) -> None:
        self._collect_stream_observations()
        server_frames = self._directed_frames("server_to_client")
        client_frames = self._directed_frames("client_to_server")
        hostname = str(self._endpoint().get("hostname"))

        banner_ok = bool(server_frames) and server_frames[0].payload.startswith(b"220 ")
        banner_detail = (
            server_frames[0].payload[:80].decode("ascii", errors="replace") if server_frames else ""
        )
        banner_full_ok = banner_ok and hostname.encode() in server_frames[0].payload
        self._record(
            "smtp_banner_direction_content",
            banner_full_ok,
            f"first server payload is '220 ' banner containing {hostname}",
            f"frame {server_frames[0].frame_number}: {banner_detail}"
            if server_frames
            else "no server payload",
        )

        ehlo_seen = any(frame.payload.startswith(b"EHLO ") for frame in client_frames)
        server_buffer = b"".join(frame.payload for frame in server_frames)
        capabilities_seen = b"STARTTLS\r\n" in server_buffer.replace(b"250-", b"250 ")
        self._record(
            "smtp_ehlo_and_starttls_capability",
            ehlo_seen and capabilities_seen,
            "client EHLO request and server STARTTLS capability visible pre-TLS",
            f"ehlo={ehlo_seen}, capability={capabilities_seen}",
        )

    def _check_starttls_split_and_reconstruction(self) -> None:
        client_frames = self._directed_frames("client_to_server")
        split_writes = self._section("smtp").get("split_writes", {})
        minimum = int(split_writes.get("minimum_frames_required", 2))
        expected_command = str(split_writes.get("reconstructed_command", "")).encode("ascii")

        window = locate_command_window(client_frames, expected_command, minimum_frames=minimum)
        self._state.starttls_window = window
        if window is None:
            self._record(
                "starttls_split_across_two_frames",
                False,
                f"STARTTLS carried across >= {minimum} client payload frames",
                "command bytes not located across enough frames",
            )
            self._record(
                "starttls_reconstruction_matches_manifest",
                False,
                f"reconstructed command equals {expected_command!r}",
                "not reconstructable",
            )
            return
        frame_numbers = [frame.frame_number for frame in window.frames]
        client_buffer = b"".join(frame.payload for frame in client_frames)
        reconstructed = client_buffer[window.start_offset : window.end_offset]
        self._record(
            "starttls_split_across_two_frames",
            True,
            f"STARTTLS carried across >= {minimum} client payload frames",
            f"contributing frames: {frame_numbers}",
        )
        self._record(
            "starttls_reconstruction_matches_manifest",
            reconstructed == expected_command,
            f"reconstructed command equals {expected_command.decode('ascii', errors='replace')!r}",
            f"frames {frame_numbers} reconstruct exactly one command span",
        )

    def _check_starttls_ordering(self) -> None:
        window = self._state.starttls_window
        client_hello_frame = self._state.client_hello_frame
        if window is None or client_hello_frame is None:
            self._record(
                "starttls_before_220_before_clienthello",
                False,
                "last STARTTLS frame < 220 reply frame < ClientHello frame",
                f"window={window is not None}, client_hello={client_hello_frame}",
            )
            return
        server_frames = self._directed_frames("server_to_client")
        after_window = [
            frame for frame in server_frames if frame.frame_number > window.frames[-1].frame_number
        ]
        accept_frame = next(
            (frame.frame_number for frame in after_window if frame.payload.startswith(b"220 ")),
            None,
        )
        last_split = window.frames[-1].frame_number
        ordered = accept_frame is not None and last_split < accept_frame < client_hello_frame
        self._record(
            "starttls_before_220_before_clienthello",
            ordered,
            f"{last_split} < 220-reply frame < {client_hello_frame}",
            f"220-reply frame: {accept_frame}",
        )

    def _check_tls_negotiation(self) -> None:
        views = self._state.handshake_views
        order_ok, order_reason = handshake_order_result(views)
        self._record(
            "tls_handshake_message_order",
            order_ok,
            "ClientHello -> ServerHello -> Certificate -> ServerKeyExchange",
            order_reason,
        )
        server_hello = first_type_positions(views, (HANDSHAKE_TYPE_SERVER_HELLO,)).get(
            HANDSHAKE_TYPE_SERVER_HELLO
        )
        if server_hello is None:
            self._record(
                "negotiated_tls_version_0x0303", False, "TLS 1.2 (0x0303)", "ServerHello missing"
            )
            self._record(
                "negotiated_cipher_0xC02F",
                False,
                f"ciphersuite {EXPECTED_CIPHER_ID_INT:#06x}",
                "ServerHello missing",
            )
            return
        version_ok, version_actual = negotiated_version_result(server_hello)
        self._record(
            "negotiated_tls_version_0x0303", version_ok, "TLS 1.2 (0x0303)", version_actual
        )
        cipher_ok = EXPECTED_CIPHER_ID_INT in server_hello.cipher_suites
        suites = ", ".join(f"0x{suite:04x}" for suite in server_hello.cipher_suites) or "none"
        self._record(
            "negotiated_cipher_0xC02F",
            cipher_ok,
            f"ciphersuite {EXPECTED_CIPHER_ID_INT:#06x}",
            f"[{suites}]",
        )
        tls_section = self._section("tls")
        expected_wire = int(str(tls_section.get("wire_version", "0xFFFF")), 16)
        expected_cipher = int(str(tls_section.get("cipher_id_hex", "0xFFFF")), 16)
        consistent = (
            expected_wire == TLS_12_WIRE_VERSION_INT and expected_cipher == EXPECTED_CIPHER_ID_INT
        )
        self._record(
            "manifest_expectations_consistent",
            consistent,
            "manifest wire version/cipher agree with frozen T01 facts",
            f"wire={expected_wire:#06x}, cipher={expected_cipher:#06x}",
        )
        curve_ok, curve_actual, _group = named_curve_result(views, SECP256R1_GROUP_ID)
        self._record(
            "server_named_curve_secp256r1_group23",
            curve_ok,
            "tls.handshake.server_named_curve identifies group 23 (secp256r1)",
            curve_actual,
        )

    def _check_forward_secrecy(self) -> None:
        tls_section = self._section("tls")
        expected_fs = bool(tls_section.get("forward_secrecy_expected"))
        expected_key_exchange = str(tls_section.get("key_exchange"))
        derived, passed, detail = forward_secrecy_check(self._state.handshake_views, expected_fs)
        self._record(
            "forward_secrecy_derived_from_packets_only",
            passed,
            f"FS derived from packets; manifest expectation fs={expected_fs}, "
            f"ke={expected_key_exchange}",
            detail,
            "derivation uses only wire observations; manifest consulted afterwards for comparison",
        )

    def _wire_fingerprint(self, der: bytes) -> str:
        cert = x509.load_der_x509_certificate(der)
        return cert.fingerprint(hashes.SHA256()).hex()

    def _file_cert_fingerprint(self, role: str) -> str | None:
        relative = self._path_by_role(role)
        if relative is None:
            return None
        path = self._resolve(relative)
        if not path.is_file():
            return None
        cert = x509.load_pem_x509_certificate(path.read_bytes())
        return cert.fingerprint(hashes.SHA256()).hex()

    def _check_wire_certificates(self) -> None:
        certificate = self._section("certificate")
        ders = self._state.wire_certificates
        both_observable = len(ders) >= 2
        self._record(
            "both_wire_certificates_observable",
            both_observable,
            "at least two DER certificates observable (leaf + root)",
            f"{len(ders)} certificate(s) extracted",
        )
        expected_leaf_fp = str(certificate.get("sha256_fingerprint", ""))
        if not ders:
            self._record(
                "wire_leaf_certificate_fingerprint_matches_controlled_leaf",
                False,
                f"fingerprint {expected_leaf_fp}",
                "no DER certificate observable in the capture",
            )
            self._record(
                "wire_root_certificate_fingerprint_matches_controlled_root",
                False,
                "root fingerprint match",
                "no DER available",
            )
            self._record(
                "wire_certificate_properties_match_manifest",
                False,
                "properties match",
                "no DER available",
            )
            return
        leaf_der = ders[0]
        wire_leaf_fp = self._wire_fingerprint(leaf_der)
        self._record(
            "wire_leaf_certificate_fingerprint_matches_controlled_leaf",
            wire_leaf_fp == expected_leaf_fp,
            f"fingerprint {expected_leaf_fp}",
            f"fingerprint {wire_leaf_fp} from wire DER",
        )
        controlled_root_fp = self._file_cert_fingerprint(ROOT_CERT_ARTIFACT_ROLE)
        wire_root_fp = self._wire_fingerprint(ders[-1])
        root_known = controlled_root_fp is not None
        self._record(
            "wire_root_certificate_fingerprint_matches_controlled_root",
            root_known and wire_root_fp == controlled_root_fp,
            f"fingerprint {controlled_root_fp or 'unavailable'} from root_ca_cert artifact",
            f"fingerprint {wire_root_fp} from wire DER",
        )
        try:
            wire_facts = facts_from_certificate(x509.load_der_x509_certificate(leaf_der))
        except ValueError as exc:
            self._record(
                "wire_certificate_properties_match_manifest",
                False,
                "parsed wire certificate properties match manifest",
                f"DER parse failure: {bound_text(str(exc))}",
            )
            return
        mismatches = _compare_certificate_block(certificate, wire_facts)
        self._record(
            "wire_certificate_properties_match_manifest",
            not mismatches,
            "subject/issuer/SAN/serial/validity/key/sig match manifest",
            "; ".join(mismatches) if mismatches else "all properties match",
        )

    def _check_openssl_chain_verification(self) -> None:
        chain_validation = self._section("chain_validation")
        ca_role = str(chain_validation.get("cafile_artifact_role", ""))
        target_role = str(chain_validation.get("target_artifact_role", ""))
        cafile = self._path_by_role(ca_role)
        target = self._path_by_role(target_role)
        if cafile is None or target is None:
            self._record(
                "openssl_chain_verify_ok_at_capture_time",
                False,
                "openssl verify succeeds with CAfile at capture time",
                f"missing artifact role(s): {ca_role}/{target_role}",
            )
            return
        attime_source = self._state.first_packet_epoch
        actual_first_epoch = parse_validated_epoch(attime_source) if attime_source else None
        if actual_first_epoch is None:
            self._record(
                "openssl_chain_verify_ok_at_capture_time",
                False,
                "leaf verifies OK at the independently extracted first PCAP epoch",
                "not executable: no valid first PCAP epoch was extracted; "
                "manifest attime is never used as a fallback",
            )
            return
        attime_epoch = int(actual_first_epoch)
        result = run_bounded(
            [
                "openssl",
                "verify",
                "-CAfile",
                str(self._resolve(cafile)),
                "-attime",
                str(attime_epoch),
                "-verify_hostname",
                str(chain_validation.get("verify_hostname", "")),
                str(self._resolve(target)),
            ],
            error_stage="openssl verify",
        )
        verified = result.ok and ": OK" in result.stdout_text
        observed = result.stdout_text.strip() or bound_text(result.stderr_text)
        self._record(
            "openssl_chain_verify_ok_at_capture_time",
            verified,
            "leaf verifies OK at a captured packet epoch with hostname verification",
            f"rc={result.returncode}: {observed} (attime={attime_epoch})",
        )

    def _check_connection_lifecycle(self) -> None:
        flag_rows = parse_flag_rows(
            self._tshark(
                self._stream_filter(),
                (
                    "frame.number",
                    "ip.src",
                    "tcp.srcport",
                    "tcp.flags",
                ),
            )
        )
        lifecycle = connection_lifecycle_summary(flag_rows, self._server_port)
        self._record(
            "connection_lifecycle_syn_synack_fin_no_rst",
            lifecycle.complete_and_clean,
            "same-stream evidence: client SYN, server SYN/ACK, FIN both directions, zero RST",
            f"syn_c={lifecycle.client_syn}, synack_s={lifecycle.server_syn_ack}, "
            f"resets={lifecycle.reset_count}, fin_c={lifecycle.fin_from_client}, "
            f"fin_s={lifecycle.fin_from_server}",
        )


def _compare_certificate_block(block: Mapping[str, Any], facts: CertificateFacts) -> list[str]:
    mismatches: list[str] = []
    expected_map = {
        "subject": facts.subject_rfc4514,
        "issuer": facts.issuer_rfc4514,
        "serial_hex": facts.serial_hex,
        "not_before_utc": facts.not_before_utc,
        "not_after_utc": facts.not_after_utc,
        "public_key_algorithm": facts.public_key_algorithm,
        "signature_algorithm": facts.signature_algorithm_name,
        "sha256_fingerprint": facts.sha256_fingerprint_hex,
    }
    for key, actual_value in expected_map.items():
        expected_value = block.get(key)
        if str(expected_value) != str(actual_value):
            mismatches.append(f"{key}: manifest={expected_value} wire={actual_value}")
    san_expected = block.get("san_dns_names")
    if list(san_expected or []) != list(facts.san_dns_names):
        mismatches.append(
            f"san_dns_names: manifest={san_expected} wire={list(facts.san_dns_names)}"
        )
    bits_expected = block.get("public_key_bits")
    if bits_expected != facts.public_key_bits:
        mismatches.append(f"public_key_bits: manifest={bits_expected} wire={facts.public_key_bits}")
    return mismatches


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog=VERIFIER_NAME,
        description="Independently verify the T01 fixture against its ground-truth manifest.",
    )
    parser.add_argument(
        "manifest",
        nargs="?",
        default=str(REPO_ROOT / DEFAULT_MANIFEST_PATH),
        help="path to t01_ground_truth.json",
    )
    parser.add_argument(
        "--evidence-out",
        default=None,
        help="bounded evidence JSON path (default fixtures/evidence/t01_manual_evidence.json)",
    )
    args = parser.parse_args(argv)

    try:
        verifier = ManualVerifier(Path(args.manifest))
        comparisons = verifier.run()
    except VerificationInputError as exc:
        print(f"INPUT ERROR: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except ManifestValidationError as exc:
        print(f"MANIFEST INVALID: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except FixtureToolError as exc:
        print(f"TOOL FAILURE: {exc}", file=sys.stderr)
        return EXIT_TOOL_FAILURE

    failed = [comparison for comparison in comparisons if not comparison.passed]
    for comparison in comparisons:
        marker = "PASS" if comparison.passed else "FAIL"
        print(f"[{marker}] {comparison.identifier}")
        print(f"        expected: {comparison.expected}")
        print(f"        actual:   {comparison.actual}")

    evidence_out = (
        Path(args.evidence_out) if args.evidence_out else REPO_ROOT / EVIDENCE_RELATIVE_PATH
    )
    manifest_digest = sha256_file(Path(args.manifest))
    write_json_file(
        evidence_out,
        {
            "tool": VERIFIER_NAME,
            "version": VERIFIER_VERSION,
            "checked_at_utc": iso_utc(utc_now()),
            "manifest_path": str(Path(args.manifest)),
            "manifest_sha256": manifest_digest.sha256_hex,
            "comparisons": [
                {
                    "id": comparison.identifier,
                    "status": "pass" if comparison.passed else "fail",
                    "expected": comparison.expected,
                    "actual": comparison.actual,
                    "detail": comparison.detail,
                }
                for comparison in comparisons
            ],
            "summary": {
                "total": len(comparisons),
                "passed": len(comparisons) - len(failed),
                "failed": len(failed),
            },
        },
    )
    print(f"evidence: {evidence_out}")

    if failed:
        print(f"T01 MANUAL VERIFICATION FAILED ({len(failed)} comparison(s)); see evidence above.")
        return EXIT_COMPARISONS_FAILED
    print(f"T01 MANUAL VERIFICATION PASSED ({len(comparisons)} comparisons).")
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
