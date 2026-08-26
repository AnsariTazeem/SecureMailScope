"""Controlled loopback SMTP STARTTLS endpoint for the T01 fixture.

A minimal single-connection SMTP server (banner, EHLO, STARTTLS capability,
STARTTLS acceptance, TLS 1.2 upgrade, post-TLS EHLO, QUIT) and a matching
client that deliberately sends `STARTTLS\\r\\n` across two separate writes.
Both sides record bounded JSONL events; no credentials, addresses, or message
bodies are ever transmitted or logged.
"""

from __future__ import annotations

import socket
import ssl
import threading
import time
from dataclasses import dataclass
from json import dumps
from pathlib import Path

from _fixture_common import DETAIL_TEXT_LIMIT, FixtureError, bound_text, iso_utc, utc_now
from t01_pki import FIXTURE_HOSTNAME

BIND_IP = "127.0.0.1"
SERVER_PORT = 2525
EHLO_CLIENT_NAME = "client.securemailscope.test"

CIPHER_OPENSSL_NAME = "ECDHE-RSA-AES128-GCM-SHA256"
CIPHER_IANA_NAME = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
CIPHER_ID_HEX = "0xC02F"
TLS_VERSION_LABEL = "TLS 1.2"
TLS_WIRE_VERSION_HEX = "0x0303"
EC_GROUP_OPENSSL_NAME = "prime256v1"
EC_GROUP_NAME = "secp256r1"
EC_GROUP_ID = 23

STARTTLS_WRITE_PARTS = ("START", "TLS\r\n")
INTER_WRITE_DELAY_SECONDS = 0.08
SOCKET_TIMEOUT_SECONDS = 10.0
MAX_LOG_EVENTS = 400

BANNER_LINE = f"220 {FIXTURE_HOSTNAME} ESMTP SecureMailScope controlled fixture ready"
CAPABILITIES_REPLY = f"250-{FIXTURE_HOSTNAME}\r\n250-SIZE 10240000\r\n250 STARTTLS\r\n"
POST_TLS_CAPABILITIES_REPLY = f"250-{FIXTURE_HOSTNAME}\r\n250 OK\r\n"
STARTTLS_ACCEPT_LINE = "220 Ready to start TLS"
BYE_LINE = "221 Bye"
NOT_IMPLEMENTED_LINE = "502 Command not implemented"


class SmtpSessionError(FixtureError):
    """The controlled SMTP/TLS session could not be completed as configured."""


@dataclass(frozen=True)
class SessionFacts:
    """Negotiation facts observed directly on the client TLS socket."""

    tls_protocol_version: str
    cipher_openssl_name: str
    cipher_bits: int
    peer_san_dns_names: tuple[str, ...]


class EndpointEventLog:
    """Bounded in-memory event log serialized to JSONL."""

    def __init__(self, max_events: int = MAX_LOG_EVENTS) -> None:
        self._max_events = max_events
        self._events: list[dict[str, object]] = []
        self._lock = threading.Lock()

    def add(self, actor: str, event: str, **details: str) -> None:
        with self._lock:
            if len(self._events) >= self._max_events:
                raise SmtpSessionError("endpoint event log overflowed its bounded size")
            bounded = {key: bound_text(value, DETAIL_TEXT_LIMIT) for key, value in details.items()}
            self._events.append(
                {
                    "seq": len(self._events) + 1,
                    "ts_utc": iso_utc(utc_now()),
                    "actor": actor,
                    "event": event,
                    "details": bounded,
                }
            )

    def to_jsonl(self) -> str:
        lines = [json_line(event) for event in self._events]
        return "".join(line + "\n" for line in lines)

    def __len__(self) -> int:
        return len(self._events)


def json_line(event: dict[str, object]) -> str:
    return dumps(event, separators=(",", ":"), ensure_ascii=True)


class ControlledSmtpServer:
    """Single-connection SMTP server that upgrades exactly once via STARTTLS."""

    def __init__(self, chain_path: Path, key_path: Path, log: EndpointEventLog) -> None:
        self._chain_path = chain_path
        self._key_path = key_path
        self._log = log
        self._listener: socket.socket | None = None
        self._conn: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self.error: Exception | None = None

    def start(self) -> None:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((BIND_IP, SERVER_PORT))
        listener.listen(1)
        listener.settimeout(SOCKET_TIMEOUT_SECONDS)
        self._listener = listener
        self._thread = threading.Thread(target=self._serve, name="t01-smtp-server", daemon=True)
        self._thread.start()

    def join(self, timeout: float) -> None:
        if self._thread is not None:
            self._thread.join(timeout=timeout)

    def stop(self) -> None:
        self._close_listener()
        self.join(timeout=SOCKET_TIMEOUT_SECONDS * 2)

    def abort(self) -> None:
        self._close_listener()
        conn = self._conn
        if conn is not None:
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        self.join(timeout=2.0)

    def _close_listener(self) -> None:
        listener = self._listener
        self._listener = None
        if listener is not None:
            try:
                listener.close()
            except OSError:
                pass

    def _serve(self) -> None:
        try:
            self._serve_once()
        except Exception as exc:  # noqa: BLE001 - surfaced through `.error`
            self.error = exc
            self._log.add("server", "session_error", detail=bound_text(str(exc)))
            conn = self._conn
            if conn is not None:
                try:
                    conn.close()
                except OSError:
                    pass
        finally:
            self._close_listener()

    def _serve_once(self) -> None:
        assert self._listener is not None
        conn, addr = self._listener.accept()
        self._conn = conn
        conn.settimeout(SOCKET_TIMEOUT_SECONDS)
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self._log.add("server", "connection_accepted", peer=f"{addr[0]}:{addr[1]}")
        _send_line(conn, BANNER_LINE)
        self._log.add("server", "banner_sent", line=BANNER_LINE)

        upgraded = False
        while True:
            line = _read_line(conn)
            if not line:
                raise SmtpSessionError("server observed EOF before a clean QUIT exchange")
            command = line.strip()
            upper = command.upper()
            if upper.startswith("EHLO"):
                reply = POST_TLS_CAPABILITIES_REPLY if upgraded else CAPABILITIES_REPLY
                _send_line(conn, reply)
                self._log.add("server", "ehlo_answered", phase=_phase(upgraded), line=command)
            elif upper == "STARTTLS" and not upgraded:
                _send_line(conn, STARTTLS_ACCEPT_LINE)
                self._log.add("server", "starttls_accepted", line=command)
                tls_conn = self._server_context().wrap_socket(conn, server_side=True)
                self._conn = tls_conn
                self._record_negotiation(tls_conn)
                conn = tls_conn
                upgraded = True
            elif upper.startswith("QUIT"):
                _send_line(conn, BYE_LINE)
                self._log.add("server", "bye_sent", line=command)
                break
            else:
                _send_line(conn, NOT_IMPLEMENTED_LINE)
                self._log.add("server", "unrecognized_command", line=command)
        if not upgraded:
            raise SmtpSessionError("connection closed before the STARTTLS upgrade")
        _clean_close(conn)
        self._log.add("server", "connection_closed_clean")

    def _server_context(self) -> ssl.SSLContext:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.maximum_version = ssl.TLSVersion.TLSv1_2
        context.set_ciphers(CIPHER_OPENSSL_NAME)
        context.set_ecdh_curve(EC_GROUP_OPENSSL_NAME)
        context.load_cert_chain(certfile=str(self._chain_path), keyfile=str(self._key_path))
        return context

    def _record_negotiation(self, tls_conn: ssl.SSLSocket) -> None:
        cipher = tls_conn.cipher()
        self._log.add(
            "server",
            "tls_negotiated",
            version=tls_conn.version() or "unknown",
            cipher=cipher[0] if cipher else "unknown",
            cipher_bits=str(cipher[2]) if cipher else "0",
        )


class ControlledStarttlsClient:
    """Client that splits STARTTLS across writes and enforces TLS 1.2 ECDHE."""

    def __init__(self, root_cert_path: Path, log: EndpointEventLog) -> None:
        self._root_cert_path = root_cert_path
        self._log = log

    def run(self) -> SessionFacts:
        raw = socket.create_connection((BIND_IP, SERVER_PORT), timeout=SOCKET_TIMEOUT_SECONDS)
        try:
            return self._run_over(raw)
        finally:
            try:
                raw.close()
            except OSError:
                pass

    def _run_over(self, raw: socket.socket) -> SessionFacts:
        raw.settimeout(SOCKET_TIMEOUT_SECONDS)
        raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self._log.add("client", "connection_opened", peer=f"{BIND_IP}:{SERVER_PORT}")

        banner = _read_line(raw)
        if not banner.startswith("220 "):
            raise SmtpSessionError(f"unexpected SMTP banner: {bound_text(banner)}")
        self._log.add("client", "banner_received", line=banner.strip())

        _send_line(raw, f"EHLO {EHLO_CLIENT_NAME}")
        self._log.add("client", "ehlo_sent", line=f"EHLO {EHLO_CLIENT_NAME}")
        capabilities = _read_reply_block(raw)
        self._log.add("client", "capabilities_received", lines=" / ".join(capabilities))
        if not any(_capability_name(line) == "STARTTLS" for line in capabilities):
            raise SmtpSessionError("server capabilities did not advertise STARTTLS")

        part_one, part_two = STARTTLS_WRITE_PARTS
        raw.sendall(part_one.encode(encoding="ascii"))
        self._log.add("client", "starttls_write_part", index="1", payload=part_one.rstrip("\r\n"))
        time.sleep(INTER_WRITE_DELAY_SECONDS)
        raw.sendall(part_two.encode(encoding="ascii"))
        self._log.add("client", "starttls_write_part", index="2", payload=part_two.rstrip("\r\n"))

        accept = _read_line(raw)
        if not accept.startswith("220 "):
            raise SmtpSessionError(f"STARTTLS was not accepted: {bound_text(accept)}")
        self._log.add("client", "starttls_accept_received", line=accept.strip())

        tls_conn = self._client_context().wrap_socket(raw, server_hostname=FIXTURE_HOSTNAME)
        try:
            facts = self._facts_from(tls_conn)
            self._log.add(
                "client",
                "tls_negotiated",
                version=facts.tls_protocol_version,
                cipher=facts.cipher_openssl_name,
                cipher_bits=str(facts.cipher_bits),
                peer_san=", ".join(facts.peer_san_dns_names),
            )
            _send_line(tls_conn, f"EHLO {EHLO_CLIENT_NAME}")
            self._log.add("client", "ehlo_post_tls_sent", line=f"EHLO {EHLO_CLIENT_NAME}")
            post_tls = _read_reply_block(tls_conn)
            self._log.add("client", "ehlo_post_tls_received", lines=" / ".join(post_tls))
            _send_line(tls_conn, "QUIT")
            self._log.add("client", "quit_sent")
            bye = _read_line(tls_conn)
            if not bye.startswith("221"):
                raise SmtpSessionError(f"unexpected reply to QUIT: {bound_text(bye)}")
            self._log.add("client", "bye_received", line=bye.strip())
            _clean_close(tls_conn)
            self._log.add("client", "connection_closed_clean")
            return facts
        except BaseException:
            try:
                tls_conn.close()
            except OSError:
                pass
            raise

    def _client_context(self) -> ssl.SSLContext:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.maximum_version = ssl.TLSVersion.TLSv1_2
        context.set_ciphers(CIPHER_OPENSSL_NAME)
        context.set_ecdh_curve(EC_GROUP_OPENSSL_NAME)
        context.load_verify_locations(cafile=str(self._root_cert_path))
        return context

    def _facts_from(self, tls_conn: ssl.SSLSocket) -> SessionFacts:
        cipher = tls_conn.cipher()
        if cipher is None or tls_conn.version() is None:
            raise SmtpSessionError("TLS negotiation produced no version/cipher information")
        peer_cert = tls_conn.getpeercert()
        if not isinstance(peer_cert, dict):
            raise SmtpSessionError("peer certificate was not returned for verification")
        san_names = dns_names_from_peercert(peer_cert)
        if FIXTURE_HOSTNAME not in san_names:
            raise SmtpSessionError("peer certificate did not carry the controlled SAN")
        return SessionFacts(
            tls_protocol_version=tls_conn.version() or "unknown",
            cipher_openssl_name=cipher[0],
            cipher_bits=int(cipher[2]),
            peer_san_dns_names=san_names,
        )


def dns_names_from_peercert(peer_cert: dict[str, object]) -> tuple[str, ...]:
    """Extract DNS SAN names; getpeercert() labels entries 'DNS', not 'DNSName'."""
    entries = peer_cert.get("subjectAltName", ())
    if not isinstance(entries, tuple):
        return ()
    names: list[str] = []
    for entry in entries:
        if not isinstance(entry, tuple) or len(entry) != 2:
            continue
        kind, value = entry
        if kind == "DNS":
            names.append(str(value))
    return tuple(names)


EXPECTED_TLS_PROTOCOL_VERSION = "TLSv1.2"
EXPECTED_CIPHER_BITS = 128


def validate_negotiated_facts(facts: SessionFacts) -> None:
    """Abort unless actual endpoint negotiation matches the frozen T01 contract."""
    if facts.tls_protocol_version != EXPECTED_TLS_PROTOCOL_VERSION:
        raise SmtpSessionError(
            f"negotiated TLS version {facts.tls_protocol_version!r} != "
            f"{EXPECTED_TLS_PROTOCOL_VERSION!r}"
        )
    if facts.cipher_openssl_name != CIPHER_OPENSSL_NAME:
        raise SmtpSessionError(
            f"negotiated cipher {facts.cipher_openssl_name!r} != {CIPHER_OPENSSL_NAME!r}"
        )
    if facts.cipher_bits != EXPECTED_CIPHER_BITS:
        raise SmtpSessionError(
            f"effective cipher bits {facts.cipher_bits} != {EXPECTED_CIPHER_BITS}"
        )
    if FIXTURE_HOSTNAME not in facts.peer_san_dns_names:
        raise SmtpSessionError(
            f"peer SAN {list(facts.peer_san_dns_names)} does not contain {FIXTURE_HOSTNAME!r}"
        )


def run_controlled_session(
    root_cert_path: Path,
    chain_path: Path,
    leaf_key_path: Path,
    *,
    log: EndpointEventLog | None = None,
) -> tuple[SessionFacts, EndpointEventLog]:
    """Run one full controlled session and return negotiated facts plus log."""
    log = log if log is not None else EndpointEventLog()
    server = ControlledSmtpServer(chain_path, leaf_key_path, log)
    server.start()
    client_error: BaseException | None = None
    facts: SessionFacts | None = None
    try:
        facts = ControlledStarttlsClient(root_cert_path, log).run()
    except BaseException as exc:  # noqa: BLE001 - combined into SmtpSessionError below
        client_error = exc
    finally:
        server.stop()
    if client_error is not None or server.error is not None:
        parts = []
        if client_error is not None:
            parts.append(f"client: {bound_text(str(client_error))}")
        if server.error is not None:
            parts.append(f"server: {bound_text(str(server.error))}")
        raise SmtpSessionError("; ".join(parts)) from client_error or server.error
    assert facts is not None
    return facts, log


def _phase(upgraded: bool) -> str:
    return "post_tls" if upgraded else "plaintext"


def _send_line(sock: socket.socket, line: str) -> None:
    sock.sendall((line.rstrip("\r\n") + "\r\n").encode(encoding="ascii"))


def _read_line(sock: socket.socket, limit: int = 1024) -> str:
    buffer = bytearray()
    while len(buffer) < limit:
        chunk = sock.recv(1)
        if not chunk:
            break
        buffer += chunk
        if buffer.endswith(b"\r\n"):
            break
    return bytes(buffer).decode(encoding="ascii", errors="replace").rstrip("\r\n")


def _read_reply_block(sock: socket.socket, limit_lines: int = 64) -> list[str]:
    lines: list[str] = []
    while len(lines) < limit_lines:
        line = _read_line(sock)
        if not line:
            break
        lines.append(line)
        if len(line) >= 4 and line[3] == " ":
            break
    return lines


def _capability_name(reply_line: str) -> str:
    if len(reply_line) >= 4 and reply_line[:3] == "250":
        return reply_line[4:].strip().split(" ")[0]
    return ""


def _clean_close(tls_conn: ssl.SSLSocket) -> None:
    try:
        plain = tls_conn.unwrap()
        try:
            plain.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        plain.close()
    except OSError as exc:
        raise SmtpSessionError(f"clean TLS close failed: {bound_text(str(exc))}") from exc
