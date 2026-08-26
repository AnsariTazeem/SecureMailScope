"""Controlled disposable PKI for the T01 SMTP STARTTLS fixture.

Generates an RSA-2048 controlled root CA and an RSA-2048 SMTP leaf certificate
for `mail.securemailscope.test` using SHA-256 signatures. Private keys are
written only under `fixtures/pki/private/` with mode 0600 inside a 0700
directory; key material is never returned, logged, hashed, or printed.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import cryptography
from _fixture_common import FixtureError, iso_utc, parse_utc_iso
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, SignatureAlgorithmOID

FIXTURE_HOSTNAME = "mail.securemailscope.test"
KEY_BITS = 2048
PUBLIC_EXPONENT = 65537
NOT_BEFORE_BACKDATE = timedelta(days=1)
VALIDITY_DAYS = timedelta(days=365)

ROOT_CERT_FILENAME = "root-ca.pem"
LEAF_CERT_FILENAME = "smtp-server-cert.pem"
CHAIN_FILENAME = "server-chain.pem"
PRIVATE_DIRNAME = "private"
ROOT_KEY_FILENAME = "root-ca.key"
LEAF_KEY_FILENAME = "smtp-server.key"

SIGNATURE_ALGORITHM_NAMES = {
    SignatureAlgorithmOID.RSA_WITH_SHA256: "sha256WithRSAEncryption",
    SignatureAlgorithmOID.RSA_WITH_SHA384: "sha384WithRSAEncryption",
    SignatureAlgorithmOID.RSA_WITH_SHA512: "sha512WithRSAEncryption",
    SignatureAlgorithmOID.RSA_WITH_SHA1: "sha1WithRSAEncryption",
    SignatureAlgorithmOID.ECDSA_WITH_SHA256: "ecdsa-with-SHA256",
}


class PkiError(FixtureError):
    """The controlled PKI could not be generated or inspected."""


@dataclass(frozen=True)
class CertificateFacts:
    """Inspected public facts of one controlled certificate."""

    subject_rfc4514: str
    issuer_rfc4514: str
    san_dns_names: tuple[str, ...]
    serial_hex: str
    not_before_utc: str
    not_after_utc: str
    public_key_algorithm: str
    public_key_bits: int
    signature_algorithm_name: str
    sha256_fingerprint_hex: str


@dataclass(frozen=True)
class GeneratedPki:
    """Paths and inspected public facts of one generated PKI set."""

    root_cert_path: Path
    leaf_cert_path: Path
    chain_path: Path
    root_key_path: Path
    leaf_key_path: Path
    root_facts: CertificateFacts
    leaf_facts: CertificateFacts


def _name(organization_unit: str, common_name: str) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureMailScope POC"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, organization_unit),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )


ROOT_SUBJECT = _name("Controlled PKI", "SecureMailScope Controlled Root CA")
LEAF_SUBJECT = _name("Controlled SMTP Endpoint", FIXTURE_HOSTNAME)


def generate_pki(pki_dir: Path, *, now: datetime) -> GeneratedPki:
    """Generate root CA, leaf certificate, chain file, and restricted keys."""
    now = now.astimezone(UTC)
    private_dir = pki_dir / PRIVATE_DIRNAME
    private_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(private_dir, stat.S_IRWXU)

    root_key_path = private_dir / ROOT_KEY_FILENAME
    leaf_key_path = private_dir / LEAF_KEY_FILENAME
    root_cert_path = pki_dir / ROOT_CERT_FILENAME
    leaf_cert_path = pki_dir / LEAF_CERT_FILENAME
    chain_path = pki_dir / CHAIN_FILENAME

    not_before = now - NOT_BEFORE_BACKDATE
    not_after = now + VALIDITY_DAYS

    root_key = rsa.generate_private_key(public_exponent=PUBLIC_EXPONENT, key_size=KEY_BITS)
    root_cert = (
        x509.CertificateBuilder()
        .subject_name(ROOT_SUBJECT)
        .issuer_name(ROOT_SUBJECT)
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()), critical=False
        )
        .sign(root_key, hashes.SHA256())
    )

    leaf_key = rsa.generate_private_key(public_exponent=PUBLIC_EXPONENT, key_size=KEY_BITS)
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(LEAF_SUBJECT)
        .issuer_name(root_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(FIXTURE_HOSTNAME)]), critical=False
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()),
            critical=False,
        )
        .sign(root_key, hashes.SHA256())
    )

    root_pem = root_cert.public_bytes(serialization.Encoding.PEM)
    leaf_pem = leaf_cert.public_bytes(serialization.Encoding.PEM)
    root_key_pem = _key_pem(root_key)
    leaf_key_pem = _key_pem(leaf_key)

    _write_restricted(root_key_path, root_key_pem)
    _write_restricted(leaf_key_path, leaf_key_pem)
    _write_public(root_cert_path, root_pem)
    _write_public(leaf_cert_path, leaf_pem)
    _write_public(chain_path, leaf_pem + root_pem)

    return GeneratedPki(
        root_cert_path=root_cert_path,
        leaf_cert_path=leaf_cert_path,
        chain_path=chain_path,
        root_key_path=root_key_path,
        leaf_key_path=leaf_key_path,
        root_facts=inspect_certificate(root_cert_path),
        leaf_facts=inspect_certificate(leaf_cert_path),
    )


def inspect_certificate(cert_path: Path) -> CertificateFacts:
    """Parse public certificate facts from a PEM file on disk."""
    try:
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    except (OSError, ValueError) as exc:
        raise PkiError(f"could not parse certificate '{cert_path}': {exc}") from exc
    return facts_from_certificate(cert)


def facts_from_certificate(cert: x509.Certificate) -> CertificateFacts:
    san_names: tuple[str, ...] = ()
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        san_names = tuple(san.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        san_names = ()
    public_key = cert.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        algorithm, bits = "RSA", public_key.key_size
    else:
        algorithm, bits = type(public_key).__name__, 0
    return CertificateFacts(
        subject_rfc4514=cert.subject.rfc4514_string(),
        issuer_rfc4514=cert.issuer.rfc4514_string(),
        san_dns_names=san_names,
        serial_hex=f"0x{cert.serial_number:X}",
        not_before_utc=iso_utc(cert.not_valid_before_utc),
        not_after_utc=iso_utc(cert.not_valid_after_utc),
        public_key_algorithm=algorithm,
        public_key_bits=bits,
        signature_algorithm_name=_signature_name(cert),
        sha256_fingerprint_hex=cert.fingerprint(hashes.SHA256()).hex(),
    )


def certificate_valid_at(cert_path: Path, moment: datetime) -> bool:
    """Return whether the certificate validity window contains `moment`."""
    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    moment = moment.astimezone(UTC)
    return cert.not_valid_before_utc <= moment <= cert.not_valid_after_utc


def load_crypto_version() -> str:
    return cryptography.__version__


def validity_window(cert_path: Path) -> tuple[str, str]:
    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    return iso_utc(cert.not_valid_before_utc), iso_utc(cert.not_valid_after_utc)


def parsed_validity_window_iso(facts: CertificateFacts) -> tuple[datetime, datetime]:
    return parse_utc_iso(facts.not_before_utc), parse_utc_iso(facts.not_after_utc)


def _key_pem(key: rsa.RSAPrivateKey) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _write_restricted(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
    os.chmod(path, 0o600)


def _write_public(path: Path, data: bytes) -> None:
    path.write_bytes(data)
    os.chmod(path, 0o644)


def _signature_name(cert: x509.Certificate) -> str:
    oid = cert.signature_algorithm_oid
    return SIGNATURE_ALGORITHM_NAMES.get(oid, oid.dotted_string)
