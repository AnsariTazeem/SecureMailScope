"""Backend V2 analysis identity and fingerprint contracts.

These contracts distinguish one submitted execution request from capture
content and deterministic analysis inputs.  They intentionally contain no
filenames, storage paths, request IDs, timestamps, or raw capture bytes.
"""

from __future__ import annotations

import hashlib
import re
import secrets
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from securemailscope.chain.canonical import canonical_json
from securemailscope.chain.ids import SEMVER_PATTERN, SHA256_DIGEST_PATTERN, is_semver

ANALYSIS_FINGERPRINT_SCHEMA_VERSION = "1.0.0"
JOB_ID_PATTERN = r"^job_[0-9a-f]{32}$"
CANONICAL_ID_PATTERN = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}", flags=re.ASCII)
ANALYZER_VERSION_PATTERN = re.compile(r"[a-z0-9][a-z0-9._/-]{0,127}", flags=re.ASCII)
PACKET_TOOL_VERSION_PATTERN = re.compile(r"[\x20-\x7e]{1,256}", flags=re.ASCII)

Sha256Digest = Annotated[str, Field(pattern=SHA256_DIGEST_PATTERN)]
SemanticVersion = Annotated[str, Field(pattern=SEMVER_PATTERN)]
BoundedIdentity = Annotated[str, Field(min_length=1, max_length=128)]
BoundedPacketToolVersion = Annotated[str, Field(min_length=1, max_length=256)]


def _require_canonical_id(value: str) -> str:
    """Require an exact lowercase ASCII identity without normalizing input."""
    if CANONICAL_ID_PATTERN.fullmatch(value) is None:
        raise ValueError(
            "identity must contain only lowercase ASCII letters, digits, dot, "
            "underscore, and hyphen"
        )
    return value


def _require_analyzer_version(value: str) -> str:
    """Require a bounded lowercase ASCII analyzer version; slash is allowed."""
    if ANALYZER_VERSION_PATTERN.fullmatch(value) is None:
        raise ValueError(
            "analyzer version must contain only lowercase ASCII letters, digits, "
            "dot, underscore, hyphen, and slash"
        )
    return value


def _require_packet_tool_version(value: str, *, tool_name: str) -> str:
    """Require semver or the exact bounded printable-ASCII tool banner shape."""
    if value != value.strip() or PACKET_TOOL_VERSION_PATTERN.fullmatch(value) is None:
        raise ValueError(
            "packet-tool version must be exact printable ASCII without surrounding whitespace"
        )
    banner_pattern = rf"{re.escape(tool_name)}(?: \(Wireshark\))? \d+\.\d+\.\d+(?: .+)?"
    if not is_semver(value) and re.fullmatch(banner_pattern, value, flags=re.ASCII) is None:
        raise ValueError(
            f"packet-tool version must be semantic version or an exact {tool_name} version banner"
        )
    return value


class ProtocolPluginIdentity(BaseModel):
    """Identity of trusted protocol-plugin code that can affect analysis output."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    plugin_id: BoundedIdentity
    plugin_version: SemanticVersion

    @field_validator("plugin_id")
    @classmethod
    def _validate_plugin_id(cls, value: str) -> str:
        return _require_canonical_id(value)


class PacketToolchainIdentity(BaseModel):
    """Exact packet-tool versions whose output can affect analysis results."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    tshark_version: BoundedPacketToolVersion
    capinfos_version: BoundedPacketToolVersion

    @field_validator("tshark_version")
    @classmethod
    def _validate_tshark_version(cls, value: str) -> str:
        return _require_packet_tool_version(value, tool_name="TShark")

    @field_validator("capinfos_version")
    @classmethod
    def _validate_capinfos_version(cls, value: str) -> str:
        return _require_packet_tool_version(value, tool_name="Capinfos")


class MlExecutionIdentity(BaseModel):
    """Exact feature-schema, model, and inference-runtime identity for executed ML."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    feature_schema_id: BoundedIdentity
    feature_schema_version: SemanticVersion
    feature_schema_digest: Sha256Digest
    model_id: BoundedIdentity
    model_version: SemanticVersion
    model_digest: Sha256Digest
    inference_runtime_id: BoundedIdentity
    inference_runtime_version: SemanticVersion

    @field_validator("feature_schema_id", "model_id", "inference_runtime_id")
    @classmethod
    def _validate_identity(cls, value: str) -> str:
        return _require_canonical_id(value)


class AnalysisFingerprintInput(BaseModel):
    """Complete, versioned set of deterministic output-affecting inputs.

    Protocol plugins are normalized by ``plugin_id`` and version so caller
    ordering cannot affect the canonical payload.  Duplicate plugin IDs are
    rejected even when their versions differ because one execution cannot
    unambiguously select two implementations of the same plugin.

    ``ml_identity=None`` means ML did not execute.  When it did execute, the
    feature schema, model, and inference-runtime identities are mandatory.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    fingerprint_schema_version: Literal[ANALYSIS_FINGERPRINT_SCHEMA_VERSION]
    capture_sha256: Sha256Digest
    analyzer_version: BoundedIdentity
    chain_schema_version: SemanticVersion
    packet_toolchain: PacketToolchainIdentity
    analysis_configuration_digest: Sha256Digest
    policy_pack_id: BoundedIdentity
    policy_pack_digest: Sha256Digest
    profile_id: BoundedIdentity
    protocol_plugins: tuple[ProtocolPluginIdentity, ...] = Field(min_length=1, max_length=32)
    ml_identity: MlExecutionIdentity | None

    @field_validator("analyzer_version")
    @classmethod
    def _validate_analyzer_version(cls, value: str) -> str:
        return _require_analyzer_version(value)

    @field_validator("policy_pack_id", "profile_id")
    @classmethod
    def _validate_identifiers(cls, value: str) -> str:
        return _require_canonical_id(value)

    @field_validator("protocol_plugins")
    @classmethod
    def _sort_and_validate_plugins(
        cls, plugins: tuple[ProtocolPluginIdentity, ...]
    ) -> tuple[ProtocolPluginIdentity, ...]:
        plugin_ids = [plugin.plugin_id for plugin in plugins]
        if len(set(plugin_ids)) != len(plugin_ids):
            raise ValueError("duplicate protocol plugin IDs are not allowed")
        return tuple(
            sorted(
                plugins,
                key=lambda plugin: (plugin.plugin_id, plugin.plugin_version),
            )
        )


def new_job_id() -> str:
    """Return a public-safe opaque 128-bit identifier for one submitted job."""
    return f"job_{secrets.token_hex(16)}"


def is_job_id(value: object) -> bool:
    """Return whether *value* has the public Backend V2 job-ID shape."""
    return isinstance(value, str) and re.fullmatch(JOB_ID_PATTERN, value) is not None


def canonical_analysis_fingerprint_bytes(inputs: AnalysisFingerprintInput) -> bytes:
    """Return the complete fingerprint input as deterministic UTF-8 JSON bytes."""
    if not isinstance(inputs, AnalysisFingerprintInput):
        raise TypeError("inputs must be an AnalysisFingerprintInput")
    # ``model_copy(update=...)`` does not validate updates.  Rebuild the entire
    # nested contract at this trust boundary so a copied invalid model can
    # never reach canonical serialization or fingerprinting.
    validated = AnalysisFingerprintInput.model_validate(inputs.model_dump(mode="python"))
    # ML identity is an input only when ML actually executed.  Absence is
    # represented by omission rather than a fabricated placeholder identity.
    payload = validated.model_dump(mode="json", exclude_none=True)
    return canonical_json(payload).encode("utf-8")


def compute_analysis_fingerprint(inputs: AnalysisFingerprintInput) -> str:
    """Return raw lowercase-hex SHA-256 over canonical, versioned input bytes."""
    return hashlib.sha256(canonical_analysis_fingerprint_bytes(inputs)).hexdigest()
