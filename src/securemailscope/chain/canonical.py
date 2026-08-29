"""Canonical JSON serialization and reproducible content hashing.

Two distinct concepts are kept separate:

* **Canonical JSON** (:func:`canonical_json`) is the deterministic text form
  used for the canonical chain document. Keys are sorted, separators are fixed,
  non-ASCII characters are preserved, and NaN/infinity are rejected.
* **Canonical content** (:func:`extract_canonical_content`) is the chain copy
  that can actually be reproduced: it excludes the execution envelope and all
  volatile presentation timestamps, and it removes the ``artifacts`` node so an
  artifact's content hash never depends on itself.

The reproducibility rules are exactly the ones from spec §16 and the frozen
POC requirements: volatile clock timestamps (analysis created/started/completed,
rule ``evaluated_at``, finding ``created_at``, artifact ``generated_at``) are
excluded from the content hash, while capture/session/packet/protocol-event
timestamps are evidence and are kept.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from decimal import Decimal
from enum import Enum
from numbers import Real

from securemailscope.chain.errors import ChainError, ChainErrorCode

_CONTENT_NAMESPACE = "securemailscope.chain.canonical"
_CONTENT_VERSION = "1.0.0"

#: Dotted paths of volatile, presentation-only fields excluded from the
#: reproducible canonical content. ``*`` means "every element of the list".
VOLATILE_EXCLUDED_PATHS: tuple[tuple[str | None | str, ...], ...] = (
    ("analysis", "created_at"),
    ("analysis", "started_at"),
    ("analysis", "completed_at"),
    ("execution",),
    ("rule_evaluations", "*", "evaluated_at"),
    ("findings", "*", "created_at"),
    ("artifacts", "*", "generated_at"),
)

_WILD = "*"


def decimal_canonical_str(value: Decimal) -> str:
    """Deterministic decimal-to-string normalization that preserves precision.

    Non-finite Decimals are rejected. Finite values are never quantized to a
    fixed scale, so distinct valid decimal values never silently canonicalize
    to the same string. The plain ``'f'`` format is used because it is
    deterministic, locale-independent, and exactly preserves the coefficient.
    """
    if value.is_nan() or value.is_infinite():
        raise ChainError(
            ChainErrorCode.UNSUPPORTED_JSON_VALUE,
            "canonical",
            "non-finite decimal is not representable in canonical JSON",
        )
    if not value.is_finite():
        raise ChainError(
            ChainErrorCode.UNSUPPORTED_JSON_VALUE,
            "canonical",
            "non-finite decimal is not representable in canonical JSON",
        )
    text = format(value, "f")
    if text in ("-0", "-0.0", "0.0"):
        return "0"
    return text


def datetime_canonical_str(value: datetime) -> str:
    """UTC-normalized timezone-aware datetime string, ``Z`` suffixed."""
    if value.tzinfo is None:
        raise ChainError(
            ChainErrorCode.NAIVE_DATETIME,
            "canonical",
            "naive datetime is not reproducible canonical content",
            value.isoformat(),
        )
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def to_canonical(value):  # noqa: ANN001 - recursive normalization
    """Normalize a Python value tree into reproducible canonical components.

    Rejects non-finite floats, bytes, and naive datetimes. Enums become their
    values, Decimals become deterministic strings, aware datetimes are UTC, and
    unordered sets are sorted.
    """
    if value is None or isinstance(value, (bool, str, int)):
        return value
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Decimal):
        return decimal_canonical_str(value)
    if isinstance(value, datetime):
        return datetime_canonical_str(value)
    if isinstance(value, Real):
        if value != value or value in (float("inf"), float("-inf")):
            raise ChainError(
                ChainErrorCode.UNSUPPORTED_JSON_VALUE,
                "canonical",
                "non-finite float is not representable in canonical JSON",
                repr(value),
            )
        return value
    if isinstance(value, bytes):
        raise ChainError(
            ChainErrorCode.UNSUPPORTED_JSON_VALUE,
            "canonical",
            "bytes are not allowed in canonical chain content",
        )
    if isinstance(value, (set, frozenset)):
        return sorted((to_canonical(item) for item in value), key=repr)
    if isinstance(value, (list, tuple)):
        return [to_canonical(item) for item in value]
    if isinstance(value, dict):
        return {key: to_canonical(item) for key, item in value.items()}
    raise ChainError(
        ChainErrorCode.UNSUPPORTED_JSON_VALUE,
        "canonical",
        f"unsupported canonical value type: {type(value).__name__}",
    )


def canonical_json(value) -> str:  # noqa: ANN001
    """Deterministic canonical JSON text (sorted keys, fixed separators)."""
    normalized = to_canonical(value)
    try:
        return json.dumps(
            normalized,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except ValueError as exc:
        raise ChainError(
            ChainErrorCode.UNSUPPORTED_JSON_VALUE,
            "canonical",
            "value is not JSON-serializable in canonical form",
            str(exc),
        ) from exc


def _prune(node: object, path: tuple[str | None, ...], index: int) -> object:
    """Return ``node`` with the given dotted path removed.

    ``*`` means "every element of the list".
    """
    if index >= len(path):
        return None
    key = path[index]
    if key == _WILD:
        if isinstance(node, list):
            return [_prune(item, path, index + 1) for item in node]
        if isinstance(node, dict):
            return {item_key: item for item_key, item in node.items()}
        return node
    if isinstance(node, dict) and key in node:
        sub = _prune(node[key], path, index + 1)
        if sub is None:
            return {item_key: item for item_key, item in node.items() if item_key != key}
        return {**node, key: sub}
    return node


def extract_canonical_content(chain: object) -> dict:  # noqa: ANN001
    """Model dump minus the artifacts node and all volatile fields.

    Accepts either a :class:`ChainOfProof` model or a python-dumped dict.
    """
    if not isinstance(chain, dict):
        chain = chain.model_dump(mode="python")
    content = {item_key: item for item_key, item in chain.items() if item_key != "artifacts"}
    for path in VOLATILE_EXCLUDED_PATHS:
        content = _prune(content, path, 0)
    return content


def canonical_content_json(chain: object) -> str:  # noqa: ANN001
    """Canonical JSON of the reproducible chain content."""
    return canonical_json(extract_canonical_content(chain))


def canonical_content_hash(chain: object) -> str:  # noqa: ANN001
    """Raw 64-lowercase-hex SHA-256 of the reproducible canonical content.

    The result is a bare digest (no ``sha256:`` tag) because it is stored in
    the ArtifactManifest ``canonical_json_sha256`` field, which per the
    contract uses raw digests. Use :func:`stable_sha256_key` /
    :func:`semantic_content_hash` when a tagged stable semantic key is wanted.
    """
    text = canonical_content_json(chain)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def semantic_content_hash(
    content: str,
    namespace: str = _CONTENT_NAMESPACE,
    version: str = _CONTENT_VERSION,
) -> str:
    """Namespace- and version-separated stable ``sha256:<hex>`` key.

    Components are encoded as a canonical JSON array so component boundaries
    can never collide with a separator character inside the content.
    """
    payload = json.dumps(
        [namespace, version, content],
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()
