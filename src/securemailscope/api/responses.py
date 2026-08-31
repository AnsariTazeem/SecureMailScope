"""Deterministic canonical response helpers and digest headers for Commit 5B."""

from __future__ import annotations

import hashlib
from typing import Any

from fastapi.responses import Response

from securemailscope.chain.canonical import canonical_json


def canonical_response_bytes(value: Any) -> bytes:  # noqa: ANN401
    """Deterministic UTF-8 bytes from any JSON-serializable value."""
    return canonical_json(value).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    """Lowercase hex SHA-256 digest."""
    return hashlib.sha256(data).hexdigest()


def add_common_headers(response: Response, content: bytes, cache_control: str = "no-store") -> None:
    """Add ETag, X-Content-SHA256, nosniff, Content-Length, and Cache-Control."""
    digest = sha256_hex(content)
    response.headers["ETag"] = f'"{digest}"'
    response.headers["X-Content-SHA256"] = digest
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cache-Control"] = cache_control
    response.headers["Content-Length"] = str(len(content))


def add_html_security_headers(response: Response) -> None:
    """Add restrictive CSP for self-contained inline-CSS HTML artifacts."""
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; "
        "style-src 'unsafe-inline'; "
        "img-src 'none'; "
        "font-src 'none'; "
        "script-src 'none'; "
        "connect-src 'none'; "
        "object-src 'none'; "
        "base-uri 'none'; "
        "form-action 'none'; "
        "frame-ancestors 'none'"
    )
