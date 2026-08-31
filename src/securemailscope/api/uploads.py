"""Single-capture multipart intake for the Commit 6B HTTP boundary."""

from __future__ import annotations

import tempfile
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from starlette.datastructures import FormData, UploadFile
from starlette.formparsers import MultiPartException, MultiPartParser
from starlette.requests import Request

UPLOAD_READ_CHUNK_BYTES = 64 * 1024
MAX_MULTIPART_OVERHEAD_BYTES = 64 * 1024
_SUPPORTED_CAPTURE_SUFFIXES = frozenset({".pcap", ".pcapng"})
_UPLOAD_FIELD_NAME = "capture"


class CaptureUploadErrorCode(StrEnum):
    """Closed failure categories owned by the HTTP upload intake."""

    INVALID_MULTIPART = "invalid_multipart"
    UNSUPPORTED_CAPTURE_TYPE = "unsupported_capture_type"
    EMPTY_UPLOAD = "empty_upload"
    UPLOAD_TOO_LARGE = "upload_too_large"


class CaptureUploadError(RuntimeError):
    """A path-safe upload failure suitable for stable HTTP mapping."""

    def __init__(self, code: CaptureUploadErrorCode) -> None:
        super().__init__(code.value)
        self.code = code


@dataclass(frozen=True)
class ParsedCaptureUpload:
    """The sole accepted multipart file and its allow-listed suffix."""

    upload: UploadFile
    suffix: str


def _capture_suffix(filename: str | None) -> str:
    """Return only an allow-listed suffix; never interpret the name as a path."""
    if not filename:
        raise CaptureUploadError(CaptureUploadErrorCode.UNSUPPORTED_CAPTURE_TYPE)
    basename = filename.replace("\\", "/").rsplit("/", 1)[-1]
    suffix = Path(basename).suffix.lower()
    if suffix not in _SUPPORTED_CAPTURE_SUFFIXES:
        raise CaptureUploadError(CaptureUploadErrorCode.UNSUPPORTED_CAPTURE_TYPE)
    return suffix


async def _bounded_request_stream(
    request: Request,
    *,
    max_body_bytes: int,
) -> AsyncIterator[bytes]:
    """Bound the complete multipart body before the parser can spool it."""
    received = 0
    async for chunk in request.stream():
        received += len(chunk)
        if received > max_body_bytes:
            raise CaptureUploadError(CaptureUploadErrorCode.UPLOAD_TOO_LARGE)
        yield chunk


@asynccontextmanager
async def parse_capture_upload(
    request: Request,
    *,
    max_upload_bytes: int,
) -> AsyncIterator[ParsedCaptureUpload]:
    """Parse exactly one multipart capture with bounded total request spooling."""
    max_body_bytes = max_upload_bytes + MAX_MULTIPART_OVERHEAD_BYTES
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            if int(content_length) > max_body_bytes:
                raise CaptureUploadError(CaptureUploadErrorCode.UPLOAD_TOO_LARGE)
        except ValueError:
            raise CaptureUploadError(CaptureUploadErrorCode.INVALID_MULTIPART) from None

    form: FormData | None = None
    try:
        parser = MultiPartParser(
            request.headers,
            _bounded_request_stream(request, max_body_bytes=max_body_bytes),
            max_files=1,
            max_fields=0,
            max_part_size=8 * 1024,
        )
        form = await parser.parse()
    except CaptureUploadError:
        raise
    except (AssertionError, KeyError, MultiPartException):
        raise CaptureUploadError(CaptureUploadErrorCode.INVALID_MULTIPART) from None

    try:
        items = form.multi_items()
        if len(items) != 1 or items[0][0] != _UPLOAD_FIELD_NAME:
            raise CaptureUploadError(CaptureUploadErrorCode.INVALID_MULTIPART)
        upload = items[0][1]
        if not isinstance(upload, UploadFile):
            raise CaptureUploadError(CaptureUploadErrorCode.INVALID_MULTIPART)
        if upload.size is None:
            raise CaptureUploadError(CaptureUploadErrorCode.INVALID_MULTIPART)
        if upload.size == 0:
            raise CaptureUploadError(CaptureUploadErrorCode.EMPTY_UPLOAD)
        if upload.size > max_upload_bytes:
            raise CaptureUploadError(CaptureUploadErrorCode.UPLOAD_TOO_LARGE)
        yield ParsedCaptureUpload(upload=upload, suffix=_capture_suffix(upload.filename))
    finally:
        await form.close()


@asynccontextmanager
async def temporary_capture_path(
    parsed: ParsedCaptureUpload,
    *,
    max_upload_bytes: int,
) -> AsyncIterator[Path]:
    """Copy the bounded upload to a server-named path and always remove it."""
    with tempfile.TemporaryDirectory(prefix="securemailscope-intake-") as directory:
        capture_path = Path(directory) / f"capture{parsed.suffix}"
        written = 0
        await parsed.upload.seek(0)
        with capture_path.open("xb") as destination:
            while True:
                remaining_with_sentinel = max_upload_bytes - written + 1
                read_size = min(UPLOAD_READ_CHUNK_BYTES, remaining_with_sentinel)
                chunk = await parsed.upload.read(read_size)
                if not chunk:
                    break
                written += len(chunk)
                if written > max_upload_bytes:
                    raise CaptureUploadError(CaptureUploadErrorCode.UPLOAD_TOO_LARGE)
                destination.write(chunk)
        if written == 0:
            raise CaptureUploadError(CaptureUploadErrorCode.EMPTY_UPLOAD)
        yield capture_path
