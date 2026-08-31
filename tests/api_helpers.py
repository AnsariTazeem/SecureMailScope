"""Shared helpers for Commit 5B API tests."""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure tests/ is on the path so presentation_helpers can import _e3a_helpers
_TESTS_DIR = Path(__file__).resolve().parent
if str(_TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(_TESTS_DIR))


from securemailscope.api import (  # noqa: E402
    ApiSettings,
    InMemoryAnalysisChainRepository,
    create_app,
)
from securemailscope.chain.models import ChainOfProof  # noqa: E402


def make_app(
    chain: ChainOfProof,
    *,
    max_entries: int = 8,
    max_json_response_bytes: int = 16 * 1024 * 1024,
) -> object:
    """Create a FastAPI app pre-loaded with a single Chain for testing."""
    settings = ApiSettings(
        max_repository_entries=max_entries,
        max_json_response_bytes=max_json_response_bytes,
    )
    repo = InMemoryAnalysisChainRepository(max_entries=max_entries)
    repo.register(chain)
    return create_app(settings=settings, repository=repo)


def make_empty_app(
    *,
    max_entries: int = 8,
    allowed_origins: tuple[str, ...] = (),
) -> object:
    """Create a FastAPI app with an empty repository."""
    settings = ApiSettings(
        max_repository_entries=max_entries,
        allowed_origins=allowed_origins,
    )
    repo = InMemoryAnalysisChainRepository(max_entries=max_entries)
    return create_app(settings=settings, repository=repo)
