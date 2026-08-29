"""Shared helpers for Chain-of-Proof contract tests.

The schema builder here is the single source of truth for the *checked-in*
schema shape. The drift test regenerates it from the current Pydantic models and
compares against the committed ``schemas/chain-of-proof-1.0.0.schema.json``, so
any intentional schema change must start here (and the committed file must be
regenerated to match).
"""

from __future__ import annotations

import json
from pathlib import Path

from securemailscope.chain.models import (
    SCHEMA_ID,
    ChainOfProof,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = REPO_ROOT / "schemas" / "chain-of-proof-1.0.0.schema.json"
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures" / "chain_of_proof" / "v1"
SECURE_FIXTURE = FIXTURES_DIR / "secure-smtp-chain.json"
INSECURE_FIXTURE = FIXTURES_DIR / "insecure-smtp-chain.json"

JSON_SCHEMA_DIALECT = "https://json-schema.org/draft/2020-12/schema"


def build_chain_schema() -> dict:
    """Deterministic Draft 2020-12 schema for the canonical chain.

    The body is Pydantic's canonical model schema. ``$schema`` and ``$id`` are
    the only fields added on top, matching the frozen schema version constants.
    """
    body = ChainOfProof.model_json_schema()
    return {
        "$schema": JSON_SCHEMA_DIALECT,
        "$id": SCHEMA_ID,
        **body,
    }


def load_fixture(path: Path) -> dict:
    """Load (and cache-transparently) a chain fixture as plain JSON."""
    return json.loads(path.read_text(encoding="utf-8"))


def load_secure_fixture() -> dict:
    return load_fixture(SECURE_FIXTURE)


def load_insecure_fixture() -> dict:
    return load_fixture(INSECURE_FIXTURE)


def load_checked_in_schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
