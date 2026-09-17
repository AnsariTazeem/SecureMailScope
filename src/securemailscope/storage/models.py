"""Persistence-neutral values for durable completed-analysis storage."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from securemailscope.chain.ids import SHA256_DIGEST_PATTERN
from securemailscope.chain.models import ChainOfProof


class AnalysisResultRegistration(BaseModel):
    """One final Chain and its explicit output-affecting-input fingerprint.

    The fingerprint is supplied by the caller that knows every analysis input;
    storage adapters must never derive or guess it from the Chain or its ID.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    analysis_fingerprint: str = Field(pattern=SHA256_DIGEST_PATTERN)
    chain: ChainOfProof
