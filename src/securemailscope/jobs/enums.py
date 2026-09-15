"""Closed initial analysis-job state vocabulary for Backend V2."""

from __future__ import annotations

from enum import StrEnum


class JobState(StrEnum):
    """Persistence-neutral snapshot states selected before lifecycle wiring."""

    ACCEPTED = "accepted"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    INTERRUPTED = "interrupted"
