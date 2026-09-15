"""Backend V2 V2-1 Slice 3 analysis-job snapshot contract tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from securemailscope.jobs import JobSnapshot, JobState

SUBMITTED = datetime(2026, 9, 15, 10, 0, tzinfo=UTC)
STARTED = SUBMITTED + timedelta(seconds=1)
COMPLETED = STARTED + timedelta(seconds=2)
JOB_ID = "job_0123456789abcdef0123456789abcdef"
ANALYSIS_ID = "ana_0123456789abcdef"
CAPTURE_SHA256 = "a" * 64
FINGERPRINT = "b" * 64


def job_snapshot(state: JobState = JobState.ACCEPTED, **updates: object) -> JobSnapshot:
    values: dict[str, object] = {
        "job_id": JOB_ID,
        "state": state,
        "capture_sha256": CAPTURE_SHA256,
        "analysis_fingerprint": None,
        "analysis_id": None,
        "submitted_at": SUBMITTED,
        "started_at": None,
        "completed_at": None,
        "public_failure_code": None,
        "revision": 0,
    }
    state_values: dict[JobState, dict[str, object]] = {
        JobState.ACCEPTED: {},
        JobState.QUEUED: {},
        JobState.RUNNING: {"started_at": STARTED},
        JobState.COMPLETED: {
            "started_at": STARTED,
            "completed_at": COMPLETED,
            "analysis_fingerprint": FINGERPRINT,
            "analysis_id": ANALYSIS_ID,
        },
        JobState.FAILED: {
            "started_at": STARTED,
            "completed_at": COMPLETED,
            "analysis_fingerprint": FINGERPRINT,
            "public_failure_code": "analysis_failed",
        },
        JobState.INTERRUPTED: {
            "started_at": STARTED,
            "completed_at": COMPLETED,
            "analysis_fingerprint": FINGERPRINT,
            "public_failure_code": "worker_interrupted",
        },
    }
    values.update(state_values[state])
    values.update(updates)
    return JobSnapshot.model_validate(values)


@pytest.mark.parametrize("state", list(JobState))
def test_one_valid_immutable_snapshot_for_every_initial_state(state: JobState) -> None:
    snapshot = job_snapshot(state)

    assert snapshot.state is state
    assert set(snapshot.model_dump()) == {
        "analysis_fingerprint",
        "analysis_id",
        "capture_sha256",
        "completed_at",
        "job_id",
        "public_failure_code",
        "revision",
        "started_at",
        "state",
        "submitted_at",
    }
    with pytest.raises(ValidationError):
        snapshot.revision = 9


def test_closed_initial_state_enum_contains_no_later_lifecycle_states() -> None:
    assert {state.value for state in JobState} == {
        "accepted",
        "queued",
        "running",
        "completed",
        "failed",
        "interrupted",
    }


def test_extra_fields_are_rejected() -> None:
    values = job_snapshot().model_dump(mode="python")
    values["client_filename"] = "private.pcapng"

    with pytest.raises(ValidationError, match="client_filename"):
        JobSnapshot.model_validate(values)


@pytest.mark.parametrize(
    "invalid",
    ["", "job_" + "a" * 31, "job_" + "A" * 32, "ana_" + "a" * 32, " job_" + "a" * 32],
)
def test_invalid_job_ids_are_rejected_without_normalization(invalid: str) -> None:
    with pytest.raises(ValidationError, match="job_id"):
        job_snapshot(job_id=invalid)


@pytest.mark.parametrize("invalid", ["a" * 63, "A" * 64, "sha256:" + "a" * 64, "xyz"])
def test_invalid_capture_digest_is_rejected_without_normalization(invalid: str) -> None:
    with pytest.raises(ValidationError, match="capture_sha256"):
        job_snapshot(capture_sha256=invalid)


@pytest.mark.parametrize("invalid", ["b" * 63, "B" * 64, "sha256:" + "b" * 64, "none"])
def test_invalid_optional_analysis_fingerprint_is_rejected(invalid: str) -> None:
    with pytest.raises(ValidationError, match="analysis_fingerprint"):
        job_snapshot(analysis_fingerprint=invalid)


@pytest.mark.parametrize(
    "invalid",
    ["", "ana_" + "a" * 15, "ana_" + "A" * 16, "job_" + "a" * 16, " ana_" + "a" * 16],
)
def test_invalid_analysis_id_is_rejected_without_normalization(invalid: str) -> None:
    with pytest.raises(ValidationError, match="analysis_id"):
        job_snapshot(
            JobState.COMPLETED,
            analysis_id=invalid,
        )


@pytest.mark.parametrize(
    "unsafe",
    ["", " code", "code ", "CODE", "code-name", "code.name", "failure\ncode", "fáilure"],
)
def test_unsafe_public_failure_codes_are_rejected_without_repair(unsafe: str) -> None:
    with pytest.raises(ValidationError, match="public_failure_code"):
        job_snapshot(JobState.FAILED, public_failure_code=unsafe)


@pytest.mark.parametrize("field", ["submitted_at", "started_at", "completed_at"])
def test_naive_timestamps_are_rejected(field: str) -> None:
    with pytest.raises(ValidationError, match=field):
        job_snapshot(
            JobState.COMPLETED,
            **{field: datetime(2026, 9, 15, 10, 0)},
        )


def test_non_utc_timestamp_is_rejected_instead_of_normalized() -> None:
    with pytest.raises(ValidationError, match="UTC"):
        job_snapshot(submitted_at=SUBMITTED.astimezone(timezone(timedelta(hours=5, minutes=30))))


@pytest.mark.parametrize(
    "updates",
    [
        {"started_at": SUBMITTED - timedelta(microseconds=1)},
        {"completed_at": SUBMITTED - timedelta(microseconds=1)},
        {"completed_at": STARTED - timedelta(microseconds=1)},
    ],
)
def test_timestamp_ordering_is_rejected(updates: dict[str, object]) -> None:
    with pytest.raises(ValidationError, match="precede"):
        job_snapshot(JobState.COMPLETED, **updates)


@pytest.mark.parametrize(
    ("state", "updates", "problem"),
    [
        (JobState.ACCEPTED, {"started_at": STARTED}, "started_at"),
        (JobState.ACCEPTED, {"completed_at": COMPLETED}, "completed_at"),
        (JobState.QUEUED, {"analysis_id": ANALYSIS_ID}, "analysis_id"),
        (JobState.QUEUED, {"public_failure_code": "failed"}, "public_failure_code"),
        (JobState.RUNNING, {"started_at": None}, "started_at"),
        (JobState.RUNNING, {"completed_at": COMPLETED}, "completed_at"),
        (JobState.RUNNING, {"analysis_id": ANALYSIS_ID}, "analysis_id"),
        (JobState.RUNNING, {"public_failure_code": "failed"}, "public_failure_code"),
        (JobState.COMPLETED, {"started_at": None}, "started_at"),
        (JobState.COMPLETED, {"completed_at": None}, "completed_at"),
        (JobState.COMPLETED, {"analysis_fingerprint": None}, "analysis_fingerprint"),
        (JobState.COMPLETED, {"analysis_id": None}, "analysis_id"),
        (JobState.COMPLETED, {"public_failure_code": "failed"}, "public_failure_code"),
        (JobState.FAILED, {"completed_at": None}, "completed_at"),
        (JobState.FAILED, {"analysis_id": ANALYSIS_ID}, "analysis_id"),
        (JobState.FAILED, {"public_failure_code": None}, "public_failure_code"),
        (JobState.INTERRUPTED, {"completed_at": None}, "completed_at"),
        (JobState.INTERRUPTED, {"analysis_id": ANALYSIS_ID}, "analysis_id"),
        (JobState.INTERRUPTED, {"public_failure_code": None}, "public_failure_code"),
    ],
)
def test_invalid_state_field_combinations_are_rejected(
    state: JobState,
    updates: dict[str, object],
    problem: str,
) -> None:
    with pytest.raises(ValidationError, match=problem):
        job_snapshot(state, **updates)


def test_failed_and_interrupted_may_truthfully_have_no_started_timestamp() -> None:
    assert job_snapshot(JobState.FAILED, started_at=None).started_at is None
    assert job_snapshot(JobState.INTERRUPTED, started_at=None).started_at is None


def test_analysis_fingerprint_may_be_absent_before_completion() -> None:
    assert job_snapshot(JobState.ACCEPTED).analysis_fingerprint is None
    assert job_snapshot(JobState.QUEUED).analysis_fingerprint is None
    assert job_snapshot(JobState.RUNNING).analysis_fingerprint is None


@pytest.mark.parametrize("revision", [True, False])
def test_boolean_revision_is_rejected(revision: bool) -> None:
    with pytest.raises(ValidationError, match="revision"):
        job_snapshot(revision=revision)


def test_negative_revision_is_rejected() -> None:
    with pytest.raises(ValidationError, match="revision"):
        job_snapshot(revision=-1)


def test_job_snapshot_serializes_without_adapter_specific_types() -> None:
    dumped = job_snapshot(JobState.COMPLETED).model_dump(mode="json")

    assert dumped["state"] == "completed"
    assert dumped["submitted_at"].endswith("Z")
    assert all(
        forbidden not in dumped
        for forbidden in ("capture_bytes", "database_row", "client_filename", "temporary_path")
    )
