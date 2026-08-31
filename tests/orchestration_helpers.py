"""Shared deterministic inputs for Commit 6A orchestration tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path

from _e3a_helpers import frame, stream

from securemailscope.chain.policy.loader import load_default_policy_pack
from securemailscope.chain.policy.models import PolicyPack
from securemailscope.models import (
    AnalyzeResult,
    CaptureFormat,
    CaptureProvenance,
    Direction,
    Protocol,
    ProvenanceStatus,
)
from securemailscope.orchestration.models import OrchestrationExecutionContext
from securemailscope.protocols import classify_stream
from securemailscope.sessions import build_transition

C = Direction.CLIENT_TO_SERVER
S = Direction.SERVER_TO_CLIENT
CAPTURE_SHA256 = "a" * 64
BASE_TIME = datetime(2026, 8, 31, 10, 0, 0, tzinfo=UTC)


def build_analyze_result(
    *,
    capture_path: Path | None = None,
    capture_sha256: str = CAPTURE_SHA256,
) -> AnalyzeResult:
    frames = [
        frame(1, b"", direction=C, syn=True),
        frame(2, b"", direction=S, syn=True, ack=True),
        frame(3, b"", direction=C, ack=True),
        frame(4, b"220 secure.example ESMTP\r\n", direction=S),
        frame(5, b"EHLO client.example\r\n", direction=C),
        frame(6, b"250-STARTTLS\r\n", direction=S),
        frame(7, b"MAIL FROM:<private@example.test>\r\n", direction=C),
        frame(8, b"QUIT\r\n", direction=C),
    ]
    tcp_stream = stream(frames)
    classification = classify_stream(tcp_stream)
    assert classification.protocol is Protocol.SMTP
    transition = build_transition(tcp_stream, capture_truncation=False)
    return AnalyzeResult(
        provenance=CaptureProvenance(
            input_path=str(capture_path or Path("capture.pcapng")),
            sha256=capture_sha256,
            size_bytes=4096,
            capture_format=CaptureFormat.PCAPNG,
            packet_count=len(frames),
            first_epoch_seconds=Decimal("1800000000.100000000"),
            last_epoch_seconds=Decimal("1800000002.300000000"),
            link_layer_types=["ethernet"],
            snaplen=262144,
            truncated_packet_count=0,
            tshark_version="TShark 4.2.5",
            capinfos_version="Capinfos 4.2.5",
            status=ProvenanceStatus.OK,
            warnings=[],
        ),
        streams=[tcp_stream],
        classifications=[classification],
        smtp_transitions=[transition],
    )


def execution_context(*, offset: timedelta = timedelta()) -> OrchestrationExecutionContext:
    return OrchestrationExecutionContext(
        source_configuration_digest="c" * 64,
        analyzer_version="securemailscope/0.1.0",
        profile_id="sms-liberal",
        created_at=BASE_TIME + offset,
        started_at=BASE_TIME + offset + timedelta(seconds=1),
        completed_at=BASE_TIME + offset + timedelta(seconds=2),
        evaluated_at=BASE_TIME + offset + timedelta(seconds=3),
    )


def default_policy_pack() -> PolicyPack:
    return load_default_policy_pack()
