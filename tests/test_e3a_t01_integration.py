"""Read-only integration test against the frozen T01 PCAP.

This test runs the real analyzer (real TShark in read-only mode) against the
immutable controlled T01 capture and checks the outcome against independently
verified frozen facts. It never writes, rewrites, or repairs the capture,
manifest, or any evidence file. The PCAP being a mutable fixture archive, the
test is skipped when the frozen file is absent.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from securemailscope.analyze import analyze_capture
from securemailscope.models import (
    CaptureFormat,
    ClassificationStatus,
    CompleteStatus,
    Protocol,
    TransitionOutcome,
)

REPO = Path(__file__).resolve().parents[1]
PCAP = REPO / "fixtures" / "pcaps" / "smtp_tls12_valid.pcapng"
PCAP_SHA256 = "772d166b5e2b32516c76833357ff309af0d99d7bc962cf4c685279fc662ab086"

FROZEN_PACKET_COUNT = 28
FROZEN_STREAM_COUNT = 1
FROZEN_SERVER_PORT = 2525
FROZEN_STARTTLS_COMMAND_FRAMES = [9, 11]
FROZEN_ACCEPTANCE_FRAME = 13
FROZEN_CLIENT_HELLO_FRAME = 15


def _t01() -> pytest.MarkDecorator:
    return pytest.mark.skipif(
        not PCAP.is_file(),
        reason="frozen T01 PCAP not present in this working tree",
    )


@_t01()
def test_t01_analyzer_matches_frozen_facts() -> None:
    result = analyze_capture(PCAP)
    prov = result.provenance

    assert prov.capture_format is CaptureFormat.PCAPNG
    assert prov.sha256 == PCAP_SHA256
    assert prov.packet_count == FROZEN_PACKET_COUNT
    assert prov.link_layer_types
    assert prov.snaplen is None or prov.snaplen > 0
    assert prov.truncated_packet_count is not None
    assert prov.truncated_packet_count >= 0

    assert len(result.streams) == FROZEN_STREAM_COUNT
    stream = result.streams[0]
    assert stream.server_port == FROZEN_SERVER_PORT
    assert stream.client_syn is True

    classification = result.classifications[0]
    assert classification.protocol is Protocol.SMTP
    assert classification.status is ClassificationStatus.CONFIRMED

    assert len(result.smtp_transitions) == 1
    transition = result.smtp_transitions[0]
    assert transition.starttls_command == "STARTTLS\r\n"
    assert transition.starttls_command_frames == FROZEN_STARTTLS_COMMAND_FRAMES
    assert transition.starttls_response_frames == [FROZEN_ACCEPTANCE_FRAME]
    assert transition.client_hello_frame == FROZEN_CLIENT_HELLO_FRAME
    assert transition.client_hello_same_stream is True
    assert transition.starttls_capability_evidence == [8]
    assert transition.outcome is TransitionOutcome.ACCEPTED_TLS
    assert transition.completeness is CompleteStatus.COMPLETE

    assert prov.first_epoch_seconds is not None
    assert prov.last_epoch_seconds is not None
    assert prov.last_epoch_seconds > prov.first_epoch_seconds

    follow_stages = [r.stage for r in result.tool_records if r.stage == "tshark_follow"]
    assert follow_stages, "native TShark reassembly (follow,tcp,raw) must be used"


@_t01()
def test_t01_result_serializes_as_typed_pydantic() -> None:
    result = analyze_capture(PCAP)
    payload = result.model_dump(mode="json")
    assert isinstance(payload["provenance"]["sha256"], str)
    assert len(payload["smtp_transitions"]) == 1
