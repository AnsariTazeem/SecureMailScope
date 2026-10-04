import type { AnalysisResult } from "@/lib/contracts/analysis";

export const completenessLabels = {
  complete: "Complete",
  capture_incomplete: "Capture incomplete",
  insufficient: "Insufficient evidence",
} as const;

export const tlsTransitionLabels = {
  accepted: "Accepted event present",
  rejected: "Rejected event present",
  requested_no_outcome: "Request present; outcome unavailable",
  conflicting_outcomes: "Conflicting outcome events",
  no_transition_event: "No transition event present",
} as const;

export type TlsTransitionState = keyof typeof tlsTransitionLabels;

export type TransitionEvidenceState = {
  eventStatus: string;
  observability: string;
};

export type SessionExplorerRow = {
  sessionId: string;
  captureId: string;
  captureName: string | null;
  tcpStreamId: number;
  sourceIp: string;
  sourcePort: number;
  destinationIp: string;
  destinationPort: number;
  protocol: string;
  completeness: keyof typeof completenessLabels;
  tlsTransition: TlsTransitionState;
  transitionEvidenceStates: TransitionEvidenceState[];
  linkedFindingCount: number;
  highestFindingSeverity: string | null;
  evidenceConfidence: string | null;
};

export type SessionsExplorerData = {
  analysisId: string;
  dataSource: AnalysisResult["data_source"];
  datasetLabel: string | null;
  mlEngineStatus: AnalysisResult["chain"]["analysis"]["ml_engine_status"];
  anomalyResultCount: number;
  totalSessions: number;
  completeSessions: number;
  captureIncompleteSessions: number;
  insufficientSessions: number;
  sessionsWithFindings: number;
  protocolCounts: Array<{ protocol: string; count: number }>;
  captureOptions: Array<{
    captureId: string;
    captureName: string | null;
  }>;
  rows: SessionExplorerRow[];
};

const transitionEventTypes = new Set([
  "tls_upgrade_requested",
  "tls_upgrade_accepted",
  "tls_upgrade_rejected",
]);

function transitionState(
  eventTypes: Set<string>,
): TlsTransitionState {
  const accepted = eventTypes.has("tls_upgrade_accepted");
  const rejected = eventTypes.has("tls_upgrade_rejected");

  if (accepted && rejected) return "conflicting_outcomes";
  if (accepted) return "accepted";
  if (rejected) return "rejected";
  if (eventTypes.has("tls_upgrade_requested")) return "requested_no_outcome";
  return "no_transition_event";
}

function relevantEventTypes(state: TlsTransitionState): Set<string> {
  switch (state) {
    case "accepted":
      return new Set(["tls_upgrade_accepted"]);
    case "rejected":
      return new Set(["tls_upgrade_rejected"]);
    case "requested_no_outcome":
      return new Set(["tls_upgrade_requested"]);
    case "conflicting_outcomes":
      return new Set(["tls_upgrade_accepted", "tls_upgrade_rejected"]);
    case "no_transition_event":
      return new Set();
  }
}

export function buildSessionsExplorerData(
  result: AnalysisResult,
): SessionsExplorerData {
  const { analysis, captures, sessions, protocol_events, findings } =
    result.chain;
  const capturesById = new Map(
    captures.map((capture) => [capture.capture_id, capture]),
  );
  const findingsBySession = new Map<string, typeof findings>();
  for (const finding of findings) {
    const sessionFindings = findingsBySession.get(finding.session_id) ?? [];
    sessionFindings.push(finding);
    findingsBySession.set(finding.session_id, sessionFindings);
  }
  const severityOrder: Record<string, number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
    info: 4,
  };

  const eventsBySession = new Map<
    string,
    typeof result.chain.protocol_events
  >();
  for (const event of protocol_events) {
    if (!transitionEventTypes.has(event.event_type)) continue;
    const sessionEvents = eventsBySession.get(event.session_id) ?? [];
    sessionEvents.push(event);
    eventsBySession.set(event.session_id, sessionEvents);
  }

  const rows = sessions
    .map((session): SessionExplorerRow => {
      const sessionEvents = eventsBySession.get(session.session_id) ?? [];
      const state = transitionState(
        new Set(sessionEvents.map((event) => event.event_type)),
      );
      const relevantTypes = relevantEventTypes(state);
      const transitionEvidenceStates = [
        ...new Map(
          sessionEvents
            .filter((event) => relevantTypes.has(event.event_type))
            .map((event) => [
              `${event.event_status}:${event.observability}`,
              {
                eventStatus: event.event_status,
                observability: event.observability,
              },
            ]),
        ).values(),
      ].sort((left, right) =>
        `${left.eventStatus}:${left.observability}`.localeCompare(
          `${right.eventStatus}:${right.observability}`,
        ),
      );
      const capture = capturesById.get(session.capture_id);
      const sessionFindings = [...(findingsBySession.get(session.session_id) ?? [])].sort(
        (left, right) =>
          (severityOrder[left.severity] ?? 99) -
          (severityOrder[right.severity] ?? 99),
      );
      const primaryFinding = sessionFindings[0];

      return {
        sessionId: session.session_id,
        captureId: session.capture_id,
        captureName: capture?.original_filename_sanitized || null,
        tcpStreamId: session.tcp_stream_id,
        sourceIp: session.source_endpoint.ip,
        sourcePort: session.source_endpoint.port,
        destinationIp: session.destination_endpoint.ip,
        destinationPort: session.destination_endpoint.port,
        protocol: session.protocol,
        completeness: session.capture_completeness,
        tlsTransition: state,
        transitionEvidenceStates,
        linkedFindingCount: sessionFindings.length,
        highestFindingSeverity: primaryFinding?.severity ?? null,
        evidenceConfidence: primaryFinding?.evidence_confidence ?? null,
      };
    })
    .sort((left, right) => left.sessionId.localeCompare(right.sessionId));

  const protocolCounts = new Map<string, number>();
  for (const row of rows) {
    protocolCounts.set(
      row.protocol,
      (protocolCounts.get(row.protocol) ?? 0) + 1,
    );
  }

  const captureOptions = [
    ...new Map(
      rows.map((row) => [
        row.captureId,
        { captureId: row.captureId, captureName: row.captureName },
      ]),
    ).values(),
  ].sort((left, right) =>
    (left.captureName ?? left.captureId).localeCompare(
      right.captureName ?? right.captureId,
    ),
  );

  return {
    analysisId: analysis.analysis_id,
    dataSource: result.data_source,
    datasetLabel: result.dataset_label,
    mlEngineStatus: analysis.ml_engine_status,
    anomalyResultCount: result.chain.anomaly_results.length,
    totalSessions: rows.length,
    completeSessions: rows.filter((row) => row.completeness === "complete")
      .length,
    captureIncompleteSessions: rows.filter(
      (row) => row.completeness === "capture_incomplete",
    ).length,
    insufficientSessions: rows.filter(
      (row) => row.completeness === "insufficient",
    ).length,
    sessionsWithFindings: rows.filter((row) => row.linkedFindingCount > 0)
      .length,
    protocolCounts: [...protocolCounts.entries()]
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([protocol, count]) => ({ protocol, count })),
    captureOptions,
    rows,
  };
}
