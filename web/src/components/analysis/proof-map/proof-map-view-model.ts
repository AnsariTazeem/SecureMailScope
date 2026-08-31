import type { AnalysisResult } from "@/lib/contracts/analysis";

import { humanize } from "../sessions/session-formatters";
import type { XRayEvidence } from "../session-xray/session-xray-view-model";
import {
  type ProofMapIntegrityContext,
  validateProofMapIntegrity,
} from "./proof-map-integrity";

type Chain = AnalysisResult["chain"];
type ProtocolEvent = Chain["protocol_events"][number];
type CryptoObservation = Chain["crypto_observations"][number];
type DerivedFact = Chain["derived_facts"][number];
type Finding = Chain["findings"][number];
type Limitation = Chain["analysis"]["limitations"][number];

export type ProofNodeKind =
  | "capture"
  | "session"
  | "event"
  | "observation"
  | "fact"
  | "finding";

export type ProofGraphNodeKind = ProofNodeKind | "evidence";

export type ProofNodeState =
  | "observed"
  | "derived"
  | "policy_inferred"
  | "not_observable"
  | "incomplete_capture"
  | "session_secrets_required"
  | "not_applicable";

export type ProofNode = {
  kind: ProofNodeKind;
  id: string;
  title: string;
  detail: string;
  state: ProofNodeState;
  stateLabel: string;
  directEvidence: XRayEvidence[];
  throughSourceEvidence: XRayEvidence[];
  href: string | null;
  incomingRelationship: string | null;
};

export type ProofPath = {
  pathId: string;
  sessionId: string;
  nodes: ProofNode[];
};

export type DirectEvidenceLink = {
  kind: "classification" | "event" | "observation" | "finding" | "anomaly";
  id: string;
  label: string;
  href: string | null;
};

export type EvidenceRoute = {
  evidence: XRayEvidence;
  links: DirectEvidenceLink[];
};

export type ProofRelationship = {
  relationshipId: string;
  sessionId: string;
  fromId: string;
  fromKind: string;
  toId: string;
  toKind: string;
  contractField: string;
  relationshipType:
    | "structural"
    | "direct_evidence"
    | "declared_source"
    | "policy"
    | "anomaly";
};

export type ProofGraphInspectorRow = {
  label: string;
  value: string | string[];
  monospace?: boolean;
};

export type ProofGraphNode = {
  id: string;
  kind: ProofGraphNodeKind;
  sessionIds: string[];
  captureId: string;
  title: string;
  shortId: string;
  state: ProofNodeState;
  stateLabel: string;
  metadata: string;
  order: number;
  inspectorRows: ProofGraphInspectorRow[];
  directEvidence: XRayEvidence[];
  throughSourceEvidence: XRayEvidence[];
  limitations: ProofLimitation[];
  href: string | null;
  hrefLabel: string | null;
};

export type ProofSession = {
  sessionId: string;
  captureId: string;
  protocol: string;
  tcpStreamId: number;
  completeness: string;
  xrayHref: string;
  paths: ProofPath[];
  evidenceRoutes: EvidenceRoute[];
  relationships: ProofRelationship[];
  notices: string[];
};

export type ProofLimitation = Limitation & {
  scope: string;
};

export type ProofMapData = {
  analysisId: string;
  dataSource: AnalysisResult["data_source"];
  datasetLabel: string | null;
  analysisStatus: string;
  chainSchemaVersion: string;
  sessionsHref: string;
  overviewHref: string;
  sessions: ProofSession[];
  graphNodes: ProofGraphNode[];
  graphEdges: ProofRelationship[];
  defaultSessionId: string | null;
  relationshipCount: number;
  directEvidenceRelationshipCount: number;
  declaredSourceRelationshipCount: number;
  policyRisk: {
    status: "available" | "not_present";
    policyRiskId: string | null;
    profileId: string | null;
    cappedScore: number | null;
    uncappedScore: number | null;
    findingCount: number;
    contributionCount: number;
  };
  mlAnomaly: {
    engineStatus: string;
    resultCount: number;
    explicitEvidenceCount: number;
    explicitLinkedFactCount: number;
    explicitLinkedObservationCount: number;
  };
  limitations: ProofLimitation[];
  partial: boolean;
  empty: boolean;
};

function observabilityState(value: string): ProofNodeState {
  switch (value) {
    case "derived":
    case "policy_inferred":
    case "not_observable":
    case "incomplete_capture":
    case "session_secrets_required":
    case "not_applicable":
      return value;
    default:
      return "observed";
  }
}

function nodeStateLabel(state: ProofNodeState): string {
  if (state === "session_secrets_required") return "not_observable";
  return state;
}

function collectFactEvidenceIds(
  fact: DerivedFact,
  context: ProofMapIntegrityContext,
  visited = new Set<string>(),
): string[] {
  if (visited.has(fact.fact_id)) return [];
  visited.add(fact.fact_id);
  const ids: string[] = [];
  const add = (id: string) => {
    if (!ids.includes(id)) ids.push(id);
  };

  for (const eventId of fact.source_event_ids) {
    for (const evidenceId of context.eventsById.get(eventId)!.evidence_ids) {
      add(evidenceId);
    }
  }
  for (const observationId of fact.source_observation_ids) {
    for (const evidenceId of context.observationsById.get(observationId)!
      .evidence_ids) {
      add(evidenceId);
    }
  }
  for (const sourceFactId of fact.source_fact_ids) {
    for (const evidenceId of collectFactEvidenceIds(
      context.factsById.get(sourceFactId)!,
      context,
      new Set(visited),
    )) {
      add(evidenceId);
    }
  }
  return ids;
}

function buildEvidenceById(
  context: ProofMapIntegrityContext,
): Map<string, XRayEvidence> {
  const factIdsByEvidence = new Map<string, string[]>();
  for (const fact of context.chain.derived_facts) {
    for (const evidenceId of collectFactEvidenceIds(fact, context)) {
      factIdsByEvidence.set(evidenceId, [
        ...(factIdsByEvidence.get(evidenceId) ?? []),
        fact.fact_id,
      ]);
    }
  }

  return new Map(
    context.chain.evidence.map((evidence) => [
      evidence.evidence_id,
      {
        evidenceId: evidence.evidence_id,
        captureId: evidence.capture_id,
        captureSha256: evidence.capture_sha256,
        sessionId: evidence.session_id,
        frameNumbers: [...evidence.frame_numbers],
        occurrenceIndex: evidence.occurrence_index,
        timestampStart: evidence.timestamp_start,
        timestampEnd: evidence.timestamp_end,
        direction: evidence.direction,
        sourceKind: evidence.source_kind,
        sourceField: evidence.source_field,
        safeExcerpt: evidence.safe_excerpt,
        displayFilter: evidence.display_filter,
        observability: evidence.observability,
        redaction: evidence.redaction,
        extractorVersion: evidence.extractor_version,
        eventIds: context.chain.protocol_events
          .filter((event) => event.evidence_ids.includes(evidence.evidence_id))
          .map((event) => event.event_id),
        observationIds: context.chain.crypto_observations
          .filter((observation) =>
            observation.evidence_ids.includes(evidence.evidence_id),
          )
          .map((observation) => observation.observation_id),
        factIdsThroughSources: factIdsByEvidence.get(evidence.evidence_id) ?? [],
        findingIds: context.chain.findings
          .filter((finding) =>
            finding.evidence_ids.includes(evidence.evidence_id),
          )
          .map((finding) => finding.finding_id),
      },
    ]),
  );
}

function evidenceRecords(
  evidenceIds: string[],
  evidenceById: Map<string, XRayEvidence>,
): XRayEvidence[] {
  return evidenceIds.map((id) => evidenceById.get(id)!);
}

function captureNode(
  analysisId: string,
  capture: Chain["captures"][number],
): ProofNode {
  return {
    kind: "capture",
    id: capture.capture_id,
    title: capture.original_filename_sanitized,
    detail: `${capture.format} · ${capture.packet_count.toLocaleString("en")} packets`,
    state: "observed",
    stateLabel: "observed",
    directEvidence: [],
    throughSourceEvidence: [],
    href: `/analysis/${analysisId}/sessions?capture=${capture.capture_id}`,
    incomingRelationship: null,
  };
}

function sessionNode(
  analysisId: string,
  session: Chain["sessions"][number],
): ProofNode {
  const state: ProofNodeState =
    session.capture_completeness === "complete"
      ? "observed"
      : "incomplete_capture";
  return {
    kind: "session",
    id: session.session_id,
    title: `${session.protocol.toUpperCase()} session`,
    detail: `TCP stream ${session.tcp_stream_id} · ${session.capture_completeness}`,
    state,
    stateLabel: nodeStateLabel(state),
    directEvidence: [],
    throughSourceEvidence: [],
    href: `/analysis/${analysisId}/sessions/${session.session_id}`,
    incomingRelationship: "session.capture_id",
  };
}

function eventNode(
  analysisId: string,
  event: ProtocolEvent,
  evidenceById: Map<string, XRayEvidence>,
): ProofNode {
  const state = observabilityState(event.observability);
  return {
    kind: "event",
    id: event.event_id,
    title: humanize(event.event_type),
    detail: `sequence ${event.sequence_index} · ${event.state_before} → ${event.state_after}`,
    state,
    stateLabel: nodeStateLabel(state),
    directEvidence: evidenceRecords(event.evidence_ids, evidenceById),
    throughSourceEvidence: [],
    href: `/analysis/${analysisId}/sessions/${event.session_id}`,
    incomingRelationship: "event.session_id",
  };
}

function observationNode(
  analysisId: string,
  observation: CryptoObservation,
  evidenceById: Map<string, XRayEvidence>,
): ProofNode {
  const state = observabilityState(observation.observability);
  const tls13Unavailable = observation.kind === "tls13_certificate_unavailable";
  return {
    kind: "observation",
    id: observation.observation_id,
    title: tls13Unavailable
      ? "TLS 1.3 certificate contents"
      : humanize(observation.kind),
    detail: tls13Unavailable
      ? "not_observable · authorized session secrets required"
      : `Contract observability: ${observation.observability}`,
    state,
    stateLabel: tls13Unavailable ? "not_observable" : nodeStateLabel(state),
    directEvidence: evidenceRecords(observation.evidence_ids, evidenceById),
    throughSourceEvidence: [],
    href: `/analysis/${analysisId}/sessions/${observation.session_id}`,
    incomingRelationship: "observation.session_id",
  };
}

function factNode(
  analysisId: string,
  fact: DerivedFact,
  context: ProofMapIntegrityContext,
  evidenceById: Map<string, XRayEvidence>,
  incomingRelationship = "declared fact source",
): ProofNode {
  const state = observabilityState(fact.observability);
  return {
    kind: "fact",
    id: fact.fact_id,
    title: humanize(fact.fact_type),
    detail: `${fact.derivation_id} v${fact.derivation_version} · confidence ${fact.confidence_level}`,
    state,
    stateLabel: nodeStateLabel(state),
    directEvidence: [],
    throughSourceEvidence: evidenceRecords(
      collectFactEvidenceIds(fact, context),
      evidenceById,
    ),
    href: `/analysis/${analysisId}/sessions/${fact.session_id}`,
    incomingRelationship,
  };
}

function findingNode(
  analysisId: string,
  finding: Finding,
  evidenceById: Map<string, XRayEvidence>,
): ProofNode {
  const state = observabilityState(finding.observability);
  return {
    kind: "finding",
    id: finding.finding_id,
    title: finding.title,
    detail: `severity ${finding.severity} · Policy Risk +${finding.policy_risk_contribution}`,
    state,
    stateLabel: nodeStateLabel(state),
    directEvidence: evidenceRecords(finding.evidence_ids, evidenceById),
    throughSourceEvidence: [],
    href: `/analysis/${analysisId}/findings#${finding.finding_id}`,
    incomingRelationship: "finding.fact_ids",
  };
}

function sourceChains(
  analysisId: string,
  fact: DerivedFact,
  context: ProofMapIntegrityContext,
  evidenceById: Map<string, XRayEvidence>,
): ProofNode[][] {
  const chains: ProofNode[][] = [];
  for (const eventId of fact.source_event_ids) {
    chains.push([
      eventNode(analysisId, context.eventsById.get(eventId)!, evidenceById),
    ]);
  }
  for (const observationId of fact.source_observation_ids) {
    chains.push([
      observationNode(
        analysisId,
        context.observationsById.get(observationId)!,
        evidenceById,
      ),
    ]);
  }
  for (const sourceFactId of fact.source_fact_ids) {
    const sourceFact = context.factsById.get(sourceFactId)!;
    for (const chain of sourceChains(
      analysisId,
      sourceFact,
      context,
      evidenceById,
    )) {
      chains.push([
        ...chain,
        factNode(
          analysisId,
          sourceFact,
          context,
          evidenceById,
          factSourceRelationship(chain.at(-1)!.kind),
        ),
      ]);
    }
  }
  return chains;
}

function factSourceRelationship(sourceKind: ProofNodeKind): string {
  if (sourceKind === "event") return "fact.source_event_ids";
  if (sourceKind === "observation") return "fact.source_observation_ids";
  return "fact.source_fact_ids";
}

function buildPaths(
  analysisId: string,
  session: Chain["sessions"][number],
  context: ProofMapIntegrityContext,
  evidenceById: Map<string, XRayEvidence>,
): ProofPath[] {
  const capture = context.capturesById.get(session.capture_id)!;
  const prefix = [captureNode(analysisId, capture), sessionNode(analysisId, session)];
  const facts = context.chain.derived_facts.filter(
    (fact) => fact.session_id === session.session_id,
  );
  const findings = context.chain.findings.filter(
    (finding) => finding.session_id === session.session_id,
  );
  const paths: ProofPath[] = [];

  for (const fact of facts) {
    const terminalFindings = findings.filter((finding) =>
      finding.fact_ids.includes(fact.fact_id),
    );
    const endings: Array<Finding | null> =
      terminalFindings.length > 0 ? terminalFindings : [null];
    const chains = sourceChains(analysisId, fact, context, evidenceById);
    for (const [chainIndex, sourceChain] of chains.entries()) {
      for (const finding of endings) {
        const nodes = [
          ...prefix,
          ...sourceChain,
          factNode(
            analysisId,
            fact,
            context,
            evidenceById,
            factSourceRelationship(sourceChain.at(-1)!.kind),
          ),
          ...(finding
            ? [findingNode(analysisId, finding, evidenceById)]
            : []),
        ];
        paths.push({
          pathId: `${session.session_id}:${fact.fact_id}:${chainIndex}:${finding?.finding_id ?? "fact"}`,
          sessionId: session.session_id,
          nodes,
        });
      }
    }
  }
  return paths;
}

function buildEvidenceRoutes(
  analysisId: string,
  session: Chain["sessions"][number],
  context: ProofMapIntegrityContext,
  evidenceById: Map<string, XRayEvidence>,
): EvidenceRoute[] {
  return context.chain.evidence
    .filter((evidence) => evidence.session_id === session.session_id)
    .map((evidence) => {
      const links: DirectEvidenceLink[] = [];
      if (session.classification_evidence_ids.includes(evidence.evidence_id)) {
        links.push({
          kind: "classification",
          id: session.session_id,
          label: "Session classification",
          href: `/analysis/${analysisId}/sessions/${session.session_id}`,
        });
      }
      for (const event of context.chain.protocol_events) {
        if (event.evidence_ids.includes(evidence.evidence_id)) {
          links.push({
            kind: "event",
            id: event.event_id,
            label: humanize(event.event_type),
            href: `/analysis/${analysisId}/sessions/${session.session_id}`,
          });
        }
      }
      for (const observation of context.chain.crypto_observations) {
        if (observation.evidence_ids.includes(evidence.evidence_id)) {
          links.push({
            kind: "observation",
            id: observation.observation_id,
            label: humanize(observation.kind),
            href: `/analysis/${analysisId}/sessions/${session.session_id}`,
          });
        }
      }
      for (const finding of context.chain.findings) {
        if (finding.evidence_ids.includes(evidence.evidence_id)) {
          links.push({
            kind: "finding",
            id: finding.finding_id,
            label: finding.title,
            href: `/analysis/${analysisId}/findings#${finding.finding_id}`,
          });
        }
      }
      for (const anomaly of context.chain.anomaly_results) {
        if ((anomaly.evidence_ids ?? []).includes(evidence.evidence_id)) {
          links.push({
            kind: "anomaly",
            id: anomaly.anomaly_result_id,
            label: "Explicit ML Anomaly evidence",
            href: null,
          });
        }
      }
      return { evidence: evidenceById.get(evidence.evidence_id)!, links };
    });
}

function buildRelationships(
  session: Chain["sessions"][number],
  context: ProofMapIntegrityContext,
): ProofRelationship[] {
  const relationships: ProofRelationship[] = [];
  const add = (
    fromId: string,
    fromKind: string,
    toId: string,
    toKind: string,
    contractField: string,
    relationshipType: ProofRelationship["relationshipType"],
  ) => {
    relationships.push({
      relationshipId: `${contractField}:${fromId}:${toId}`,
      sessionId: session.session_id,
      fromId,
      fromKind,
      toId,
      toKind,
      contractField,
      relationshipType,
    });
  };

  add(
    session.capture_id,
    "capture",
    session.session_id,
    "session",
    "session.capture_id",
    "structural",
  );
  for (const evidenceId of session.classification_evidence_ids) {
    add(
      evidenceId,
      "evidence",
      session.session_id,
      "session",
      "session.classification_evidence_ids",
      "direct_evidence",
    );
  }
  for (const event of context.chain.protocol_events.filter(
    (record) => record.session_id === session.session_id,
  )) {
    add(
      session.session_id,
      "session",
      event.event_id,
      "event",
      "event.session_id",
      "structural",
    );
    for (const evidenceId of event.evidence_ids) {
      add(
        evidenceId,
        "evidence",
        event.event_id,
        "event",
        "event.evidence_ids",
        "direct_evidence",
      );
    }
  }
  for (const observation of context.chain.crypto_observations.filter(
    (record) => record.session_id === session.session_id,
  )) {
    add(
      session.session_id,
      "session",
      observation.observation_id,
      "observation",
      "observation.session_id",
      "structural",
    );
    for (const evidenceId of observation.evidence_ids) {
      add(
        evidenceId,
        "evidence",
        observation.observation_id,
        "observation",
        "observation.evidence_ids",
        "direct_evidence",
      );
    }
  }
  for (const fact of context.chain.derived_facts.filter(
    (record) => record.session_id === session.session_id,
  )) {
    for (const eventId of fact.source_event_ids) {
      add(
        eventId,
        "event",
        fact.fact_id,
        "fact",
        "fact.source_event_ids",
        "declared_source",
      );
    }
    for (const observationId of fact.source_observation_ids) {
      add(
        observationId,
        "observation",
        fact.fact_id,
        "fact",
        "fact.source_observation_ids",
        "declared_source",
      );
    }
    for (const sourceFactId of fact.source_fact_ids) {
      add(
        sourceFactId,
        "fact",
        fact.fact_id,
        "fact",
        "fact.source_fact_ids",
        "declared_source",
      );
    }
  }
  for (const evaluation of context.chain.rule_evaluations.filter(
    (record) => record.session_id === session.session_id,
  )) {
    for (const factId of evaluation.input_fact_ids) {
      add(
        factId,
        "fact",
        evaluation.evaluation_id,
        "rule evaluation",
        "evaluation.input_fact_ids",
        "policy",
      );
    }
    if (evaluation.generated_finding_id) {
      add(
        evaluation.evaluation_id,
        "rule evaluation",
        evaluation.generated_finding_id,
        "finding",
        "evaluation.generated_finding_id",
        "policy",
      );
    }
  }
  for (const finding of context.chain.findings.filter(
    (record) => record.session_id === session.session_id,
  )) {
    for (const factId of finding.fact_ids) {
      add(
        factId,
        "fact",
        finding.finding_id,
        "finding",
        "finding.fact_ids",
        "policy",
      );
    }
    for (const evidenceId of finding.evidence_ids) {
      add(
        evidenceId,
        "evidence",
        finding.finding_id,
        "finding",
        "finding.evidence_ids",
        "direct_evidence",
      );
    }
  }
  for (const anomaly of context.chain.anomaly_results.filter(
    (record) => record.session_id === session.session_id,
  )) {
    for (const factId of anomaly.linked_fact_ids ?? []) {
      add(
        factId,
        "fact",
        anomaly.anomaly_result_id,
        "ML Anomaly",
        "anomaly.linked_fact_ids",
        "anomaly",
      );
    }
    for (const observationId of anomaly.linked_observation_ids ?? []) {
      add(
        observationId,
        "observation",
        anomaly.anomaly_result_id,
        "ML Anomaly",
        "anomaly.linked_observation_ids",
        "anomaly",
      );
    }
    for (const evidenceId of anomaly.evidence_ids ?? []) {
      add(
        evidenceId,
        "evidence",
        anomaly.anomaly_result_id,
        "ML Anomaly",
        "anomaly.evidence_ids",
        "anomaly",
      );
    }
  }
  return relationships;
}

function shortId(id: string): string {
  return id.length <= 18 ? id : `${id.slice(0, 7)}…${id.slice(-8)}`;
}

function scopedLimitations(
  scope: string,
  limitations: Limitation[],
): ProofLimitation[] {
  return limitations.map((limitation) => ({ ...limitation, scope }));
}

function buildGraphNodes(
  analysisId: string,
  context: ProofMapIntegrityContext,
  evidenceById: Map<string, XRayEvidence>,
): ProofGraphNode[] {
  const nodes: ProofGraphNode[] = [];
  const sessionIdsByCapture = new Map<string, string[]>();
  for (const session of context.chain.sessions) {
    sessionIdsByCapture.set(session.capture_id, [
      ...(sessionIdsByCapture.get(session.capture_id) ?? []),
      session.session_id,
    ]);
  }

  for (const capture of context.chain.captures) {
    const sessionIds = sessionIdsByCapture.get(capture.capture_id) ?? [];
    if (sessionIds.length === 0) continue;
    nodes.push({
      id: capture.capture_id,
      kind: "capture",
      sessionIds: [...sessionIds].sort(),
      captureId: capture.capture_id,
      title: capture.original_filename_sanitized,
      shortId: shortId(capture.capture_id),
      state: "observed",
      stateLabel: "observed",
      metadata: `${capture.packet_count.toLocaleString("en")} packets`,
      order: Math.min(
        ...context.chain.sessions
          .filter((session) => session.capture_id === capture.capture_id)
          .map((session) => session.first_frame),
      ),
      inspectorRows: [
        { label: "Capture ID", value: capture.capture_id, monospace: true },
        {
          label: "Capture SHA-256",
          value: capture.sha256,
          monospace: true,
        },
        { label: "Sanitized filename", value: capture.original_filename_sanitized },
        { label: "Format", value: capture.format, monospace: true },
        { label: "Packet count", value: String(capture.packet_count), monospace: true },
        { label: "Size (bytes)", value: String(capture.size_bytes), monospace: true },
        {
          label: "Truncated packets",
          value: String(capture.truncated_packet_count),
          monospace: true,
        },
      ],
      directEvidence: [],
      throughSourceEvidence: [],
      limitations: [],
      href: `/analysis/${analysisId}/sessions`,
      hrefLabel: "Open Sessions Explorer",
    });
  }

  for (const session of context.chain.sessions) {
    const state: ProofNodeState =
      session.capture_completeness === "complete"
        ? "observed"
        : "incomplete_capture";
    nodes.push({
      id: session.session_id,
      kind: "session",
      sessionIds: [session.session_id],
      captureId: session.capture_id,
      title: `${session.protocol.toUpperCase()} session`,
      shortId: shortId(session.session_id),
      state,
      stateLabel: nodeStateLabel(state),
      metadata: `TCP stream ${session.tcp_stream_id}`,
      order: session.first_frame,
      inspectorRows: [
        { label: "Session ID", value: session.session_id, monospace: true },
        {
          label: "Stable session key",
          value: session.stable_session_key,
          monospace: true,
        },
        { label: "Capture ID", value: session.capture_id, monospace: true },
        { label: "Protocol", value: session.protocol, monospace: true },
        {
          label: "TCP stream ID",
          value: String(session.tcp_stream_id),
          monospace: true,
        },
        {
          label: "Frame range",
          value: `${session.first_frame} — ${session.last_frame}`,
          monospace: true,
        },
        {
          label: "Capture completeness",
          value: session.capture_completeness,
          monospace: true,
        },
        {
          label: "Classification evidence IDs",
          value: session.classification_evidence_ids,
          monospace: true,
        },
      ],
      directEvidence: evidenceRecords(
        session.classification_evidence_ids,
        evidenceById,
      ),
      throughSourceEvidence: [],
      limitations: scopedLimitations(
        `session ${session.session_id}`,
        session.limitations,
      ),
      href: `/analysis/${analysisId}/sessions/${session.session_id}`,
      hrefLabel: "Open Session X-Ray",
    });
  }

  for (const evidence of context.chain.evidence) {
    const inspectorEvidence = evidenceById.get(evidence.evidence_id)!;
    nodes.push({
      id: evidence.evidence_id,
      kind: "evidence",
      sessionIds: [evidence.session_id],
      captureId: evidence.capture_id,
      title: humanize(evidence.source_kind),
      shortId: shortId(evidence.evidence_id),
      state: "observed",
      stateLabel: "observed",
      metadata: `frame ${evidence.frame_numbers.join(", ")} · occurrence ${evidence.occurrence_index}`,
      order: evidence.frame_numbers[0] * 1000 + evidence.occurrence_index,
      inspectorRows: [
        { label: "Evidence ID", value: evidence.evidence_id, monospace: true },
        { label: "Capture ID", value: evidence.capture_id, monospace: true },
        {
          label: "Capture SHA-256",
          value: evidence.capture_sha256,
          monospace: true,
        },
        { label: "Session ID", value: evidence.session_id, monospace: true },
        {
          label: "Frame numbers",
          value: evidence.frame_numbers.map(String),
          monospace: true,
        },
        {
          label: "Occurrence",
          value: String(evidence.occurrence_index),
          monospace: true,
        },
        { label: "Direction", value: evidence.direction, monospace: true },
        { label: "Source type", value: evidence.source_kind, monospace: true },
        { label: "Source field", value: evidence.source_field, monospace: true },
        { label: "Observability", value: evidence.observability, monospace: true },
        { label: "Redaction", value: evidence.redaction, monospace: true },
        {
          label: "Extractor version",
          value: evidence.extractor_version,
          monospace: true,
        },
      ],
      directEvidence: [inspectorEvidence],
      throughSourceEvidence: [],
      limitations: [],
      href: `/analysis/${analysisId}/sessions/${evidence.session_id}`,
      hrefLabel: "Open Session X-Ray",
    });
  }

  for (const event of context.chain.protocol_events) {
    const state = observabilityState(event.observability);
    nodes.push({
      id: event.event_id,
      kind: "event",
      sessionIds: [event.session_id],
      captureId: context.sessionsById.get(event.session_id)!.capture_id,
      title: humanize(event.event_type),
      shortId: shortId(event.event_id),
      state,
      stateLabel: nodeStateLabel(state),
      metadata: `sequence ${event.sequence_index}`,
      order: event.sequence_index,
      inspectorRows: [
        { label: "Event ID", value: event.event_id, monospace: true },
        { label: "Session ID", value: event.session_id, monospace: true },
        {
          label: "Sequence index",
          value: String(event.sequence_index),
          monospace: true,
        },
        { label: "Event type", value: event.event_type, monospace: true },
        { label: "State before", value: event.state_before, monospace: true },
        { label: "State after", value: event.state_after, monospace: true },
        { label: "Direction", value: event.direction, monospace: true },
        { label: "Event status", value: event.event_status, monospace: true },
        { label: "Observability", value: event.observability, monospace: true },
        { label: "Evidence IDs", value: event.evidence_ids, monospace: true },
      ],
      directEvidence: evidenceRecords(event.evidence_ids, evidenceById),
      throughSourceEvidence: [],
      limitations: scopedLimitations(`event ${event.event_id}`, event.limitations),
      href: `/analysis/${analysisId}/sessions/${event.session_id}`,
      hrefLabel: "Open Session X-Ray",
    });
  }

  for (const observation of context.chain.crypto_observations) {
    const state = observabilityState(observation.observability);
    const tls13Unavailable =
      observation.kind === "tls13_certificate_unavailable";
    nodes.push({
      id: observation.observation_id,
      kind: "observation",
      sessionIds: [observation.session_id],
      captureId: context.sessionsById.get(observation.session_id)!.capture_id,
      title: tls13Unavailable
        ? "TLS 1.3 certificate contents"
        : humanize(observation.kind),
      shortId: shortId(observation.observation_id),
      state,
      stateLabel: tls13Unavailable ? "not_observable" : nodeStateLabel(state),
      metadata: tls13Unavailable
        ? "passive evidence unavailable"
        : `state ${observation.observability}`,
      order: Number.MAX_SAFE_INTEGER,
      inspectorRows: [
        {
          label: "Observation ID",
          value: observation.observation_id,
          monospace: true,
        },
        { label: "Session ID", value: observation.session_id, monospace: true },
        { label: "Kind", value: observation.kind, monospace: true },
        {
          label: "Contract observability",
          value: observation.observability,
          monospace: true,
        },
        ...(tls13Unavailable
          ? [
              {
                label: "Displayed state",
                value: "not_observable",
                monospace: true,
              },
            ]
          : []),
        {
          label: "Evidence IDs",
          value: observation.evidence_ids,
          monospace: true,
        },
      ],
      directEvidence: evidenceRecords(observation.evidence_ids, evidenceById),
      throughSourceEvidence: [],
      limitations: scopedLimitations(
        `observation ${observation.observation_id}`,
        observation.limitations,
      ),
      href: `/analysis/${analysisId}/sessions/${observation.session_id}`,
      hrefLabel: "Open Session X-Ray",
    });
  }

  for (const fact of context.chain.derived_facts) {
    const state = observabilityState(fact.observability);
    nodes.push({
      id: fact.fact_id,
      kind: "fact",
      sessionIds: [fact.session_id],
      captureId: context.sessionsById.get(fact.session_id)!.capture_id,
      title: humanize(fact.fact_type),
      shortId: shortId(fact.fact_id),
      state,
      stateLabel: nodeStateLabel(state),
      metadata: `confidence ${fact.confidence_level}`,
      order: Number.MAX_SAFE_INTEGER,
      inspectorRows: [
        { label: "Fact ID", value: fact.fact_id, monospace: true },
        { label: "Session ID", value: fact.session_id, monospace: true },
        { label: "Fact type", value: fact.fact_type, monospace: true },
        { label: "Derivation ID", value: fact.derivation_id, monospace: true },
        {
          label: "Derivation version",
          value: fact.derivation_version,
          monospace: true,
        },
        { label: "Observability", value: fact.observability, monospace: true },
        {
          label: "Confidence",
          value: fact.confidence_level,
          monospace: true,
        },
        {
          label: "Source event IDs",
          value: fact.source_event_ids,
          monospace: true,
        },
        {
          label: "Source observation IDs",
          value: fact.source_observation_ids,
          monospace: true,
        },
        {
          label: "Source fact IDs",
          value: fact.source_fact_ids,
          monospace: true,
        },
      ],
      directEvidence: [],
      throughSourceEvidence: evidenceRecords(
        collectFactEvidenceIds(fact, context),
        evidenceById,
      ),
      limitations: scopedLimitations(`fact ${fact.fact_id}`, fact.limitations),
      href: `/analysis/${analysisId}/sessions/${fact.session_id}`,
      hrefLabel: "Open Session X-Ray",
    });
  }

  for (const finding of context.chain.findings) {
    const state = observabilityState(finding.observability);
    nodes.push({
      id: finding.finding_id,
      kind: "finding",
      sessionIds: [finding.session_id],
      captureId: context.sessionsById.get(finding.session_id)!.capture_id,
      title: finding.title,
      shortId: shortId(finding.finding_id),
      state,
      stateLabel: nodeStateLabel(state),
      metadata: `${finding.severity} · Policy Risk +${finding.policy_risk_contribution}`,
      order: Number.MAX_SAFE_INTEGER,
      inspectorRows: [
        { label: "Finding ID", value: finding.finding_id, monospace: true },
        {
          label: "Stable finding key",
          value: finding.stable_finding_key,
          monospace: true,
        },
        { label: "Session ID", value: finding.session_id, monospace: true },
        { label: "Rule ID", value: finding.rule_id, monospace: true },
        {
          label: "Rule evaluation ID",
          value: finding.rule_evaluation_id,
          monospace: true,
        },
        { label: "Severity", value: finding.severity, monospace: true },
        {
          label: "Policy Risk contribution",
          value: String(finding.policy_risk_contribution),
          monospace: true,
        },
        {
          label: "Evidence confidence",
          value: finding.evidence_confidence,
          monospace: true,
        },
        { label: "Observability", value: finding.observability, monospace: true },
        { label: "Fact IDs", value: finding.fact_ids, monospace: true },
        { label: "Evidence IDs", value: finding.evidence_ids, monospace: true },
        {
          label: "Recommendation ID",
          value: finding.recommendation_id,
          monospace: true,
        },
      ],
      directEvidence: evidenceRecords(finding.evidence_ids, evidenceById),
      throughSourceEvidence: [],
      limitations: scopedLimitations(
        `finding ${finding.finding_id}`,
        finding.limitations,
      ),
      href: `/analysis/${analysisId}/findings#${finding.finding_id}`,
      hrefLabel: "Open Findings",
    });
  }

  return nodes.sort((left, right) => left.id.localeCompare(right.id));
}

function collectLimitations(context: ProofMapIntegrityContext): ProofLimitation[] {
  const limitations: ProofLimitation[] = context.chain.analysis.limitations.map(
    (limitation) => ({ ...limitation, scope: "analysis" }),
  );
  for (const session of context.chain.sessions) {
    for (const limitation of session.limitations) {
      limitations.push({
        ...limitation,
        scope: `session ${session.session_id}`,
      });
    }
  }
  for (const event of context.chain.protocol_events) {
    for (const limitation of event.limitations) {
      limitations.push({ ...limitation, scope: `event ${event.event_id}` });
    }
  }
  for (const observation of context.chain.crypto_observations) {
    for (const limitation of observation.limitations) {
      limitations.push({
        ...limitation,
        scope: `observation ${observation.observation_id}`,
      });
    }
  }
  for (const fact of context.chain.derived_facts) {
    for (const limitation of fact.limitations) {
      limitations.push({ ...limitation, scope: `fact ${fact.fact_id}` });
    }
  }
  for (const finding of context.chain.findings) {
    for (const limitation of finding.limitations) {
      limitations.push({ ...limitation, scope: `finding ${finding.finding_id}` });
    }
  }
  for (const anomaly of context.chain.anomaly_results) {
    for (const limitation of anomaly.limitations) {
      limitations.push({
        ...limitation,
        scope: `ML Anomaly ${anomaly.anomaly_result_id}`,
      });
    }
  }
  return limitations;
}

export function buildProofMapData(result: AnalysisResult): ProofMapData {
  const context = validateProofMapIntegrity(result);
  const evidenceById = buildEvidenceById(context);
  const analysisId = context.chain.analysis.analysis_id;
  const sessions = [...context.chain.sessions]
    .sort((left, right) => left.session_id.localeCompare(right.session_id))
    .map((session): ProofSession => {
      const paths = buildPaths(analysisId, session, context, evidenceById);
      const evidenceRoutes = buildEvidenceRoutes(
        analysisId,
        session,
        context,
        evidenceById,
      );
      const relationships = buildRelationships(session, context);
      const notices: string[] = [];
      if (session.capture_completeness !== "complete") {
        notices.push(
          `Capture completeness is ${session.capture_completeness}; relationship coverage may be partial.`,
        );
      }
      if (paths.length === 0) {
        notices.push(
          "No declared fact-source path is present for this session. Event and direct-evidence relationships remain listed without an inferred conclusion.",
        );
      }
      if (
        context.chain.crypto_observations.some(
          (observation) =>
            observation.session_id === session.session_id &&
            (observation.observability === "not_observable" ||
              observation.observability === "session_secrets_required" ||
              observation.observability === "incomplete_capture"),
        )
      ) {
        notices.push(
          "At least one declared observation is incomplete or not observable; no missing edge was filled by inference.",
        );
      }
      return {
        sessionId: session.session_id,
        captureId: session.capture_id,
        protocol: session.protocol,
        tcpStreamId: session.tcp_stream_id,
        completeness: session.capture_completeness,
        xrayHref: `/analysis/${analysisId}/sessions/${session.session_id}`,
        paths,
        evidenceRoutes,
        relationships,
        notices,
      };
    });

  const relationships = sessions.flatMap((session) => session.relationships);
  const graphNodes = buildGraphNodes(analysisId, context, evidenceById);
  const graphNodeIds = new Set(graphNodes.map((node) => node.id));
  const graphEdges = relationships.filter(
    (relationship) =>
      graphNodeIds.has(relationship.fromId) &&
      graphNodeIds.has(relationship.toId),
  );
  const defaultSessionId =
    sessions.find((session) =>
      context.chain.findings.some(
        (finding) => finding.session_id === session.sessionId,
      ),
    )?.sessionId ??
    sessions.find((session) => session.completeness !== "complete")?.sessionId ??
    sessions[0]?.sessionId ??
    null;
  const limitations = collectLimitations(context);
  const policyRisk = context.chain.policy_risk;
  const anomalyResults = context.chain.anomaly_results;
  const partial =
    context.chain.analysis.analysis_status !== "complete" ||
    sessions.some((session) => session.notices.length > 0);

  return {
    analysisId,
    dataSource: result.data_source,
    datasetLabel: result.dataset_label,
    analysisStatus: context.chain.analysis.analysis_status,
    chainSchemaVersion: context.chain.chain_schema_version,
    sessionsHref: `/analysis/${analysisId}/sessions`,
    overviewHref: `/analysis/${analysisId}/overview`,
    sessions,
    graphNodes,
    graphEdges,
    defaultSessionId,
    relationshipCount: relationships.length,
    directEvidenceRelationshipCount: relationships.filter(
      (relationship) => relationship.relationshipType === "direct_evidence",
    ).length,
    declaredSourceRelationshipCount: relationships.filter(
      (relationship) => relationship.relationshipType === "declared_source",
    ).length,
    policyRisk: policyRisk
      ? {
          status: "available",
          policyRiskId: policyRisk.policy_risk_id,
          profileId: policyRisk.profile_id,
          cappedScore: policyRisk.capped_score,
          uncappedScore: policyRisk.uncapped_score,
          findingCount: context.chain.findings.length,
          contributionCount: policyRisk.contributions.length,
        }
      : {
          status: "not_present",
          policyRiskId: null,
          profileId: null,
          cappedScore: null,
          uncappedScore: null,
          findingCount: context.chain.findings.length,
          contributionCount: 0,
        },
    mlAnomaly: {
      engineStatus: context.chain.analysis.ml_engine_status,
      resultCount: anomalyResults.length,
      explicitEvidenceCount: anomalyResults.reduce(
        (count, result) => count + (result.evidence_ids?.length ?? 0),
        0,
      ),
      explicitLinkedFactCount: anomalyResults.reduce(
        (count, result) => count + (result.linked_fact_ids?.length ?? 0),
        0,
      ),
      explicitLinkedObservationCount: anomalyResults.reduce(
        (count, result) => count + (result.linked_observation_ids?.length ?? 0),
        0,
      ),
    },
    limitations,
    partial,
    empty: sessions.length === 0,
  };
}
