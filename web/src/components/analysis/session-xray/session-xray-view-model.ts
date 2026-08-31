import type { AnalysisResult } from "@/lib/contracts/analysis";

import { formatEndpoint, humanize } from "../sessions/session-formatters";
import {
  type SessionXRayIntegrityContext,
  validateSessionXRayIntegrity,
} from "./session-xray-integrity";

type Chain = AnalysisResult["chain"];
type ProtocolEvent = Chain["protocol_events"][number];
type CryptoObservation = Chain["crypto_observations"][number];
type DerivedFact = Chain["derived_facts"][number];
type AnalysisLimitation = Chain["analysis"]["limitations"][number];

export type EvidenceState =
  | "observed"
  | "derived"
  | "policy"
  | "unknown"
  | "not_observable"
  | "not_assessed"
  | "not_applicable"
  | "absent"
  | "incomplete";

export type XRayEvidence = {
  evidenceId: string;
  captureId: string;
  captureSha256: string;
  sessionId: string;
  frameNumbers: number[];
  occurrenceIndex: number;
  timestampStart: string;
  timestampEnd: string;
  direction: string;
  sourceKind: string;
  sourceField: string;
  safeExcerpt: string;
  displayFilter: string;
  observability: "observed";
  redaction: string;
  extractorVersion: string;
  eventIds: string[];
  observationIds: string[];
  factIdsThroughSources: string[];
  findingIds: string[];
};

export type XRayEvent = {
  eventId: string;
  sequenceIndex: number;
  title: string;
  description: string;
  eventType: string;
  protocol: string;
  stateBefore: string;
  stateAfter: string;
  timestamp: string;
  direction: string;
  eventStatus: string;
  observability: string;
  state: EvidenceState;
  frameNumbers: number[];
  evidence: XRayEvidence[];
  limitations: AnalysisLimitation[];
};

export type PostureItem = {
  label: string;
  value: string;
  detail: string;
  state: EvidenceState;
};

export type CryptoEntry = {
  id: string;
  label: string;
  value: string;
  detail: string;
  state: EvidenceState;
  observability: string;
  evidence: XRayEvidence[];
  evidenceRelationship: "direct" | "through_sources" | "none";
};

export type XRayFinding = {
  findingId: string;
  title: string;
  severity: string;
  category: string;
  ruleId: string;
  ruleVersion: string;
  profileId: string;
  ruleOutcome: string;
  ruleReasonCode: string;
  policyRiskContribution: number;
  evidenceConfidence: string;
  observability: string;
  rationale: string;
  impact: string;
  remediation: string;
  recommendationId: string;
  evidence: XRayEvidence[];
  limitations: AnalysisLimitation[];
};

export type XRayAnomaly = {
  anomalyResultId: string;
  modelId: string;
  modelVersion: string;
  featureSchemaVersion: string;
  rawScore: number;
  normalizedScore: number;
  threshold: number;
  band: string;
  unusualFeatureIndicators: string[];
  interpretationNote: string;
  linkedFactIds: string[];
  linkedObservationIds: string[];
  evidence: XRayEvidence[];
  limitations: AnalysisLimitation[];
};

export type ScopedLimitation = AnalysisLimitation & {
  scope: "session" | "analysis";
};

export type SessionXRayData = {
  analysisId: string;
  sessionId: string;
  dataSource: AnalysisResult["data_source"];
  datasetLabel: string | null;
  protocol: string;
  protocolConfidence: string;
  sourceEndpoint: string;
  destinationEndpoint: string;
  tcpStreamId: number;
  captureId: string;
  captureName: string | null;
  captureCompleteness: string;
  firstFrame: number;
  lastFrame: number;
  startedAt: string;
  endedAt: string;
  packetCount: number;
  byteCount: number;
  posture: PostureItem[];
  events: XRayEvent[];
  cryptoEntries: CryptoEntry[];
  certificateEntries: CryptoEntry[];
  tls13CertificateUnavailable: boolean;
  findings: XRayFinding[];
  anomalies: XRayAnomaly[];
  mlEngineStatus: string;
  evidence: XRayEvidence[];
  sessionLimitations: ScopedLimitation[];
  analysisLimitations: ScopedLimitation[];
};

const eventCopy: Record<
  ProtocolEvent["event_type"],
  { title: string; description: string }
> = {
  tcp_connected: {
    title: "TCP session established",
    description: "The validated event sequence records an open TCP session.",
  },
  server_greeting: {
    title: "Server greeting observed",
    description: "A privacy-safe server greeting event was recorded.",
  },
  capability_request: {
    title: "Capability request observed",
    description: "The client requested protocol capabilities.",
  },
  capability_advertised: {
    title: "Capability advertised",
    description: "The server advertised a protocol capability.",
  },
  tls_upgrade_requested: {
    title: "TLS upgrade requested",
    description: "The client requested an in-session TLS upgrade.",
  },
  tls_upgrade_accepted: {
    title: "TLS upgrade accepted",
    description: "The server accepted the upgrade request.",
  },
  tls_upgrade_rejected: {
    title: "TLS upgrade rejected",
    description: "The server rejected the upgrade request.",
  },
  client_hello: {
    title: "TLS ClientHello observed",
    description: "A ClientHello handshake message was recorded.",
  },
  server_hello: {
    title: "TLS ServerHello observed",
    description: "A ServerHello handshake message was recorded.",
  },
  certificate_message: {
    title: "Certificate message observed",
    description: "A certificate-message event was visible in the capture.",
  },
  key_exchange_observed: {
    title: "Key-exchange evidence observed",
    description: "A key-exchange-related event was recorded.",
  },
  handshake_finished: {
    title: "Handshake completion recorded",
    description:
      "The event record states handshake completion; its status identifies whether this was observed or derived.",
  },
  encrypted_application_data: {
    title: "Encrypted application data observed",
    description:
      "Encrypted application data was present. Its contents were not inspected.",
  },
  plaintext_command_after_tls_offer: {
    title: "Plaintext continued after TLS offer",
    description:
      "A privacy-safe event records plaintext protocol continuation after an advertised TLS upgrade.",
  },
  session_closed: {
    title: "Session closed",
    description: "The validated event sequence records session closure.",
  },
  capture_boundary_reached: {
    title: "Capture boundary reached",
    description: "The available event sequence ends at a capture boundary.",
  },
};

const certificateObservationKinds = new Set<CryptoObservation["kind"]>([
  "signature_algorithm",
  "public_key_algorithm",
  "public_key_length",
  "certificate_subject",
  "certificate_issuer",
  "certificate_san",
  "certificate_validity_window",
  "certificate_fingerprint",
  "certificate_chain_structure",
  "certificate_serial_number",
  "certificate_basic_constraints",
  "certificate_key_usage",
  "certificate_structure_parsed",
  "certificate_signature_chain_checked",
  "certificate_trusted_path_validated",
  "certificate_service_identity_validated",
  "certificate_revocation_checked",
  "tls13_certificate_unavailable",
]);

const cryptoObservationLabels: Partial<
  Record<CryptoObservation["kind"], string>
> = {
  tls_negotiated_version: "TLS version",
  selected_cipher_suite: "Cipher suite",
  key_share_group: "Key-share group",
  psk_key_exchange_mode: "PSK key-exchange mode",
  record_layer_legacy_version: "Record-layer legacy version",
  supported_versions: "Supported versions evidence",
  session_resumption_indicator: "Session resumption indicator",
};

export function stateFromObservability(observability: string): EvidenceState {
  if (observability === "incomplete_capture") return "incomplete";
  if (
    observability === "not_observable" ||
    observability === "session_secrets_required"
  ) {
    return "not_observable";
  }
  if (observability === "not_applicable") return "not_applicable";
  if (observability === "policy_inferred") return "policy";
  if (observability === "derived") return "derived";
  return "observed";
}

function formatJsonValue(value: unknown): string {
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  if (value === null) return "null";
  return JSON.stringify(value);
}

function uniqueLimitations(
  limitations: AnalysisLimitation[],
  scope: ScopedLimitation["scope"],
): ScopedLimitation[] {
  return [
    ...new Map(
      limitations.map((limitation) => [
        `${limitation.code}:${limitation.summary}:${limitation.detail}`,
        { ...limitation, scope },
      ]),
    ).values(),
  ].sort((left, right) =>
    `${left.code}:${left.summary}`.localeCompare(
      `${right.code}:${right.summary}`,
    ),
  );
}

function collectFactEvidenceIds(
  fact: DerivedFact,
  factsById: Map<string, DerivedFact>,
  eventsById: Map<string, ProtocolEvent>,
  observationsById: Map<string, CryptoObservation>,
  visited = new Set<string>(),
): Set<string> {
  if (visited.has(fact.fact_id)) return new Set();
  visited.add(fact.fact_id);

  const evidenceIds = new Set<string>();
  for (const eventId of fact.source_event_ids) {
    for (const evidenceId of eventsById.get(eventId)!.evidence_ids) {
      evidenceIds.add(evidenceId);
    }
  }
  for (const observationId of fact.source_observation_ids) {
    for (const evidenceId of observationsById.get(observationId)!.evidence_ids) {
      evidenceIds.add(evidenceId);
    }
  }
  for (const sourceFactId of fact.source_fact_ids) {
    for (const evidenceId of collectFactEvidenceIds(
      factsById.get(sourceFactId)!,
      factsById,
      eventsById,
      observationsById,
      visited,
    )) {
      evidenceIds.add(evidenceId);
    }
  }
  return evidenceIds;
}

function buildEvidence(
  context: SessionXRayIntegrityContext,
): Map<string, XRayEvidence> {
  const {
    sessionEvents,
    sessionObservations,
    sessionFacts,
    sessionFindings,
    sessionEvidence,
    eventsById,
    observationsById,
    factsById,
  } = context;

  const factIdsByEvidence = new Map<string, string[]>();
  for (const fact of sessionFacts) {
    for (const evidenceId of collectFactEvidenceIds(
      fact,
      factsById,
      eventsById,
      observationsById,
    )) {
      factIdsByEvidence.set(evidenceId, [
        ...(factIdsByEvidence.get(evidenceId) ?? []),
        fact.fact_id,
      ]);
    }
  }

  return new Map(
    sessionEvidence.map((evidence) => [
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
          eventIds: sessionEvents
            .filter((event) => event.evidence_ids.includes(evidence.evidence_id))
            .map((event) => event.event_id),
          observationIds: sessionObservations
            .filter((observation) =>
              observation.evidence_ids.includes(evidence.evidence_id),
            )
            .map((observation) => observation.observation_id),
          factIdsThroughSources: [
            ...(factIdsByEvidence.get(evidence.evidence_id) ?? []),
          ],
          findingIds: sessionFindings
            .filter((finding) =>
              finding.evidence_ids.includes(evidence.evidence_id),
            )
            .map((finding) => finding.finding_id),
        },
      ]),
  );
}

function linkedEvidence(
  evidenceById: Map<string, XRayEvidence>,
  evidenceIds: string[],
): XRayEvidence[] {
  return evidenceIds.map((evidenceId) => evidenceById.get(evidenceId)!);
}

function eventPresence(
  events: XRayEvent[],
  eventTypes: string[],
  label: string,
): PostureItem {
  const matches = events.filter((event) => eventTypes.includes(event.eventType));
  if (matches.length === 0) {
    return {
      label,
      value: "No validated event present",
      detail: "Absence of an event record is not treated as a verified failure.",
      state: "absent",
    };
  }

  const state = matches.some((event) => event.state === "incomplete")
    ? "incomplete"
    : matches.some((event) => event.state === "not_observable")
      ? "not_observable"
      : matches.some((event) => event.state === "unknown")
        ? "unknown"
        : matches.some((event) => event.state === "not_assessed")
          ? "not_assessed"
          : matches.some((event) => event.state === "not_applicable")
            ? "not_applicable"
      : matches.some((event) => event.state === "derived")
        ? "derived"
        : "observed";
  return {
    label,
    value: `${matches.length} validated ${matches.length === 1 ? "event" : "events"}`,
    detail: matches.map((event) => event.title).join(" · "),
    state,
  };
}

function buildUpgradeState(events: XRayEvent[]): PostureItem {
  const hasAccepted = events.some(
    (event) => event.eventType === "tls_upgrade_accepted",
  );
  const hasRejected = events.some(
    (event) => event.eventType === "tls_upgrade_rejected",
  );
  const hasRequested = events.some(
    (event) => event.eventType === "tls_upgrade_requested",
  );
  const hasAdvertised = events.some(
    (event) => event.eventType === "capability_advertised",
  );

  if (hasAccepted && hasRejected) {
    return {
      label: "TLS upgrade state",
      value: "Conflicting validated outcomes",
      detail:
        "Acceptance and rejection events are both present; no single outcome is inferred.",
      state: "unknown",
    };
  }
  if (hasAccepted) {
    return {
      label: "TLS upgrade state",
      value: "Acceptance event present",
      detail:
        "This is the server transition response, not by itself proof that TLS negotiation completed.",
      state: "observed",
    };
  }
  if (hasRejected) {
    return {
      label: "TLS upgrade state",
      value: "Rejection event present",
      detail: "The validated event sequence contains an explicit rejection.",
      state: "observed",
    };
  }
  if (hasRequested) {
    return {
      label: "TLS upgrade state",
      value: "Request present; outcome unavailable",
      detail: "No validated acceptance or rejection event is present.",
      state: "unknown",
    };
  }
  if (hasAdvertised) {
    return {
      label: "TLS upgrade state",
      value: "Capability advertised; no request event",
      detail: "No upgrade outcome is inferred from the advertisement alone.",
      state: "absent",
    };
  }
  return {
    label: "TLS upgrade state",
    value: "No validated transition event",
    detail: "No success or failure is inferred.",
    state: "absent",
  };
}

function observationEntry(
  observation: CryptoObservation,
  evidenceById: Map<string, XRayEvidence>,
  label: string,
): CryptoEntry {
  return {
    id: observation.observation_id,
    label,
    value: observation.normalized_value,
    detail: `Validated ${humanize(observation.kind)} observation.`,
    state: stateFromObservability(observation.observability),
    observability: observation.observability,
    evidence: linkedEvidence(evidenceById, observation.evidence_ids),
    evidenceRelationship: "direct",
  };
}

function factEntry(
  fact: DerivedFact,
  evidenceById: Map<string, XRayEvidence>,
  context: SessionXRayIntegrityContext,
  label: string,
): CryptoEntry {
  return {
    id: fact.fact_id,
    label,
    value: formatJsonValue(fact.value),
    detail: `Derived by ${fact.derivation_id} v${fact.derivation_version}; confidence ${humanize(fact.confidence_level)}.`,
    state: stateFromObservability(fact.observability),
    observability: fact.observability,
    evidence: factEvidence(fact, evidenceById, context),
    evidenceRelationship: "through_sources",
  };
}

function factEvidence(
  fact: DerivedFact,
  evidenceById: Map<string, XRayEvidence>,
  context: SessionXRayIntegrityContext,
): XRayEvidence[] {
  return linkedEvidence(
    evidenceById,
    [
      ...collectFactEvidenceIds(
        fact,
        context.factsById,
        context.eventsById,
        context.observationsById,
      ),
    ],
  );
}

export function orderProtocolEvents(
  events: ProtocolEvent[],
): ProtocolEvent[] {
  return events
    .map((event, contractOccurrence) => ({ event, contractOccurrence }))
    .sort(
      (left, right) =>
        left.event.sequence_index - right.event.sequence_index ||
        left.contractOccurrence - right.contractOccurrence,
    )
    .map(({ event }) => event);
}

export function buildSessionXRayData(
  result: AnalysisResult,
  sessionId: string,
): SessionXRayData | null {
  const context = validateSessionXRayIntegrity(result, sessionId);
  if (!context) return null;
  const { chain, session, capture } = context;
  const evidenceById = buildEvidence(context);
  const sourceEvents = orderProtocolEvents(context.sessionEvents);
  const events: XRayEvent[] = sourceEvents.map((event) => {
    const evidence = linkedEvidence(evidenceById, event.evidence_ids);
    const copy = eventCopy[event.event_type];
    return {
      eventId: event.event_id,
      sequenceIndex: event.sequence_index,
      title: copy.title,
      description: copy.description,
      eventType: event.event_type,
      protocol: event.protocol,
      stateBefore: event.state_before,
      stateAfter: event.state_after,
      timestamp: event.timestamp,
      direction: event.direction,
      eventStatus: event.event_status,
      observability: event.observability,
      state: stateFromObservability(event.observability),
      frameNumbers: evidence.flatMap((item) => item.frameNumbers),
      evidence,
      limitations: event.limitations,
    };
  });

  const sessionObservations = [...context.sessionObservations]
    .sort((left, right) => left.observation_id.localeCompare(right.observation_id));
  const sessionFacts = [...context.sessionFacts]
    .sort((left, right) => left.fact_id.localeCompare(right.fact_id));
  const upgradeFact = sessionFacts.find(
    (fact) => fact.fact_type === "tls_upgrade_completed",
  );
  const cryptoEntries: CryptoEntry[] = [];
  if (upgradeFact) {
    cryptoEntries.push({
      id: upgradeFact.fact_id,
      label: "TLS upgrade completion",
      value:
        upgradeFact.value === true
          ? "Completed"
          : upgradeFact.value === false
            ? "Not completed"
            : formatJsonValue(upgradeFact.value),
      detail: `Derived by ${upgradeFact.derivation_id} v${upgradeFact.derivation_version}; confidence ${humanize(upgradeFact.confidence_level)}.`,
      state: stateFromObservability(upgradeFact.observability),
      observability: upgradeFact.observability,
      evidence: factEvidence(upgradeFact, evidenceById, context),
      evidenceRelationship: "through_sources",
    });
  } else {
    cryptoEntries.push({
      id: "tls-upgrade-not-assessed",
      label: "TLS upgrade completion",
      value: "Not assessed",
      detail: "No validated TLS upgrade-completion fact is present.",
      state: "not_assessed",
      observability: "not_assessed",
      evidence: [],
      evidenceRelationship: "none",
    });
  }

  for (const observation of sessionObservations) {
    const label = cryptoObservationLabels[observation.kind];
    if (!label) continue;
    cryptoEntries.push(observationEntry(observation, evidenceById, label));
  }
  const forwardSecrecyFact = sessionFacts.find(
    (fact) => fact.fact_type === "forward_secrecy",
  );
  cryptoEntries.push(
    forwardSecrecyFact
      ? factEntry(
          forwardSecrecyFact,
          evidenceById,
          context,
          "Forward Secrecy",
        )
      : {
          id: "forward-secrecy-not-assessed",
          label: "Forward Secrecy",
          value: "Not assessed",
          detail:
            "The frontend does not infer Forward Secrecy from the TLS version, cipher suite, or key-share group.",
          state: "not_assessed",
          observability: "not_assessed",
          evidence: [],
          evidenceRelationship: "none",
        },
  );

  const certificateObservations = sessionObservations.filter((observation) =>
    certificateObservationKinds.has(observation.kind),
  );
  const tls13CertificateUnavailable = certificateObservations.some(
    (observation) => observation.kind === "tls13_certificate_unavailable",
  );
  const certificateEntries = certificateObservations
    .filter(
      (observation) => observation.kind !== "tls13_certificate_unavailable",
    )
    .map((observation) =>
      observationEntry(
        observation,
        evidenceById,
        humanize(observation.kind),
      ),
    );
  const certificateVisibilityFact = sessionFacts.find(
    (fact) => fact.fact_type === "certificate_observability",
  );
  if (certificateVisibilityFact) {
    certificateEntries.unshift(
      factEntry(
        certificateVisibilityFact,
        evidenceById,
        context,
        "Certificate observability",
      ),
    );
  }
  const findings: XRayFinding[] = [...context.sessionFindings]
    .sort((left, right) => left.finding_id.localeCompare(right.finding_id))
    .map((finding) => {
      const evaluation = context.evaluationsById.get(
        finding.rule_evaluation_id,
      )!;
      const recommendation = context.recommendationsById.get(
        finding.recommendation_id,
      )!;
      return {
        findingId: finding.finding_id,
        title: finding.title,
        severity: finding.severity,
        category: finding.category,
        ruleId: finding.rule_id,
        ruleVersion: finding.rule_version,
        profileId: evaluation.profile_id,
        ruleOutcome: evaluation.outcome,
        ruleReasonCode: evaluation.reason_code,
        policyRiskContribution: finding.policy_risk_contribution,
        evidenceConfidence: finding.evidence_confidence,
        observability: finding.observability,
        rationale: finding.rationale,
        impact: finding.impact,
        remediation: recommendation.summary,
        recommendationId: finding.recommendation_id,
        evidence: linkedEvidence(evidenceById, finding.evidence_ids),
        limitations: finding.limitations,
      };
    });

  const anomalies = [...context.sessionAnomalies]
    .sort((left, right) =>
      left.anomaly_result_id.localeCompare(right.anomaly_result_id),
    );
  const anomalyEntries: XRayAnomaly[] = anomalies.map((anomaly) => ({
    anomalyResultId: anomaly.anomaly_result_id,
    modelId: anomaly.model_id,
    modelVersion: anomaly.model_version,
    featureSchemaVersion: anomaly.feature_schema_version,
    rawScore: anomaly.raw_score,
    normalizedScore: anomaly.normalized_score,
    threshold: anomaly.threshold,
    band: anomaly.band,
    unusualFeatureIndicators: anomaly.unusual_feature_indicators,
    interpretationNote: anomaly.interpretation_note,
    linkedFactIds: anomaly.linked_fact_ids ?? [],
    linkedObservationIds: anomaly.linked_observation_ids ?? [],
    evidence: linkedEvidence(evidenceById, anomaly.evidence_ids ?? []),
    limitations: anomaly.limitations,
  }));
  const mlPosture: PostureItem =
    chain.analysis.ml_engine_status === "not_run"
      ? {
          label: "ML anomaly",
          value: "Not run",
          detail:
            "No anomaly score is present; Policy Risk remains separate.",
          state: "not_assessed",
        }
      : anomalies.length === 0
        ? {
            label: "ML anomaly",
            value: "No validated session result",
            detail: `Engine status: ${humanize(chain.analysis.ml_engine_status)}. Absence is not rendered as zero.`,
            state: "absent",
          }
        : {
            label: "ML anomaly",
            value: anomalies.map((anomaly) => humanize(anomaly.band)).join(" · "),
            detail: `${anomalies.length} validated result${anomalies.length === 1 ? "" : "s"}; anomalous behavior is not proof of malicious activity.`,
            state: "observed",
          };

  const posture: PostureItem[] = [
    {
      label: "Email protocol",
      value: session.protocol.toUpperCase(),
      detail: `Validated classification confidence: ${humanize(session.protocol_confidence)}.`,
      state: "observed",
    },
    buildUpgradeState(events),
    eventPresence(
      events,
      ["capability_advertised"],
      "Capability advertisement",
    ),
    eventPresence(events, ["tls_upgrade_requested"], "Upgrade request"),
    eventPresence(
      events,
      ["tls_upgrade_accepted", "tls_upgrade_rejected"],
      "Server outcome",
    ),
    eventPresence(
      events,
      ["plaintext_command_after_tls_offer"],
      "Plaintext continuation",
    ),
    eventPresence(
      events,
      [
        "client_hello",
        "server_hello",
        "certificate_message",
        "key_exchange_observed",
        "handshake_finished",
      ],
      "TLS handshake messages",
    ),
    {
      label: "Linked Policy Risk",
      value:
        findings.length === 0
          ? "No linked findings"
          : `${findings.length} linked ${findings.length === 1 ? "finding" : "findings"}`,
      detail:
        findings.length === 0
          ? "No deterministic policy finding is linked to this session."
          : "Validated deterministic policy output; kept separate from ML Anomaly.",
      state: findings.length === 0 ? "absent" : "policy",
    },
    mlPosture,
  ];

  const sessionScopedLimitations = [
    ...session.limitations,
    ...sourceEvents.flatMap((event) => event.limitations),
    ...sessionObservations.flatMap((observation) => observation.limitations),
    ...sessionFacts.flatMap((fact) => fact.limitations),
    ...chain.findings
      .filter((finding) => finding.session_id === sessionId)
      .flatMap((finding) => finding.limitations),
    ...anomalies.flatMap((anomaly) => anomaly.limitations),
  ];

  return {
    analysisId: chain.analysis.analysis_id,
    sessionId: session.session_id,
    dataSource: result.data_source,
    datasetLabel: result.dataset_label,
    protocol: session.protocol,
    protocolConfidence: session.protocol_confidence,
    sourceEndpoint: formatEndpoint(
      session.source_endpoint.ip,
      session.source_endpoint.port,
    ),
    destinationEndpoint: formatEndpoint(
      session.destination_endpoint.ip,
      session.destination_endpoint.port,
    ),
    tcpStreamId: session.tcp_stream_id,
    captureId: session.capture_id,
    captureName: capture.original_filename_sanitized,
    captureCompleteness: session.capture_completeness,
    firstFrame: session.first_frame,
    lastFrame: session.last_frame,
    startedAt: session.started_at,
    endedAt: session.ended_at,
    packetCount: session.packet_count,
    byteCount: session.byte_count,
    posture,
    events,
    cryptoEntries,
    certificateEntries,
    tls13CertificateUnavailable,
    findings,
    anomalies: anomalyEntries,
    mlEngineStatus: chain.analysis.ml_engine_status,
    evidence: [...evidenceById.values()],
    sessionLimitations: uniqueLimitations(sessionScopedLimitations, "session"),
    analysisLimitations: uniqueLimitations(
      chain.analysis.limitations,
      "analysis",
    ),
  };
}
