import { buildSessionXRayData, type XRayEvidence } from "@/components/analysis/session-xray/session-xray-view-model";
import { formatEndpoint, humanize } from "@/components/analysis/sessions/session-formatters";
import type { AnalysisResult } from "@/lib/contracts/analysis";

type Chain = AnalysisResult["chain"];
type Session = Chain["sessions"][number];
type ProtocolEvent = Chain["protocol_events"][number];
type CryptoObservation = Chain["crypto_observations"][number];
type DerivedFact = Chain["derived_facts"][number];
type Limitation = Chain["analysis"]["limitations"][number];
type SafeComparisonObservationKind = Extract<
  CryptoObservation["kind"],
  | "tls_negotiated_version"
  | "selected_cipher_suite"
  | "key_share_group"
  | "psk_key_exchange_mode"
  | "tls13_certificate_unavailable"
>;
type SafeComparisonFactType =
  | "tls_upgrade_completed"
  | "forward_secrecy"
  | "certificate_observability";

export type ComparisonEvidenceRelationship =
  | "direct"
  | "through_sources"
  | "none";

export type ComparisonCell = {
  value: string;
  state: string | null;
  detail: string[];
  evidence: XRayEvidence[];
  evidenceRelationship: ComparisonEvidenceRelationship;
};

export type ComparisonRow = {
  key: string;
  label: string;
  sessionA: ComparisonCell;
  sessionB: ComparisonCell;
  differs: boolean;
};

export type ComparisonCategory = {
  key: string;
  title: string;
  description: string;
  rows: ComparisonRow[];
};

export type ComparisonSessionOption = {
  sessionId: string;
  protocol: string;
  captureName: string;
  sourceEndpoint: string;
  destinationEndpoint: string;
  tcpStreamId: number;
};

export type ComparisonSessionSummary = {
  sessionId: string;
  captureId: string;
  captureName: string;
  captureSha256: string;
  xrayHref: string;
  highlights: Array<{
    label: string;
    value: string;
    state: string | null;
  }>;
};

export type ComparisonPageData = {
  analysisId: string;
  dataSource: AnalysisResult["data_source"];
  datasetLabel: string | null;
  analysisStatus: string;
  options: ComparisonSessionOption[];
  selectedA: string;
  selectedB: string;
  sessionA: ComparisonSessionSummary;
  sessionB: ComparisonSessionSummary;
  categories: ComparisonCategory[];
  differenceCount: number;
  policyRisk: {
    status: "available" | "not_present";
    profileId: string | null;
    cappedScore: number | null;
    uncappedScore: number | null;
  };
  mlAnomaly: {
    engineStatus: string;
    resultCount: number;
  };
  overviewHref: string;
  sessionsHref: string;
  proofMapHref: string;
  policyFindingsHref: string;
};

function textCell(
  value: string,
  options: Partial<Omit<ComparisonCell, "value">> = {},
): ComparisonCell {
  return {
    value,
    state: options.state ?? null,
    detail: options.detail ?? [],
    evidence: options.evidence ?? [],
    evidenceRelationship: options.evidenceRelationship ?? "none",
  };
}

function missingCell(
  state: "not_present" | "not_assessed" | "not_observable",
  detail: string,
): ComparisonCell {
  return textCell(state, { state, detail: [detail] });
}

function formatValue(value: unknown): string {
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  if (value === null) return "null";
  return JSON.stringify(value);
}

function uniqueEvidence(records: XRayEvidence[]): XRayEvidence[] {
  return [
    ...new Map(records.map((record) => [record.evidenceId, record])).values(),
  ];
}

function uniqueLimitations(limitations: Limitation[]): Limitation[] {
  return [
    ...new Map(
      limitations.map((limitation) => [
        `${limitation.code}:${limitation.summary}:${limitation.detail}`,
        limitation,
      ]),
    ).values(),
  ];
}

function cellKey(cell: ComparisonCell): string {
  return JSON.stringify({
    value: cell.value,
    state: cell.state,
    detail: cell.detail,
  });
}

function row(
  key: string,
  label: string,
  sessionA: ComparisonCell,
  sessionB: ComparisonCell,
): ComparisonRow {
  return {
    key,
    label,
    sessionA,
    sessionB,
    differs: cellKey(sessionA) !== cellKey(sessionB),
  };
}

type SessionContext = {
  session: Session;
  capture: Chain["captures"][number];
  events: ProtocolEvent[];
  observations: CryptoObservation[];
  facts: DerivedFact[];
  findings: Chain["findings"];
  anomalies: Chain["anomaly_results"];
  evidence: XRayEvidence[];
  sessionLimitations: Limitation[];
};

function buildSessionContext(
  result: AnalysisResult,
  session: Session,
): SessionContext {
  const capture = result.chain.captures.find(
    (record) => record.capture_id === session.capture_id,
  )!;
  const xray = buildSessionXRayData(result, session.session_id);
  if (!xray) {
    throw new Error(`Selected session ${session.session_id} is unavailable.`);
  }
  return {
    session,
    capture,
    events: result.chain.protocol_events.filter(
      (event) => event.session_id === session.session_id,
    ),
    observations: result.chain.crypto_observations.filter(
      (observation) => observation.session_id === session.session_id,
    ),
    facts: result.chain.derived_facts.filter(
      (fact) => fact.session_id === session.session_id,
    ),
    findings: result.chain.findings.filter(
      (finding) => finding.session_id === session.session_id,
    ),
    anomalies: result.chain.anomaly_results.filter(
      (anomaly) => anomaly.session_id === session.session_id,
    ),
    evidence: xray.evidence,
    sessionLimitations: xray.sessionLimitations,
  };
}

function evidenceByIds(
  context: SessionContext,
  evidenceIds: string[],
): XRayEvidence[] {
  const byId = new Map(
    context.evidence.map((evidence) => [evidence.evidenceId, evidence]),
  );
  return evidenceIds.map((evidenceId) => byId.get(evidenceId)!);
}

function eventCell(
  context: SessionContext,
  eventTypes: ProtocolEvent["event_type"][],
  absentDetail: string,
): ComparisonCell {
  const events = context.events
    .filter((event) => eventTypes.includes(event.event_type))
    .sort(
      (left, right) =>
        left.sequence_index - right.sequence_index ||
        left.event_id.localeCompare(right.event_id),
    );
  if (events.length === 0) return missingCell("not_present", absentDetail);

  return textCell(events.map((event) => event.event_type).join(" · "), {
    state: [...new Set(events.map((event) => event.observability))].join(" · "),
    detail: events.map(
      (event) =>
        `${event.event_id} · ${event.event_status} · ${event.state_before} → ${event.state_after}`,
    ),
    evidence: uniqueEvidence(
      events.flatMap((event) => evidenceByIds(context, event.evidence_ids)),
    ),
    evidenceRelationship: "direct",
  });
}

function observationCell(
  context: SessionContext,
  kinds: SafeComparisonObservationKind[],
  missingState: "not_present" | "not_assessed" = "not_present",
): ComparisonCell {
  const allowedKinds = new Set<CryptoObservation["kind"]>(kinds);
  const observations = context.observations
    .filter((observation) => allowedKinds.has(observation.kind))
    .sort((left, right) => left.observation_id.localeCompare(right.observation_id));
  if (observations.length === 0) {
    return missingCell(
      missingState,
      `No validated ${kinds.map(humanize).join(" or ")} observation is present.`,
    );
  }
  return textCell(
    observations
      .map((observation) =>
        observations.length === 1
          ? observation.normalized_value
          : `${observation.kind}: ${observation.normalized_value}`,
      )
      .join(" · "),
    {
      state: [
        ...new Set(observations.map((observation) => observation.observability)),
      ].join(" · "),
      detail: observations.flatMap((observation) => [
        observation.observation_id,
        ...observation.limitations.map(
          (limitation) => `${limitation.code}: ${limitation.summary}`,
        ),
      ]),
      evidence: uniqueEvidence(
        observations.flatMap((observation) =>
          evidenceByIds(context, observation.evidence_ids),
        ),
      ),
      evidenceRelationship: "direct",
    },
  );
}

function factCell(
  context: SessionContext,
  factType: SafeComparisonFactType,
  missingDetail: string,
): ComparisonCell {
  const facts = context.facts
    .filter((fact) => fact.fact_type === factType)
    .sort((left, right) => left.fact_id.localeCompare(right.fact_id));
  if (facts.length === 0) return missingCell("not_assessed", missingDetail);

  return textCell(
    facts
      .map((fact) =>
        facts.length === 1
          ? formatValue(fact.value)
          : `${fact.fact_id}: ${formatValue(fact.value)}`,
      )
      .join(" · "),
    {
      state: [...new Set(facts.map((fact) => fact.observability))].join(" · "),
      detail: facts.flatMap((fact) => [
        `${fact.fact_id} · ${fact.derivation_id} v${fact.derivation_version} · confidence ${fact.confidence_level}`,
        ...fact.limitations.map(
          (limitation) => `${limitation.code}: ${limitation.summary}`,
        ),
      ]),
      evidence: uniqueEvidence(
        facts.flatMap((fact) =>
          context.evidence.filter((evidence) =>
            evidence.factIdsThroughSources.includes(fact.fact_id),
          ),
        ),
      ),
      evidenceRelationship: "through_sources",
    },
  );
}

function certificateCell(context: SessionContext): ComparisonCell {
  const fact = context.facts.find(
    (candidate) => candidate.fact_type === "certificate_observability",
  );
  if (fact) {
    return factCell(
      context,
      "certificate_observability",
      "Certificate observability was not assessed.",
    );
  }
  return observationCell(
    context,
    ["tls13_certificate_unavailable"],
    "not_assessed",
  );
}

function findingCell(context: SessionContext): ComparisonCell {
  if (context.findings.length === 0) {
    return missingCell(
      "not_present",
      "No deterministic policy finding is explicitly linked to this session.",
    );
  }
  const findings = [...context.findings].sort((left, right) =>
    left.finding_id.localeCompare(right.finding_id),
  );
  return textCell(findings.map((finding) => finding.finding_id).join(" · "), {
    state: "policy_inferred",
    detail: findings.map(
      (finding) =>
        `${finding.title} · severity ${finding.severity} · ${finding.rule_id} v${finding.rule_version}`,
    ),
    evidence: uniqueEvidence(
      findings.flatMap((finding) =>
        context.evidence.filter((evidence) =>
          evidence.findingIds.includes(finding.finding_id),
        ),
      ),
    ),
    evidenceRelationship: "direct",
  });
}

function policyContributionCell(
  result: AnalysisResult,
  context: SessionContext,
): ComparisonCell {
  const findingIds = new Set(
    context.findings.map((finding) => finding.finding_id),
  );
  const contributions = (result.chain.policy_risk?.contributions ?? [])
    .filter((contribution) => findingIds.has(contribution.finding_id))
    .sort((left, right) =>
      left.contribution_id.localeCompare(right.contribution_id),
    );
  if (contributions.length === 0) {
    return missingCell(
      "not_present",
      "No deterministic Policy Risk contribution is linked to this session.",
    );
  }
  return textCell(
    contributions
      .map(
        (contribution) =>
          `${contribution.finding_id}: ${contribution.policy_risk_contribution}`,
      )
      .join(" · "),
    {
      state: "policy_inferred",
      detail: contributions.map(
        (contribution) =>
          `${contribution.contribution_id} · adjusted ${contribution.confidence_adjusted_points} · factor ${contribution.confidence_factor} · ${contribution.severity} / ${contribution.evidence_confidence} confidence`,
      ),
      evidence: findingCell(context).evidence,
      evidenceRelationship: "direct",
    },
  );
}

function mlEngineCell(
  result: AnalysisResult,
  context: SessionContext,
): ComparisonCell {
  return textCell(result.chain.analysis.ml_engine_status, {
    state: result.chain.analysis.ml_engine_status,
    detail: [
      `${context.anomalies.length} explicit session result${context.anomalies.length === 1 ? "" : "s"} supplied`,
      "ML Anomaly remains independent of deterministic Policy Risk.",
    ],
  });
}

function anomalyCell(context: SessionContext): ComparisonCell {
  if (context.anomalies.length === 0) {
    return missingCell(
      "not_present",
      "No explicit ML anomaly result is supplied for this session; no zero score is implied.",
    );
  }
  const anomalies = [...context.anomalies].sort((left, right) =>
    left.anomaly_result_id.localeCompare(right.anomaly_result_id),
  );
  return textCell(
    anomalies.map((anomaly) => anomaly.anomaly_result_id).join(" · "),
    {
      state: anomalies.map((anomaly) => anomaly.band).join(" · "),
      detail: anomalies.map(
        (anomaly) =>
          `${anomaly.model_id} v${anomaly.model_version} · raw ${anomaly.raw_score} · normalized ${anomaly.normalized_score} · threshold ${anomaly.threshold} · ${anomaly.interpretation_note}`,
      ),
      evidence: uniqueEvidence(
        anomalies.flatMap((anomaly) =>
          evidenceByIds(context, anomaly.evidence_ids ?? []),
        ),
      ),
      evidenceRelationship: "direct",
    },
  );
}

function evidenceCell(context: SessionContext): ComparisonCell {
  if (context.evidence.length === 0) {
    return missingCell(
      "not_present",
      "No evidence reference is supplied for this session.",
    );
  }
  return textCell(
    context.evidence.map((evidence) => evidence.evidenceId).join(" · "),
    {
      state: "observed",
      detail: context.evidence.map(
        (evidence) =>
          `${evidence.evidenceId} · frame ${evidence.frameNumbers.join(", ")} · ${evidence.sourceKind}:${evidence.sourceField}`,
      ),
      evidence: context.evidence,
      evidenceRelationship: "direct",
    },
  );
}

function limitationCell(
  limitations: Limitation[],
  emptyDetail: string,
): ComparisonCell {
  const records = uniqueLimitations(limitations);
  if (records.length === 0) return missingCell("not_present", emptyDetail);
  return textCell(records.map((limitation) => limitation.code).join(" · "), {
    state: records.map((limitation) => limitation.code).join(" · "),
    detail: records.map(
      (limitation) =>
        `${limitation.code}: ${limitation.summary}${limitation.detail ? ` · ${limitation.detail}` : ""}`,
    ),
  });
}

function captureIdentityCell(context: SessionContext): ComparisonCell {
  return textCell(
    `${context.capture.capture_id} · ${context.capture.original_filename_sanitized}`,
    {
      detail: [
        `${context.capture.format} · ${context.capture.size_bytes.toLocaleString("en")} bytes`,
      ],
    },
  );
}

function buildCategories(
  result: AnalysisResult,
  sessionA: SessionContext,
  sessionB: SessionContext,
): ComparisonCategory[] {
  const both = (
    key: string,
    label: string,
    getCell: (context: SessionContext) => ComparisonCell,
  ) => row(key, label, getCell(sessionA), getCell(sessionB));

  return [
    {
      key: "identity",
      title: "Session identity and provenance",
      description:
        "Validated session and capture metadata; endpoints and ports are identifiers, not protocol proof.",
      rows: [
        both("session-id", "Session ID", (context) =>
          textCell(context.session.session_id),
        ),
        both("capture", "Capture ID and filename", captureIdentityCell),
        both("capture-sha256", "Capture SHA-256", (context) =>
          textCell(context.capture.sha256),
        ),
        both("protocol", "Protocol and confidence", (context) =>
          textCell(
            `${context.session.protocol.toUpperCase()} · ${context.session.protocol_confidence}`,
            {
              state: context.session.protocol_confidence,
              evidence: evidenceByIds(
                context,
                context.session.classification_evidence_ids,
              ),
              evidenceRelationship: "direct",
            },
          ),
        ),
        both("source", "Source endpoint", (context) =>
          textCell(
            formatEndpoint(
              context.session.source_endpoint.ip,
              context.session.source_endpoint.port,
            ),
          ),
        ),
        both("destination", "Destination endpoint", (context) =>
          textCell(
            formatEndpoint(
              context.session.destination_endpoint.ip,
              context.session.destination_endpoint.port,
            ),
          ),
        ),
        both("tcp-stream", "TCP stream", (context) =>
          textCell(String(context.session.tcp_stream_id)),
        ),
        both("completeness", "Session completeness", (context) =>
          textCell(context.session.capture_completeness, {
            state: context.session.capture_completeness,
          }),
        ),
        both("boundaries", "Frame and timestamp boundaries", (context) =>
          textCell(
            `frames ${context.session.first_frame}–${context.session.last_frame}`,
            {
              detail: [
                `${context.session.started_at} → ${context.session.ended_at}`,
              ],
            },
          ),
        ),
        both("packets", "Packet count", (context) =>
          textCell(context.session.packet_count.toLocaleString("en")),
        ),
        both("bytes", "Byte count", (context) =>
          textCell(context.session.byte_count.toLocaleString("en")),
        ),
      ],
    },
    {
      key: "transition",
      title: "Email-to-TLS transition",
      description:
        "Explicit event and derived-fact records only. An advertisement or acceptance event is not silently promoted into handshake success.",
      rows: [
        both("capability", "TLS capability advertisement", (context) =>
          eventCell(
            context,
            ["capability_advertised"],
            "No validated capability-advertisement event is present.",
          ),
        ),
        both("request", "Upgrade request", (context) =>
          eventCell(
            context,
            ["tls_upgrade_requested"],
            "No validated TLS-upgrade request event is present.",
          ),
        ),
        both("outcome", "Accepted/rejected upgrade event", (context) =>
          eventCell(
            context,
            ["tls_upgrade_accepted", "tls_upgrade_rejected"],
            "No validated acceptance or rejection event is present.",
          ),
        ),
        both("handshake", "TLS handshake completion", (context) =>
          factCell(
            context,
            "tls_upgrade_completed",
            "No validated TLS upgrade-completion fact is present.",
          ),
        ),
        both("plaintext", "Plaintext continuation", (context) =>
          eventCell(
            context,
            ["plaintext_command_after_tls_offer"],
            "No validated plaintext-continuation event is present; absence is not converted to false.",
          ),
        ),
      ],
    },
    {
      key: "cryptography",
      title: "Cryptographic observations",
      description:
        "Whitelisted TLS observations and declared facts only. Forward Secrecy is never inferred from a cipher name or TLS version in this view.",
      rows: [
        both("tls-version", "TLS version", (context) =>
          observationCell(context, ["tls_negotiated_version"]),
        ),
        both("cipher", "Cipher suite", (context) =>
          observationCell(context, ["selected_cipher_suite"]),
        ),
        both("key-exchange", "Key exchange observations", (context) =>
          observationCell(context, ["key_share_group", "psk_key_exchange_mode"]),
        ),
        both("forward-secrecy", "Forward Secrecy assessment", (context) =>
          factCell(
            context,
            "forward_secrecy",
            "No validated Forward Secrecy fact is present; TLS version, cipher, and key-share data are not used as a browser inference.",
          ),
        ),
        both("certificate", "Certificate observability", certificateCell),
      ],
    },
    {
      key: "policy",
      title: "Deterministic Policy Risk",
      description:
        "Only explicit deterministic findings and their declared contributions. Analysis-wide capped and uncapped values remain separate context.",
      rows: [
        both(
          "findings",
          "Linked deterministic policy findings",
          findingCell,
        ),
        row(
          "policy-contribution",
          "Policy Risk contribution",
          policyContributionCell(result, sessionA),
          policyContributionCell(result, sessionB),
        ),
      ],
    },
    {
      key: "ml",
      title: "ML Anomaly",
      description:
        "Independent engine state and explicit session results only. Anomaly is not proof of malicious activity and is never combined with Policy Risk.",
      rows: [
        row(
          "ml-state",
          "ML engine/session state",
          mlEngineCell(result, sessionA),
          mlEngineCell(result, sessionB),
        ),
        both("ml-result", "Explicit ML result", anomalyCell),
      ],
    },
    {
      key: "evidence-limitations",
      title: "Evidence and declared limitations",
      description:
        "Evidence is linked only through explicit contract references. Safe metadata and excerpts are available in the inspectors.",
      rows: [
        both("evidence", "Evidence references", evidenceCell),
        both("session-limitations", "Declared session limitations", (context) =>
          limitationCell(
            context.sessionLimitations,
            "No session-scoped limitation record is present.",
          ),
        ),
        row(
          "analysis-limitations",
          "Declared analysis limitations",
          limitationCell(
            result.chain.analysis.limitations,
            "No analysis-level limitation record is present.",
          ),
          limitationCell(
            result.chain.analysis.limitations,
            "No analysis-level limitation record is present.",
          ),
        ),
      ],
    },
  ];
}

function buildSessionSummary(
  analysisId: string,
  context: SessionContext,
  categories: ComparisonCategory[],
  side: "sessionA" | "sessionB",
): ComparisonSessionSummary {
  const rows = categories.flatMap((category) => category.rows);
  const highlight = (key: string) => rows.find((item) => item.key === key)![side];
  return {
    sessionId: context.session.session_id,
    captureId: context.capture.capture_id,
    captureName: context.capture.original_filename_sanitized,
    captureSha256: context.capture.sha256,
    xrayHref: `/analysis/${analysisId}/sessions/${context.session.session_id}`,
    highlights: [
      { label: "Protocol", ...highlight("protocol") },
      { label: "Upgrade outcome", ...highlight("outcome") },
      { label: "TLS version", ...highlight("tls-version") },
      { label: "Policy findings", ...highlight("findings") },
      { label: "ML Anomaly", ...highlight("ml-state") },
    ].map(({ label, value, state }) => ({ label, value, state })),
  };
}

export function buildComparisonPageData(
  result: AnalysisResult,
  selectedA: string,
  selectedB: string,
): ComparisonPageData {
  const sessions = [...result.chain.sessions].sort((left, right) =>
    left.session_id.localeCompare(right.session_id),
  );
  const sessionA = sessions.find((session) => session.session_id === selectedA)!;
  const sessionB = sessions.find((session) => session.session_id === selectedB)!;
  const contextA = buildSessionContext(result, sessionA);
  const contextB = buildSessionContext(result, sessionB);
  const categories = buildCategories(result, contextA, contextB);
  const capturesById = new Map(
    result.chain.captures.map((capture) => [capture.capture_id, capture]),
  );
  const analysisId = result.chain.analysis.analysis_id;
  const policyRisk = result.chain.policy_risk;

  return {
    analysisId,
    dataSource: result.data_source,
    datasetLabel: result.dataset_label,
    analysisStatus: result.chain.analysis.analysis_status,
    options: sessions.map((session) => ({
      sessionId: session.session_id,
      protocol: session.protocol,
      captureName:
        capturesById.get(session.capture_id)?.original_filename_sanitized ??
        "Validated capture name unavailable",
      sourceEndpoint: formatEndpoint(
        session.source_endpoint.ip,
        session.source_endpoint.port,
      ),
      destinationEndpoint: formatEndpoint(
        session.destination_endpoint.ip,
        session.destination_endpoint.port,
      ),
      tcpStreamId: session.tcp_stream_id,
    })),
    selectedA,
    selectedB,
    sessionA: buildSessionSummary(analysisId, contextA, categories, "sessionA"),
    sessionB: buildSessionSummary(analysisId, contextB, categories, "sessionB"),
    categories,
    differenceCount: categories
      .flatMap((category) => category.rows)
      .filter((item) => item.differs).length,
    policyRisk: policyRisk
      ? {
          status: "available",
          profileId: policyRisk.profile_id,
          cappedScore: policyRisk.capped_score,
          uncappedScore: policyRisk.uncapped_score,
        }
      : {
          status: "not_present",
          profileId: null,
          cappedScore: null,
          uncappedScore: null,
        },
    mlAnomaly: {
      engineStatus: result.chain.analysis.ml_engine_status,
      resultCount: result.chain.anomaly_results.length,
    },
    overviewHref: `/analysis/${analysisId}/overview`,
    sessionsHref: `/analysis/${analysisId}/sessions`,
    proofMapHref: `/analysis/${analysisId}/proof-map`,
    policyFindingsHref: `/analysis/${analysisId}/findings?view=policy`,
  };
}
