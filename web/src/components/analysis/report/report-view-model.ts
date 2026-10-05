import { severityOrder } from "@/components/analysis/findings/findings-view-model";
import type { AnalysisResult } from "@/lib/contracts/analysis";

type Chain = AnalysisResult["chain"];
type Session = Chain["sessions"][number];
type CryptoObservation = Chain["crypto_observations"][number];
type DerivedFact = Chain["derived_facts"][number];
type Limitation = Chain["analysis"]["limitations"][number];

type SafeReportObservationKind = CryptoObservation["kind"];

type SafeReportFactType =
  | "tls_upgrade_completed"
  | "forward_secrecy"
  | "certificate_observability";

export type ReportCapture = {
  captureId: string;
  filename: string;
  format: string;
  sha256: string;
};

export type ReportProtocolCoverage = {
  protocol: string;
  sessionCount: number;
  tlsUpgradeStates: Array<{ label: string; count: number }>;
};

export type ReportCryptoDimension = {
  key: string;
  label: string;
  description: string;
  notes: ReportNoteGroup[];
  values: Array<{
    value: string;
    state: string;
    sessionCount: number;
  }>;
};

export type ReportFinding = {
  findingId: string;
  title: string;
  severity: string;
  sessionId: string;
  rationale: string;
  evidenceCount: number;
  factCount: number;
  impact: string;
  confidence: string;
  observability: string;
  sessionLabel: string;
  recommendationId: string;
  limitations: Limitation[];
  source: Chain["findings"][number];
  evidence: Chain["evidence"];
};

export type ReportRecommendation = {
  recommendationId: string;
  title: string;
  summary: string;
  priority: string;
  scope: string;
  automationStatus: string;
  affectedFindingIds: string[];
  actionSteps: string[];
  verificationSteps: string[];
  affectedFindings: Array<{ id: string; title: string }>;
  affectedSessions: Array<{ id: string; label: string }>;
  standardsReferences: Chain["recommendations"][number]["standards_references"];
};

export type ReportNoteGroup = Limitation & { owners: string[] };

export type ReportPageData = {
  chain: Chain;
  affectedSessionCount: number;
  analysisId: string;
  analysisStatus: string;
  analysisTimestamp: string | null;
  dataSource: AnalysisResult["data_source"];
  datasetLabel: string | null;
  captures: ReportCapture[];
  totalSessions: number;
  emailProtocolCount: number;
  policyFindingCount: number;
  cryptoCoverageSessionCount: number;
  protocolCoverage: ReportProtocolCoverage[];
  cryptoDimensions: ReportCryptoDimension[];
  additionalCryptoDimensions: ReportCryptoDimension[];
  coverageNotes: ReportNoteGroup[];
  anomalyNotes: ReportNoteGroup[];
  importantFindings: ReportFinding[];
  totalFindings: number;
  graphCounts: {
    captures: number;
    sessions: number;
    evidence: number;
    facts: number;
    findings: number;
  };
  policyRisk: {
    engineStatus: string;
    available: boolean;
    score: number | null;
    profileId: string | null;
    contributionCount: number;
    findingCount: number;
    severityDistribution: Array<{
      severity: string;
      count: number;
    }>;
  };
  mlAnomaly: {
    engineStatus: string;
    resultCount: number;
    modelId: string | null;
    modelVersion: string | null;
    bandDistribution: Array<{ band: string; count: number }>;
  };
  limitations: Array<Limitation & { owner: string }>;
  recommendations: ReportRecommendation[];
  links: {
    overview: string;
    sessions: string;
    proofMap: string;
    findings: string;
    compare: string;
    recommendations: string;
  };
};

const emailProtocols = new Set(["smtp", "imap", "pop3"]);

const cryptoDimensions: Array<{
  key: string;
  label: string;
  description: string;
  observationKinds?: SafeReportObservationKind[];
  factType?: SafeReportFactType;
}> = [
  {
    key: "tls-version",
    label: "TLS version",
    description: "Negotiated-version observations only.",
    observationKinds: ["tls_negotiated_version"],
  },
  {
    key: "cipher-suite",
    label: "Cipher suite",
    description: "Server-selected cipher-suite observations only.",
    observationKinds: ["selected_cipher_suite"],
  },
  {
    key: "key-share-group",
    label: "Key-share group",
    description: "Observed key-share group without browser inference.",
    observationKinds: ["key_share_group"],
  },
  {
    key: "psk-mode",
    label: "PSK exchange mode",
    description: "Observed PSK key-exchange mode when supplied.",
    observationKinds: ["psk_key_exchange_mode"],
  },
  {
    key: "forward-secrecy",
    label: "Forward Secrecy",
    description: "Declared Forward Secrecy facts only.",
    factType: "forward_secrecy",
  },
  {
    key: "certificate-observability",
    label: "Certificate observability",
    description:
      "Declared certificate visibility, including session-secret requirements.",
    factType: "certificate_observability",
    observationKinds: ["tls13_certificate_unavailable"],
  },
];

function formatFactValue(factType: SafeReportFactType, value: unknown): string {
  if (factType === "tls_upgrade_completed" && typeof value === "boolean") {
    return value ? "Completed" : "Not completed";
  }
  if (factType === "forward_secrecy" && typeof value === "boolean") {
    return value ? "Supported" : "Not supported";
  }
  if (
    factType === "certificate_observability" &&
    value === "session_secrets_required"
  ) {
    return "Certificate not observable · session_secrets_required";
  }
  if (typeof value === "string" || typeof value === "number") {
    return String(value);
  }
  return "Declared value unavailable";
}

function upgradeStateForSession(
  session: Session,
  facts: DerivedFact[],
): string {
  const values = facts
    .filter(
      (fact) =>
        fact.session_id === session.session_id &&
        fact.fact_type === "tls_upgrade_completed",
    )
    .map((fact) => fact.value);

  const hasCompleted = values.includes(true);
  const hasNotCompleted = values.includes(false);
  if (hasCompleted && hasNotCompleted) return "Conflicting declared outcomes";
  if (hasCompleted) return "Completed";
  if (hasNotCompleted) return "Not completed";
  return "Not assessed";
}

function buildProtocolCoverage(
  sessions: Session[],
  facts: DerivedFact[],
): ReportProtocolCoverage[] {
  const byProtocol = new Map<string, Session[]>();
  for (const session of sessions) {
    byProtocol.set(session.protocol, [
      ...(byProtocol.get(session.protocol) ?? []),
      session,
    ]);
  }

  return [...byProtocol.entries()]
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([protocol, protocolSessions]) => {
      const stateCounts = new Map<string, number>();
      for (const session of protocolSessions) {
        const state = upgradeStateForSession(session, facts);
        stateCounts.set(state, (stateCounts.get(state) ?? 0) + 1);
      }
      return {
        protocol,
        sessionCount: protocolSessions.length,
        tlsUpgradeStates: [...stateCounts.entries()]
          .sort(([left], [right]) => left.localeCompare(right))
          .map(([label, count]) => ({ label, count })),
      };
    });
}

function dimensionRecordsForSession(
  session: Session,
  observations: CryptoObservation[],
  facts: DerivedFact[],
  dimension: (typeof cryptoDimensions)[number],
): Array<{ value: string; state: string }> {
  const matchingFacts = dimension.factType
    ? facts.filter(
        (fact) =>
          fact.session_id === session.session_id &&
          fact.fact_type === dimension.factType,
      )
    : [];

  if (matchingFacts.length > 0 && dimension.factType) {
    return matchingFacts.map((fact) => ({
      value: formatFactValue(dimension.factType!, fact.value),
      state: fact.observability,
    }));
  }

  const allowedKinds = new Set<CryptoObservation["kind"]>(
    dimension.observationKinds ?? [],
  );
  return observations
    .filter(
      (observation) =>
        observation.session_id === session.session_id &&
        allowedKinds.has(observation.kind),
    )
    .map((observation) => ({
      value:
        observation.kind === "tls13_certificate_unavailable"
          ? "Certificate not observable"
          : observation.normalized_value,
      state: observation.observability,
    }));
}

function buildCryptoDimensions(
  sessions: Session[],
  observations: CryptoObservation[],
  facts: DerivedFact[],
  dimensions = cryptoDimensions,
): ReportCryptoDimension[] {
  return dimensions.flatMap((dimension) => {
    const explicitRecords = sessions.map((session) => ({
      session,
      records: dimensionRecordsForSession(
        session,
        observations,
        facts,
        dimension,
      ),
    }));
    if (explicitRecords.every(({ records }) => records.length === 0)) return [];

    const counts = new Map<string, { value: string; state: string; count: number }>();
    for (const { records } of explicitRecords) {
      const sessionRecords = [
        ...new Map(
          (records.length > 0
            ? records
            : [{ value: "Not assessed", state: "not_assessed" }]
          ).map((record) => [
            `${record.value}\u0000${record.state}`,
            record,
          ]),
        ).values(),
      ];
      for (const record of sessionRecords) {
        const key = `${record.value}\u0000${record.state}`;
        const current = counts.get(key);
        counts.set(key, {
          ...record,
          count: (current?.count ?? 0) + 1,
        });
      }
    }

    return [
      {
        key: dimension.key,
        label: dimension.label,
        description: dimension.description,
        notes: groupReportNotes(sessions.flatMap((session) => {
          const matchingFacts = dimension.factType
            ? facts.filter((fact) => fact.session_id === session.session_id && fact.fact_type === dimension.factType)
            : [];
          if (matchingFacts.length) {
            return matchingFacts.flatMap((fact) => fact.limitations.map((note) => ({ ...note, owner: fact.fact_id })));
          }
          const kinds = new Set(dimension.observationKinds ?? []);
          return observations
            .filter((observation) => observation.session_id === session.session_id && kinds.has(observation.kind))
            .flatMap((observation) => observation.limitations.map((note) => ({ ...note, owner: observation.observation_id })));
        })),
        values: [...counts.values()]
          .sort(
            (left, right) =>
              left.value.localeCompare(right.value) ||
              left.state.localeCompare(right.state),
          )
          .map(({ value, state, count }) => ({
            value,
            state,
            sessionCount: count,
          })),
      },
    ];
  });
}

export function reportNoteKey(note: Limitation): string {
  return JSON.stringify([note.code, note.summary, note.detail]);
}

/** Only exact duplicate notes are grouped; differing details remain distinct. */
export function groupReportNotes(notes: ReportPageData["limitations"]): ReportNoteGroup[] {
  const groups = new Map<string, ReportNoteGroup>();
  for (const { owner, ...note } of notes) {
    const key = reportNoteKey(note);
    const existing = groups.get(key);
    if (existing) {
      if (!existing.owners.includes(owner)) existing.owners.push(owner);
    } else {
      groups.set(key, { ...note, owners: [owner] });
    }
  }
  return [...groups.values()];
}

function additionalObservationDimensions(observations: CryptoObservation[]) {
  const primaryKinds = new Set(cryptoDimensions.flatMap((dimension) => dimension.observationKinds ?? []));
  const labels: Partial<Record<CryptoObservation["kind"], string>> = {
    record_layer_legacy_version: "Record-layer legacy version",
    supported_versions: "Advertised TLS versions",
    signature_algorithm: "Signature algorithm",
    public_key_algorithm: "Public-key algorithm",
    public_key_length: "Public-key length",
    certificate_subject: "Certificate subject",
    certificate_issuer: "Certificate issuer",
    certificate_san: "Certificate subject alternative names",
    certificate_validity_window: "Certificate validity period",
    certificate_fingerprint: "Certificate fingerprint",
    certificate_chain_structure: "Certificate chain structure",
    certificate_serial_number: "Certificate serial number",
    certificate_basic_constraints: "Certificate basic constraints",
    certificate_key_usage: "Certificate key usage",
    certificate_structure_parsed: "Certificate structure parsing",
    certificate_signature_chain_checked: "Certificate signature-chain check",
    certificate_trusted_path_validated: "Certificate trusted-path validation",
    certificate_service_identity_validated: "Certificate service-identity validation",
    certificate_revocation_checked: "Certificate revocation check",
    session_resumption_indicator: "Session resumption indicator",
  };
  return [...new Set(observations.map((observation) => observation.kind))]
    .filter((kind) => !primaryKinds.has(kind))
    .map((kind) => ({
      key: "observation-" + kind,
      label: labels[kind] ?? kind.replaceAll("_", " "),
      description: kind === "record_layer_legacy_version"
        ? "Record-layer value; this is not the negotiated TLS version."
        : "Supplied observations with their recorded evidence states.",
      observationKinds: [kind],
    }));
}

export function reportSessionLabel(session: Session): string {
  const endpoint = ({ ip, port }: Session["source_endpoint"]) =>
    (ip.includes(":") ? "[" + ip + "]" : ip) + ":" + port;
  return session.protocol.toUpperCase() + " · stream " + session.tcp_stream_id +
    " · " + endpoint(session.source_endpoint) + " → " + endpoint(session.destination_endpoint);
}

function collectLimitations(chain: Chain): ReportPageData["limitations"] {
  const limitations: ReportPageData["limitations"] = [];
  const collect = (owner: string, records: Limitation[]) => {
    for (const limitation of records) limitations.push({ ...limitation, owner });
  };
  collect(chain.analysis.analysis_id, chain.analysis.limitations);
  for (const session of chain.sessions) collect(session.session_id, session.limitations);
  for (const event of chain.protocol_events) collect(event.event_id, event.limitations);
  for (const observation of chain.crypto_observations) collect(observation.observation_id, observation.limitations);
  for (const fact of chain.derived_facts) collect(fact.fact_id, fact.limitations);
  for (const finding of chain.findings) collect(finding.finding_id, finding.limitations);
  if (chain.policy_risk) collect(chain.policy_risk.policy_risk_id, chain.policy_risk.limitations);
  for (const anomaly of chain.anomaly_results) collect(anomaly.anomaly_result_id, anomaly.limitations);
  chain.execution.stage_diagnostics.forEach((stage, index) => {
    if (stage.limitation) collect("Stage " + stage.stage + " · record " + (index + 1), [stage.limitation]);
  });
  return limitations;
}

export function buildReportPageData(result: AnalysisResult): ReportPageData {
  const {
    analysis,
    captures,
    sessions,
    evidence,
    crypto_observations,
    derived_facts,
    findings,
    policy_risk,
    anomaly_results,
    recommendations,
  } = result.chain;
  const analysisId = analysis.analysis_id;

  const sortedFindings = [...findings].sort((left, right) => {
    const severityDifference =
      (severityOrder[left.severity] ?? 99) -
      (severityOrder[right.severity] ?? 99);
    if (severityDifference !== 0) return severityDifference;
    const contributionDifference =
      right.policy_risk_contribution - left.policy_risk_contribution;
    if (contributionDifference !== 0) return contributionDifference;
    return (
      left.title.localeCompare(right.title) ||
      left.finding_id.localeCompare(right.finding_id)
    );
  });

  const severityCounts = new Map<string, number>();
  for (const finding of findings) {
    severityCounts.set(
      finding.severity,
      (severityCounts.get(finding.severity) ?? 0) + 1,
    );
  }

  const bandCounts = new Map<string, number>();
  for (const anomaly of anomaly_results) {
    bandCounts.set(anomaly.band, (bandCounts.get(anomaly.band) ?? 0) + 1);
  }

  const safeObservationKinds = new Set<CryptoObservation["kind"]>([
    "tls_negotiated_version",
    "selected_cipher_suite",
    "key_share_group",
    "psk_key_exchange_mode",
    "tls13_certificate_unavailable",
  ]);
  const safeFactTypes = new Set<string>([
    "tls_upgrade_completed",
    "forward_secrecy",
    "certificate_observability",
  ]);
  const cryptoCoverageSessionIds = new Set([
    ...crypto_observations
      .filter((observation) => safeObservationKinds.has(observation.kind))
      .map((observation) => observation.session_id),
    ...derived_facts
      .filter((fact) => safeFactTypes.has(fact.fact_type))
      .map((fact) => fact.session_id),
  ]);

  const declaredLimitations = collectLimitations(result.chain);
  const sessionById = new Map(sessions.map((session) => [session.session_id, session]));
  const anomalyNoteKeys = new Set(anomaly_results.flatMap((anomaly) => anomaly.limitations).map(reportNoteKey));
  const anomalyIds = new Set(anomaly_results.map((anomaly) => anomaly.anomaly_result_id));
  const locallyDisplayedOwners = new Set([
    ...findings.map((finding) => finding.finding_id),
    ...anomalyIds,
  ]);

  return {
    chain: result.chain,
    affectedSessionCount: new Set(findings.map((finding) => finding.session_id)).size,
    analysisId,
    analysisStatus: analysis.analysis_status,
    analysisTimestamp: analysis.completed_at,
    dataSource: result.data_source,
    datasetLabel: result.dataset_label,
    captures: captures.map((capture) => ({
      captureId: capture.capture_id,
      filename: capture.original_filename_sanitized,
      format: capture.format,
      sha256: capture.sha256,
    })),
    totalSessions: sessions.length,
    emailProtocolCount: new Set(
      sessions
        .map((session) => session.protocol)
        .filter((protocol) => emailProtocols.has(protocol)),
    ).size,
    policyFindingCount: findings.length,
    cryptoCoverageSessionCount: cryptoCoverageSessionIds.size,
    protocolCoverage: buildProtocolCoverage(sessions, derived_facts),
    cryptoDimensions: buildCryptoDimensions(
      sessions,
      crypto_observations,
      derived_facts,
    ),
    additionalCryptoDimensions: buildCryptoDimensions(
      sessions, crypto_observations, [],
      additionalObservationDimensions(crypto_observations),
    ),
    coverageNotes: groupReportNotes(declaredLimitations.filter((note) =>
      !locallyDisplayedOwners.has(note.owner) &&
      !((note.owner === analysisId || note.owner.startsWith("Stage ")) && anomalyNoteKeys.has(reportNoteKey(note)))
    )),
    anomalyNotes: groupReportNotes(declaredLimitations.filter((note) => anomalyIds.has(note.owner))),
    importantFindings: sortedFindings.map((finding) => ({
      findingId: finding.finding_id,
      title: finding.title,
      severity: finding.severity,
      sessionId: finding.session_id,
      rationale: finding.rationale,
      evidenceCount: finding.evidence_ids.length,
      factCount: finding.fact_ids.length,
      impact: finding.impact,
      confidence: finding.evidence_confidence,
      observability: finding.observability,
      sessionLabel: reportSessionLabel(sessionById.get(finding.session_id)!),
      recommendationId: finding.recommendation_id,
      limitations: finding.limitations,
      source: finding,
      evidence: evidence.filter((record) => finding.evidence_ids.includes(record.evidence_id)),
    })),
    totalFindings: findings.length,
    graphCounts: {
      captures: captures.length,
      sessions: sessions.length,
      evidence: evidence.length,
      facts: derived_facts.length,
      findings: findings.length,
    },
    policyRisk: {
      engineStatus: analysis.rule_engine_status,
      available: policy_risk !== null,
      score: policy_risk?.capped_score ?? null,
      profileId: policy_risk?.profile_id ?? null,
      contributionCount: policy_risk?.contributions.length ?? 0,
      findingCount: findings.length,
      severityDistribution: [...severityCounts.entries()]
        .sort(
          ([left], [right]) =>
            (severityOrder[left] ?? 99) - (severityOrder[right] ?? 99),
        )
        .map(([severity, count]) => ({ severity, count })),
    },
    mlAnomaly: {
      engineStatus: analysis.ml_engine_status,
      resultCount: anomaly_results.length,
      modelId: analysis.model_id,
      modelVersion: analysis.model_version,
      bandDistribution: [...bandCounts.entries()]
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([band, count]) => ({ band, count })),
    },
    limitations: declaredLimitations,
    recommendations: recommendations.map((recommendation) => ({
      recommendationId: recommendation.recommendation_id,
      title: recommendation.title,
      summary: recommendation.summary,
      priority: recommendation.priority,
      scope: recommendation.scope,
      automationStatus: recommendation.automation_status,
      affectedFindingIds: [...recommendation.affected_finding_ids],
      actionSteps: [...recommendation.action_steps],
      verificationSteps: [...recommendation.verification_steps],
      affectedFindings: findings
        .filter((finding) => recommendation.affected_finding_ids.includes(finding.finding_id))
        .map((finding) => ({ id: finding.finding_id, title: finding.title })),
      affectedSessions: sessions
        .filter((session) => findings.some((finding) =>
          recommendation.affected_finding_ids.includes(finding.finding_id) &&
          finding.session_id === session.session_id))
        .map((session) => ({ id: session.session_id, label: reportSessionLabel(session) })),
      standardsReferences: recommendation.standards_references,
    })),
    links: {
      overview: `/analysis/${analysisId}/overview`,
      sessions: `/analysis/${analysisId}/sessions`,
      proofMap: `/analysis/${analysisId}/proof-map`,
      findings: `/analysis/${analysisId}/findings?view=policy`,
      recommendations: '/analysis/' + analysisId + '/recommendations',
      compare: `/analysis/${analysisId}/compare`,
    },
  };
}
