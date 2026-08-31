import { severityOrder } from "@/components/analysis/findings/findings-view-model";
import type { AnalysisResult } from "@/lib/contracts/analysis";

type Chain = AnalysisResult["chain"];
type Session = Chain["sessions"][number];
type CryptoObservation = Chain["crypto_observations"][number];
type DerivedFact = Chain["derived_facts"][number];
type Limitation = Chain["analysis"]["limitations"][number];

type SafeReportObservationKind = Extract<
  CryptoObservation["kind"],
  | "tls_negotiated_version"
  | "selected_cipher_suite"
  | "key_share_group"
  | "psk_key_exchange_mode"
  | "tls13_certificate_unavailable"
>;

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
};

export type ReportPageData = {
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
  limitations: Array<{ code: string; summary: string }>;
  recommendations: ReportRecommendation[];
  links: {
    overview: string;
    sessions: string;
    proofMap: string;
    findings: string;
    compare: string;
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
    key: "tls-upgrade-completion",
    label: "TLS upgrade completion",
    description: "Declared completion facts; no event is promoted to success.",
    factType: "tls_upgrade_completed",
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
): ReportCryptoDimension[] {
  return cryptoDimensions.flatMap((dimension) => {
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

function uniqueLimitations(limitations: Limitation[]): Limitation[] {
  return [
    ...new Map(
      limitations.map((limitation) => [
        `${limitation.code}:${limitation.summary}`,
        limitation,
      ]),
    ).values(),
  ];
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

  const declaredLimitations = uniqueLimitations([
    ...analysis.limitations,
    ...crypto_observations
      .filter(
        (observation) =>
          observation.kind === "tls13_certificate_unavailable",
      )
      .flatMap((observation) => observation.limitations),
    ...derived_facts
      .filter((fact) => fact.fact_type === "certificate_observability")
      .flatMap((fact) => fact.limitations),
  ]);

  return {
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
    importantFindings: sortedFindings.slice(0, 5).map((finding) => ({
      findingId: finding.finding_id,
      title: finding.title,
      severity: finding.severity,
      sessionId: finding.session_id,
      rationale: finding.rationale,
      evidenceCount: finding.evidence_ids.length,
      factCount: finding.fact_ids.length,
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
    limitations: declaredLimitations.map((limitation) => ({
      code: limitation.code,
      summary: limitation.summary,
    })),
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
    })),
    links: {
      overview: `/analysis/${analysisId}/overview`,
      sessions: `/analysis/${analysisId}/sessions`,
      proofMap: `/analysis/${analysisId}/proof-map`,
      findings: `/analysis/${analysisId}/findings?view=policy`,
      compare: `/analysis/${analysisId}/compare`,
    },
  };
}
