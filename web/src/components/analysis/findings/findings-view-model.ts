import {
  buildSessionXRayData,
  type XRayEvidence,
} from "@/components/analysis/session-xray/session-xray-view-model";
import type { AnalysisResult } from "@/lib/contracts/analysis";

type Chain = AnalysisResult["chain"];
type DerivedFact = Chain["derived_facts"][number];
type CryptoObservation = Chain["crypto_observations"][number];
type AnalysisLimitation = Chain["analysis"]["limitations"][number];

export const severityOrder: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
} as const;

export const severityStyles: Record<string, string> = {
  critical: "border-red-300 bg-red-50 text-red-800",
  high: "border-orange-300 bg-orange-50 text-orange-800",
  medium: "border-amber-300 bg-amber-50 text-amber-800",
  low: "border-neutral-300 bg-neutral-50 text-neutral-700",
  info: "border-blue-300 bg-blue-50 text-blue-800",
} as const;

export const categoryLabels: Record<string, string> = {
  encryption_transition: "Encryption transition",
  tls_version: "TLS version",
  key_exchange: "Key exchange",
  certificate_validity: "Certificate validity",
  certificate_identity: "Certificate identity",
  authentication: "Authentication",
  sensitive_data: "Sensitive data",
  configuration: "Configuration",
  not_classified: "Not classified",
} as const;

export const engineStatusLabels: Record<string, string> = {
  not_run: "Not run",
  complete: "Complete",
  partial: "Partial",
  failed: "Failed",
  unavailable: "Unavailable",
} as const;

export type FindingSessionLink = {
  sessionId: string;
  captureName: string | null;
  protocol: string;
  tcpStreamId: number;
  sourceEndpoint: string;
  destinationEndpoint: string;
  captureCompleteness: string;
};

export type FindingFactLink = {
  factId: string;
  factType: string;
  observability: string;
  confidenceLevel: string;
};

export type FindingRecommendation = {
  recommendationId: string;
  title: string;
  summary: string;
  priority: string;
  actionSteps: string[];
  verificationSteps: string[];
  standardsReferences: Array<{ id: string; section?: string | null }>;
  scope: string;
  automationStatus: string;
};

export type FindingDetail = {
  findingId: string;
  stableFindingKey: string;
  title: string;
  category: string;
  severity: string;
  policyRiskContribution: number;
  evidenceConfidence: string;
  observability: string;
  ruleId: string;
  ruleVersion: string;
  ruleOutcome: string;
  ruleReasonCode: string;
  profileId: string;
  rationale: string;
  impact: string;
  recommendationId: string;
  linkedSessions: FindingSessionLink[];
  directEvidence: XRayEvidence[];
  linkedFacts: FindingFactLink[];
  evidenceThroughSources: XRayEvidence[];
  recommendation: FindingRecommendation | null;
  limitations: AnalysisLimitation[];
};

export type PolicyFindingsData = {
  analysisId: string;
  dataSource: AnalysisResult["data_source"];
  datasetLabel: string | null;
  analysisStatus: string;
  ruleEngineStatus: string;
  hasIncompleteSessions: boolean;
  policyRisk: {
    policyRiskId: string;
    profileId: string;
    cappedScore: number;
    uncappedScore: number;
    contributionCount: number;
    affectedSessionCount: number;
  } | null;
  findings: FindingDetail[];
  recommendations: FindingRecommendation[];
  totalFindings: number;
  sessions: Array<{
    sessionId: string;
    captureName: string | null;
    protocol: string;
    tcpStreamId: number;
    sourceEndpoint: string;
    destinationEndpoint: string;
    captureCompleteness: string;
  }>;
  analysisSessions: FindingSessionLink[];
  categories: Array<{ key: string; label: string; count: number }>;
  severities: Array<{ key: string; label: string; count: number }>;
  profiles: Array<{ key: string; count: number }>;
};

export type AnomalyFindingsData = {
  analysisId: string;
  dataSource: AnalysisResult["data_source"];
  datasetLabel: string | null;
  mlEngineStatus: string;
  modelId: string | null;
  modelVersion: string | null;
  resultCount: number;
  results: AnomalyDetail[];
  sessions: FindingSessionLink[];
  bands: Array<{ key: string; count: number }>;
  models: Array<{ key: string; label: string; count: number }>;
};

export type AnomalyObservationLink = {
  observationId: string;
  kind: string;
  observability: string;
};

export type AnomalyDetail = {
  anomalyResultId: string;
  session: FindingSessionLink;
  modelId: string;
  modelVersion: string;
  featureSchemaVersion: string;
  rawScore: number;
  normalizedScore: number;
  threshold: number;
  band: string;
  unusualFeatureIndicators: string[];
  interpretationNote: string;
  linkedFacts: FindingFactLink[];
  linkedObservations: AnomalyObservationLink[];
  directEvidence: XRayEvidence[];
  evidenceThroughSources: XRayEvidence[];
  limitations: AnalysisLimitation[];
};

function formatEndpoint(ip: string, port: number): string {
  const host = ip.includes(":") ? `[${ip}]` : ip;
  return `${host}:${port}`;
}

function buildFactLinks(
  factIds: string[],
  factsMap: Map<string, DerivedFact>,
): FindingFactLink[] {
  return factIds
    .map((id) => factsMap.get(id))
    .filter((f): f is DerivedFact => f !== undefined)
    .map((f) => ({
      factId: f.fact_id,
      factType: f.fact_type,
      observability: f.observability,
      confidenceLevel: f.confidence_level,
    }));
}

function buildObservationLinks(
  observationIds: string[],
  observationsMap: Map<string, CryptoObservation>,
): AnomalyObservationLink[] {
  return observationIds.map((id) => observationsMap.get(id)!).map((item) => ({
    observationId: item.observation_id,
    kind: item.kind,
    observability: item.observability,
  }));
}

function uniqueEvidence(evidence: XRayEvidence[]): XRayEvidence[] {
  return [...new Map(evidence.map((item) => [item.evidenceId, item])).values()];
}

export function buildPolicyFindingsData(
  result: AnalysisResult,
): PolicyFindingsData {
  const { analysis, sessions, findings, policy_risk, recommendations, derived_facts, rule_evaluations, captures } =
    result.chain;

  const capturesById = new Map(
    captures.map((c) => [c.capture_id, c]),
  );

  const sessionsById = new Map(
    sessions.map((s) => [s.session_id, s]),
  );

  const factsMap = new Map(
    derived_facts.map((f) => [f.fact_id, f]),
  );

  const recommendationsMap = new Map(
    recommendations.map((r) => [r.recommendation_id, r]),
  );
  const recommendationList: FindingRecommendation[] = recommendations.map(
    (recommendation) => ({
      recommendationId: recommendation.recommendation_id,
      title: recommendation.title,
      summary: recommendation.summary,
      priority: recommendation.priority,
      actionSteps: recommendation.action_steps,
      verificationSteps: recommendation.verification_steps,
      standardsReferences: recommendation.standards_references,
      scope: recommendation.scope,
      automationStatus: recommendation.automation_status,
    }),
  );

  const evaluationsMap = new Map(
    rule_evaluations.map((e) => [e.evaluation_id, e]),
  );

  const sessionEvidence = new Map(
    sessions.map((session) => {
      const data = buildSessionXRayData(result, session.session_id)!;
      return [session.session_id, data.evidence] as const;
    }),
  );

  const findingsWithDetails: FindingDetail[] = findings.map((finding) => {
    const session = sessionsById.get(finding.session_id);
    const evaluation = evaluationsMap.get(finding.rule_evaluation_id);

    const linkedSessions: FindingSessionLink[] = session
      ? [
          {
            sessionId: session.session_id,
            captureName:
              capturesById.get(session.capture_id)
                ?.original_filename_sanitized ?? null,
            protocol: session.protocol,
            tcpStreamId: session.tcp_stream_id,
            sourceEndpoint: formatEndpoint(
              session.source_endpoint.ip,
              session.source_endpoint.port,
            ),
            destinationEndpoint: formatEndpoint(
              session.destination_endpoint.ip,
              session.destination_endpoint.port,
            ),
            captureCompleteness: session.capture_completeness,
          },
        ]
      : [];

    const evidenceForSession = sessionEvidence.get(finding.session_id) ?? [];
    const evidenceById = new Map(
      evidenceForSession.map((item) => [item.evidenceId, item]),
    );
    const directEvidence = finding.evidence_ids.map((id) => evidenceById.get(id)!);

    const linkedFacts = buildFactLinks(
      finding.fact_ids,
      factsMap,
    );

    const directEvidenceIds = new Set(finding.evidence_ids);
    const findingFactIds = new Set(finding.fact_ids);
    const evidenceThroughSources = evidenceForSession.filter(
      (item) =>
        !directEvidenceIds.has(item.evidenceId) &&
        item.factIdsThroughSources.some((factId) => findingFactIds.has(factId)),
    );

    const recommendation = recommendationsMap.get(finding.recommendation_id) ?? null;
    const recommendationData: FindingRecommendation | null = recommendation
      ? {
          recommendationId: recommendation.recommendation_id,
          title: recommendation.title,
          summary: recommendation.summary,
          priority: recommendation.priority,
          actionSteps: recommendation.action_steps,
          verificationSteps: recommendation.verification_steps,
          standardsReferences: recommendation.standards_references,
          scope: recommendation.scope,
          automationStatus: recommendation.automation_status,
        }
      : null;

    return {
      findingId: finding.finding_id,
      stableFindingKey: finding.stable_finding_key,
      title: finding.title,
      category: finding.category,
      severity: finding.severity,
      policyRiskContribution: finding.policy_risk_contribution,
      evidenceConfidence: finding.evidence_confidence,
      observability: finding.observability,
      ruleId: finding.rule_id,
      ruleVersion: finding.rule_version,
      ruleOutcome: evaluation?.outcome ?? "unknown",
      ruleReasonCode: evaluation?.reason_code ?? "unknown",
      profileId: evaluation?.profile_id ?? "unknown",
      rationale: finding.rationale,
      impact: finding.impact,
      recommendationId: finding.recommendation_id,
      linkedSessions,
      directEvidence,
      linkedFacts,
      evidenceThroughSources,
      recommendation: recommendationData,
      limitations: finding.limitations,
    };
  });

  const affectedSessionIds = new Set(
    findings.map((f) => f.session_id),
  );

  const policyRiskData = policy_risk
    ? {
        policyRiskId: policy_risk.policy_risk_id,
        profileId: policy_risk.profile_id,
        cappedScore: policy_risk.capped_score,
        uncappedScore: policy_risk.uncapped_score,
        contributionCount: policy_risk.contributions.length,
        affectedSessionCount: affectedSessionIds.size,
      }
    : null;

  const sessionList = [
    ...new Map(
      findingsWithDetails.flatMap((finding) =>
        finding.linkedSessions.map((session) => [session.sessionId, session]),
      ),
    ).values(),
  ];

  const analysisSessions: FindingSessionLink[] = sessions.map((session) => ({
    sessionId: session.session_id,
    captureName:
      capturesById.get(session.capture_id)?.original_filename_sanitized ?? null,
    protocol: session.protocol,
    tcpStreamId: session.tcp_stream_id,
    sourceEndpoint: formatEndpoint(
      session.source_endpoint.ip,
      session.source_endpoint.port,
    ),
    destinationEndpoint: formatEndpoint(
      session.destination_endpoint.ip,
      session.destination_endpoint.port,
    ),
    captureCompleteness: session.capture_completeness,
  }));

  const categoryCounts = new Map<string, number>();
  for (const f of findingsWithDetails) {
    categoryCounts.set(f.category, (categoryCounts.get(f.category) ?? 0) + 1);
  }
  const categories = [...categoryCounts.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, count]) => ({
      key,
      label: categoryLabels[key] ?? key,
      count,
    }));

  const severityCounts = new Map<string, number>();
  for (const f of findingsWithDetails) {
    severityCounts.set(f.severity, (severityCounts.get(f.severity) ?? 0) + 1);
  }
  const severities = [...severityCounts.entries()]
    .sort(
      ([a], [b]) =>
        (severityOrder[a] ?? 99) - (severityOrder[b] ?? 99),
    )
    .map(([key, count]) => ({
      key,
      label: key.charAt(0).toUpperCase() + key.slice(1),
      count,
    }));

  const profileCounts = new Map<string, number>();
  for (const f of findingsWithDetails) {
    profileCounts.set(f.profileId, (profileCounts.get(f.profileId) ?? 0) + 1);
  }
  const profiles = [...profileCounts.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, count]) => ({ key, count }));

  const sortedFindings = [...findingsWithDetails].sort((a, b) => {
    const sevDiff =
      (severityOrder[a.severity] ?? 99) - (severityOrder[b.severity] ?? 99);
    if (sevDiff !== 0) return sevDiff;
    const contribDiff = b.policyRiskContribution - a.policyRiskContribution;
    if (contribDiff !== 0) return contribDiff;
    const titleDiff = a.title.localeCompare(b.title);
    if (titleDiff !== 0) return titleDiff;
    return a.findingId.localeCompare(b.findingId);
  });

  return {
    analysisId: analysis.analysis_id,
    dataSource: result.data_source,
    datasetLabel: result.dataset_label,
    analysisStatus: analysis.analysis_status,
    ruleEngineStatus: analysis.rule_engine_status,
    hasIncompleteSessions: sessions.some(
      (session) => session.capture_completeness !== "complete",
    ),
    policyRisk: policyRiskData,
    findings: sortedFindings,
    recommendations: recommendationList,
    totalFindings: findings.length,
    sessions: sessionList,
    analysisSessions,
    categories,
    severities,
    profiles,
  };
}

export function buildAnomalyFindingsData(
  result: AnalysisResult,
): AnomalyFindingsData {
  const {
    analysis,
    anomaly_results,
    sessions,
    captures,
    derived_facts,
    crypto_observations,
  } = result.chain;
  const capturesById = new Map(captures.map((item) => [item.capture_id, item]));
  const factsById = new Map(derived_facts.map((item) => [item.fact_id, item]));
  const observationsById = new Map(
    crypto_observations.map((item) => [item.observation_id, item]),
  );
  const xrayBySession = new Map(
    sessions.map((session) => [
      session.session_id,
      buildSessionXRayData(result, session.session_id)!,
    ]),
  );

  const sessionLinks = new Map(
    sessions.map((session) => [
      session.session_id,
      {
        sessionId: session.session_id,
        captureName:
          capturesById.get(session.capture_id)?.original_filename_sanitized ?? null,
        protocol: session.protocol,
        tcpStreamId: session.tcp_stream_id,
        sourceEndpoint: formatEndpoint(
          session.source_endpoint.ip,
          session.source_endpoint.port,
        ),
        destinationEndpoint: formatEndpoint(
          session.destination_endpoint.ip,
          session.destination_endpoint.port,
        ),
        captureCompleteness: session.capture_completeness,
      },
    ]),
  );

  const results: AnomalyDetail[] = anomaly_results
    .map((anomaly) => {
      const xray = xrayBySession.get(anomaly.session_id)!;
      const evidenceById = new Map(
        xray.evidence.map((item) => [item.evidenceId, item]),
      );
      const directEvidenceIds = new Set(anomaly.evidence_ids ?? []);
      const directEvidence = [...directEvidenceIds].map(
        (evidenceId) => evidenceById.get(evidenceId)!,
      );
      const linkedFactIds = new Set(anomaly.linked_fact_ids ?? []);
      const observationEvidenceIds = new Set(
        (anomaly.linked_observation_ids ?? []).flatMap(
          (observationId) => observationsById.get(observationId)!.evidence_ids,
        ),
      );
      const evidenceThroughSources = uniqueEvidence(
        xray.evidence.filter(
          (item) =>
            !directEvidenceIds.has(item.evidenceId) &&
            (observationEvidenceIds.has(item.evidenceId) ||
              item.factIdsThroughSources.some((factId) =>
                linkedFactIds.has(factId),
              )),
        ),
      );

      return {
        anomalyResultId: anomaly.anomaly_result_id,
        session: sessionLinks.get(anomaly.session_id)!,
        modelId: anomaly.model_id,
        modelVersion: anomaly.model_version,
        featureSchemaVersion: anomaly.feature_schema_version,
        rawScore: anomaly.raw_score,
        normalizedScore: anomaly.normalized_score,
        threshold: anomaly.threshold,
        band: anomaly.band,
        unusualFeatureIndicators: anomaly.unusual_feature_indicators,
        interpretationNote: anomaly.interpretation_note,
        linkedFacts: buildFactLinks(
          anomaly.linked_fact_ids ?? [],
          factsById,
        ),
        linkedObservations: buildObservationLinks(
          anomaly.linked_observation_ids ?? [],
          observationsById,
        ),
        directEvidence,
        evidenceThroughSources,
        limitations: anomaly.limitations,
      };
    })
    .sort(
      (left, right) =>
        right.normalizedScore - left.normalizedScore ||
        left.anomalyResultId.localeCompare(right.anomalyResultId),
    );

  const bands = [
    ...new Map(
      results.map((item) => [
        item.band,
        results.filter((candidate) => candidate.band === item.band).length,
      ]),
    ).entries(),
  ]
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([key, count]) => ({ key, count }));
  const models = [
    ...new Map(
      results.map((item) => {
        const key = JSON.stringify([item.modelId, item.modelVersion]);
        return [
        key,
        {
          key,
          label: `${item.modelId} v${item.modelVersion}`,
          count: results.filter(
            (candidate) =>
              candidate.modelId === item.modelId &&
              candidate.modelVersion === item.modelVersion,
          ).length,
        },
        ] as const;
      }),
    ).values(),
  ].sort((left, right) => left.label.localeCompare(right.label));

  const resultSessionIds = new Set(results.map((item) => item.session.sessionId));

  return {
    analysisId: analysis.analysis_id,
    dataSource: result.data_source,
    datasetLabel: result.dataset_label,
    mlEngineStatus: analysis.ml_engine_status,
    modelId: analysis.model_id,
    modelVersion: analysis.model_version,
    resultCount: anomaly_results.length,
    results,
    sessions: [...sessionLinks.values()].filter((session) =>
      resultSessionIds.has(session.sessionId),
    ),
    bands,
    models,
  };
}
