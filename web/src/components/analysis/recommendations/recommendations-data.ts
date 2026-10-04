import type { AnalysisResult } from "@/lib/contracts/analysis";
import {
  buildPolicyFindingsData,
  type FindingDetail,
  type FindingRecommendation,
  type FindingSessionLink,
  type PolicyFindingsData,
} from "../findings/findings-view-model";

export type RecommendationSession = FindingSessionLink & {
  tcpStreamId: number;
  captureCompleteness: string;
};

export type RecommendationRecord = FindingRecommendation & {
  standardsReferences: Array<{ id: string; section?: string | null }>;
};

export type RecommendationFinding = Omit<
  FindingDetail,
  "linkedSessions" | "recommendation"
> & {
  linkedSessions: RecommendationSession[];
  recommendation: RecommendationRecord | null;
};

export type RecommendationsPolicyData = Omit<PolicyFindingsData, "findings"> & {
  findings: RecommendationFinding[];
  ruleEngineStatus: string;
  hasIncompleteSessions: boolean;
  analysisSessions: RecommendationSession[];
  recommendations: RecommendationRecord[];
};

/** Project the validated result for this page without changing the Findings model. */
export function buildRecommendationsPolicyData(
  result: AnalysisResult,
): RecommendationsPolicyData {
  const base = buildPolicyFindingsData(result);
  const { analysis, sessions, captures, recommendations } = result.chain;
  const capturesById = new Map(captures.map((capture) => [capture.capture_id, capture]));
  const analysisSessions: RecommendationSession[] = sessions.map((session) => {
    const endpoint = (ip: string, port: number) =>
      (ip.includes(":") ? "[" + ip + "]" : ip) + ":" + port;

    return {
      sessionId: session.session_id,
      captureName: capturesById.get(session.capture_id)?.original_filename_sanitized ?? null,
      protocol: session.protocol,
      tcpStreamId: session.tcp_stream_id,
      sourceEndpoint: endpoint(session.source_endpoint.ip, session.source_endpoint.port),
      destinationEndpoint: endpoint(session.destination_endpoint.ip, session.destination_endpoint.port),
      captureCompleteness: session.capture_completeness,
    };
  });
  const sessionsById = new Map(analysisSessions.map((session) => [session.sessionId, session]));
  const recommendationList: RecommendationRecord[] = recommendations.map((recommendation) => ({
    recommendationId: recommendation.recommendation_id,
    title: recommendation.title,
    summary: recommendation.summary,
    priority: recommendation.priority,
    actionSteps: recommendation.action_steps,
    verificationSteps: recommendation.verification_steps,
    standardsReferences: recommendation.standards_references,
    scope: recommendation.scope,
    automationStatus: recommendation.automation_status,
  }));
  const recommendationsById = new Map(
    recommendationList.map((recommendation) => [recommendation.recommendationId, recommendation]),
  );

  return {
    ...base,
    findings: base.findings.map((finding) => ({
      ...finding,
      linkedSessions: finding.linkedSessions.map((session) => sessionsById.get(session.sessionId)!),
      recommendation: recommendationsById.get(finding.recommendationId) ?? null,
    })),
    sessions: base.sessions.map((session) => sessionsById.get(session.sessionId)!),
    ruleEngineStatus: analysis.rule_engine_status,
    hasIncompleteSessions: sessions.some((session) => session.capture_completeness !== "complete"),
    analysisSessions,
    recommendations: recommendationList,
  };
}
