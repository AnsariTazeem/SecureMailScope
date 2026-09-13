import type {
  FindingDetail,
  FindingRecommendation,
  PolicyFindingsData,
} from "../findings/findings-view-model";

export type RecommendationGroup = {
  recommendation: FindingRecommendation;
  linkedFindings: FindingDetail[];
  linkedSessions: FindingDetail["linkedSessions"];
};

export type RecommendationSelection = {
  filterState: "all" | "valid" | "invalid";
  selectedSession: PolicyFindingsData["analysisSessions"][number] | null;
  findings: FindingDetail[];
  groups: RecommendationGroup[];
};

export function selectRecommendations(
  data: PolicyFindingsData,
  sessionId: string | null,
): RecommendationSelection {
  const selectedSession = sessionId
    ? (data.analysisSessions.find((session) => session.sessionId === sessionId) ??
      null)
    : null;
  const filterState = sessionId
    ? selectedSession
      ? "valid"
      : "invalid"
    : "all";
  const findings =
    filterState === "invalid"
      ? []
      : data.findings.filter(
          (finding) =>
            !selectedSession ||
            finding.linkedSessions.some(
              (session) => session.sessionId === selectedSession.sessionId,
            ),
        );

  const filteredRecommendationIds = new Set(
    findings.map((finding) => finding.recommendationId),
  );
  const recommendations =
    filterState === "all"
      ? data.recommendations
      : filterState === "valid"
        ? data.recommendations.filter((recommendation) =>
            filteredRecommendationIds.has(recommendation.recommendationId),
          )
        : [];

  return {
    filterState,
    selectedSession,
    findings,
    groups: recommendations.map((recommendation) => {
      const linkedFindings = findings.filter(
        (finding) =>
          finding.recommendationId === recommendation.recommendationId,
      );
      const allLinkedFindings = data.findings.filter(
        (finding) =>
          finding.recommendationId === recommendation.recommendationId,
      );
      const linkedSessions = [
        ...new Map(
          allLinkedFindings.flatMap((finding) =>
            finding.linkedSessions.map((session) => [session.sessionId, session]),
          ),
        ).values(),
      ];
      return { recommendation, linkedFindings, linkedSessions };
    }),
  };
}
