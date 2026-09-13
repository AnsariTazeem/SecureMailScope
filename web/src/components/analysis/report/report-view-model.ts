import type { AnalysisResult } from "@/lib/contracts/analysis";
import type { AnalysisLimitation, Session } from "@/lib/contracts/chain";

export type ReportLimitation = AnalysisLimitation & { owner: string };

export function reportSessionLabel(session: Session): string {
  const endpoint = ({ ip, port }: Session["source_endpoint"]) =>
    `${ip.includes(":") ? `[${ip}]` : ip}:${port}`;
  return `${session.protocol.toUpperCase()} · stream ${session.tcp_stream_id} · ${endpoint(session.source_endpoint)} → ${endpoint(session.destination_endpoint)}`;
}

/** Presentation only: retain complete source records, ordering and ownership. */
export function buildReportPageData(result: AnalysisResult) {
  const chain = result.chain;
  const analysisId = chain.analysis.analysis_id;
  const base = `/analysis/${analysisId}`;
  const limitations: ReportLimitation[] = [];
  const collect = (owner: string, supplied: AnalysisLimitation[]) => {
    for (const limitation of supplied) limitations.push({ ...limitation, owner });
  };
  collect(analysisId, chain.analysis.limitations);
  for (const session of chain.sessions) collect(session.session_id, session.limitations);
  for (const event of chain.protocol_events) collect(event.event_id, event.limitations);
  for (const observation of chain.crypto_observations) collect(observation.observation_id, observation.limitations);
  for (const fact of chain.derived_facts) collect(fact.fact_id, fact.limitations);
  for (const finding of chain.findings) collect(finding.finding_id, finding.limitations);
  if (chain.policy_risk) collect(chain.policy_risk.policy_risk_id, chain.policy_risk.limitations);
  for (const anomaly of chain.anomaly_results) collect(anomaly.anomaly_result_id, anomaly.limitations);
  chain.execution.stage_diagnostics.forEach((stage, index) => {
    if (stage.limitation) collect(`Stage ${stage.stage} · record ${index + 1}`, [stage.limitation]);
  });

  return {
    analysisId,
    dataSource: result.data_source,
    datasetLabel: result.dataset_label,
    chain,
    limitations,
    sessions: chain.sessions.map((session) => ({
      source: session,
      label: reportSessionLabel(session),
      href: `${base}/sessions/${session.session_id}?tab=findings`,
      evidenceHref: `${base}/sessions/${session.session_id}?tab=findings#session-evidence-records-heading`,
      findings: chain.findings.filter((finding) => finding.session_id === session.session_id),
      observations: chain.crypto_observations.filter((observation) => observation.session_id === session.session_id),
      facts: chain.derived_facts.filter((fact) => fact.session_id === session.session_id),
    })),
    recommendations: chain.recommendations.map((recommendation) => {
      const findings = chain.findings.filter((finding) => finding.recommendation_id === recommendation.recommendation_id);
      return {
        source: recommendation,
        findings,
        sessions: chain.sessions.filter((session) => findings.some((finding) => finding.session_id === session.session_id)),
        href: `${base}/recommendations#${recommendation.recommendation_id}`,
      };
    }),
    links: {
      overview: `${base}/overview`,
      sessions: `${base}/sessions`,
      findings: `${base}/findings?view=policy`,
      recommendations: `${base}/recommendations`,
    },
  };
}

export type ReportPageData = ReturnType<typeof buildReportPageData>;
