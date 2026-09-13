import type { ReportPageData } from "./report-view-model";

export function ReportPrintIdentity({ data }: { data: ReportPageData }) {
  return (
    <section data-report-print-only data-report-section aria-labelledby="print-report-identity">
      <h2 id="print-report-identity" className="text-lg font-semibold">Analysis and capture identity</h2>
      <p className="text-sm"><strong>{data.datasetLabel ?? "Production analysis result"}</strong> · <code>{data.analysisId}</code></p>
      <p className="text-xs">Started: {data.chain.analysis.started_at} · Completed: {data.chain.analysis.completed_at ?? "Not available"}</p>
      {data.chain.captures.map((capture) => (
        <div key={capture.capture_id} className="mt-2 text-xs leading-5">
          <p><strong>{capture.original_filename_sanitized || "Filename not available"}</strong> · {capture.format} · {capture.packet_count} packets · {capture.size_bytes} bytes</p>
          <p>Capture: <code>{capture.capture_id}</code></p>
          <p>SHA-256: <code>{capture.sha256}</code></p>
        </div>
      ))}
      <p className="text-xs">Full provenance, timestamps, tool versions and raw records follow in the technical appendix.</p>
    </section>
  );
}

/** Each top-level source record appears once in the printed appendix. */
export function ReportPrintAppendix({ data }: { data: ReportPageData }) {
  const { chain } = data;
  const groups: Array<{ title: string; records: Array<{ id: string; value: unknown }> }> = [
    { title: "Analysis manifest", records: [{ id: chain.analysis.analysis_id, value: chain.analysis }] },
    { title: "Execution diagnostics and tool versions", records: [{ id: "execution", value: chain.execution }] },
    { title: "Capture provenance", records: chain.captures.map(value => ({ id: value.capture_id, value })) },
    { title: "Sessions", records: chain.sessions.map(value => ({ id: value.session_id, value })) },
    { title: "Policy Risk", records: chain.policy_risk ? [{ id: chain.policy_risk.policy_risk_id, value: chain.policy_risk }] : [] },
    { title: "ML results", records: chain.anomaly_results.map(value => ({ id: value.anomaly_result_id, value })) },
    { title: "Findings", records: chain.findings.map(value => ({ id: value.finding_id, value })) },
    { title: "Recommendations", records: chain.recommendations.map(value => ({ id: value.recommendation_id, value })) },
    { title: "Evidence records", records: chain.evidence.map(value => ({ id: value.evidence_id, value })) },
    { title: "Protocol events", records: chain.protocol_events.map(value => ({ id: value.event_id, value })) },
    { title: "Cryptographic observations", records: chain.crypto_observations.map(value => ({ id: value.observation_id, value })) },
    { title: "Derived facts", records: chain.derived_facts.map(value => ({ id: value.fact_id, value })) },
    { title: "Rule evaluations", records: chain.rule_evaluations.map(value => ({ id: value.evaluation_id, value })) },
    { title: "Artifact manifests", records: chain.artifacts.map(value => ({ id: value.artifact_manifest_id, value })) },
  ];

  return (
    <section data-report-print-only data-report-appendix aria-labelledby="report-appendix">
      <h2 id="report-appendix" className="text-xl font-semibold">Technical appendix — complete source records</h2>
      <p className="text-sm leading-6">{data.datasetLabel ?? "Production analysis result"} · <code>{data.analysisId}</code>. Exact source values and record ownership are preserved below. Each complete record is printed once; nested limitations and contributions remain with their owning record.</p>
      <p className="text-xs">Schema: {chain.schema_id} · Version: {chain.chain_schema_version}</p>
      <h3 className="mt-4 text-base font-semibold">Limitation ownership index</h3>
      <p className="text-xs leading-5">Every supplied occurrence is listed, including equal summaries with distinct details. Complete detail remains in the corresponding source record below; stage limitations belong to execution diagnostics.</p>
      {data.limitations.length ? (
        <ul className="mt-2 space-y-2 text-xs leading-5">
          {data.limitations.map((limitation, index) => (
            <li key={index} data-report-limitation-owner={limitation.owner}>
              <strong>{limitation.owner}</strong> · {limitation.code}: {limitation.summary}
            </li>
          ))}
        </ul>
      ) : <p className="text-xs">No limitation records supplied.</p>}
      {groups.map(({ title, records }) => (
        <section key={title} data-report-section className="mt-5">
          <h3 className="text-base font-semibold">{title} ({records.length})</h3>
          {records.length ? records.map(({ id, value }) => (
            <div key={id} data-report-raw-record={id} className="mt-3">
              <h4 className="font-mono text-xs font-semibold">{id}</h4>
              <pre className="mt-2 whitespace-pre-wrap break-all font-mono text-[11px] leading-5">{JSON.stringify(value, null, 2)}</pre>
            </div>
          )) : <p className="text-xs">No records supplied.</p>}
        </section>
      ))}
    </section>
  );
}
