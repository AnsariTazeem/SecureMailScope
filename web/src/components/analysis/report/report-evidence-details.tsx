import Link from "next/link";
import type { ReactNode } from "react";
import type { ReportPageData } from "./report-view-model";

const focusStyle = "cursor-pointer rounded-sm text-sm font-medium text-neutral-950 outline-none focus-visible:ring-2 focus-visible:ring-neutral-950 focus-visible:ring-offset-2";

export function ReportDetails({ title, children }: { title: string; children: ReactNode }) {
  return (
    <details data-report-print-expand className="min-w-0 rounded-md border border-neutral-200 bg-neutral-50 p-4">
      <summary className={focusStyle}>{title}</summary>
      <div className="mt-4 min-w-0 space-y-4">{children}</div>
    </details>
  );
}

export function SourceRecordDetails({ title = "View source record", value }: { title?: string; value: unknown }) {
  return (
    <details data-print-hide className="min-w-0">
      <summary className={focusStyle}>{title}</summary>
      <pre className="mt-3 max-w-full whitespace-pre-wrap break-all rounded-md border border-neutral-200 bg-white p-3 font-mono text-[11px] leading-5">
        {JSON.stringify(value, null, 2)}
      </pre>
    </details>
  );
}

function fieldLabel(key: string): string {
  const label = key.replaceAll("_", " ");
  return label.charAt(0).toUpperCase() + label.slice(1);
}

/** Render supplied values without interpreting unknown states or cryptographic results. */
function RecordValue({ value }: { value: unknown }): ReactNode {
  if (value === null || value === undefined) return <span>Not supplied</span>;
  if (typeof value === "boolean") return <span>{value ? "True" : "False"}</span>;
  if (typeof value === "string" || typeof value === "number") return <span>{String(value) || "Empty"}</span>;
  if (Array.isArray(value)) {
    return value.length ? (
      <ul className="space-y-2">{value.map((item, index) => <li key={index}><RecordValue value={item} /></li>)}</ul>
    ) : <span>None supplied</span>;
  }
  if (typeof value === "object") {
    return <RecordFields record={value as Record<string, unknown>} />;
  }
  return <span>Not supplied</span>;
}

function RecordFields({ record }: { record: Record<string, unknown> }) {
  return (
    <dl className="min-w-0 divide-y divide-neutral-200">
      {Object.entries(record).map(([key, value]) => (
        <div key={key} className="grid min-w-0 gap-1 py-2 sm:grid-cols-[minmax(0,10rem)_minmax(0,1fr)] sm:gap-4">
          <dt title={key} className="break-words text-xs font-medium text-neutral-600">{fieldLabel(key)}</dt>
          <dd className="min-w-0 break-words text-xs leading-5 text-neutral-900 [overflow-wrap:anywhere]"><RecordValue value={value} /></dd>
        </div>
      ))}
    </dl>
  );
}

export function ReportEvidenceDetails({ data }: { data: ReportPageData }) {
  const chain = data.chain;
  const groups: Array<{ title: string; records: Array<{ id: string; value: Record<string, unknown> }> }> = [
    { title: "Analysis and execution", records: [{ id: chain.analysis.analysis_id, value: chain.analysis }, { id: "Execution diagnostics", value: chain.execution }] },
    { title: "Capture provenance", records: chain.captures.map(value => ({ id: value.capture_id, value })) },
    { title: "Session records", records: chain.sessions.map(value => ({ id: value.session_id, value })) },
    { title: "Evidence records", records: chain.evidence.map(value => ({ id: value.evidence_id, value })) },
    { title: "Protocol events", records: chain.protocol_events.map(value => ({ id: value.event_id, value })) },
    { title: "Cryptographic observations", records: chain.crypto_observations.map(value => ({ id: value.observation_id, value })) },
    { title: "Derived facts", records: chain.derived_facts.map(value => ({ id: value.fact_id, value })) },
    { title: "Rule evaluations", records: chain.rule_evaluations.map(value => ({ id: value.evaluation_id, value })) },
    { title: "Policy Risk record", records: chain.policy_risk ? [{ id: chain.policy_risk.policy_risk_id, value: chain.policy_risk }] : [] },
    { title: "ML result records", records: chain.anomaly_results.map(value => ({ id: value.anomaly_result_id, value })) },
    { title: "Finding source records", records: chain.findings.map(value => ({ id: value.finding_id, value })) },
    { title: "Recommendation source records", records: chain.recommendations.map(value => ({ id: value.recommendation_id, value })) },
    { title: "Artifact manifests", records: chain.artifacts.map(value => ({ id: value.artifact_manifest_id, value })) },
  ];

  return (
    <section data-report-appendix aria-labelledby="report-evidence-heading" className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h2 id="report-evidence-heading" className="text-lg font-semibold tracking-tight text-neutral-950">Technical appendix</h2>
        <Link href={data.links.proofMap} data-print-hide className="report-text-link text-sm">Open Proof Map</Link>
      </div>
      <p className="text-sm leading-6 text-neutral-600">Complete source records for audit and traceability. The report above contains the readable assessment and actions.</p>
      <ReportDetails title="Complete evidence and source records">
      {groups.filter(({ records }) => records.length > 0).map(({ title, records }) => (
        <ReportDetails key={title} title={title + " (" + records.length + ")"}>
          {records.length ? records.map(({ id, value }) => (
            <article key={id} id={"source-" + id.replaceAll(" ", "-")} data-report-source-id={id} className="min-w-0 rounded-md border border-neutral-200 bg-white p-4">
              <h3 className="break-all font-mono text-xs font-semibold text-neutral-950">{id}</h3>
              <RecordFields record={value} />
              <SourceRecordDetails value={value} />
            </article>
          )) : <p className="text-sm text-neutral-600">No records supplied.</p>}
        </ReportDetails>
      ))}
      </ReportDetails>
    </section>
  );
}
