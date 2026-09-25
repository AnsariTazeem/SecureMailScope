import Link from "next/link";
import type { ReactNode } from "react";

import { engineStatusLabels, severityStyles } from "@/components/analysis/findings/findings-view-model";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type { ChainOfProof } from "@/lib/contracts/chain";
import { cn } from "@/lib/utils";

import { FindingArtifactActions, ReportExportActions } from "./report-export-actions";
import { reportSessionLabel, type ReportPageData } from "./report-view-model";
import styles from "./report.module.css";
import { ReportPrintAppendix, ReportPrintIdentity } from "./report-print-appendix";

const linkStyle = "rounded-sm underline decoration-neutral-300 underline-offset-4 outline-none hover:decoration-neutral-950 focus-visible:ring-2 focus-visible:ring-neutral-950 focus-visible:ring-offset-2";
const textStyle = "whitespace-pre-wrap break-words text-sm leading-6 text-neutral-700";
const severityOrder: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

function ReportSection({ id, title, children }: { id: string; title: string; children: ReactNode }) {
  return (
    <section data-report-section aria-labelledby={id} className="min-w-0 space-y-4">
      <h2 id={id} className="text-lg font-semibold tracking-tight text-neutral-950">{title}</h2>
      {children}
    </section>
  );
}

// Screen disclosures stay in place; complete print records live in the appendix.
function TechnicalDetails({ title, children }: { title: string; children: ReactNode }) {
  return (
    <details data-report-screen-only className="min-w-0 rounded-md border border-neutral-200 bg-neutral-50 p-3">
      <summary className="cursor-pointer rounded-sm text-xs font-semibold outline-none focus-visible:ring-2 focus-visible:ring-neutral-950">{title}</summary>
      <div className="mt-3 min-w-0 space-y-3">{children}</div>
    </details>
  );
}

function SourceRecord({ value }: { value: unknown }) {
  return <pre className="max-w-full whitespace-pre-wrap break-all font-mono text-[11px] leading-5 text-neutral-700">{JSON.stringify(value, null, 2)}</pre>;
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return <div className="min-w-0"><dt className="text-[10px] font-bold uppercase tracking-wide text-neutral-500">{label}</dt><dd className="mt-1 whitespace-pre-wrap break-all text-xs leading-5 text-neutral-950">{children}</dd></div>;
}

function Severity({ value }: { value: string }) {
  return <Badge variant="outline" className={cn("w-fit rounded-md uppercase", severityStyles[value] ?? severityStyles.info)}>{value}</Badge>;
}

function SessionLink({ data, sessionId }: { data: ReportPageData; sessionId: string }) {
  const session = data.sessions.find((item) => item.source.session_id === sessionId)!;
  return <Link href={session.href} className={cn(linkStyle, "block text-xs leading-5")}>{session.label}</Link>;
}

function ExecutiveSummary({ data }: { data: ReportPageData }) {
  const primaryFinding = [...data.chain.findings].sort(
    (left, right) =>
      (severityOrder[left.severity] ?? 99) -
      (severityOrder[right.severity] ?? 99),
  )[0];
  const recommendation = primaryFinding
    ? data.chain.recommendations.find(
        (item) =>
          item.recommendation_id === primaryFinding.recommendation_id,
      )
    : null;

  return (
    <ReportSection id="report-executive-summary" title="Executive summary">
      <Card className="overflow-hidden rounded-xl border-neutral-200 shadow-sm ring-0">
        <CardContent className="p-0">
          <div className="grid gap-0 lg:grid-cols-[minmax(0,1.4fr)_minmax(18rem,0.6fr)]">
            <div className="p-5 sm:p-6">
              {primaryFinding ? (
                <>
                  <div className="flex flex-wrap items-center gap-2">
                    <Severity value={primaryFinding.severity} />
                    <span className="text-xs text-neutral-600">
                      Evidence confidence: {primaryFinding.evidence_confidence}
                    </span>
                  </div>
                  <h3 className="mt-3 text-xl font-semibold tracking-tight text-neutral-950">
                    {primaryFinding.title}
                  </h3>
                  <p className={cn("mt-3", textStyle)}>
                    {primaryFinding.rationale}
                  </p>
                  <p className={cn("mt-2", textStyle)}>
                    <strong className="text-neutral-950">Impact:</strong>{" "}
                    {primaryFinding.impact}
                  </p>
                  {recommendation ? (
                    <div className="mt-4 rounded-md border border-neutral-200 bg-neutral-50 p-4">
                      <p className="text-[10px] font-bold uppercase tracking-wide text-neutral-500">
                        Recommended action
                      </p>
                      <p className="mt-1 text-sm font-semibold text-neutral-950">
                        {recommendation.title}
                      </p>
                      <p className="mt-1 text-xs leading-5 text-neutral-600">
                        {recommendation.summary}
                      </p>
                    </div>
                  ) : null}
                </>
              ) : (
                <>
                  <h3 className="text-lg font-semibold text-neutral-950">
                    No deterministic finding was supplied
                  </h3>
                  <p className={cn("mt-2", textStyle)}>
                    This does not establish that the analyzed scope is secure.
                    Review completion and observability limitations below.
                  </p>
                </>
              )}
            </div>
            <div className="border-t border-neutral-200 bg-neutral-50 p-5 sm:p-6 lg:border-l lg:border-t-0">
              <dl className="grid grid-cols-3 gap-4 lg:grid-cols-1">
                <Field label="Reconstructed sessions">
                  {data.sessions.length}
                </Field>
                <Field label="Deterministic findings">
                  {data.chain.findings.length}
                </Field>
                <Field label="Evidence records">
                  {data.chain.evidence.length}
                </Field>
              </dl>
              {primaryFinding ? (
                <div data-print-hide className="mt-5 flex flex-col gap-2">
                  <Link
                    href={`/analysis/${data.analysisId}/sessions/${primaryFinding.session_id}?tab=findings`}
                    className="inline-flex min-h-9 items-center justify-center rounded-md bg-neutral-950 px-4 text-sm font-medium text-white"
                  >
                    Trace the primary finding
                  </Link>
                  <Link
                    href={data.links.recommendations}
                    className="inline-flex min-h-9 items-center justify-center rounded-md border border-neutral-300 bg-white px-4 text-sm font-medium text-neutral-900"
                  >
                    Review actions
                  </Link>
                </div>
              ) : null}
            </div>
          </div>
        </CardContent>
      </Card>
    </ReportSection>
  );
}

function Identity({ data }: { data: ReportPageData }) {
  const { analysis, captures } = data.chain;
  return (
    <ReportSection id="report-identity" title="Capture and analysis provenance">
      <Card className="rounded-lg border-neutral-200 shadow-sm ring-0">
        <CardContent className="space-y-5">
          <dl className="grid gap-4 sm:grid-cols-2">
            <Field label="Analysis ID">{data.analysisId}</Field>
            <Field label="Source">Validated analysis result</Field>
            <Field label="Started (UTC)">{analysis.started_at}</Field>
            <Field label="Completed (UTC)">{analysis.completed_at ?? "Not available"}</Field>
          </dl>
          {captures.map((capture) => (
            <article key={capture.capture_id} className="space-y-3 rounded-md border border-neutral-200 bg-neutral-50 p-4">
              <h3 className="break-words text-sm font-semibold">{capture.original_filename_sanitized || "Filename not available"}</h3>
              <dl className="grid gap-3 sm:grid-cols-2">
                <Field label="Capture ID">{capture.capture_id}</Field>
                <Field label="Format / size">{capture.format} · {capture.size_bytes} bytes</Field>
                <div className="min-w-0 sm:col-span-2"><Field label="Capture SHA-256">{capture.sha256}</Field></div>
                <Field label="Capture start (UTC)">{capture.captured_at_start ?? "Not available"}</Field>
                <Field label="Capture end (UTC)">{capture.captured_at_end ?? "Not available"}</Field>
                <Field label="Packets / truncated packets">{capture.packet_count} / {capture.truncated_packet_count}</Field>
              </dl>
              <TechnicalDetails title="Complete capture provenance"><SourceRecord value={capture} /></TechnicalDetails>
            </article>
          ))}
          <TechnicalDetails title="Analysis manifest, tool versions and execution stages"><SourceRecord value={analysis} /><SourceRecord value={data.chain.execution} /></TechnicalDetails>
        </CardContent>
      </Card>
    </ReportSection>
  );
}

function Scope({ data }: { data: ReportPageData }) {
  const { analysis, captures, findings, evidence, recommendations } = data.chain;
  const completenessStates = [...new Set(data.sessions.map(({ source }) => source.capture_completeness))];
  return (
    <ReportSection id="report-scope" title="Scope, completion and limitations">
      <Card className="rounded-lg border-neutral-200 shadow-sm ring-0">
        <CardContent className="space-y-4">
          <dl className="grid gap-4 sm:grid-cols-2">
            <Field label="Analysis state">{analysis.analysis_status.replaceAll("_", " ")}</Field>
            <Field label="Supplied records">{data.sessions.length} sessions · {findings.length} findings · {recommendations.length} recommendations · {evidence.length} evidence records</Field>
          </dl>
          <p className={textStyle}>This assessment covers the supplied capture and reconstructed sessions. Missing records and absent findings do not establish that a service is secure. Policy and ML completion are reported separately below.</p>
          {analysis.analysis_status !== "complete" ? <p className="text-sm font-medium text-amber-800">Analysis is {analysis.analysis_status}; read the supplied limitations before using these results.</p> : null}
          <p data-report-print-only className="text-xs leading-5">
            Session capture completeness: {completenessStates.length ? completenessStates.map(state => `${state}: ${data.sessions.filter(({ source }) => source.capture_completeness === state).length}`).join("; ") : "No sessions supplied"}. Exact session records follow in the appendix.
          </p>
          {data.sessions.map(({ source, label }) => (
            <div data-report-screen-only key={source.session_id} className="space-y-1 border-t border-neutral-100 pt-3">
              <p className={textStyle}>{label}</p>
              <p className="text-xs text-neutral-600">Capture completeness: <strong>{source.capture_completeness.replaceAll("_", " ")}</strong></p>
            </div>
          ))}
          {captures.map((capture) => capture.capture_warnings.map((warning, index) => (
            <div key={`${capture.capture_id}-${index}`} className="rounded-md border border-amber-200 bg-amber-50 p-3">
              <p className="break-all text-xs font-semibold">Capture warning · {capture.capture_id}</p><p className={textStyle}>{warning}</p>
            </div>
          )))}
          <div data-report-print-only>
            <h3 className="text-sm font-semibold">Analysis limitations</h3>
            <ul className="mt-2 space-y-2 text-xs leading-5">
              {analysis.limitations.map((limitation, index) => <li key={index}>{limitation.summary} <code>({limitation.code})</code></li>)}
            </ul>
            {data.sessions.flatMap(({ source }) => source.limitations.map((limitation, index) => (
              <p key={`${source.session_id}-${index}`} className="mt-2 text-xs leading-5"><code>{source.session_id}</code> · {limitation.summary} <code>({limitation.code})</code></p>
            )))}
            <p className="mt-2 text-xs">Finding-specific uncertainty appears with each finding. All {data.limitations.length} supplied limitation records and their owners are retained in the technical appendix, including session, evidence-derived, policy, ML and execution limitations.</p>
          </div>
          <div data-report-screen-only>
          <details>
          <summary className="cursor-pointer text-sm font-semibold">Supplied limitations ({data.limitations.length})</summary>
          {data.limitations.length === 0 ? <p className={textStyle}>No limitation records supplied. This is not a claim of complete observability.</p> : (
            <ul className="space-y-3">
              {data.limitations.map((limitation, index) => (
                <li key={index} className="space-y-2 rounded-md border border-neutral-200 bg-neutral-50 p-3">
                  <p className={textStyle}>{limitation.summary}</p>
                  <p className="break-all text-[11px] text-neutral-500">{limitation.code} · {limitation.owner}</p>
                  {limitation.detail ? <TechnicalDetails title="Limitation detail"><p className={textStyle}>{limitation.detail}</p></TechnicalDetails> : null}
                </li>
              ))}
            </ul>
          )}
          </details>
          </div>
        </CardContent>
      </Card>
    </ReportSection>
  );
}

function Assessments({ data }: { data: ReportPageData }) {
  const { analysis, policy_risk, anomaly_results } = data.chain;
  const anomalyBands = [
    ...new Set(anomaly_results.map((anomaly) => anomaly.band.replaceAll("_", " "))),
  ];
  return (
    <ReportSection id="report-assessments" title="Policy Risk and separate ML status">
      <div data-report-print-flow className="grid items-start gap-4 lg:grid-cols-2">
        <Card className="rounded-lg border-neutral-200 shadow-sm ring-0">
          <CardHeader><CardTitle><h3>Policy Risk</h3></CardTitle></CardHeader>
          <CardContent className="space-y-4">
            <div data-report-keep>
              <p className="text-2xl font-semibold">{policy_risk ? `${policy_risk.capped_score} / 100` : "Not available"}</p>
              <p className="mt-2 text-sm text-neutral-600">
                {engineStatusLabels[analysis.rule_engine_status] ?? analysis.rule_engine_status}
                {policy_risk ? ` · ${policy_risk.contributions.length} contribution${policy_risk.contributions.length === 1 ? "" : "s"}` : ""}
              </p>
            </div>
            {policy_risk ? <TechnicalDetails title="Policy profile, uncapped score, and contributions"><SourceRecord value={policy_risk} /></TechnicalDetails> : <p className={textStyle}>No policy score was supplied.</p>}
            <p className="text-xs leading-5 text-neutral-600">Scores and contributions are supplied by the analysis source. This report does not recalculate risk.</p>
          </CardContent>
        </Card>
        <Card className="rounded-lg border-neutral-200 shadow-sm ring-0">
          <CardHeader><CardTitle><h3>ML Anomaly</h3></CardTitle></CardHeader>
          <CardContent className="space-y-4">
            <p className="text-2xl font-semibold">{anomalyBands.length > 0 ? anomalyBands.join(", ") : engineStatusLabels[analysis.ml_engine_status] ?? analysis.ml_engine_status}</p>
            {analysis.ml_engine_status === "not_run" ? <p className={textStyle}>ML did not run. No anomaly score or ML conclusion is available.</p> : <p className={textStyle}>{anomaly_results.length} anomaly result records supplied.</p>}
            {anomaly_results.length > 0 ? (
              <details data-report-screen-only className="rounded-md border border-neutral-200 bg-neutral-50">
                <summary className="cursor-pointer px-3 py-2 text-xs font-semibold outline-none focus-visible:ring-2 focus-visible:ring-neutral-950">
                  Review anomaly results
                </summary>
                <div className="space-y-4 border-t border-neutral-200 p-3">
                  {anomaly_results.map((anomaly) => <div key={anomaly.anomaly_result_id} className="space-y-3 border-b border-neutral-200 pb-4 last:border-b-0 last:pb-0"><SessionLink data={data} sessionId={anomaly.session_id} /><p className={textStyle}>Anomaly band: {anomaly.band.replaceAll("_", " ")}</p><p className={textStyle}>{anomaly.interpretation_note}</p><TechnicalDetails title="Exact ML result, features and limitations"><SourceRecord value={anomaly} /></TechnicalDetails></div>)}
                </div>
              </details>
            ) : null}
            <p className="text-xs leading-5 text-neutral-600">Anomalous behavior is not proof of malicious activity. ML is separate from deterministic Policy Risk.</p>
          </CardContent>
        </Card>
      </div>
    </ReportSection>
  );
}

function Findings({ data }: { data: ReportPageData }) {
  return (
    <ReportSection id="report-findings" title="Findings and affected sessions">
      {data.chain.findings.length === 0 ? <p className={textStyle}>No findings supplied. Analysis: {data.chain.analysis.analysis_status}; policy engine: {data.chain.analysis.rule_engine_status}. Absence of findings is not a security conclusion.</p> : null}
      {data.chain.findings.map((finding) => (
        <article id={finding.finding_id} key={finding.finding_id} className="min-w-0 space-y-4 rounded-lg border border-neutral-200 bg-white p-5 shadow-sm">
          <div data-report-heading className="flex flex-col items-start justify-between gap-3 sm:flex-row"><h3 className="break-words text-base font-semibold">{finding.title}</h3><Severity value={finding.severity} /></div>
          <SessionLink data={data} sessionId={finding.session_id} />
          <p className={textStyle}>{finding.rationale}</p>
          <div><h4 className="text-xs font-semibold">Impact</h4><p className={textStyle}>{finding.impact}</p></div>
          <p className="text-xs leading-5">Evidence confidence: {finding.evidence_confidence.replaceAll("_", " ")}</p>
          {finding.limitations.map((limitation, index) => <p key={index} className={textStyle}>{limitation.summary} <span className="text-xs">({limitation.code}; full detail in limitations and the technical appendix)</span></p>)}
          <div className="space-y-2"><h4 className="text-xs font-semibold">Direct evidence references</h4><ul className="space-y-1">{finding.evidence_ids.map((id) => <li key={id}><a href={`#${id}`} className={cn(linkStyle, "break-all font-mono text-xs")}>{id}</a></li>)}</ul></div>
          <Link href={`${data.links.recommendations}#${finding.recommendation_id}`} className={cn(linkStyle, "block text-xs")}>Review recommended action</Link>
          <TechnicalDetails title="Finding rule, fact references and exact source record"><SourceRecord value={finding} /></TechnicalDetails>
          {data.dataSource === "api" ? <FindingArtifactActions analysisId={data.analysisId} findingId={finding.finding_id} /> : null}
        </article>
      ))}
      <Link href={data.links.findings} className={cn(linkStyle, "inline-block text-sm")}>Open Policy Findings</Link>
    </ReportSection>
  );
}

function Recommendations({ data }: { data: ReportPageData }) {
  return (
    <ReportSection id="report-recommendations" title="Recommendations and verification">
      {data.recommendations.length === 0 ? <p className={textStyle}>No recommendations supplied. This does not establish that no follow-up is needed; review the assessment state and limitations.</p> : null}
      {data.recommendations.map(({ source, findings, sessions, href }) => (
        <article id={source.recommendation_id} key={source.recommendation_id} className="min-w-0 space-y-4 rounded-lg border border-neutral-200 bg-white p-5 shadow-sm">
          <div data-report-heading className="flex flex-col items-start justify-between gap-3 sm:flex-row"><h3 className="break-words text-base font-semibold"><Link href={href} className={linkStyle}>{source.title}</Link></h3><Severity value={source.priority} /></div>
          <p className={textStyle}>{source.summary}</p>
          {findings.length ? <ul className="space-y-2">{findings.map((finding) => <li key={finding.finding_id}><a href={`#${finding.finding_id}`} className={cn(linkStyle, "text-xs")}>{finding.title}</a></li>)}</ul> : <p className={textStyle}>No finding relationship supplied for this recommendation.</p>}
          {sessions.map((session) => <SessionLink key={session.session_id} data={data} sessionId={session.session_id} />)}
          <div data-report-print-flow className="grid gap-4 md:grid-cols-2">
            {([["Action steps", source.action_steps], ["Verification steps", source.verification_steps]] as const).map(([title, steps]) => (
              <div key={title} className="min-w-0"><h4 className="text-xs font-semibold">{title}</h4>{steps.length ? <ol className="mt-2 list-decimal space-y-2 pl-5">{steps.map((step, index) => <li key={index} className={textStyle}>{step}</li>)}</ol> : <p className={textStyle}>No steps supplied.</p>}</div>
            ))}
          </div>
          <p className="text-xs">Scope: {source.scope.replaceAll("_", " ")} · Automation: {source.automation_status.replaceAll("_", " ")}</p>
          <TechnicalDetails title="Recommendation identity, relationships and standards"><SourceRecord value={source} /></TechnicalDetails>
        </article>
      ))}
    </ReportSection>
  );
}

function EvidenceDetails({ data }: { data: ReportPageData }) {
  return (
    <ReportSection id="report-evidence" title="Evidence references and technical details">
      <p className={textStyle}>Exact source records retain their identities, raw values and assessment states. Expand details to inspect them; printing places full records in the technical appendix.</p>
      {data.sessions.map((session) => (
        <div data-report-screen-only key={session.source.session_id} className="min-w-0 space-y-4 rounded-lg border border-neutral-200 bg-white p-5">
          <h3 className="break-words text-sm font-semibold">{reportSessionLabel(session.source)}</h3>
          <SessionLink data={data} sessionId={session.source.session_id} />
          <p className="text-xs">{session.findings.length} linked findings · Capture completeness: {session.source.capture_completeness}</p>
          <TechnicalDetails title="Session identity, endpoints, timing and reconstruction"><SourceRecord value={session.source} /></TechnicalDetails>
          <dl className="grid gap-3 sm:grid-cols-2">
            {([["tls_upgrade_completed", "TLS upgrade completion"], ["forward_secrecy", "Forward Secrecy"]] as const).map(([kind, label]) => {
              const facts = session.facts.filter((fact) => fact.fact_type === kind);
              return <Field key={kind} label={label}>{facts.length ? facts.map((fact) => `${JSON.stringify(fact.value)} (${fact.observability})`).join("; ") : "Not assessed — no supplied fact"}</Field>;
            })}
          </dl>
          <h4 className="text-sm font-semibold">Supplied cryptographic observations and facts</h4>
          {session.observations.length === 0 ? <p className={textStyle}>No cryptographic observation records supplied. Negotiated parameters and certificate results are unavailable unless explicitly supplied as facts below.</p> : null}
          {session.observations.map((observation) => <div key={observation.observation_id} className="min-w-0 space-y-2"><p className={textStyle}><strong>{observation.kind}</strong>: {observation.normalized_value}</p><p className="text-xs">Observability: {observation.observability}</p><TechnicalDetails title={`Observation · ${observation.observation_id}`}><SourceRecord value={observation} /></TechnicalDetails></div>)}
          {session.facts.length === 0 ? <p className={textStyle}>No derived fact records supplied. TLS upgrade completion and Forward Secrecy remain Not assessed without their respective supplied facts.</p> : null}
          {session.facts.map((fact) => <div key={fact.fact_id} className="min-w-0 space-y-2"><p className={textStyle}><strong>{fact.fact_type}</strong>: {JSON.stringify(fact.value)}</p><p className="text-xs">Observability: {fact.observability} · Confidence: {fact.confidence_level}</p><TechnicalDetails title={`Fact · ${fact.fact_id}`}><SourceRecord value={fact} /></TechnicalDetails></div>)}
          <Link href={session.evidenceHref} className={cn(linkStyle, "inline-block text-xs")}>Open session Evidence records</Link>
        </div>
      ))}
      <h3 className="text-sm font-semibold">Evidence records ({data.chain.evidence.length})</h3>
      {data.chain.evidence.map((evidence) => (
        <div data-report-reference id={evidence.evidence_id} key={evidence.evidence_id} className="min-w-0 space-y-3 rounded-md border border-neutral-200 bg-white p-4">
          <h4 className="break-all font-mono text-xs font-semibold">{evidence.evidence_id}</h4>
          <p className={textStyle}>{evidence.source_field}: {evidence.normalized_value}</p>
          <p className="break-words text-xs">Frames: {evidence.frame_numbers.join(", ")} · {evidence.direction} · {evidence.observability}</p>
          <SessionLink data={data} sessionId={evidence.session_id} />
          <TechnicalDetails title="Exact evidence provenance and safe excerpt"><SourceRecord value={evidence} /></TechnicalDetails>
        </div>
      ))}
      <TechnicalDetails title="Protocol events and rule evaluations"><SourceRecord value={data.chain.protocol_events} /><SourceRecord value={data.chain.rule_evaluations} /></TechnicalDetails>
      <TechnicalDetails title="Supplied artifact manifests"><SourceRecord value={data.chain.artifacts} /></TechnicalDetails>
    </ReportSection>
  );
}

export function ReportWorkspace({ data, demoChain }: { data: ReportPageData; demoChain: ChainOfProof | null }) {
  return (
    <div className={cn("report-print-root mx-auto w-full min-w-0 max-w-6xl space-y-8", styles.report)}>
      <header className="flex min-w-0 flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
        <div className="min-w-0"><p className="text-[11px] font-bold uppercase tracking-wide text-neutral-500">Analysis / Report</p><h1 className="mt-1 text-2xl font-semibold tracking-tight sm:text-3xl">SecureMailScope Assessment Report</h1><p className={cn("mt-2", textStyle)}>Decision summary, supporting evidence, and recommended actions for this analysis.</p></div>
        <ReportExportActions analysisId={data.analysisId} dataSource={data.dataSource} demoChain={demoChain} />
      </header>
      <ExecutiveSummary data={data} />
      <ReportPrintIdentity data={data} />
      <Assessments data={data} />
      <Findings data={data} />
      <Recommendations data={data} />
      <Scope data={data} />
      <div data-report-screen-only><Identity data={data} /></div>
      <EvidenceDetails data={data} />
      <ReportPrintAppendix data={data} />
      <nav aria-label="Report investigation links" data-print-hide className="flex flex-wrap gap-4 rounded-lg border border-neutral-200 bg-white p-4 text-sm">
        <Link href={data.links.overview} className={linkStyle}>Overview</Link><Link href={data.links.sessions} className={linkStyle}>Sessions</Link><Link href={data.links.findings} className={linkStyle}>Policy Findings</Link><Link href={data.links.recommendations} className={linkStyle}>Recommendations</Link>
      </nav>
    </div>
  );
}
