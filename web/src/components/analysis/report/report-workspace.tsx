import { AnalysisBreadcrumbs } from "@/components/layout/analysis-breadcrumbs";

import Link from "next/link";
import {
  Brain,
  Database,
  FileCheck2,
  Fingerprint,
  Network,
  ShieldAlert,
} from "lucide-react";

import {
  engineStatusLabels,
  severityStyles,
} from "@/components/analysis/findings/findings-view-model";
import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { cn } from "@/lib/utils";
import type { ChainOfProof } from "@/lib/contracts/chain";

import {
  FindingArtifactActions,
  ReportExportActions,
} from "./report-export-actions";

import { ReportDetails, ReportEvidenceDetails } from "./report-evidence-details";
import { groupReportNotes, reportSessionLabel } from "./report-view-model";
import styles from "./report.module.css";

import type {
  ReportCryptoDimension,
  ReportPageData,
  ReportProtocolCoverage,
  ReportNoteGroup,
} from "./report-view-model";

const analysisStatusStyles: Record<string, string> = {
  complete: "border-emerald-300 bg-emerald-50 text-emerald-800",
  partial: "border-amber-300 bg-amber-50 text-amber-800",
  failed: "border-red-300 bg-red-50 text-red-800",
};

const stateStyles: Record<string, string> = {
  observed: "border-emerald-300 bg-emerald-50 text-emerald-800",
  derived: "border-blue-300 bg-blue-50 text-blue-800",
  policy_inferred: "border-violet-300 bg-violet-50 text-violet-800",
  not_observable: "border-neutral-300 bg-neutral-50 text-neutral-700",
  session_secrets_required:
    "border-neutral-300 bg-neutral-50 text-neutral-700",
  not_assessed: "border-neutral-300 bg-neutral-50 text-neutral-700",
  not_applicable: "border-neutral-300 bg-neutral-50 text-neutral-700",
  incomplete_capture: "border-amber-300 bg-amber-50 text-amber-800",
};

function humanize(value: string): string {
  return value.replaceAll("_", " ");
}

function formatDateTime(value: string | null): string {
  if (!value) return "Not available";
  return `${new Intl.DateTimeFormat("en", {
    dateStyle: "medium",
    timeStyle: "medium",
    timeZone: "UTC",
  }).format(new Date(value))} UTC`;
}

function pluralize(count: number, singular: string, plural = `${singular}s`) {
  return `${count.toLocaleString("en")} ${count === 1 ? singular : plural}`;
}

function SectionHeading({
  id,
  title,
  description,
}: {
  id: string;
  title: string;
  description: string;
}) {
  return (
    <div data-report-heading>
      <h2
        id={id}
        className="text-lg font-semibold tracking-tight text-neutral-950"
      >
        {title}
      </h2>
      <p className="mt-1 max-w-3xl text-sm leading-6 text-neutral-600">
        {description}
      </p>
    </div>
  );
}

function readableDetail(detail: string): string | null {
  // Identifier-only diagnostics stay in the exact source records.
  return detail && !/^[a-z0-9_:-]+$/i.test(detail) ? detail : null;
}

function sessionCaptureLabel(data: ReportPageData, sessionId: string): string | null {
  if (data.chain.captures.length < 2) return null;
  const session = data.chain.sessions.find((item) => item.session_id === sessionId);
  if (!session) return null;
  const capture = data.chain.captures.find((item) => item.capture_id === session.capture_id);
  return capture?.original_filename_sanitized || session.capture_id;
}

function ReportNotes({ notes, data, anomalyContext = false, context }: {
  notes: ReportNoteGroup[];
  data: ReportPageData;
  anomalyContext?: boolean;
  context?: "crypto" | "protocol";
}) {
  return (
    <ul className="space-y-3">
      {notes.map((note) => {
        const scopedSessionIds = new Set(
          anomalyContext
            ? data.chain.anomaly_results.filter((result) => note.owners.includes(result.anomaly_result_id)).map((result) => result.session_id)
            : context === "crypto"
              ? [
                  ...data.chain.crypto_observations.filter((record) => note.owners.includes(record.observation_id)).map((record) => record.session_id),
                  ...data.chain.derived_facts.filter((record) => note.owners.includes(record.fact_id)).map((record) => record.session_id),
                ]
              : context === "protocol"
                ? data.chain.protocol_events.filter((record) => note.owners.includes(record.event_id)).map((record) => record.session_id)
                : [],
        );
        const sessions = data.chain.sessions.filter((session) => scopedSessionIds.has(session.session_id));
        return (
          <li key={JSON.stringify([note.code, note.summary, note.detail])} data-report-note className="space-y-1 text-xs leading-5 text-neutral-600">
            <p>{note.summary}</p>
            {readableDetail(note.detail) ? <p>{note.detail}</p> : null}
            {sessions.length > 0 && (context || sessions.length < new Set(data.chain.anomaly_results.map((result) => result.session_id)).size) ? (
              <p className="font-medium">Applies to: {sessions.map((session) => [sessionCaptureLabel(data, session.session_id), session.protocol.toUpperCase() + " · stream " + session.tcp_stream_id].filter(Boolean).join(" · ")).join(", ")}</p>
            ) : null}
          </li>
        );
      })}
    </ul>
  );
}

function ReportIdentity({ data }: { data: ReportPageData }) {
  const analysis = data.chain.analysis;
  const methodFields = [
    ["Method", data.dataSource === "mock" ? "Prepared sample analysis" : "Passive analysis of supplied packet captures"],
    ["Analyzer version", analysis.analyzer_version || "Not supplied"],
    ["TShark version", analysis.tshark_version ?? "Not supplied"],
    ["Report schema version", data.chain.chain_schema_version],
    ["Rule pack", analysis.rule_pack_id ?? "Not supplied"],
    ["Rule pack version", analysis.rule_pack_version ?? "Not supplied"],
    ["TLS 1.3 session secrets", humanize(analysis.tls13_authorized_secrets)],
  ];
  return (
    <section aria-labelledby="report-identity-heading">
      <Card className="rounded-lg border-neutral-200 shadow-sm ring-0">
        <CardHeader className="border-b border-neutral-200 bg-neutral-50">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <CardTitle><h2 id="report-identity-heading">Report identity and scope</h2></CardTitle>
            <Badge variant="outline" className={cn("rounded-md capitalize", analysisStatusStyles[data.analysisStatus])}>
              {humanize(data.analysisStatus)}
            </Badge>
          </div>
          <CardDescription>This assessment covers the supplied captures and reconstructed sessions.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <dl className="grid gap-4 sm:grid-cols-2">
            <div className="min-w-0">
              <dt className="text-xs font-medium text-neutral-500">Analysis ID</dt>
              <dd className="mt-1 break-all font-mono text-xs text-neutral-950">{data.analysisId}</dd>
            </div>
            <div>
              <dt className="text-xs font-medium text-neutral-500">Analysis source</dt>
              <dd className="mt-1 text-sm text-neutral-950">
                {data.dataSource === "mock" ? data.datasetLabel : "Backend analysis"}
              </dd>
            </div>
            <div>
              <dt className="text-xs font-medium text-neutral-500">Assessment started</dt>
              <dd className="mt-1 text-sm text-neutral-950">{formatDateTime(analysis.started_at)}</dd>
            </div>
            <div>
              <dt className="text-xs font-medium text-neutral-500">Assessment completed</dt>
              <dd className="mt-1 text-sm text-neutral-950">{formatDateTime(data.analysisTimestamp)}</dd>
            </div>
          </dl>
          {data.chain.captures.map((capture) => (
            <div key={capture.capture_id} className="min-w-0 border-t border-neutral-100 pt-4">
              <h3 className="break-words text-sm font-semibold">{capture.original_filename_sanitized || "Filename not available"}</h3>
              <p className="mt-1 text-xs leading-5 text-neutral-600">
                {capture.format.toUpperCase()} · {pluralize(capture.packet_count, "packet")} · {capture.size_bytes.toLocaleString("en")} bytes
              </p>
              <p className="mt-1 text-xs leading-5 text-neutral-600">
                Capture period: {formatDateTime(capture.captured_at_start)} – {formatDateTime(capture.captured_at_end)}
              </p>
              {capture.truncated_packet_count > 0 ? (
                <p className="mt-2 text-xs leading-5 text-amber-800">
                  {pluralize(capture.truncated_packet_count, "truncated packet")} recorded in this capture.
                </p>
              ) : null}
              {data.chain.sessions.filter((session) => session.capture_id === capture.capture_id && session.capture_completeness !== "complete").map((session) => (
                <p key={session.session_id} className="mt-2 break-words text-xs leading-5 text-amber-800">
                  {reportSessionLabel(session)} — capture {humanize(session.capture_completeness)}.
                </p>
              ))}
              {[...new Set(capture.capture_warnings)].map((warning) => (
                <p key={warning} className="mt-2 text-xs leading-5 text-amber-800">{warning}</p>
              ))}
              <div className="mt-3">
                <ReportDetails title="Capture identity and integrity">
                  <dl className="space-y-3">
                    <div>
                      <dt className="text-xs font-medium text-neutral-500">Capture ID</dt>
                      <dd className="mt-1 break-all font-mono text-xs">{capture.capture_id}</dd>
                    </div>
                    <div>
                      <dt className="flex items-center gap-2 text-xs font-medium text-neutral-500">
                        <Fingerprint className="size-3" aria-hidden />
                        {data.dataSource === "mock" ? "Fixture SHA-256" : "Capture SHA-256"}
                      </dt>
                      <dd className="mt-1 break-all font-mono text-xs">{capture.sha256}</dd>
                    </div>
                  </dl>
                </ReportDetails>
              </div>
            </div>
          ))}
          <ReportDetails title="Assessment method and versions">
            <dl className="grid gap-4 sm:grid-cols-2">
              {methodFields.map(([label, value]) => (
                <div key={label} className="min-w-0">
                  <dt className="text-xs font-medium text-neutral-500">{label}</dt>
                  <dd className="mt-1 break-words text-xs leading-5 text-neutral-950">{value}</dd>
                </div>
              ))}
            </dl>
          </ReportDetails>
          {data.analysisStatus !== "complete" ? (
            <p className="text-sm font-medium text-amber-800">
              Analysis is {humanize(data.analysisStatus)}. Review the coverage notes before using these results.
            </p>
          ) : null}
        </CardContent>
      </Card>
    </section>
  );
}

function AssessmentOverview({ data }: { data: ReportPageData }) {
  const metrics = [
    {
      label: "Sessions analyzed",
      value: data.totalSessions.toLocaleString("en"),
      detail: "Reconstructed sessions in this assessment.",
      icon: Network,
    },
    {
      label: "Email protocols",
      value: data.emailProtocolCount.toLocaleString("en"),
      detail: "Email protocol families represented in the capture.",
      icon: Database,
    },
    {
      label: "Policy findings",
      value: data.policyFindingCount.toLocaleString("en"),
      detail: "Issues identified by the policy rules.",
      icon: ShieldAlert,
    },
    {
      label: "Affected sessions",
      value: data.affectedSessionCount.toLocaleString("en"),
      detail: "Sessions associated with policy findings.",
      icon: FileCheck2,
    },
  ];

  return (
    <section aria-labelledby="assessment-overview-heading" className="space-y-4">
      <SectionHeading
        id="assessment-overview-heading"
        title="Assessment overview"
        description="Session coverage and policy findings in this assessment."
      />
      <div data-report-metrics className="grid gap-px overflow-hidden rounded-lg border border-neutral-200 bg-neutral-200 shadow-sm sm:grid-cols-2 xl:grid-cols-4">
        {metrics.map((metric) => {
          const Icon = metric.icon;
          return (
            <article key={metric.label} className="bg-white p-4">
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <p className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
                    {metric.label}
                  </p>
                  <p className="mt-2 text-2xl font-semibold tracking-tight text-neutral-950">
                    {metric.value}
                  </p>
                </div>
                <span className="flex size-8 shrink-0 items-center justify-center rounded-md border border-neutral-200 bg-neutral-50 text-neutral-600">
                  <Icon className="size-4" aria-hidden />
                </span>
              </div>
              <p className="mt-2 text-xs leading-5 text-neutral-600">
                {metric.detail}
              </p>
            </article>
          );
        })}
      </div>
    </section>
  );
}

function UpgradeStates({
  coverage,
}: {
  coverage: ReportProtocolCoverage;
}) {
  return (
    <ul className="space-y-1.5">
      {coverage.tlsUpgradeStates.map((state) => (
        <li
          key={state.label}
          className="flex items-center justify-between gap-3"
        >
          <span className="text-neutral-700">{state.label}</span>
          <span className="font-mono text-[11px] text-neutral-950">
            {state.count}
          </span>
        </li>
      ))}
    </ul>
  );
}

function CommunicationCoverage({ data }: { data: ReportPageData }) {
  const protocolNotes = groupReportNotes(data.chain.protocol_events.flatMap((event) =>
    event.limitations.map((note) => ({ ...note, owner: event.event_id }))));
  return (
    <section aria-labelledby="communication-coverage-heading" className="space-y-4">
      <SectionHeading
        id="communication-coverage-heading"
        title="Communication Coverage"
        description="Protocols represented in the capture and their recorded TLS-upgrade outcomes."
      />
      {data.protocolCoverage.length === 0 ? (
        <div className="rounded-lg border border-dashed border-neutral-300 bg-white px-5 py-10 text-center text-sm text-neutral-600">
          No reconstructed communication sessions are present in the validated
          result.
        </div>
      ) : (
        <>
          <div className="hidden overflow-hidden rounded-lg border border-neutral-200 bg-white shadow-sm md:block">
            <table className="w-full table-fixed text-left text-sm">
              <caption className="sr-only">
                Communication coverage by validated protocol
              </caption>
              <thead className="border-b border-neutral-200 bg-neutral-50 text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-600">
                <tr>
                  <th className="w-1/4 px-4 py-3">Protocol</th>
                  <th className="w-1/4 px-4 py-3">Sessions</th>
                  <th className="w-1/2 px-4 py-3">
                    Declared TLS upgrade state
                  </th>
                </tr>
              </thead>
              <tbody>
                {data.protocolCoverage.map((coverage) => (
                  <tr
                    key={coverage.protocol}
                    className="border-b border-neutral-100 last:border-0"
                  >
                    <td className="px-4 py-4 font-mono text-xs font-semibold uppercase text-neutral-950">
                      {coverage.protocol}
                    </td>
                    <td className="px-4 py-4 text-neutral-800">
                      {coverage.sessionCount.toLocaleString("en")}
                    </td>
                    <td className="px-4 py-4 text-xs">
                      <UpgradeStates coverage={coverage} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="grid gap-3 md:hidden">
            {data.protocolCoverage.map((coverage) => (
              <article
                key={coverage.protocol}
                className="rounded-lg border border-neutral-200 bg-white p-4 shadow-sm"
              >
                <div className="flex items-center justify-between gap-3">
                  <h3 className="font-mono text-xs font-semibold uppercase text-neutral-950">
                    {coverage.protocol}
                  </h3>
                  <Badge
                    variant="outline"
                    className="rounded-md border-neutral-300 bg-neutral-50"
                  >
                    {pluralize(coverage.sessionCount, "session")}
                  </Badge>
                </div>
                <div className="mt-4 border-t border-neutral-100 pt-3 text-xs">
                  <p className="mb-2 text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
                    Declared TLS upgrade state
                  </p>
                  <UpgradeStates coverage={coverage} />
                </div>
              </article>
            ))}
          </div>
        </>
      )}
      {protocolNotes.length ? (
        <ReportDetails title="Protocol evidence context">
          <ReportNotes notes={protocolNotes} data={data} context="protocol" />
        </ReportDetails>
      ) : null}
    </section>
  );
}

function CryptoDimension({
  dimension,
  data,
}: {
  dimension: ReportCryptoDimension;
  data: ReportPageData;
}) {
  return (
    <article className="rounded-lg border border-neutral-200 bg-white p-4 shadow-sm">
      <h3 className="text-sm font-semibold text-neutral-950">
        {dimension.label}
      </h3>
      <p className="mt-1 text-xs leading-5 text-neutral-600">
        {dimension.description}
      </p>
      <ul className="mt-4 space-y-3">
        {dimension.values.map((item) => (
          <li
            key={`${item.value}-${item.state}`}
            className="min-w-0 rounded-md border border-neutral-100 bg-neutral-50 p-3"
          >
            <div className="flex min-w-0 flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
              <code className="min-w-0 break-all font-mono text-[11px] leading-5 text-neutral-950">
                {item.value}
              </code>
              <Badge
                variant="outline"
                className={cn(
                  "w-fit rounded-md font-mono text-[10px]",
                  stateStyles[item.state] ??
                    "border-neutral-300 bg-white text-neutral-700",
                )}
              >
                {item.state}
              </Badge>
            </div>
            <p className="mt-2 text-xs text-neutral-600">
              {pluralize(item.sessionCount, "session")}
            </p>
          </li>
        ))}
      </ul>
      {dimension.notes.length ? (
        <div className="mt-4">
          <ReportDetails title="Evidence context">
            <ReportNotes notes={dimension.notes} data={data} context="crypto" />
          </ReportDetails>
        </div>
      ) : null}
    </article>
  );
}

function CryptographicPosture({ data }: { data: ReportPageData }) {
  return (
    <section aria-labelledby="cryptographic-posture-heading" className="space-y-4">
      <SectionHeading
        id="cryptographic-posture-heading"
        title="Cryptographic Posture"
        description="Recorded TLS parameters and cryptographic assessment facts. Unavailable evidence remains explicitly marked."
      />
      {data.cryptoDimensions.length === 0 ? (
        <div className="rounded-lg border border-dashed border-neutral-300 bg-white px-5 py-10 text-center text-sm text-neutral-600">
          No allowlisted cryptographic observations or facts are present. No
          cryptographic posture was inferred.
        </div>
      ) : (
        <div data-report-print-flow className="grid gap-4 lg:grid-cols-2">
          {data.cryptoDimensions.map((dimension) => (
            <CryptoDimension key={dimension.key} dimension={dimension} data={data} />
          ))}
        </div>
      )}
      {data.additionalCryptoDimensions.length ? (
        <ReportDetails title="Additional cryptographic and certificate observations">
          <div data-report-print-flow className="grid gap-4 lg:grid-cols-2">
            {data.additionalCryptoDimensions.map((dimension) => <CryptoDimension key={dimension.key} dimension={dimension} data={data} />)}
          </div>
        </ReportDetails>
      ) : null}
    </section>
  );
}

function ImportantFindings({ data }: { data: ReportPageData }) {
  return (
    <section aria-labelledby="important-findings-heading" className="space-y-4">
      <SectionHeading id="important-findings-heading" title="Findings and supporting evidence" description="All policy findings, ordered by severity and supplied risk contribution. Each entry retains its affected session and recommended action." />
      {data.importantFindings.length === 0 ? (
        <p className="rounded-lg border border-neutral-200 bg-white p-5 text-sm leading-6 text-neutral-600">No policy findings were supplied.</p>
      ) : data.importantFindings.map((finding, index) => {
        const recommendation = data.recommendations.find((item) => item.recommendationId === finding.recommendationId);
        return (
          <article key={finding.findingId} id={"report-" + finding.findingId} data-report-finding className="min-w-0 rounded-lg border border-neutral-200 bg-white p-5 shadow-sm">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <h3 className="min-w-0 break-words text-base font-semibold">{index + 1}. {finding.title}</h3>
              <Badge variant="outline" className={cn("rounded-md capitalize", severityStyles[finding.severity] ?? severityStyles.info)}>{finding.severity}</Badge>
            </div>
            <p className="mt-3 text-sm leading-6 text-neutral-700">{finding.rationale}</p>
            <p className="mt-2 text-sm leading-6 text-neutral-700"><strong className="text-neutral-950">Impact:</strong> {finding.impact}</p>
            <dl className="mt-4 grid gap-3 border-t border-neutral-100 pt-4 sm:grid-cols-2">
              <div className="min-w-0"><dt className="text-xs font-medium text-neutral-500">Affected session</dt><dd className="mt-1 break-words text-xs leading-5"><Link href={"/analysis/" + data.analysisId + "/sessions/" + finding.sessionId + "?tab=findings"} className="report-text-link">{finding.sessionLabel}</Link></dd></div>
              <div><dt className="text-xs font-medium text-neutral-500">Evidence confidence</dt><dd className="mt-1 text-sm capitalize">{humanize(finding.confidence)} · {humanize(finding.observability)}</dd></div>
            </dl>
            {finding.limitations.length ? <div className="mt-3"><ReportNotes data={data} notes={groupReportNotes(finding.limitations.map((note) => ({ ...note, owner: finding.findingId })))} /></div> : null}
            <div className="mt-4 space-y-2 border-t border-neutral-100 pt-4 text-sm">
              <p>{pluralize(finding.evidenceCount, "direct evidence reference")} · {pluralize(finding.factCount, "supporting fact")}</p>
              <Link href={"/analysis/" + data.analysisId + "/sessions/" + finding.sessionId + "?tab=findings#session-evidence-records-heading"} className="report-text-link" data-print-hide>View session evidence</Link>
              {recommendation ? <p><span className="font-medium">Recommended action:</span> <Link href={"#report-" + recommendation.recommendationId} className="report-text-link" title={recommendation.title}>Action {data.recommendations.findIndex((item) => item.recommendationId === recommendation.recommendationId) + 1}</Link></p> : null}
            </div>
            <div className="mt-4">
              <ReportDetails title="Supporting packet evidence">
                <ul className="space-y-3">
                  {finding.evidence.map((record) => (
                    <li key={record.evidence_id} data-report-evidence className="min-w-0 rounded-md border border-neutral-200 bg-white p-3">
                      <p className="text-xs font-medium">Frames {record.frame_numbers.join(", ")} · {humanize(record.direction)}</p>
                      <p className="mt-1 break-words text-xs leading-5 text-neutral-700 [overflow-wrap:anywhere]">
                        <span className="font-medium">{record.source_field}:</span> {record.normalized_value}
                      </p>
                    </li>
                  ))}
                </ul>
              </ReportDetails>
            </div>
            {data.dataSource === "api" ? <div className="mt-4"><FindingArtifactActions analysisId={data.analysisId} findingId={finding.findingId} /></div> : null}
          </article>
        );
      })}
    </section>
  );
}

function PolicyRisk({ data }: { data: ReportPageData }) {
  return (
    <section aria-labelledby="policy-risk-heading">
      <Card className="h-full rounded-lg border-neutral-200 shadow-sm ring-0">
        <CardHeader className="border-b border-neutral-200">
          <div className="flex items-start gap-3">
            <ShieldAlert className="mt-1 size-5 shrink-0 text-neutral-700" aria-hidden />
            <div>
              <CardTitle><h2 id="policy-risk-heading">Policy Risk</h2></CardTitle>
              <CardDescription className="mt-1">Assessment against the selected policy rules.</CardDescription>
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          <p className="text-2xl font-semibold text-neutral-950">
            {data.policyRisk.score === null ? "Not available" : data.policyRisk.score + " / 100"}
          </p>
          <dl className="grid gap-3 sm:grid-cols-2">
            <div>
              <dt className="text-xs font-medium text-neutral-500">Engine state</dt>
              <dd className="mt-1 text-sm">{engineStatusLabels[data.policyRisk.engineStatus] ?? humanize(data.policyRisk.engineStatus)}</dd>
            </div>
            {data.policyRisk.profileId ? (
              <div>
                <dt className="text-xs font-medium text-neutral-500">Policy profile</dt>
                <dd className="mt-1 break-all font-mono text-xs">{data.policyRisk.profileId}</dd>
              </div>
            ) : null}
          </dl>
          {data.policyRisk.severityDistribution.length ? (
            <div className="border-t border-neutral-100 pt-4">
              <p className="mb-2 text-xs font-medium text-neutral-500">Severity distribution</p>
              <div className="flex flex-wrap gap-2">
                {data.policyRisk.severityDistribution.map((item) => (
                  <Badge key={item.severity} variant="outline" className={cn("rounded-md capitalize", severityStyles[item.severity] ?? severityStyles.info)}>
                    {item.severity}: {item.count}
                  </Badge>
                ))}
              </div>
            </div>
          ) : null}
          <p className="text-xs leading-5 text-neutral-600">
            This rule-based score is not a probability of compromise.
          </p>
        </CardContent>
      </Card>
    </section>
  );
}

function MLAnomaly({ data }: { data: ReportPageData }) {
  const statusLabel =
    engineStatusLabels[data.mlAnomaly.engineStatus] ??
    humanize(data.mlAnomaly.engineStatus);

  return (
    <section aria-labelledby="ml-anomaly-heading">
      <Card className="h-full rounded-lg border-neutral-200 shadow-sm ring-0">
        <CardHeader className="border-b border-neutral-200">
          <div className="flex items-start gap-3">
            <span className="flex size-9 shrink-0 items-center justify-center rounded-md border border-blue-200 bg-blue-50 text-blue-700">
              <Brain className="size-4" aria-hidden />
            </span>
            <div>
              <CardTitle>
                <h2 id="ml-anomaly-heading">ML Anomaly</h2>
              </CardTitle>
              <CardDescription className="mt-1">
                Behavioral anomaly results, assessed separately from policy risk.
              </CardDescription>
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="rounded-md border border-neutral-200 bg-neutral-50 p-4">
            <p className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
              Engine state
            </p>
            <p className="mt-1 text-lg font-semibold text-neutral-950">
              {statusLabel}
            </p>
            <p className="mt-2 text-xs leading-5 text-neutral-600">
              {data.mlAnomaly.engineStatus === "not_run"
                ? "The validated result contains no anomaly score or anomaly conclusion."
                : `${pluralize(data.mlAnomaly.resultCount, "validated anomaly result")} supplied.`}
            </p>
          </div>
          {data.mlAnomaly.modelId ? (
            <p className="break-all text-xs text-neutral-600">
              Model: <code>{data.mlAnomaly.modelId}</code>
              {data.mlAnomaly.modelVersion
                ? ` v${data.mlAnomaly.modelVersion}`
                : ""}
            </p>
          ) : null}
          {data.mlAnomaly.bandDistribution.length > 0 ? (
            <div className="flex flex-wrap gap-2">
              {data.mlAnomaly.bandDistribution.map((item) => (
                <Badge
                  key={item.band}
                  variant="outline"
                  className="rounded-md border-blue-300 bg-blue-50 text-blue-800"
                >
                  {humanize(item.band)}: {item.count}
                </Badge>
              ))}
            </div>
          ) : null}
          {data.chain.anomaly_results.length ? (
            <ReportDetails title="Anomaly results by session">
              {data.chain.anomaly_results.map((anomaly) => {
                const session = data.chain.sessions.find((item) => item.session_id === anomaly.session_id)!;
                return (
                  <div key={anomaly.anomaly_result_id} data-report-anomaly className="space-y-2 border-b border-neutral-200 pb-4 last:border-0 last:pb-0">
                    <p className="break-words text-xs font-medium"><Link href={"/analysis/" + data.analysisId + "/sessions/" + anomaly.session_id} className="report-text-link">{reportSessionLabel(session)}</Link></p>
                    {sessionCaptureLabel(data, anomaly.session_id) ? <p className="break-words text-xs text-neutral-600">Capture: {sessionCaptureLabel(data, anomaly.session_id)}</p> : null}
                    <p className="text-sm capitalize">{humanize(anomaly.band)} · normalized anomaly score {anomaly.normalized_score}</p>
                  </div>
                );
              })}
            </ReportDetails>
          ) : null}
          {data.dataSource === "mock" && data.chain.anomaly_results.length ? (
            <p data-report-model-context className="text-xs leading-5 text-neutral-600">
              Sample ML scores are curated for this walkthrough; no trained model was executed. They are not calibrated to your mail flow.
            </p>
          ) : data.anomalyNotes.length ? (
            <ReportDetails title="Model assessment context">
              <ReportNotes notes={data.anomalyNotes} data={data} anomalyContext />
            </ReportDetails>
          ) : null}
          <p className="text-xs leading-5 text-neutral-600">
            Anomalous behavior is not proof of malicious activity.
          </p>
        </CardContent>
      </Card>
    </section>
  );
}

function Recommendations({ data }: { data: ReportPageData }) {
  return (
    <section aria-labelledby="recommendations-heading" className="space-y-4">
      <SectionHeading
        id="recommendations-heading"
        title={
          data.recommendations.length > 0
            ? "Recommendations"
            : "Recommended Follow-up"
        }
        description="Actions supplied for the identified findings, with steps to verify the change."
      />
      {data.recommendations.length === 0 ? (
        <div className="flex flex-wrap gap-3 rounded-lg border border-neutral-200 bg-white p-4 shadow-sm">
          <Link
            href={data.links.findings}
            className="inline-flex min-h-9 items-center justify-center rounded-md bg-neutral-950 px-4 text-sm font-medium text-white outline-none hover:bg-neutral-800 focus-visible:ring-2 focus-visible:ring-neutral-950 focus-visible:ring-offset-2"
          >
            Review findings
          </Link>
          <Link
            href={data.links.sessions}
            className="inline-flex min-h-9 items-center justify-center rounded-md border border-neutral-300 bg-white px-4 text-sm font-medium text-neutral-900 outline-none hover:bg-neutral-50 focus-visible:ring-2 focus-visible:ring-neutral-950 focus-visible:ring-offset-2"
          >
            Review sessions
          </Link>
        </div>
      ) : (
        <div className="grid gap-4">
          {data.recommendations.map((recommendation, actionIndex) => (
            <article
              key={recommendation.recommendationId}
              id={"report-" + recommendation.recommendationId}
              data-report-recommendation
              className="min-w-0 rounded-lg border border-neutral-200 bg-white p-5 shadow-sm"
            >
              <div className="flex min-w-0 flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                <div className="min-w-0">
                  <h3 className="text-sm font-semibold text-neutral-950">
                    Action {actionIndex + 1}: {recommendation.title}
                  </h3>

                </div>
                <Badge
                  variant="outline"
                  className={cn(
                    "w-fit rounded-md uppercase",
                    severityStyles[recommendation.priority] ??
                      severityStyles.info,
                  )}
                >
                  {recommendation.priority}
                </Badge>
              </div>
              <p className="mt-3 text-sm leading-6 text-neutral-700">
                {recommendation.summary}
              </p>
              <div className="mt-4 flex flex-wrap items-center gap-x-3 gap-y-2 text-xs leading-5">
                <span className="font-medium text-neutral-500">Applies to:</span>
                {recommendation.affectedFindings.map((finding) => (
                  <Link key={finding.id} href={"#report-" + finding.id} title={finding.title} className="report-text-link">
                    Finding {data.importantFindings.findIndex((item) => item.findingId === finding.id) + 1}
                  </Link>
                ))}
                {recommendation.affectedSessions.length ? (
                  <span className="text-neutral-600">Across {pluralize(recommendation.affectedSessions.length, "session")}</span>
                ) : null}
              </div>
              <div data-report-print-flow className="mt-4 grid gap-4 border-t border-neutral-100 pt-4 md:grid-cols-2">
                <div>
                  <h4 className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
                    Action steps
                  </h4>
                  <ul className="mt-2 list-disc space-y-1 pl-4 text-xs leading-5 text-neutral-700 marker:text-neutral-400">
                    {recommendation.actionSteps.length ? recommendation.actionSteps.map((step) => (
                      <li key={step}>{step}</li>
                    )) : <li>No action steps were supplied.</li>}
                  </ul>
                </div>
                <div>
                  <h4 className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
                    Verification steps
                  </h4>
                  <ul className="mt-2 list-disc space-y-1 pl-4 text-xs leading-5 text-neutral-700 marker:text-neutral-400">
                    {recommendation.verificationSteps.length ? recommendation.verificationSteps.map((step) => (
                      <li key={step}>{step}</li>
                    )) : <li>No verification steps were supplied.</li>}
                  </ul>
                </div>
              </div>
              {recommendation.standardsReferences.length ? <p className="mt-3 text-xs leading-5 text-neutral-600">Standards: {recommendation.standardsReferences.map((reference) => reference.id + (reference.section ? " §" + reference.section : "")).join(", ")}</p> : null}
              <Link data-print-hide href={data.links.recommendations + "#" + recommendation.recommendationId} className="report-text-link mt-3 inline-block text-xs">Open recommendation details</Link>
              <div className="mt-4 flex flex-wrap gap-x-4 gap-y-2 border-t border-neutral-100 pt-3 text-[11px] text-neutral-600">
                <span>Scope: {humanize(recommendation.scope)}</span>
                <span>
                  Automation: {humanize(recommendation.automationStatus)}
                </span>

              </div>
            </article>
          ))}
        </div>
      )}
    </section>
  );
}

export function ReportWorkspace({
  data,
  demoChain,
}: {
  data: ReportPageData;
  demoChain: ChainOfProof | null;
}) {
  return (
    <div data-assessment-report className={cn(styles.report, "report-print-root mx-auto min-w-0 w-full max-w-[92rem] space-y-8")}>
      <header className="flex min-w-0 flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
        <div className="min-w-0">
          <AnalysisBreadcrumbs />
          <h1 className="mt-1 text-2xl font-semibold tracking-tight text-neutral-950 sm:text-3xl">
            SecureMailScope Assessment Report
          </h1>
          <p className="mt-2 max-w-3xl text-sm leading-6 text-neutral-600">
            Assessment coverage, findings, supporting evidence, and recommended actions.
          </p>
        </div>
        <div className="flex max-w-full flex-col gap-3 sm:items-end">
          <ReportExportActions
            analysisId={data.analysisId}
            dataSource={data.dataSource}
            demoChain={demoChain}
          />
        </div>
      </header>

      <nav aria-label="Report contents" data-report-contents className="flex flex-wrap gap-x-5 gap-y-3 border-y border-neutral-200 py-4 text-xs">
        {[
          ["Identity and scope", "report-identity-heading"],
          ["Assessment overview", "assessment-overview-heading"],
          ["Communication coverage", "communication-coverage-heading"],
          ["Cryptographic posture", "cryptographic-posture-heading"],
          ["Findings", "important-findings-heading"],
          ["Policy and ML assessments", "report-assessments"],
          ["Recommended actions", "recommendations-heading"],
          ["Technical appendix", "report-evidence-heading"],
        ].map(([label, id]) => <Link key={id} href={"#" + id} className="report-text-link">{label}</Link>)}
      </nav>

      <ReportIdentity data={data} />
      <AssessmentOverview data={data} />
      <CommunicationCoverage data={data} />
      <CryptographicPosture data={data} />
      <ImportantFindings data={data} />

      <div id="report-assessments" data-report-assessments className="grid items-stretch gap-4 xl:grid-cols-2">
        <PolicyRisk data={data} />
        <MLAnomaly data={data} />
      </div>

      <Recommendations data={data} />
      <ReportEvidenceDetails data={data} />
    </div>
  );
}
