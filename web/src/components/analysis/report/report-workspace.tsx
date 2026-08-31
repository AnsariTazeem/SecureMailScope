import Link from "next/link";
import {
  ArrowRight,
  Brain,
  Database,
  FileCheck2,
  FileSearch,
  Fingerprint,
  GitCompareArrows,
  GitFork,
  Info,
  ListChecks,
  Network,
  ShieldAlert,
} from "lucide-react";

import { PrototypeDatasetBanner } from "@/components/analysis/findings/findings-states";
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

import type {
  ReportCryptoDimension,
  ReportPageData,
  ReportProtocolCoverage,
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
    <div>
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

function ReportIdentity({ data }: { data: ReportPageData }) {
  return (
    <Card className="rounded-lg border-neutral-200 shadow-sm ring-0">
      <CardHeader className="border-b border-neutral-200 bg-neutral-50">
        <div className="flex min-w-0 flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
          <div className="min-w-0">
            <CardTitle>
              <h2>Report identity and capture provenance</h2>
            </CardTitle>
            <CardDescription className="mt-1">
              Validated analysis and capture identifiers; no report metadata is
              synthesized.
            </CardDescription>
          </div>
          <Badge
            variant="outline"
            className={cn(
              "rounded-md capitalize",
              analysisStatusStyles[data.analysisStatus] ??
                "border-neutral-300 bg-white text-neutral-700",
            )}
          >
            {humanize(data.analysisStatus)}
          </Badge>
        </div>
      </CardHeader>
      <CardContent className="space-y-5">
        <dl className="grid gap-4 sm:grid-cols-2">
          <div className="min-w-0">
            <dt className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
              Analysis ID
            </dt>
            <dd className="mt-1 break-all font-mono text-xs text-neutral-950">
              {data.analysisId}
            </dd>
          </div>
          <div>
            <dt className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
              Analysis completed
            </dt>
            <dd className="mt-1 text-xs text-neutral-950">
              {formatDateTime(data.analysisTimestamp)}
            </dd>
          </div>
        </dl>

        <div className="space-y-3">
          {data.captures.map((capture) => (
            <article
              key={capture.captureId}
              className="min-w-0 rounded-md border border-neutral-200 bg-neutral-50 p-4"
            >
              <div className="flex min-w-0 flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
                <div className="min-w-0">
                  <h3 className="break-words text-sm font-semibold text-neutral-950">
                    {capture.filename || "Validated filename unavailable"}
                  </h3>
                  <p className="mt-1 break-all font-mono text-[11px] text-neutral-500">
                    {capture.captureId}
                  </p>
                </div>
                <Badge
                  variant="outline"
                  className="w-fit rounded-md border-neutral-300 bg-white font-mono uppercase"
                >
                  {capture.format}
                </Badge>
              </div>
              <dl className="mt-3 min-w-0">
                <div className="min-w-0">
                  <dt className="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
                    <Fingerprint className="size-3" aria-hidden />
                    {data.dataSource === "mock"
                      ? "Fixture SHA-256"
                      : "Capture SHA-256"}
                  </dt>
                  <dd className="mt-1 break-all font-mono text-[11px] leading-5 text-neutral-900">
                    {capture.sha256}
                  </dd>
                </div>
              </dl>
            </article>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

function ExecutiveAssessment({ data }: { data: ReportPageData }) {
  const metrics = [
    {
      label: "Sessions analyzed",
      value: data.totalSessions.toLocaleString("en"),
      detail: "Validated reconstructed-session records.",
      icon: Network,
    },
    {
      label: "Email protocols",
      value: data.emailProtocolCount.toLocaleString("en"),
      detail: "SMTP, IMAP, or POP3 families represented by session records.",
      icon: Database,
    },
    {
      label: "Policy findings",
      value: data.policyFindingCount.toLocaleString("en"),
      detail: "Existing deterministic findings; no Report-only findings.",
      icon: ShieldAlert,
    },
    {
      label: "Crypto coverage",
      value: `${data.cryptoCoverageSessionCount} / ${data.totalSessions}`,
      detail: "Sessions with at least one allowlisted crypto observation or fact.",
      icon: FileCheck2,
    },
  ];

  return (
    <section aria-labelledby="executive-assessment-heading" className="space-y-4">
      <SectionHeading
        id="executive-assessment-heading"
        title="Executive Assessment"
        description="A compact inventory of validated records. It is not a security score or an inferred overall posture."
      />
      <div className="grid gap-px overflow-hidden rounded-lg border border-neutral-200 bg-neutral-200 shadow-sm sm:grid-cols-2 xl:grid-cols-4">
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
  return (
    <section aria-labelledby="communication-coverage-heading" className="space-y-4">
      <SectionHeading
        id="communication-coverage-heading"
        title="Communication Coverage"
        description="Validated session protocols and declared TLS-upgrade completion facts. Ports and absent facts do not create protocol or protection claims."
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
    </section>
  );
}

function CryptoDimension({
  dimension,
}: {
  dimension: ReportCryptoDimension;
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
    </article>
  );
}

function CryptographicPosture({ data }: { data: ReportPageData }) {
  return (
    <section aria-labelledby="cryptographic-posture-heading" className="space-y-4">
      <SectionHeading
        id="cryptographic-posture-heading"
        title="Cryptographic Posture"
        description="The same bounded observation and fact allowlist used by Session X-Ray and Compare. Missing or unavailable evidence remains neutral."
      />
      {data.cryptoDimensions.length === 0 ? (
        <div className="rounded-lg border border-dashed border-neutral-300 bg-white px-5 py-10 text-center text-sm text-neutral-600">
          No allowlisted cryptographic observations or facts are present. No
          cryptographic posture was inferred.
        </div>
      ) : (
        <div className="grid gap-4 lg:grid-cols-2">
          {data.cryptoDimensions.map((dimension) => (
            <CryptoDimension key={dimension.key} dimension={dimension} />
          ))}
        </div>
      )}
    </section>
  );
}

function ImportantFindings({ data }: { data: ReportPageData }) {
  return (
    <section aria-labelledby="important-findings-heading" className="space-y-4">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <SectionHeading
          id="important-findings-heading"
          title="Important Findings"
          description="A severity-ordered subset of the deterministic findings already available in Findings."
        />
        <Link
          href={data.links.findings}
          className="inline-flex shrink-0 items-center gap-1 rounded-sm text-sm font-medium text-neutral-950 underline decoration-neutral-300 underline-offset-4 outline-none hover:decoration-neutral-950 focus-visible:ring-2 focus-visible:ring-neutral-950 focus-visible:ring-offset-2"
        >
          View all findings
          <ArrowRight className="size-4" aria-hidden />
        </Link>
      </div>
      {data.importantFindings.length === 0 ? (
        <div className="rounded-lg border border-dashed border-neutral-300 bg-white px-5 py-10 text-center shadow-sm">
          <h3 className="text-sm font-semibold text-neutral-950">
            No validated policy findings
          </h3>
          <p className="mx-auto mt-2 max-w-xl text-sm leading-6 text-neutral-600">
            The validated result contains no deterministic policy findings. No
            secure or insecure conclusion is inferred from this empty state.
          </p>
        </div>
      ) : (
        <div className="grid gap-3">
          {data.importantFindings.map((finding) => (
            <article
              key={finding.findingId}
              className="min-w-0 rounded-lg border border-neutral-200 bg-white p-4 shadow-sm"
            >
              <div className="flex min-w-0 flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                <div className="min-w-0">
                  <h3 className="text-sm font-semibold text-neutral-950">
                    {finding.title}
                  </h3>
                  <code className="mt-1 block break-all font-mono text-[11px] text-neutral-500">
                    {finding.findingId}
                  </code>
                </div>
                <Badge
                  variant="outline"
                  className={cn(
                    "w-fit rounded-md uppercase",
                    severityStyles[finding.severity] ?? severityStyles.info,
                  )}
                >
                  {finding.severity}
                </Badge>
              </div>
              <p className="mt-3 text-sm leading-6 text-neutral-700">
                {finding.rationale}
              </p>
              <div className="mt-4 flex flex-col gap-2 border-t border-neutral-100 pt-3 text-xs text-neutral-600 sm:flex-row sm:items-center sm:justify-between">
                <div className="min-w-0">
                  <span>{finding.evidenceCount} direct evidence references</span>
                  <span aria-hidden> · </span>
                  <span>{finding.factCount} declared facts</span>
                </div>
                <Link
                  href={`/analysis/${data.analysisId}/sessions/${finding.sessionId}`}
                  className="w-fit break-all font-mono text-[11px] font-medium text-neutral-950 underline decoration-neutral-300 underline-offset-4 outline-none hover:decoration-neutral-950 focus-visible:ring-2 focus-visible:ring-neutral-950 focus-visible:ring-offset-2"
                >
                  {finding.sessionId}
                </Link>
              </div>
            </article>
          ))}
          {data.totalFindings > data.importantFindings.length ? (
            <p className="text-xs text-neutral-600">
              Showing {data.importantFindings.length} of {data.totalFindings}{" "}
              validated findings.
            </p>
          ) : null}
        </div>
      )}
    </section>
  );
}

function ChainOfProofSummary({ data }: { data: ReportPageData }) {
  const stages = [
    { label: "Capture", count: data.graphCounts.captures },
    { label: "Sessions", count: data.graphCounts.sessions },
    { label: "Evidence", count: data.graphCounts.evidence },
    { label: "Facts", count: data.graphCounts.facts },
    { label: "Findings", count: data.graphCounts.findings },
  ];

  return (
    <section aria-labelledby="chain-of-proof-heading" className="space-y-4">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <SectionHeading
          id="chain-of-proof-heading"
          title="Chain of Proof"
          description="Finding → Fact → Evidence → Observed traffic remains traceable through explicit graph references."
        />
        <Link
          href={data.links.proofMap}
          className="inline-flex shrink-0 items-center gap-1 rounded-sm text-sm font-medium text-neutral-950 underline decoration-neutral-300 underline-offset-4 outline-none hover:decoration-neutral-950 focus-visible:ring-2 focus-visible:ring-neutral-950 focus-visible:ring-offset-2"
        >
          Open Proof Map
          <ArrowRight className="size-4" aria-hidden />
        </Link>
      </div>
      <div className="grid gap-2 rounded-lg border border-neutral-200 bg-white p-4 shadow-sm sm:grid-cols-[1fr_auto_1fr_auto_1fr_auto_1fr_auto_1fr] sm:items-center">
        {stages.map((stage, index) => (
          <div key={stage.label} className="contents">
            <div className="rounded-md border border-neutral-200 bg-neutral-50 px-3 py-4 text-center">
              <p className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
                {stage.label}
              </p>
              <p className="mt-1 font-mono text-lg font-semibold text-neutral-950">
                {stage.count.toLocaleString("en")}
              </p>
            </div>
            {index < stages.length - 1 ? (
              <ArrowRight
                className="mx-auto hidden size-4 text-neutral-400 sm:block"
                aria-hidden
              />
            ) : null}
          </div>
        ))}
      </div>
    </section>
  );
}

function PolicyRisk({ data }: { data: ReportPageData }) {
  return (
    <section aria-labelledby="policy-risk-heading">
      <Card className="h-full rounded-lg border-neutral-200 shadow-sm ring-0">
        <CardHeader className="border-b border-neutral-200">
          <div className="flex items-start gap-3">
            <span className="flex size-9 shrink-0 items-center justify-center rounded-md border border-neutral-200 bg-neutral-50 text-neutral-700">
              <ShieldAlert className="size-4" aria-hidden />
            </span>
            <div>
              <CardTitle>
                <h2 id="policy-risk-heading">Policy Risk</h2>
              </CardTitle>
              <CardDescription className="mt-1">
                Deterministic, rule-backed findings only.
              </CardDescription>
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          {!data.policyRisk.available ? (
            <div className="rounded-md border border-dashed border-neutral-300 bg-neutral-50 p-4 text-sm leading-6 text-neutral-600">
              No Policy Risk summary is present. No secure or insecure state is
              inferred.
            </div>
          ) : (
            <>
              <dl className="grid gap-3 sm:grid-cols-3">
                <div>
                  <dt className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
                    Engine state
                  </dt>
                  <dd className="mt-1 text-sm text-neutral-950">
                    {engineStatusLabels[data.policyRisk.engineStatus] ??
                      humanize(data.policyRisk.engineStatus)}
                  </dd>
                </div>
                <div>
                  <dt className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
                    Policy profile
                  </dt>
                  <dd className="mt-1 break-all font-mono text-xs text-neutral-950">
                    {data.policyRisk.profileId}
                  </dd>
                </div>
                <div>
                  <dt className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
                    Findings / contributions
                  </dt>
                  <dd className="mt-1 text-sm text-neutral-950">
                    {data.policyRisk.findingCount} /{" "}
                    {data.policyRisk.contributionCount}
                  </dd>
                </div>
              </dl>
              {data.policyRisk.severityDistribution.length > 0 ? (
                <div className="border-t border-neutral-100 pt-4">
                  <p className="mb-2 text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
                    Severity distribution
                  </p>
                  <div className="flex flex-wrap gap-2">
                    {data.policyRisk.severityDistribution.map((item) => (
                      <Badge
                        key={item.severity}
                        variant="outline"
                        className={cn(
                          "rounded-md uppercase",
                          severityStyles[item.severity] ?? severityStyles.info,
                        )}
                      >
                        {item.severity}: {item.count}
                      </Badge>
                    ))}
                  </div>
                </div>
              ) : (
                <p className="border-t border-neutral-100 pt-4 text-sm leading-6 text-neutral-600">
                  No deterministic findings are present. This is a neutral
                  empty state, not a declaration that the system is secure.
                </p>
              )}
            </>
          )}
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
                Independent from deterministic Policy Risk.
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
          <p className="text-xs leading-5 text-neutral-600">
            Anomalous behavior is not proof of malicious activity. No combined
            Policy Risk and ML score is presented.
          </p>
        </CardContent>
      </Card>
    </section>
  );
}

function Limitations({ data }: { data: ReportPageData }) {
  return (
    <section aria-labelledby="limitations-heading" className="space-y-4">
      <SectionHeading
        id="limitations-heading"
        title="Observability & Limitations"
        description="Declared result limitations and established passive-analysis boundaries."
      />
      <Card className="rounded-lg border-neutral-200 shadow-sm ring-0">
        <CardContent>
          <ul className="space-y-3">
            {data.limitations.map((limitation) => (
              <li
                key={`${limitation.code}:${limitation.summary}`}
                className="flex min-w-0 items-start gap-3 rounded-md border border-neutral-200 bg-neutral-50 p-3"
              >
                <Info
                  className="mt-0.5 size-4 shrink-0 text-neutral-500"
                  aria-hidden
                />
                <div className="min-w-0">
                  <code className="break-all font-mono text-[11px] text-neutral-500">
                    {limitation.code}
                  </code>
                  <p className="mt-1 text-xs leading-5 text-neutral-700">
                    {limitation.summary}
                  </p>
                </div>
              </li>
            ))}
            <li className="flex items-start gap-3 rounded-md border border-neutral-200 bg-neutral-50 p-3">
              <Info
                className="mt-0.5 size-4 shrink-0 text-neutral-500"
                aria-hidden
              />
              <p className="text-xs leading-5 text-neutral-700">
                Not observable is not equivalent to failure. Unavailable
                evidence is not automatically classified as secure or insecure.
              </p>
            </li>
            <li className="flex items-start gap-3 rounded-md border border-neutral-200 bg-neutral-50 p-3">
              <Info
                className="mt-0.5 size-4 shrink-0 text-neutral-500"
                aria-hidden
              />
              <p className="text-xs leading-5 text-neutral-700">
                SecureMailScope analyzes captured network traffic. It does not
                decrypt email content and it is not live monitoring.
              </p>
            </li>
          </ul>
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
        description={
          data.recommendations.length > 0
            ? "Advisory guidance supplied explicitly by the validated contract."
            : "No contract recommendation is present; use the validated findings and affected sessions for follow-up."
        }
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
          {data.recommendations.map((recommendation) => (
            <article
              key={recommendation.recommendationId}
              className="min-w-0 rounded-lg border border-neutral-200 bg-white p-5 shadow-sm"
            >
              <div className="flex min-w-0 flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                <div className="min-w-0">
                  <h3 className="text-sm font-semibold text-neutral-950">
                    {recommendation.title}
                  </h3>
                  <code className="mt-1 block break-all font-mono text-[11px] text-neutral-500">
                    {recommendation.recommendationId}
                  </code>
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
              <div className="mt-4 grid gap-4 border-t border-neutral-100 pt-4 md:grid-cols-2">
                <div>
                  <h4 className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
                    Action steps
                  </h4>
                  <ul className="mt-2 list-disc space-y-1 pl-4 text-xs leading-5 text-neutral-700 marker:text-neutral-400">
                    {recommendation.actionSteps.map((step) => (
                      <li key={step}>{step}</li>
                    ))}
                  </ul>
                </div>
                <div>
                  <h4 className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
                    Verification steps
                  </h4>
                  <ul className="mt-2 list-disc space-y-1 pl-4 text-xs leading-5 text-neutral-700 marker:text-neutral-400">
                    {recommendation.verificationSteps.map((step) => (
                      <li key={step}>{step}</li>
                    ))}
                  </ul>
                </div>
              </div>
              <div className="mt-4 flex flex-wrap gap-x-4 gap-y-2 border-t border-neutral-100 pt-3 text-[11px] text-neutral-600">
                <span>Scope: {humanize(recommendation.scope)}</span>
                <span>
                  Automation: {humanize(recommendation.automationStatus)}
                </span>
                <span>
                  {pluralize(
                    recommendation.affectedFindingIds.length,
                    "affected finding",
                  )}
                </span>
              </div>
            </article>
          ))}
        </div>
      )}
    </section>
  );
}

function ReportNavigation({ data }: { data: ReportPageData }) {
  const links = [
    { label: "Overview", href: data.links.overview, icon: FileSearch },
    { label: "Sessions", href: data.links.sessions, icon: Network },
    { label: "Proof Map", href: data.links.proofMap, icon: GitFork },
    { label: "Findings", href: data.links.findings, icon: ListChecks },
    { label: "Compare", href: data.links.compare, icon: GitCompareArrows },
  ];
  return (
    <nav
      aria-label="Report drill-down navigation"
      className="rounded-lg border border-neutral-200 bg-white p-4 shadow-sm"
    >
      <p className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
        Continue investigation
      </p>
      <div className="mt-3 flex flex-wrap gap-2">
        {links.map((item) => {
          const Icon = item.icon;
          return (
            <Link
              key={item.label}
              href={item.href}
              className="inline-flex min-h-9 items-center justify-center gap-2 rounded-md border border-neutral-300 bg-white px-3 text-sm font-medium text-neutral-900 outline-none hover:bg-neutral-50 focus-visible:ring-2 focus-visible:ring-neutral-950 focus-visible:ring-offset-2"
            >
              <Icon className="size-4" aria-hidden />
              {item.label}
            </Link>
          );
        })}
      </div>
    </nav>
  );
}

export function ReportWorkspace({ data }: { data: ReportPageData }) {
  return (
    <div className="mx-auto min-w-0 w-full max-w-[92rem] space-y-8">
      <header className="flex min-w-0 flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
        <div className="min-w-0">
          <p className="text-[11px] font-bold uppercase tracking-[0.08em] text-neutral-500">
            Analysis / Report
          </p>
          <h1 className="mt-1 text-2xl font-semibold tracking-tight text-neutral-950 sm:text-3xl">
            SecureMailScope Assessment Report
          </h1>
          <p className="mt-2 max-w-3xl text-sm leading-6 text-neutral-600">
            Consolidated, evidence-backed presentation of the same validated
            analysis available throughout the workspace.
          </p>
        </div>
        <Badge
          variant="outline"
          className="w-fit max-w-full rounded-md border-neutral-300 bg-white font-mono text-[11px]"
        >
          <span className="truncate" title={data.analysisId}>
            {data.analysisId}
          </span>
        </Badge>
      </header>

      {data.dataSource === "mock" ? (
        <PrototypeDatasetBanner label={data.datasetLabel} />
      ) : null}

      <ReportIdentity data={data} />
      <ExecutiveAssessment data={data} />
      <CommunicationCoverage data={data} />
      <CryptographicPosture data={data} />
      <ImportantFindings data={data} />
      <ChainOfProofSummary data={data} />

      <div className="grid items-stretch gap-4 xl:grid-cols-2">
        <PolicyRisk data={data} />
        <MLAnomaly data={data} />
      </div>

      <Limitations data={data} />
      <Recommendations data={data} />
      <ReportNavigation data={data} />
    </div>
  );
}
