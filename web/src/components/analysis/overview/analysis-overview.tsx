import Link from "next/link";
import {
  ArrowRight,
  CircleAlert,
  Database,
  EyeOff,
  FileCheck2,
  Info,
  Network,
  ShieldCheck,
} from "lucide-react";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { AnalysisDetails } from "@/components/layout/analysis-details";
import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import type { AnalysisResult } from "@/lib/contracts/analysis";
import type { ChainOfProof, Session } from "@/lib/contracts/chain";

const statusStyles = {
  complete: "border-emerald-300 bg-emerald-50 text-emerald-800",
  partial: "border-amber-300 bg-amber-50 text-amber-800",
  failed: "border-red-300 bg-red-50 text-red-800",
} as const;

const severityOrder = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
} as const;

function humanize(value: string): string {
  return value.replaceAll("_", " ");
}

function stateLabel(value: string): string {
  const readable = humanize(value);
  return readable.charAt(0).toUpperCase() + readable.slice(1);
}

function formatEndpoint(endpoint: Session["source_endpoint"]): string {
  const host = endpoint.ip.includes(":") ? `[${endpoint.ip}]` : endpoint.ip;
  return `${host}:${endpoint.port}`;
}

function pluralize(count: number, singular: string, plural = `${singular}s`) {
  return `${count.toLocaleString("en")} ${count === 1 ? singular : plural}`;
}

type DistributionItem = {
  key: string;
  label: string;
  count: number;
};

function DistributionList({
  items,
  total,
}: {
  items: DistributionItem[];
  total: number;
}) {
  if (total === 0) {
    return (
      <p className="rounded-md border border-dashed border-neutral-300 bg-neutral-50 p-4 text-sm text-neutral-600">
        No reconstructed sessions are available for this distribution.
      </p>
    );
  }

  return (
    <ul className="space-y-3">
      {items.map((item) => {
        const percentage = (item.count / total) * 100;
        return (
          <li key={item.key}>
            <div className="mb-1.5 flex items-center justify-between gap-3 text-xs">
              <span className="font-medium text-neutral-800">{item.label}</span>
              <span className="font-mono text-neutral-600">
                {item.count} · {Math.round(percentage)}%
              </span>
            </div>
            <div
              className="h-2 overflow-hidden rounded-full bg-neutral-100"
              role="img"
              aria-label={`${item.label}: ${item.count} of ${total} sessions`}
            >
              <div
                className="h-full rounded-full bg-neutral-700"
                style={{ width: `${percentage}%` }}
              />
            </div>
          </li>
        );
      })}
    </ul>
  );
}

function buildProtocolDistribution(
  sessions: ChainOfProof["sessions"],
): DistributionItem[] {
  const counts = new Map<string, number>();
  for (const session of sessions) {
    counts.set(session.protocol, (counts.get(session.protocol) ?? 0) + 1);
  }

  return [...counts.entries()]
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([protocol, count]) => ({
      key: protocol,
      label: protocol.toUpperCase(),
      count,
    }));
}

type TlsOutcomeKey =
  | "accepted"
  | "rejected"
  | "requested_no_outcome"
  | "no_transition_event";

const tlsOutcomeLabels: Record<TlsOutcomeKey, string> = {
  accepted: "Accepted transition event",
  rejected: "Rejected transition event",
  requested_no_outcome: "Request observed; outcome unavailable",
  no_transition_event: "No accepted/rejected transition event",
};

function tlsOutcomeForSession(
  sessionId: string,
  events: ChainOfProof["protocol_events"],
): TlsOutcomeKey {
  const eventTypes = new Set(
    events
      .filter((event) => event.session_id === sessionId)
      .map((event) => event.event_type),
  );

  if (eventTypes.has("tls_upgrade_accepted")) return "accepted";
  if (eventTypes.has("tls_upgrade_rejected")) return "rejected";
  if (eventTypes.has("tls_upgrade_requested")) return "requested_no_outcome";
  return "no_transition_event";
}

function buildTlsOutcomeDistribution(
  sessions: ChainOfProof["sessions"],
  events: ChainOfProof["protocol_events"],
): DistributionItem[] {
  const counts = new Map<TlsOutcomeKey, number>();
  for (const session of sessions) {
    const outcome = tlsOutcomeForSession(session.session_id, events);
    counts.set(outcome, (counts.get(outcome) ?? 0) + 1);
  }

  const order: TlsOutcomeKey[] = [
    "accepted",
    "rejected",
    "requested_no_outcome",
    "no_transition_event",
  ];
  return order
    .filter((outcome) => counts.has(outcome))
    .map((outcome) => ({
      key: outcome,
      label: tlsOutcomeLabels[outcome],
      count: counts.get(outcome) ?? 0,
    }));
}

function MetricCard({
  label,
  value,
  detail,
  icon: Icon,
}: {
  label: string;
  value: string;
  detail: string;
  icon: typeof Network;
}) {
  return (
    <Card className="rounded-lg border-neutral-200 shadow-sm ring-0">
      <CardContent className="flex h-full items-start justify-between gap-4">
        <div className="min-w-0">
          <p className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
            {label}
          </p>
          <p className="mt-2 break-words text-2xl font-semibold tracking-tight text-neutral-950">
            {value}
          </p>
          <p className="mt-2 text-xs leading-5 text-neutral-600">{detail}</p>
        </div>
        <span className="flex size-9 shrink-0 items-center justify-center rounded-md border border-neutral-200 bg-neutral-50 text-neutral-600">
          <Icon className="size-4" aria-hidden />
        </span>
      </CardContent>
    </Card>
  );
}

function SummaryCardsSection({ result }: { result: AnalysisResult }) {
  const { analysis, sessions, policy_risk, anomaly_results } = result.chain;
  const completeSessions = sessions.filter(
    (session) => session.capture_completeness === "complete",
  ).length;
  const anomalyBandCounts = new Map<string, number>();
  for (const anomaly of anomaly_results) {
    anomalyBandCounts.set(
      anomaly.band,
      (anomalyBandCounts.get(anomaly.band) ?? 0) + 1,
    );
  }
  const anomalyBands = [...anomalyBandCounts.entries()]
    .map(([band, count]) => `${humanize(band)}: ${count}`)
    .join(" · ");

  return (
    <section aria-labelledby="security-posture-heading" className="space-y-4">
      <div>
        <h2
          id="security-posture-heading"
          className="text-lg font-semibold tracking-tight text-neutral-950"
        >
          Security posture summary
        </h2>
        <p className="mt-1 text-sm leading-6 text-neutral-600">
          Assessment coverage and recorded results for this capture.
        </p>
      </div>

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <MetricCard
          label="Reconstructed sessions"
          value={sessions.length.toLocaleString("en")}
          detail={
            sessions.length === 0
              ? "No session records are present."
              : `${pluralize(completeSessions, "session")} marked complete.`
          }
          icon={Network}
        />
        <MetricCard
          label="Capture records"
          value={result.chain.captures.length.toLocaleString("en")}
          detail={pluralize(
            result.chain.captures.reduce(
              (total, capture) => total + capture.packet_count,
              0,
            ),
            "packet",
          )}
          icon={Database}
        />
        <MetricCard
          label="Policy Risk"
          value={
            policy_risk ? `${policy_risk.capped_score} / 100` : "Not available"
          }
          detail={
            result.data_source === "mock"
              ? `${policy_risk ? pluralize(policy_risk.contributions.length, "contribution") : "No summary"} in the policy result${policy_risk ? ` · ${policy_risk.profile_id}` : ""}.`
              : policy_risk
                ? `${pluralize(policy_risk.contributions.length, "contribution")} · ${policy_risk.profile_id} · deterministic policy result.`
                : `${stateLabel(analysis.rule_engine_status)} · no Policy Risk summary available.`
          }
          icon={ShieldCheck}
        />
        <MetricCard
          label="ML Anomaly"
          value={
            anomaly_results.length > 0
              ? pluralize(anomaly_results.length, "session result")
              : stateLabel(analysis.ml_engine_status)
          }
          detail={
            anomalyBands
              ? `${anomalyBands}. Separate from Policy Risk; anomaly is not proof of malicious activity.`
              : "No anomaly score is available. This is not a zero or a clean result."
          }
          icon={EyeOff}
        />
      </div>

    </section>
  );
}

function DistributionsSection({ result }: { result: AnalysisResult }) {
  const { sessions, protocol_events } = result.chain;
  const protocolDistribution = buildProtocolDistribution(sessions);
  const tlsOutcomes = buildTlsOutcomeDistribution(sessions, protocol_events);

  return (
    <section aria-labelledby="session-distributions-heading" className="space-y-4">
      <div>
        <h2
          id="session-distributions-heading"
          className="text-lg font-semibold tracking-tight text-neutral-950"
        >
          Session distribution
        </h2>
        <p className="mt-1 text-sm leading-6 text-neutral-600">
          Protocol mix and observed TLS-upgrade outcomes.
        </p>
      </div>
      <div className="grid gap-4 lg:grid-cols-2">
        <Card className="rounded-lg border-neutral-200 shadow-sm ring-0">
          <CardHeader className="border-b border-neutral-200">
            <CardTitle>
              <h3>Protocol distribution</h3>
            </CardTitle>
            <CardDescription>
              Validated reconstructed session protocols.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <DistributionList
              items={protocolDistribution}
              total={sessions.length}
            />
          </CardContent>
        </Card>

        <Card className="rounded-lg border-neutral-200 shadow-sm ring-0">
          <CardHeader className="border-b border-neutral-200">
            <CardTitle>
              <h3>TLS-upgrade event outcomes</h3>
            </CardTitle>
            <CardDescription>
              Exact transition-event presence; absence is not classified as
              failure.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <DistributionList items={tlsOutcomes} total={sessions.length} />
          </CardContent>
        </Card>
      </div>

    </section>
  );
}

type SessionReview = {
  session: Session;
  findings: ChainOfProof["findings"];
  tlsOutcome: TlsOutcomeKey;
};

function buildSessionReviews(chain: ChainOfProof): SessionReview[] {
  return chain.sessions
    .map((session) => ({
      session,
      findings: chain.findings
        .filter((finding) => finding.session_id === session.session_id)
        .sort(
          (left, right) =>
            severityOrder[left.severity] - severityOrder[right.severity],
        ),
      tlsOutcome: tlsOutcomeForSession(
        session.session_id,
        chain.protocol_events,
      ),
    }))
    .sort((left, right) => {
      if (left.findings.length !== right.findings.length) {
        return right.findings.length - left.findings.length;
      }
      return left.session.started_at.localeCompare(right.session.started_at);
    });
}

function FindingSummary({ review }: { review: SessionReview }) {
  if (review.findings.length === 0) {
    return <span className="text-neutral-500">No linked findings</span>;
  }
  const firstFinding = review.findings[0];
  return (
    <span className="inline-flex items-center gap-1.5">
      <Badge
        variant="outline"
        className="h-5 rounded-md border-neutral-300 bg-white capitalize"
      >
        {firstFinding.severity}
      </Badge>
      <span>{pluralize(review.findings.length, "linked finding")}</span>
    </span>
  );
}

function PrioritizedSessionsSection({ result }: { result: AnalysisResult }) {
  const reviews = buildSessionReviews(result.chain);

  return (
    <Card
      className="rounded-lg border-neutral-200 shadow-sm ring-0"
      aria-labelledby="prioritized-sessions-heading"
    >
      <CardHeader className="border-b border-neutral-200">
        <CardTitle>
          <h2 id="prioritized-sessions-heading">Prioritized sessions</h2>
        </CardTitle>
        <CardDescription>
          Sessions with linked findings appear first. Open a session to review
          its timeline, cryptography and evidence.
        </CardDescription>
      </CardHeader>
      <CardContent>
        {reviews.length === 0 ? (
          <div className="rounded-lg border border-dashed border-neutral-300 bg-neutral-50 px-5 py-10 text-center">
            <Network className="mx-auto size-6 text-neutral-400" aria-hidden />
            <h3 className="mt-3 text-sm font-semibold text-neutral-950">
              No reconstructed sessions
            </h3>
            <p className="mt-1 text-xs leading-5 text-neutral-600">
              The validated result contains no session records to prioritize.
            </p>
          </div>
        ) : (
          <>
            <div className="hidden overflow-x-auto md:block">
              <table className="w-full min-w-[52rem] border-collapse text-left text-xs">
                <caption className="sr-only">
                  Reconstructed sessions with Session X-Ray navigation
                </caption>
                <thead>
                  <tr className="border-b border-neutral-200 text-[10px] uppercase tracking-[0.06em] text-neutral-500">
                    <th scope="col" className="px-3 py-3 font-bold">
                      Session
                    </th>
                    <th scope="col" className="px-3 py-3 font-bold">
                      Protocol
                    </th>
                    <th scope="col" className="px-3 py-3 font-bold">
                      Endpoints
                    </th>
                    <th scope="col" className="px-3 py-3 font-bold">
                      TLS upgrade
                    </th>
                    <th scope="col" className="px-3 py-3 font-bold">
                      Policy findings
                    </th>
                    <th scope="col" className="px-3 py-3 text-right font-bold">
                      Session X-Ray
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {reviews.map((review) => (
                    <tr
                      key={review.session.session_id}
                      className="border-b border-neutral-100 last:border-0"
                    >
                      <td className="px-3 py-4 align-top">
                        <p className="font-mono text-[11px] text-neutral-950">
                          {review.session.session_id}
                        </p>
                        <p className="mt-1 text-[11px] text-neutral-500">
                          Stream {review.session.tcp_stream_id} ·{" "}
                          {humanize(review.session.capture_completeness)}
                        </p>
                      </td>
                      <td className="px-3 py-4 align-top font-medium uppercase text-neutral-800">
                        {review.session.protocol}
                      </td>
                      <td className="px-3 py-4 align-top font-mono text-[11px] leading-5 text-neutral-700">
                        <span className="block">
                          {formatEndpoint(review.session.source_endpoint)}
                        </span>
                        <span className="block">
                          →{" "}
                          {formatEndpoint(review.session.destination_endpoint)}
                        </span>
                      </td>
                      <td className="px-3 py-4 align-top text-neutral-700">
                        {tlsOutcomeLabels[review.tlsOutcome]}
                      </td>
                      <td className="px-3 py-4 align-top text-neutral-700">
                        <FindingSummary review={review} />
                      </td>
                      <td className="px-3 py-4 text-right align-top">
                        <Link
                          href={`/analysis/${result.chain.analysis.analysis_id}/sessions/${review.session.session_id}`}
                          className="inline-flex items-center gap-1 rounded-sm font-medium text-neutral-950 underline decoration-neutral-300 underline-offset-4 outline-none hover:decoration-neutral-950 focus-visible:ring-2 focus-visible:ring-neutral-950 focus-visible:ring-offset-2"
                          aria-label={`Open Session X-Ray for ${review.session.session_id}`}
                        >
                          Open
                          <ArrowRight className="size-3" aria-hidden />
                        </Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div className="space-y-3 md:hidden">
              {reviews.map((review) => (
                <article
                  key={review.session.session_id}
                  className="rounded-lg border border-neutral-200 bg-neutral-50 p-4"
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <h3 className="break-all font-mono text-xs font-semibold text-neutral-950">
                        {review.session.session_id}
                      </h3>
                      <p className="mt-1 text-[11px] uppercase text-neutral-500">
                        {review.session.protocol} · Stream{" "}
                        {review.session.tcp_stream_id}
                      </p>
                    </div>
                    <Badge
                      variant="outline"
                      className="h-5 rounded-md bg-white capitalize"
                    >
                      {humanize(review.session.capture_completeness)}
                    </Badge>
                  </div>
                  <dl className="mt-4 space-y-3 text-xs">
                    <div>
                      <dt className="font-semibold text-neutral-500">
                        Endpoints
                      </dt>
                      <dd className="mt-1 break-all font-mono text-[11px] leading-5 text-neutral-800">
                        {formatEndpoint(review.session.source_endpoint)} →{" "}
                        {formatEndpoint(review.session.destination_endpoint)}
                      </dd>
                    </div>
                    <div>
                      <dt className="font-semibold text-neutral-500">
                        TLS upgrade
                      </dt>
                      <dd className="mt-1 text-neutral-800">
                        {tlsOutcomeLabels[review.tlsOutcome]}
                      </dd>
                    </div>
                    <div>
                      <dt className="font-semibold text-neutral-500">
                        Policy findings
                      </dt>
                      <dd className="mt-1 text-neutral-800">
                        <FindingSummary review={review} />
                      </dd>
                    </div>
                  </dl>
                  <Link
                    href={`/analysis/${result.chain.analysis.analysis_id}/sessions/${review.session.session_id}`}
                    className="mt-4 inline-flex h-9 w-full items-center justify-center gap-2 rounded-md border border-neutral-300 bg-white text-sm font-medium text-neutral-900 outline-none hover:bg-neutral-100 focus-visible:ring-2 focus-visible:ring-neutral-950 focus-visible:ring-offset-2"
                  >
                    Open Session X-Ray
                    <ArrowRight className="size-4" aria-hidden />
                  </Link>
                </article>
              ))}
            </div>
          </>
        )}
      </CardContent>
    </Card>
  );
}

function AssessmentCoverageSection({ result }: { result: AnalysisResult }) {
  const limitationCount = result.chain.analysis.limitations.length;
  const captureWarningCount = result.chain.captures.reduce(
    (count, capture) => count + capture.capture_warnings.length,
    0,
  );
  const tls13UnavailableCount = result.chain.crypto_observations.filter(
    (observation) => observation.kind === "tls13_certificate_unavailable",
  ).length;
  const hasInterpretationLimits =
    limitationCount > 0 || captureWarningCount > 0 || tls13UnavailableCount > 0;

  return (
    <Card
      className={`rounded-lg shadow-sm ring-0 ${
        hasInterpretationLimits
          ? "border-amber-200 bg-amber-50/50"
          : "border-neutral-200"
      }`}
      aria-labelledby="assessment-coverage-heading"
    >
      <CardContent className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex min-w-0 items-start gap-3">
          <Info
            className={`mt-0.5 size-5 shrink-0 ${hasInterpretationLimits ? "text-amber-800" : "text-neutral-600"}`}
            aria-hidden
          />
          <div>
            <h2
              id="assessment-coverage-heading"
              className="text-sm font-semibold text-neutral-950"
            >
              Assessment coverage
            </h2>
            <p className="mt-1 text-xs leading-5 text-neutral-700">
              {hasInterpretationLimits
                ? `${pluralize(limitationCount, "analysis limitation")}, ${pluralize(captureWarningCount, "capture warning")} and ${pluralize(tls13UnavailableCount, "TLS 1.3 certificate visibility constraint")} apply.`
                : "No analysis-level limitations, capture warnings or TLS 1.3 certificate visibility constraints are recorded."}
            </p>
            <p className="mt-1 text-xs leading-5 text-neutral-600">
              Review the evidence boundary before interpreting unavailable or
              partial results.
            </p>
          </div>
        </div>
        <AnalysisDetails trigger="coverage" />
      </CardContent>
    </Card>
  );
}

export function AnalysisOverview({ result }: { result: AnalysisResult }) {

  return (
    <div className="mx-auto flex w-full max-w-7xl flex-col gap-6">
      <header>
        <p className="text-[11px] font-bold uppercase tracking-[0.08em] text-neutral-500">
          Analysis / Overview
        </p>
        <div className="mt-2 flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
          <div>
            <h1 className="text-2xl font-semibold tracking-tight text-neutral-950 sm:text-3xl">
              Analysis Overview
            </h1>
            <p className="mt-2 max-w-3xl text-sm leading-6 text-neutral-600">
              Review security findings and choose a session to investigate.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <Badge
              variant="outline"
              className="h-6 rounded-md border-neutral-300 bg-white font-mono text-[11px]"
            >
              {result.chain.analysis.analysis_id}
            </Badge>
          </div>
        </div>
      </header>

      <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-border bg-card px-5 py-4">
        <span className="min-w-0 break-all text-sm font-medium">
          {result.chain.captures
            .map((capture) => capture.original_filename_sanitized)
            .join(", ") || "No capture records"}
        </span>
        <Badge
          variant="outline"
          className={statusStyles[result.chain.analysis.analysis_status]}
        >
          Analysis {stateLabel(result.chain.analysis.analysis_status)}
        </Badge>
      </div>
      <SummaryCardsSection result={result} />

      <PrioritizedSessionsSection result={result} />
      <DistributionsSection result={result} />
      <AssessmentCoverageSection result={result} />
    </div>
  );
}

export function OverviewDataSourceFailure({
  analysisId,
  message,
}: {
  analysisId: string;
  message: string;
}) {
  return (
    <div className="mx-auto flex w-full max-w-3xl flex-1 items-center justify-center py-12 sm:py-20">
      <section className="w-full space-y-5">
        <div>
          <p className="text-[11px] font-bold uppercase tracking-[0.08em] text-neutral-500">
            Analysis / Overview
          </p>
          <h1 className="mt-2 text-2xl font-semibold tracking-tight text-neutral-950">
            Analysis result unavailable
          </h1>
        </div>
        <Alert variant="destructive" className="p-5">
          <CircleAlert aria-hidden />
          <AlertTitle>Data-source failure</AlertTitle>
          <AlertDescription>
            <p>{message}</p>
            <p>
              Analysis ID: <code className="break-all">{analysisId}</code>
            </p>
          </AlertDescription>
        </Alert>
        <div className="flex flex-col gap-3 sm:flex-row">
          <Link
            href="/analysis/new"
            className="inline-flex h-9 items-center justify-center rounded-md bg-neutral-950 px-4 text-sm font-medium text-white outline-none hover:bg-neutral-800 focus-visible:ring-2 focus-visible:ring-neutral-950 focus-visible:ring-offset-2"
          >
            Start a new analysis
          </Link>
          <Link
            href={`/analysis/${analysisId}/overview`}
            className="inline-flex h-9 items-center justify-center gap-2 rounded-md border border-neutral-300 bg-white px-4 text-sm font-medium text-neutral-900 outline-none hover:bg-neutral-50 focus-visible:ring-2 focus-visible:ring-neutral-950 focus-visible:ring-offset-2"
          >
            <FileCheck2 className="size-4" aria-hidden />
            Retry Overview
          </Link>
        </div>
      </section>
    </div>
  );
}
