import Link from "next/link";
import {
  ArrowRight,
  CircleAlert,
  FileCheck2,
  Info,
  ListChecks,
  Network,
  ShieldCheck,
  TriangleAlert,
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

const severityStyles: Record<string, string> = {
  critical: "border-red-300 bg-red-50 text-red-800",
  high: "border-orange-300 bg-orange-50 text-orange-800",
  medium: "border-amber-300 bg-amber-50 text-amber-800",
  low: "border-neutral-300 bg-neutral-50 text-neutral-700",
  info: "border-blue-300 bg-blue-50 text-blue-800",
};

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

function ExecutiveSummary({ result }: { result: AnalysisResult }) {
  const { analysis, findings, recommendations } = result.chain;
  const primaryFinding = [...findings].sort(
    (left, right) =>
      severityOrder[left.severity] - severityOrder[right.severity],
  )[0];
  const recommendation = primaryFinding
    ? recommendations.find(
        (item) => item.recommendation_id === primaryFinding.recommendation_id,
      )
    : null;
  const affectedSessions = new Set(
    findings.map((finding) => finding.session_id),
  ).size;
  const anomalyBands = [
    ...new Set(
      result.chain.anomaly_results.map((item) => stateLabel(item.band)),
    ),
  ];

  return (
    <section aria-labelledby="executive-summary-heading">
      <Card
        className={`overflow-hidden rounded-xl shadow-sm ring-0 ${
          primaryFinding
            ? "border-orange-200 bg-orange-50/30"
            : "border-neutral-200"
        }`}
      >
        <CardContent className="p-0">
          <div className="grid gap-0 lg:grid-cols-[minmax(0,1.45fr)_minmax(20rem,0.55fr)]">
            <div className="p-5 sm:p-6 lg:p-7">
              <p className="text-[11px] font-bold uppercase tracking-[0.08em] text-neutral-500">
                Executive summary
              </p>

              {primaryFinding ? (
                <>
                  <div className="mt-3 flex flex-wrap items-center gap-2">
                    <Badge
                      variant="outline"
                      className={`rounded-md uppercase ${severityStyles[primaryFinding.severity] ?? severityStyles.info}`}
                    >
                      {primaryFinding.severity} severity
                    </Badge>
                    <span className="text-xs text-neutral-600">
                      Evidence confidence: {primaryFinding.evidence_confidence}
                    </span>
                  </div>
                  <h2
                    id="executive-summary-heading"
                    className="mt-3 text-xl font-semibold tracking-tight text-neutral-950 sm:text-2xl"
                  >
                    {primaryFinding.title}
                  </h2>
                  <p className="mt-3 max-w-3xl text-sm leading-6 text-neutral-700">
                    {primaryFinding.rationale}
                  </p>
                  <p className="mt-2 max-w-3xl text-sm leading-6 text-neutral-600">
                    <strong className="text-neutral-900">Why it matters:</strong>{" "}
                    {primaryFinding.impact}
                  </p>
                  <div className="mt-5 flex flex-col gap-2 sm:flex-row">
                    <Link
                      href={`/analysis/${analysis.analysis_id}/sessions/${primaryFinding.session_id}?tab=findings`}
                      className="inline-flex min-h-9 items-center justify-center gap-2 rounded-md bg-neutral-950 px-4 text-sm font-medium text-white outline-none hover:bg-neutral-800 focus-visible:ring-2 focus-visible:ring-neutral-950 focus-visible:ring-offset-2"
                    >
                      Trace finding to evidence
                      <ArrowRight className="size-4" aria-hidden />
                    </Link>
                    {recommendation ? (
                      <Link
                        href={`/analysis/${analysis.analysis_id}/recommendations#${recommendation.recommendation_id}`}
                        className="inline-flex min-h-9 items-center justify-center rounded-md border border-neutral-300 bg-white px-4 text-sm font-medium text-neutral-900 outline-none hover:bg-neutral-50 focus-visible:ring-2 focus-visible:ring-neutral-950 focus-visible:ring-offset-2"
                      >
                        Review recommended action
                      </Link>
                    ) : null}
                  </div>
                </>
              ) : (
                <>
                  <h2
                    id="executive-summary-heading"
                    className="mt-3 text-xl font-semibold tracking-tight text-neutral-950"
                  >
                    No deterministic finding was supplied
                  </h2>
                  <p className="mt-2 text-sm leading-6 text-neutral-600">
                    This is not proof that the capture is secure. Review scope,
                    completion, and observability limits before drawing a
                    conclusion.
                  </p>
                </>
              )}
            </div>

            <div className="border-t border-neutral-200 bg-white/80 p-5 sm:p-6 lg:border-l lg:border-t-0">
              <p className="text-[11px] font-bold uppercase tracking-[0.08em] text-neutral-500">
                Decision snapshot
              </p>
              <dl className="mt-4 grid grid-cols-3 gap-3 lg:grid-cols-1">
                <div>
                  <dt className="text-xs text-neutral-500">Policy Risk</dt>
                  <dd className="mt-1 text-xl font-semibold text-neutral-950">
                    {result.chain.policy_risk
                      ? `${result.chain.policy_risk.capped_score} / 100`
                      : "Not available"}
                  </dd>
                </div>
                <div>
                  <dt className="text-xs text-neutral-500">Affected sessions</dt>
                  <dd className="mt-1 text-xl font-semibold text-neutral-950">
                    {affectedSessions}
                  </dd>
                </div>
                <div>
                  <dt className="text-xs text-neutral-500">ML Anomaly</dt>
                  <dd className="mt-1 text-sm font-semibold text-neutral-950">
                    {result.chain.anomaly_results.length > 0
                      ? anomalyBands.join(", ")
                      : stateLabel(analysis.ml_engine_status)}
                  </dd>
                </div>
              </dl>
              <p className="mt-4 text-xs leading-5 text-neutral-500">
                Policy Risk and ML Anomaly are separate assessment outputs.
              </p>
            </div>
          </div>
        </CardContent>
      </Card>
    </section>
  );
}

function SummaryCardsSection({ result }: { result: AnalysisResult }) {
  const { sessions, findings, protocol_events } = result.chain;
  const completeSessions = sessions.filter(
    (session) => session.capture_completeness === "complete",
  ).length;
  const acceptedTransitions = sessions.filter(
    (session) =>
      tlsOutcomeForSession(session.session_id, protocol_events) === "accepted",
  ).length;
  const unresolvedTransitions = sessions.length - acceptedTransitions;
  const highestSeverity = [...findings].sort(
    (left, right) =>
      severityOrder[left.severity] - severityOrder[right.severity],
  )[0]?.severity;
  const limitationCount = result.chain.analysis.limitations.length;
  const captureWarningCount = result.chain.captures.reduce(
    (count, capture) => count + capture.capture_warnings.length,
    0,
  );
  const tls13UnavailableCount = result.chain.crypto_observations.filter(
    (observation) => observation.kind === "tls13_certificate_unavailable",
  ).length;
  const evidenceGapCount =
    limitationCount + captureWarningCount + tls13UnavailableCount;

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
          Assessment coverage and recorded results for the supplied capture
          records.
        </p>
      </div>

      <div className="grid grid-cols-2 gap-3 xl:grid-cols-4">
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
          label="Policy findings"
          value={findings.length.toLocaleString("en")}
          detail={
            highestSeverity
              ? `Highest severity: ${stateLabel(highestSeverity)}.`
              : "No deterministic finding was supplied; this is not proof of security."
          }
          icon={ListChecks}
        />
        <MetricCard
          label="TLS upgrades"
          value={`${acceptedTransitions} / ${sessions.length}`}
          detail={`${pluralize(acceptedTransitions, "accepted transition")} · ${pluralize(unresolvedTransitions, "other outcome")}.`}
          icon={ShieldCheck}
        />
        <MetricCard
          label="Evidence gaps"
          value={evidenceGapCount.toLocaleString("en")}
          detail={
            evidenceGapCount > 0
              ? `${pluralize(limitationCount, "limitation")} · ${pluralize(captureWarningCount, "capture warning")} · ${pluralize(tls13UnavailableCount, "visibility constraint")}.`
              : "No analysis limitation, capture warning, or TLS 1.3 visibility constraint was supplied."
          }
          icon={TriangleAlert}
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
        className={`h-5 rounded-md capitalize ${severityStyles[firstFinding.severity] ?? severityStyles.info}`}
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
              <table className="w-full min-w-[44rem] border-collapse text-left text-xs">
                <caption className="sr-only">
                  Reconstructed sessions with Session X-Ray navigation
                </caption>
                <thead>
                  <tr className="border-b border-neutral-200 text-[10px] uppercase tracking-[0.06em] text-neutral-500">
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
                      <h3 className="text-sm font-semibold text-neutral-950">
                        {review.session.protocol.toUpperCase()} session
                      </h3>
                      <p className="mt-1 text-[11px] text-neutral-500">
                        Reconstructed transport flow
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
  const eventTypes = new Set<string>(
    result.chain.protocol_events.map((event) => event.event_type),
  );
  const observationKinds = new Set<string>(
    result.chain.crypto_observations.map((observation) => observation.kind),
  );
  const factTypes = new Set<string>(
    result.chain.derived_facts.map((fact) => fact.fact_type),
  );
  const protocols = [
    ...new Set(
      result.chain.sessions.map((session) => session.protocol.toUpperCase()),
    ),
  ].sort();
  const hasTransitionEvidence = [
    "tls_upgrade_requested",
    "tls_upgrade_accepted",
    "tls_upgrade_rejected",
  ].some((eventType) => eventTypes.has(eventType));
  const hasTlsObservations = [
    "tls_negotiated_version",
    "selected_cipher_suite",
    "key_share_group",
  ].some((kind) => observationKinds.has(kind));
  const hasCertificateObservations = result.chain.crypto_observations.some(
    (observation) => observation.kind.startsWith("certificate_"),
  );
  const coverageRows = [
    {
      label: "Protocol identification",
      status: result.chain.sessions.length > 0 ? "Assessed" : "Not assessed",
      detail:
        protocols.length > 0
          ? `${protocols.join(", ")} observed in reconstructed sessions`
          : "No reconstructed session was supplied",
    },
    {
      label: "Encryption transition",
      status:
        result.chain.sessions.length === 0
          ? "Not assessed"
          : hasTransitionEvidence
            ? "Assessed"
            : "No evidence supplied",
      detail: "STARTTLS or equivalent transition evidence",
    },
    {
      label: "TLS negotiation",
      status: hasTlsObservations ? "Assessed" : "No evidence supplied",
      detail: "Version, cipher, or key-share observations",
    },
    {
      label: "Certificates",
      status: hasCertificateObservations
        ? "Assessed"
        : tls13UnavailableCount > 0
          ? "Not observable"
          : "Not assessed",
      detail:
        tls13UnavailableCount > 0 && !hasCertificateObservations
          ? "Encrypted TLS 1.3 certificate contents"
          : "Observable certificate evidence",
    },
    {
      label: "Forward Secrecy",
      status: factTypes.has("forward_secrecy") ? "Assessed" : "Not assessed",
      detail: "Derived only from supplied cryptographic facts",
    },
    {
      label: "Policy Risk",
      status: result.chain.policy_risk ? "Assessed" : "Not assessed",
      detail: "Deterministic policy result",
    },
    {
      label: "ML Anomaly",
      status:
        result.chain.anomaly_results.length > 0
          ? "Assessed"
          : result.chain.analysis.ml_engine_status === "complete"
            ? "No results"
            : stateLabel(result.chain.analysis.ml_engine_status),
      detail: "Separate behavioral signal",
    },
  ];

  return (
    <Card
      className={`rounded-lg shadow-sm ring-0 ${
        hasInterpretationLimits
          ? "border-amber-200 bg-amber-50/30"
          : "border-neutral-200"
      }`}
      aria-labelledby="assessment-coverage-heading"
    >
      <CardHeader className="border-b border-neutral-200">
        <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
          <div className="flex min-w-0 items-start gap-3">
            <Info
              className={`mt-0.5 size-5 shrink-0 ${
                hasInterpretationLimits ? "text-amber-800" : "text-neutral-600"
              }`}
              aria-hidden
            />
            <div>
              <CardTitle>
                <h2 id="assessment-coverage-heading">Assessment coverage</h2>
              </CardTitle>
              <CardDescription className="mt-1">
                What this report assessed, did not observe, or could not
                observe from the supplied capture.
              </CardDescription>
              {hasInterpretationLimits ? (
                <p className="mt-2 text-xs leading-5 text-amber-900">
                  {pluralize(limitationCount, "limitation")} ·{" "}
                  {pluralize(captureWarningCount, "capture warning")} ·{" "}
                  {pluralize(
                    tls13UnavailableCount,
                    "TLS 1.3 visibility constraint",
                  )}
                </p>
              ) : null}
            </div>
          </div>
          <AnalysisDetails trigger="coverage" />
        </div>
      </CardHeader>
      <CardContent>
        <ul className="grid gap-px overflow-hidden rounded-lg border border-neutral-200 bg-neutral-200 sm:grid-cols-2 xl:grid-cols-4">
          {coverageRows.map((item) => (
            <li key={item.label} className="min-w-0 bg-white p-4">
              <div className="flex items-start justify-between gap-3">
                <p className="text-xs font-semibold text-neutral-950">
                  {item.label}
                </p>
                <Badge
                  variant="outline"
                  className={`shrink-0 rounded-md text-[10px] ${
                    item.status === "Assessed"
                      ? "border-emerald-200 bg-emerald-50 text-emerald-800"
                      : item.status === "Not observable"
                        ? "border-amber-200 bg-amber-50 text-amber-900"
                        : "border-neutral-300 bg-neutral-50 text-neutral-700"
                  }`}
                >
                  {item.status}
                </Badge>
              </div>
              <p className="mt-2 text-xs leading-5 text-neutral-600">
                {item.detail}
              </p>
            </li>
          ))}
        </ul>
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
      <ExecutiveSummary result={result} />
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
