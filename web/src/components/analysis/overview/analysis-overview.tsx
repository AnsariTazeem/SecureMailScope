import Link from "next/link";
import {
  ArrowRight,
  CircleAlert,
  Database,
  EyeOff,
  FileCheck2,
  Fingerprint,
  Info,
  LockKeyhole,
  Network,
  ShieldCheck,
} from "lucide-react";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
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
import { cn } from "@/lib/utils";

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

function formatDateTime(value: string | null): string {
  if (!value) return "Not available";

  return new Intl.DateTimeFormat("en", {
    dateStyle: "medium",
    timeStyle: "medium",
    timeZone: "UTC",
  }).format(new Date(value));
}

function formatBytes(value: number): string {
  if (value < 1024) return `${value.toLocaleString("en")} B`;

  const units = ["KB", "MB", "GB", "TB"];
  let size = value / 1024;
  let unitIndex = 0;
  while (size >= 1024 && unitIndex < units.length - 1) {
    size /= 1024;
    unitIndex += 1;
  }
  const digits = size >= 10 || Number.isInteger(size) ? 0 : 1;
  return `${size.toFixed(digits)} ${units[unitIndex]} (${value.toLocaleString("en")} bytes)`;
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

function IdentitySection({ result }: { result: AnalysisResult }) {
  const { analysis } = result.chain;
  const sourceLabel =
    result.data_source === "mock"
      ? (result.dataset_label ?? "Prototype Analysis Dataset")
      : "Production API";

  return (
    <section
      aria-labelledby="analysis-identity-heading"
      className="overflow-hidden rounded-lg border border-neutral-200 bg-white shadow-sm"
    >
      <div className="flex flex-col gap-4 border-b border-neutral-200 bg-neutral-50 px-5 py-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h2
            id="analysis-identity-heading"
            className="text-sm font-semibold text-neutral-950"
          >
            Analysis identity
          </h2>
          <p className="mt-1 break-all font-mono text-xs text-neutral-600">
            {analysis.analysis_id}
          </p>
        </div>
        <Badge
          variant="outline"
          className={cn(
            "h-6 rounded-md px-2.5 capitalize",
            statusStyles[analysis.analysis_status],
          )}
        >
          {humanize(analysis.analysis_status)}
        </Badge>
      </div>
      <dl className="grid gap-px bg-neutral-200 sm:grid-cols-2 xl:grid-cols-4">
        {[
          ["Result source", sourceLabel],
          ["Completed at", formatDateTime(analysis.completed_at)],
          ["Started at", formatDateTime(analysis.started_at)],
          ["Chain contract", `v${result.chain.chain_schema_version}`],
        ].map(([label, value]) => (
          <div key={label} className="min-w-0 bg-white px-5 py-4">
            <dt className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
              {label}
            </dt>
            <dd className="mt-1 break-words text-xs leading-5 text-neutral-950">
              {value}
              {label.includes(" at") && value !== "Not available" ? " UTC" : ""}
            </dd>
          </div>
        ))}
      </dl>
    </section>
  );
}

function CaptureIntegritySection({ result }: { result: AnalysisResult }) {
  return (
    <Card
      className="rounded-lg border-neutral-200 shadow-sm ring-0"
      aria-labelledby="capture-integrity-heading"
    >
      <CardHeader className="border-b border-neutral-200">
        <CardTitle>
          <h2 id="capture-integrity-heading">Capture integrity</h2>
        </CardTitle>
        <CardDescription>
          Provenance fields are rendered exactly from the validated result.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {result.chain.captures.map((capture) => (
          <article
            key={capture.capture_id}
            className="rounded-lg border border-neutral-200 bg-neutral-50 p-4"
          >
            <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
              <div className="min-w-0">
                <h3 className="break-all text-sm font-semibold text-neutral-950">
                  {capture.original_filename_sanitized || "Not available"}
                </h3>
                <p className="mt-1 break-all font-mono text-[11px] text-neutral-500">
                  {capture.capture_id}
                </p>
              </div>
              <Badge
                variant="outline"
                className="h-6 rounded-md border-neutral-300 bg-white font-mono uppercase"
              >
                {capture.format === "unknown" ? "unknown" : capture.format}
              </Badge>
            </div>
            <dl className="mt-4 grid gap-4 sm:grid-cols-2 xl:grid-cols-[0.65fr_0.65fr_2fr]">
              <div>
                <dt className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
                  File size
                </dt>
                <dd className="mt-1 text-xs text-neutral-900">
                  {formatBytes(capture.size_bytes)}
                </dd>
              </div>
              <div>
                <dt className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
                  Packets
                </dt>
                <dd className="mt-1 text-xs text-neutral-900">
                  {capture.packet_count.toLocaleString("en")}
                </dd>
              </div>
              <div className="min-w-0">
                <dt className="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
                  <Fingerprint className="size-3" aria-hidden />
                  {result.data_source === "mock"
                    ? "Fixture SHA-256"
                    : "SHA-256"}
                </dt>
                <dd className="mt-1 break-all font-mono text-[11px] leading-5 text-neutral-900">
                  {capture.sha256 || "Not available"}
                </dd>
              </div>
            </dl>
          </article>
        ))}
      </CardContent>
    </Card>
  );
}

function SecurityPostureSection({ result }: { result: AnalysisResult }) {
  const { analysis, sessions, protocol_events, policy_risk, anomaly_results } =
    result.chain;
  const protocolDistribution = buildProtocolDistribution(sessions);
  const tlsOutcomes = buildTlsOutcomeDistribution(sessions, protocol_events);
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
          Counts summarize validated contract records; they do not add
          browser-derived cryptographic conclusions.
        </p>
      </div>

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <MetricCard
          label="Reconstructed sessions"
          value={sessions.length.toLocaleString("en")}
          detail={
            sessions.length === 0
              ? "No session records are present."
              : `${sessions.filter((session) => session.capture_completeness === "complete").length} marked complete by the result.`
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
              ? "Validated prototype fixture result; production policy integration remains pending."
              : `Rule engine: ${humanize(analysis.rule_engine_status)}. Deterministic policy output only.`
          }
          icon={ShieldCheck}
        />
        <MetricCard
          label="ML Anomaly"
          value={
            anomaly_results.length > 0
              ? pluralize(anomaly_results.length, "session result")
              : humanize(analysis.ml_engine_status)
          }
          detail={
            anomalyBands ||
            "No anomaly score is present; absence is not rendered as zero."
          }
          icon={EyeOff}
        />
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
              Exact transition-event presence; absence is not classified as failure.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <DistributionList items={tlsOutcomes} total={sessions.length} />
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <div className="rounded-lg border border-neutral-200 bg-white p-4 shadow-sm">
          <div className="flex items-start gap-3">
            <ShieldCheck
              className="mt-0.5 size-4 shrink-0 text-neutral-600"
              aria-hidden
            />
            <div>
              <h3 className="text-sm font-semibold text-neutral-950">
                Policy Risk
              </h3>
              <p className="mt-1 text-xs leading-5 text-neutral-600">
                {policy_risk
                  ? `${pluralize(policy_risk.contributions.length, "validated contribution")} under profile ${policy_risk.profile_id}.`
                  : "No Policy Risk summary is present in the validated result."}
              </p>
            </div>
          </div>
        </div>
        <div className="rounded-lg border border-neutral-200 bg-white p-4 shadow-sm">
          <div className="flex items-start gap-3">
            <EyeOff
              className="mt-0.5 size-4 shrink-0 text-neutral-600"
              aria-hidden
            />
            <div>
              <h3 className="text-sm font-semibold text-neutral-950">
                ML Anomaly
              </h3>
              <p className="mt-1 text-xs leading-5 text-neutral-600">
                {anomaly_results.length > 0
                  ? `${pluralize(anomaly_results.length, "validated per-session result")}. Anomaly is not proof of malicious activity.`
                  : `Engine status is ${humanize(analysis.ml_engine_status)}. No anomaly conclusion is shown.`}
              </p>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

function EvidenceBoundariesSection({ result }: { result: AnalysisResult }) {
  const tls13Unavailable = result.chain.crypto_observations.filter(
    (observation) => observation.kind === "tls13_certificate_unavailable",
  );
  const authorizedSecrets = result.chain.analysis.tls13_authorized_secrets;

  return (
    <Card
      className="rounded-lg border-amber-200 bg-amber-50/50 shadow-sm ring-0"
      aria-labelledby="evidence-boundaries-heading"
    >
      <CardHeader className="border-b border-amber-200">
        <div className="flex items-start gap-3">
          <LockKeyhole
            className="mt-0.5 size-5 shrink-0 text-amber-800"
            aria-hidden
          />
          <div>
            <CardTitle>
              <h2 id="evidence-boundaries-heading">Evidence boundaries</h2>
            </CardTitle>
            <CardDescription className="mt-1 text-neutral-700">
              Passive observation establishes visible transport events, not
              decrypted message content.
            </CardDescription>
          </div>
        </div>
      </CardHeader>
      <CardContent className="space-y-4 text-xs leading-5 text-neutral-700">
        <p>
          SecureMailScope does not display packet payloads, message bodies,
          AUTH credentials, or secrets in this Overview. Encrypted application
          data is reported only as encrypted traffic; this interface never
          implies decryption.
        </p>
        <div className="rounded-md border border-amber-200 bg-white p-3">
          <p className="font-semibold text-neutral-950">
            TLS 1.3 certificate visibility
          </p>
          <p className="mt-1">
            Authorized session secrets: <code>{humanize(authorizedSecrets)}</code>.
            {tls13Unavailable.length > 0
              ? ` ${pluralize(tls13Unavailable.length, "certificate observation")} retain ${[
                  ...new Set(
                    tls13Unavailable.map((item) => item.observability),
                  ),
                ]
                  .map(humanize)
                  .join(", ")} semantics.`
              : " No TLS 1.3 certificate-unavailability observation is present in this result."}
          </p>
          <p className="mt-1">
            Without authorized secrets, TLS 1.3 certificate contents after
            ServerHello are not observable. That state must not be interpreted
            as missing, invalid, expired, or trusted.
          </p>
        </div>
      </CardContent>
    </Card>
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
          Sessions with validated linked findings appear first. No client-side
          severity, finding, or evidence is generated.
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
                    <th
                      scope="col"
                      className="px-3 py-3 text-right font-bold"
                    >
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
                          → {formatEndpoint(review.session.destination_endpoint)}
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

function LimitationsSection({ result }: { result: AnalysisResult }) {
  if (result.chain.analysis.limitations.length === 0) return null;

  return (
    <Card className="rounded-lg border-neutral-200 shadow-sm ring-0">
      <CardHeader className="border-b border-neutral-200">
        <CardTitle>
          <h2>Declared analysis limitations</h2>
        </CardTitle>
        <CardDescription>
          Limitations supplied by the validated result remain visible.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <ul className="space-y-3">
          {result.chain.analysis.limitations.map((limitation, index) => (
            <li
              key={`${limitation.code}-${index}`}
              className="flex items-start gap-3 rounded-md border border-neutral-200 bg-neutral-50 p-3"
            >
              <Info
                className="mt-0.5 size-4 shrink-0 text-neutral-500"
                aria-hidden
              />
              <div>
                <p className="font-mono text-[11px] text-neutral-500">
                  {limitation.code}
                </p>
                <p className="mt-1 text-xs leading-5 text-neutral-700">
                  {limitation.summary}
                </p>
              </div>
            </li>
          ))}
        </ul>
      </CardContent>
    </Card>
  );
}

export function AnalysisOverview({ result }: { result: AnalysisResult }) {
  const isPrototype = result.data_source === "mock";

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
              Validated capture provenance, reconstructed session counts,
              explicit transition events, and separate policy and anomaly
              outputs.
            </p>
          </div>
          <Badge
            variant="outline"
            className="h-6 rounded-md border-neutral-300 bg-white font-mono text-[11px]"
          >
            {result.chain.analysis.analysis_id}
          </Badge>
        </div>
      </header>

      {isPrototype ? (
        <Alert className="border-blue-200 bg-blue-50 p-4 text-blue-950">
          <Database className="text-blue-700" aria-hidden />
          <AlertTitle>
            {result.dataset_label ?? "Prototype Analysis Dataset"}
          </AlertTitle>
          <AlertDescription className="text-blue-900/80">
            Deterministic contract fixtures for frontend validation. This is
            not a production analyzer run and does not represent analysis of a
            newly uploaded capture.
          </AlertDescription>
        </Alert>
      ) : null}

      <IdentitySection result={result} />
      <SecurityPostureSection result={result} />

      <div className="grid items-start gap-6 xl:grid-cols-[minmax(0,1.5fr)_minmax(20rem,0.8fr)]">
        <CaptureIntegritySection result={result} />
        <EvidenceBoundariesSection result={result} />
      </div>

      <PrioritizedSessionsSection result={result} />
      <LimitationsSection result={result} />
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
