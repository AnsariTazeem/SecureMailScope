import Link from "next/link";
import {
  ArrowLeft,
  BrainCircuit,
  CheckCircle2,
  CircleAlert,
  Database,
  FileKey2,
  Fingerprint,
  Info,
  LockKeyhole,
  ShieldAlert,
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
import { cn } from "@/lib/utils";

import { humanize } from "../sessions/session-formatters";
import { EvidenceInspector } from "./evidence-inspector";
import type {
  CryptoEntry,
  EvidenceState,
  PostureItem,
  ScopedLimitation,
  SessionXRayData,
  XRayEvent,
  XRayEvidence,
} from "./session-xray-view-model";

const statePresentation: Record<
  EvidenceState,
  { label: string; className: string }
> = {
  observed: {
    label: "Observed",
    className: "border-emerald-200 bg-emerald-50 text-emerald-800",
  },
  derived: {
    label: "Derived",
    className: "border-blue-200 bg-blue-50 text-blue-800",
  },
  policy: {
    label: "Policy inferred",
    className: "border-violet-200 bg-violet-50 text-violet-800",
  },
  unknown: {
    label: "Unknown",
    className: "border-amber-200 bg-amber-50 text-amber-900",
  },
  not_observable: {
    label: "Not observable",
    className: "border-amber-200 bg-amber-50 text-amber-900",
  },
  not_assessed: {
    label: "Not assessed",
    className: "border-neutral-300 bg-neutral-100 text-neutral-700",
  },
  not_applicable: {
    label: "Not applicable",
    className: "border-neutral-300 bg-neutral-50 text-neutral-600",
  },
  absent: {
    label: "Not present",
    className: "border-neutral-300 bg-white text-neutral-600",
  },
  incomplete: {
    label: "Incomplete",
    className: "border-orange-200 bg-orange-50 text-orange-900",
  },
};

const severityPresentation: Record<string, string> = {
  critical: "border-red-300 bg-red-100 text-red-900",
  high: "border-red-200 bg-red-50 text-red-800",
  medium: "border-amber-200 bg-amber-50 text-amber-900",
  low: "border-blue-200 bg-blue-50 text-blue-800",
  info: "border-neutral-300 bg-neutral-100 text-neutral-700",
};

function StateBadge({ state }: { state: EvidenceState }) {
  const presentation = statePresentation[state];
  return (
    <Badge
      variant="outline"
      className={cn("rounded-md", presentation.className)}
    >
      {presentation.label}
    </Badge>
  );
}

function ScrollableCode({ value }: { value: string }) {
  return (
    <code
      className="block max-w-full break-all font-mono text-xs text-neutral-950"
      title={value}
    >
      {value}
    </code>
  );
}

function MetadataItem({
  label,
  children,
  className,
}: {
  label: string;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("min-w-0", className)}>
      <dt className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
        {label}
      </dt>
      <dd className="mt-1 min-w-0 text-sm text-neutral-950">{children}</dd>
    </div>
  );
}

function EvidenceActions({
  evidence,
  emptyLabel = "No evidence reference supplied",
  getLabel,
}: {
  evidence: XRayEvidence[];
  emptyLabel?: string;
  getLabel?: (evidence: XRayEvidence) => string;
}) {
  if (evidence.length === 0) {
    return <span className="text-xs text-neutral-500">{emptyLabel}</span>;
  }
  return (
    <div className="flex min-w-0 flex-wrap gap-2">
      {evidence.map((item) => (
        <EvidenceInspector
          key={item.evidenceId}
          evidence={item}
          label={getLabel?.(item)}
        />
      ))}
    </div>
  );
}

function IdentityHeader({ data }: { data: SessionXRayData }) {
  return (
    <header className="space-y-4">
      <div className="flex min-w-0 flex-col gap-4 md:flex-row md:items-end md:justify-between">
        <div className="min-w-0">
          <p className="text-[11px] font-bold uppercase tracking-[0.08em] text-neutral-500">
            Analysis / Sessions / Session X-Ray
          </p>
          <h1 className="mt-1 text-2xl font-semibold tracking-tight text-neutral-950 sm:text-3xl">
            Session X-Ray
          </h1>
          <p className="mt-2 max-w-3xl text-sm leading-6 text-neutral-600">
            Trace one reconstructed email session from ordered protocol events
            to evidence-backed facts, limitations, and policy output.
          </p>
        </div>
        <Link
          href={`/analysis/${data.analysisId}/sessions`}
          className="inline-flex min-h-9 w-full shrink-0 items-center justify-center gap-2 rounded-md border border-neutral-300 bg-white px-4 text-sm font-semibold text-neutral-900 outline-none hover:bg-neutral-50 focus-visible:ring-2 focus-visible:ring-neutral-950 focus-visible:ring-offset-2 md:w-auto"
        >
          <ArrowLeft className="size-4" aria-hidden />
          Back to Sessions
        </Link>
      </div>

      {data.dataSource === "mock" ? (
        <Alert className="border-blue-200 bg-blue-50/70 px-4 py-3 text-blue-950">
          <Database className="size-4" aria-hidden />
          <AlertTitle>Prototype Analysis Dataset</AlertTitle>
          <AlertDescription className="text-blue-900/80">
            {data.datasetLabel ?? "Prototype Analysis Dataset"} is a labelled,
            validated synthetic fixture. It is not a production analyzer run.
          </AlertDescription>
        </Alert>
      ) : (
        <Alert className="border-neutral-300 bg-neutral-50 px-4 py-3 text-neutral-950">
          <Database className="size-4" aria-hidden />
          <AlertTitle>Production API source</AlertTitle>
          <AlertDescription className="text-neutral-700">
            This validated result was supplied by the configured API data
            source. No fallback to prototype data was used.
          </AlertDescription>
        </Alert>
      )}

      <Card className="rounded-lg border-neutral-200 shadow-sm ring-0">
        <CardHeader className="border-b border-neutral-200">
          <CardTitle>
            <h2>Session identity</h2>
          </CardTitle>
          <CardDescription>
            Stable identifiers and capture metadata are preserved exactly.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <dl className="grid min-w-0 gap-x-6 gap-y-4 sm:grid-cols-2 xl:grid-cols-4">
            <MetadataItem label="Session ID" className="sm:col-span-2">
              <ScrollableCode value={data.sessionId} />
            </MetadataItem>
            <MetadataItem label="Analysis ID" className="sm:col-span-2">
              <ScrollableCode value={data.analysisId} />
            </MetadataItem>
            <MetadataItem label="Protocol">
              <span className="font-mono">{data.protocol}</span>
              <span className="ml-2 text-xs text-neutral-500">
                ({humanize(data.protocolConfidence)} confidence)
              </span>
            </MetadataItem>
            <MetadataItem label="TCP stream">
              <span className="font-mono">{data.tcpStreamId}</span>
            </MetadataItem>
            <MetadataItem label="Completeness">
              <span className="font-mono text-xs">
                {data.captureCompleteness}
              </span>
            </MetadataItem>
            <MetadataItem label="Source endpoint" className="sm:col-span-2">
              <ScrollableCode value={data.sourceEndpoint} />
            </MetadataItem>
            <MetadataItem
              label="Destination endpoint"
              className="sm:col-span-2"
            >
              <ScrollableCode value={data.destinationEndpoint} />
            </MetadataItem>
            <MetadataItem label="Capture ID" className="sm:col-span-2">
              <ScrollableCode value={data.captureId} />
            </MetadataItem>
            <MetadataItem label="Capture record" className="sm:col-span-2">
              <ScrollableCode
                value={data.captureName ?? "Validated capture name unavailable"}
              />
            </MetadataItem>
            <MetadataItem label="Frame range">
              <span className="font-mono">
                {data.firstFrame}–{data.lastFrame}
              </span>
            </MetadataItem>
            <MetadataItem label="Packets / bytes">
              <span className="font-mono">
                {data.packetCount.toLocaleString("en")} /{" "}
                {data.byteCount.toLocaleString("en")}
              </span>
            </MetadataItem>
            <MetadataItem label="Started at">
              <ScrollableCode value={data.startedAt} />
            </MetadataItem>
            <MetadataItem label="Ended at">
              <ScrollableCode value={data.endedAt} />
            </MetadataItem>
          </dl>
        </CardContent>
      </Card>
    </header>
  );
}

function PostureCard({ item }: { item: PostureItem }) {
  return (
    <article className="min-w-0 rounded-lg border border-neutral-200 bg-white p-4 shadow-sm">
      <div className="flex items-start justify-between gap-3">
        <p className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
          {item.label}
        </p>
        <StateBadge state={item.state} />
      </div>
      <p className="mt-3 text-sm font-semibold text-neutral-950">
        {item.value}
      </p>
      <p className="mt-1 text-xs leading-5 text-neutral-600">{item.detail}</p>
    </article>
  );
}

function PostureSummary({ data }: { data: SessionXRayData }) {
  return (
    <section aria-labelledby="session-posture-heading">
      <div className="mb-3">
        <p className="text-[10px] font-bold uppercase tracking-[0.08em] text-neutral-500">
          Validated session result
        </p>
        <h2
          id="session-posture-heading"
          className="mt-1 text-lg font-semibold text-neutral-950"
        >
          Session posture summary
        </h2>
      </div>
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
        {data.posture.map((item) => (
          <PostureCard key={item.label} item={item} />
        ))}
      </div>
    </section>
  );
}

function EventEvidence({ event }: { event: XRayEvent }) {
  return (
    <div className="mt-3 border-t border-neutral-100 pt-3">
      <EvidenceActions
        evidence={event.evidence}
        getLabel={(evidence) =>
          `Frame ${evidence.frameNumbers.join(", ")} · occurrence ${evidence.occurrenceIndex}`
        }
      />
    </div>
  );
}

function Timeline({ events }: { events: XRayEvent[] }) {
  return (
    <section aria-labelledby="forensic-timeline-heading">
      <Card className="rounded-lg border-neutral-200 shadow-sm ring-0">
        <CardHeader className="border-b border-neutral-200">
          <CardTitle>
            <h2 id="forensic-timeline-heading">
              Session Transition Twin / ordered timeline
            </h2>
          </CardTitle>
          <CardDescription>
              Privacy-safe descriptions are keyed to validated event types; raw
              payload contents are never shown. Events remain ordered by their
              contract sequence index, then their original occurrence in the
              validated event array.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {events.length === 0 ? (
            <p className="rounded-lg border border-dashed border-neutral-300 bg-neutral-50 px-5 py-8 text-center text-sm text-neutral-600">
              Empty event collection. No timeline entry was synthesized.
            </p>
          ) : (
            <ol className="relative ml-2 space-y-4 border-l border-neutral-300 pl-5 sm:ml-3 sm:pl-7">
              {events.map((event) => (
                <li key={event.eventId} className="relative min-w-0">
                  <span className="absolute -left-[1.78rem] top-5 size-3 rounded-full border-2 border-white bg-neutral-700 ring-1 ring-neutral-300 sm:-left-[2.2rem]" />
                  <article className="min-w-0 rounded-lg border border-neutral-200 bg-white p-4">
                    <div className="flex min-w-0 flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                      <div className="min-w-0">
                        <p className="font-mono text-[10px] uppercase tracking-wide text-neutral-500">
                          Sequence {event.sequenceIndex} · {event.eventType}
                        </p>
                        <h3 className="mt-1 text-sm font-semibold text-neutral-950">
                          {event.title}
                        </h3>
                        <p className="mt-1 text-sm leading-6 text-neutral-600">
                          {event.description}
                        </p>
                      </div>
                      <StateBadge state={event.state} />
                    </div>
                    <dl className="mt-4 grid min-w-0 gap-3 border-t border-neutral-100 pt-4 sm:grid-cols-2 xl:grid-cols-4">
                      <MetadataItem label="Timestamp">
                        <ScrollableCode value={event.timestamp} />
                      </MetadataItem>
                      <MetadataItem label="Direction">
                        <span className="font-mono text-xs">
                          {event.direction}
                        </span>
                      </MetadataItem>
                      <MetadataItem label="Protocol">
                        <span className="font-mono text-xs uppercase">
                          {event.protocol}
                        </span>
                      </MetadataItem>
                      <MetadataItem label="Aggregated frame references">
                        {event.frameNumbers.length > 0 ? (
                          <span className="font-mono text-xs">
                            {event.frameNumbers.join(", ")}
                          </span>
                        ) : (
                          <span className="text-neutral-500">Not supplied</span>
                        )}
                      </MetadataItem>
                      <MetadataItem label="Event / observability">
                        <span className="font-mono text-xs">
                          {event.eventStatus} / {event.observability}
                        </span>
                      </MetadataItem>
                      <MetadataItem label="State transition" className="sm:col-span-2">
                        <span className="font-mono text-xs">
                          {event.stateBefore} → {event.stateAfter}
                        </span>
                      </MetadataItem>
                      <MetadataItem label="Event ID" className="sm:col-span-2">
                        <ScrollableCode value={event.eventId} />
                      </MetadataItem>
                    </dl>
                    {event.limitations.length > 0 ? (
                      <ul className="mt-3 space-y-2 border-t border-neutral-100 pt-3">
                        {event.limitations.map((limitation) => (
                          <li
                            key={`${limitation.code}:${limitation.summary}:${limitation.detail}`}
                            className="text-xs leading-5 text-neutral-600"
                          >
                            <code className="mr-1 font-mono text-[10px] text-neutral-500">
                              {limitation.code}
                            </code>
                            {limitation.summary}
                          </li>
                        ))}
                      </ul>
                    ) : null}
                    <EventEvidence event={event} />
                  </article>
                </li>
              ))}
            </ol>
          )}
        </CardContent>
      </Card>
    </section>
  );
}

function CryptoRow({ entry }: { entry: CryptoEntry }) {
  return (
    <article className="min-w-0 border-b border-neutral-100 py-4 first:pt-0 last:border-b-0 last:pb-0">
      <div className="flex min-w-0 items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
            {entry.label}
          </p>
          <p className="mt-1 max-w-full break-all font-mono text-xs font-semibold text-neutral-950">
            {entry.value}
          </p>
        </div>
        <StateBadge state={entry.state} />
      </div>
      <p className="mt-2 text-xs leading-5 text-neutral-600">{entry.detail}</p>
      <p className="mt-1 text-[11px] text-neutral-500">
        Evidence status: <code>{entry.observability}</code>
      </p>
      <div className="mt-3">
        <p className="mb-2 text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
          {entry.evidenceRelationship === "through_sources"
            ? "Evidence through declared sources"
            : entry.evidenceRelationship === "direct"
              ? "Direct evidence references"
              : "Evidence references"}
        </p>
        <EvidenceActions evidence={entry.evidence} />
      </div>
    </article>
  );
}

function CryptographyAndCertificate({ data }: { data: SessionXRayData }) {
  return (
    <section
      aria-label="Cryptography and certificate evidence"
      className="grid min-w-0 gap-4 xl:grid-cols-2"
    >
      <Card className="rounded-lg border-neutral-200 shadow-sm ring-0">
        <CardHeader className="border-b border-neutral-200">
          <div className="flex items-start gap-3">
            <span className="flex size-9 shrink-0 items-center justify-center rounded-md border border-neutral-200 bg-neutral-50 text-neutral-700">
              <LockKeyhole className="size-4" aria-hidden />
            </span>
            <div>
              <CardTitle>
                <h2>Cryptography</h2>
              </CardTitle>
              <CardDescription className="mt-1">
                Backend-supported observations and derived facts only.
              </CardDescription>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {data.cryptoEntries.map((entry) => (
            <CryptoRow key={entry.id} entry={entry} />
          ))}
        </CardContent>
      </Card>

      <Card className="rounded-lg border-neutral-200 shadow-sm ring-0">
        <CardHeader className="border-b border-neutral-200">
          <div className="flex items-start gap-3">
            <span className="flex size-9 shrink-0 items-center justify-center rounded-md border border-neutral-200 bg-neutral-50 text-neutral-700">
              <FileKey2 className="size-4" aria-hidden />
            </span>
            <div>
              <CardTitle>
                <h2>Certificate and TLS 1.3 observability</h2>
              </CardTitle>
              <CardDescription className="mt-1">
                Missing validation inputs remain not assessed, not invalid.
              </CardDescription>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {data.tls13CertificateUnavailable ? (
            <Alert className="border-amber-200 bg-amber-50/70 text-amber-950">
              <Info className="size-4" aria-hidden />
              <AlertTitle>Certificate evidence not observable</AlertTitle>
              <AlertDescription className="leading-6 text-amber-900/85">
                In TLS 1.3, certificate messages after ServerHello are encrypted
                and cannot be extracted from a passive capture without
                authorized session secrets.
              </AlertDescription>
            </Alert>
          ) : data.certificateEntries.length === 0 ? (
            <Alert className="border-neutral-300 bg-neutral-50">
              <Fingerprint className="size-4" aria-hidden />
              <AlertTitle>Certificate evidence not assessed</AlertTitle>
              <AlertDescription>
                No validated certificate observation is present for this
                session. Absence is not interpreted as missing, invalid,
                expired, or trusted.
              </AlertDescription>
            </Alert>
          ) : null}

          {data.certificateEntries.length > 0 ? (
            <div className={data.tls13CertificateUnavailable ? "mt-4" : ""}>
              {data.certificateEntries.map((entry) => (
                <CryptoRow key={entry.id} entry={entry} />
              ))}
            </div>
          ) : null}

          <div className="mt-4 rounded-lg border border-neutral-200 bg-neutral-50 p-4">
            <div>
              <p className="text-sm font-semibold text-neutral-950">
                Trust, identity, and revocation checks
              </p>
              <p className="mt-1 text-xs leading-5 text-neutral-600">
                Each check appears above only when its own validated observation
                is supplied. Missing trust-store, service-identity, or revocation
                inputs do not become invalid results, and this view does not
                calculate an aggregate certificate status.
              </p>
            </div>
          </div>
        </CardContent>
      </Card>
    </section>
  );
}

function Findings({ data }: { data: SessionXRayData }) {
  return (
    <section aria-labelledby="linked-findings-heading">
      <Card className="rounded-lg border-neutral-200 shadow-sm ring-0">
        <CardHeader className="border-b border-neutral-200">
          <div className="flex items-start gap-3">
            <span className="flex size-9 shrink-0 items-center justify-center rounded-md border border-neutral-200 bg-neutral-50 text-neutral-700">
              <ShieldAlert className="size-4" aria-hidden />
            </span>
            <div>
              <CardTitle>
                <h2 id="linked-findings-heading">Linked policy findings</h2>
              </CardTitle>
              <CardDescription className="mt-1">
                Deterministic Policy Risk remains separate from ML Anomaly.
              </CardDescription>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {data.findings.length === 0 ? (
            <div className="rounded-lg border border-dashed border-neutral-300 bg-neutral-50 px-5 py-8 text-center">
              <ShieldCheck
                className="mx-auto size-7 text-neutral-400"
                aria-hidden
              />
              <h3 className="mt-3 text-sm font-semibold text-neutral-950">
                No linked findings
              </h3>
              <p className="mx-auto mt-2 max-w-xl text-sm leading-6 text-neutral-600">
                No validated deterministic policy finding references this
                session. This is not a derived security rating.
              </p>
            </div>
          ) : (
            <div className="space-y-4">
              {data.findings.map((finding) => (
                <article
                  key={finding.findingId}
                  className="min-w-0 rounded-lg border border-neutral-200 bg-neutral-50 p-4 sm:p-5"
                >
                  <div className="flex min-w-0 flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                    <div className="min-w-0">
                      {data.dataSource === "mock" ? (
                        <p className="text-[10px] font-bold uppercase tracking-[0.06em] text-blue-700">
                          Illustrative prototype finding
                        </p>
                      ) : null}
                      <h3 className="mt-1 break-words text-base font-semibold text-neutral-950">
                        {finding.title}
                      </h3>
                      <ScrollableCode value={finding.findingId} />
                    </div>
                    <Badge
                      variant="outline"
                      className={cn(
                        "rounded-md uppercase",
                        severityPresentation[finding.severity] ??
                          severityPresentation.info,
                      )}
                    >
                      Severity {finding.severity}
                    </Badge>
                  </div>
                  <dl className="mt-4 grid gap-3 border-t border-neutral-200 pt-4 sm:grid-cols-2 xl:grid-cols-3">
                    <MetadataItem label="Rule">
                      <ScrollableCode
                        value={`${finding.ruleId} v${finding.ruleVersion}`}
                      />
                    </MetadataItem>
                    <MetadataItem label="Profile">
                      <ScrollableCode value={finding.profileId} />
                    </MetadataItem>
                    <MetadataItem label="Rule outcome / reason">
                      <ScrollableCode
                        value={`${finding.ruleOutcome} / ${finding.ruleReasonCode}`}
                      />
                    </MetadataItem>
                    <MetadataItem label="Category">
                      <span className="font-mono text-xs">
                        {finding.category}
                      </span>
                    </MetadataItem>
                    <MetadataItem label="Evidence confidence">
                      <span className="font-mono text-xs">
                        {finding.evidenceConfidence}
                      </span>
                    </MetadataItem>
                    <MetadataItem label="Observability">
                      <span className="font-mono text-xs">
                        {finding.observability}
                      </span>
                    </MetadataItem>
                    <MetadataItem label="Policy Risk contribution">
                      <span className="font-mono text-xs">
                        {finding.policyRiskContribution}
                      </span>
                    </MetadataItem>
                  </dl>
                  <div className="mt-4 grid gap-4 lg:grid-cols-3">
                    <div>
                      <p className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
                        Rationale
                      </p>
                      <p className="mt-1 break-words text-sm leading-6 text-neutral-700">
                        {finding.rationale}
                      </p>
                    </div>
                    <div>
                      <p className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
                        Impact
                      </p>
                      <p className="mt-1 break-words text-sm leading-6 text-neutral-700">
                        {finding.impact}
                      </p>
                    </div>
                    <div>
                      <p className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
                        Remediation
                      </p>
                      <p className="mt-1 break-words text-sm leading-6 text-neutral-700">
                        {finding.remediation}
                      </p>
                      <div className="mt-1 text-neutral-500">
                        <ScrollableCode value={finding.recommendationId} />
                      </div>
                    </div>
                  </div>
                  <div className="mt-4 border-t border-neutral-200 pt-4">
                    <p className="mb-2 text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
                      Direct evidence references
                    </p>
                    <EvidenceActions evidence={finding.evidence} />
                  </div>
                </article>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </section>
  );
}

function LimitationList({
  title,
  limitations,
}: {
  title: string;
  limitations: ScopedLimitation[];
}) {
  if (limitations.length === 0) return null;
  return (
    <div>
      <h3 className="text-sm font-semibold text-neutral-950">{title}</h3>
      <ul className="mt-3 space-y-3">
        {limitations.map((limitation) => (
          <li
            key={`${limitation.scope}:${limitation.code}:${limitation.summary}:${limitation.detail}`}
            className="rounded-lg border border-neutral-200 bg-neutral-50 p-4"
          >
            <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
              <p className="break-words text-sm font-medium leading-6 text-neutral-900">
                {limitation.summary}
              </p>
              <Badge
                variant="outline"
                className="rounded-md border-neutral-300 bg-white font-mono text-[10px]"
              >
                {limitation.code}
              </Badge>
            </div>
            {limitation.detail ? (
              <p className="mt-1 break-all font-mono text-[11px] leading-5 text-neutral-500">
                {limitation.detail}
              </p>
            ) : null}
          </li>
        ))}
      </ul>
    </div>
  );
}

function Limitations({ data }: { data: SessionXRayData }) {
  const hasLimitations =
    data.sessionLimitations.length > 0 || data.analysisLimitations.length > 0;
  return (
    <section aria-labelledby="declared-limitations-heading">
      <Card className="rounded-lg border-neutral-200 shadow-sm ring-0">
        <CardHeader className="border-b border-neutral-200">
          <div className="flex items-start gap-3">
            <span className="flex size-9 shrink-0 items-center justify-center rounded-md border border-neutral-200 bg-neutral-50 text-neutral-700">
              <CircleAlert className="size-4" aria-hidden />
            </span>
            <div>
              <CardTitle>
                <h2 id="declared-limitations-heading">
                  Declared limitations
                </h2>
              </CardTitle>
              <CardDescription className="mt-1">
                Session-scoped limitations are separated from analysis-level
                limitations supplied by the current contract.
              </CardDescription>
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-6">
          {hasLimitations ? (
            <>
              <LimitationList
                title="Session-level limitations"
                limitations={data.sessionLimitations}
              />
              <LimitationList
                title="Analysis-level limitations"
                limitations={data.analysisLimitations}
              />
            </>
          ) : (
            <p className="rounded-lg border border-dashed border-neutral-300 bg-neutral-50 px-5 py-8 text-center text-sm text-neutral-600">
              No validated limitation records are attached to this session or
              analysis. No additional limitation was synthesized.
            </p>
          )}
        </CardContent>
      </Card>
    </section>
  );
}

function ModelState({ data }: { data: SessionXRayData }) {
  return (
    <section aria-labelledby="ml-anomaly-heading">
      <Card className="rounded-lg border-neutral-200 shadow-sm ring-0">
        <CardHeader className="border-b border-neutral-200">
          <div className="flex items-start gap-3">
            <span className="flex size-9 shrink-0 items-center justify-center rounded-md border border-neutral-200 bg-neutral-50 text-neutral-700">
              <BrainCircuit className="size-4" aria-hidden />
            </span>
            <div>
              <CardTitle>
                <h2 id="ml-anomaly-heading">ML Anomaly</h2>
              </CardTitle>
              <CardDescription className="mt-1">
                Model output is shown separately from deterministic Policy Risk.
              </CardDescription>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {data.mlEngineStatus === "not_run" ? (
            <Alert className="border-neutral-300 bg-neutral-50">
              <Info className="size-4" aria-hidden />
              <AlertTitle>ML anomaly engine was not run</AlertTitle>
              <AlertDescription>
                No score exists for this session. Absence is not displayed as
                zero and is not combined with Policy Risk.
              </AlertDescription>
            </Alert>
          ) : data.anomalies.length === 0 ? (
            <Alert className="border-amber-200 bg-amber-50">
              <Info className="size-4" aria-hidden />
              <AlertTitle>No validated session anomaly result</AlertTitle>
              <AlertDescription>
                Engine status is {humanize(data.mlEngineStatus)}. No score or
                band was inferred for this session.
              </AlertDescription>
            </Alert>
          ) : (
            <div className="space-y-4">
              {data.anomalies.map((anomaly) => (
                <article
                  key={anomaly.anomalyResultId}
                  className="min-w-0 rounded-lg border border-neutral-200 bg-neutral-50 p-4"
                >
                  <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                    <div className="min-w-0">
                      <p className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
                        Validated model result
                      </p>
                      <ScrollableCode value={anomaly.anomalyResultId} />
                    </div>
                    <Badge variant="outline" className="rounded-md bg-white capitalize">
                      {humanize(anomaly.band)}
                    </Badge>
                  </div>
                  <dl className="mt-4 grid min-w-0 gap-3 border-t border-neutral-200 pt-4 sm:grid-cols-2 xl:grid-cols-4">
                    <MetadataItem label="Model">
                      <span className="break-all font-mono text-xs">
                        {anomaly.modelId} v{anomaly.modelVersion}
                      </span>
                    </MetadataItem>
                    <MetadataItem label="Feature schema">
                      <span className="font-mono text-xs">
                        {anomaly.featureSchemaVersion}
                      </span>
                    </MetadataItem>
                    <MetadataItem label="Raw / normalized score">
                      <span className="font-mono text-xs">
                        {anomaly.rawScore} / {anomaly.normalizedScore}
                      </span>
                    </MetadataItem>
                    <MetadataItem label="Threshold">
                      <span className="font-mono text-xs">{anomaly.threshold}</span>
                    </MetadataItem>
                  </dl>
                  <p className="mt-4 text-xs leading-5 text-neutral-600">
                    {anomaly.interpretationNote}
                  </p>
                  {anomaly.unusualFeatureIndicators.length > 0 ? (
                    <div className="mt-3">
                      <p className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
                        Unusual feature indicators
                      </p>
                      <ul className="mt-2 flex flex-wrap gap-2">
                        {anomaly.unusualFeatureIndicators.map((indicator) => (
                          <li
                            key={indicator}
                            className="max-w-full break-all rounded-md border border-neutral-200 bg-white px-2 py-1 font-mono text-[11px]"
                          >
                            {indicator}
                          </li>
                        ))}
                      </ul>
                    </div>
                  ) : null}
                  <div className="mt-4 border-t border-neutral-200 pt-4">
                    <EvidenceActions evidence={anomaly.evidence} />
                  </div>
                </article>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </section>
  );
}

function EvidenceIndex({ data }: { data: SessionXRayData }) {
  return (
    <section aria-labelledby="evidence-inspector-heading">
      <Card className="rounded-lg border-neutral-200 shadow-sm ring-0">
        <CardHeader className="border-b border-neutral-200">
          <CardTitle>
            <h2 id="evidence-inspector-heading">Evidence inspector</h2>
          </CardTitle>
          <CardDescription>
            Exact safe references for this session. Packet payloads are never
            included.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {data.evidence.length === 0 ? (
            <Alert className="border-amber-200 bg-amber-50">
          <Info className="size-4" aria-hidden />
          <AlertTitle>Empty evidence collection for this session</AlertTitle>
          <AlertDescription>
            Evidence actions are unavailable. No evidence record was invented
            from event or finding content.
          </AlertDescription>
            </Alert>
          ) : (
            <ul className="grid min-w-0 gap-3 md:grid-cols-2 xl:grid-cols-3">
              {data.evidence.map((evidence) => (
                <li
                  key={evidence.evidenceId}
                  className="min-w-0 rounded-lg border border-neutral-200 bg-neutral-50 p-4"
                >
                  <p className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
                    Frame {evidence.frameNumbers.join(", ")} · occurrence {evidence.occurrenceIndex}
                  </p>
                  <p className="mt-2 break-all font-mono text-xs font-semibold text-neutral-950">
                    {evidence.evidenceId}
                  </p>
                  <p className="mt-2 break-all font-mono text-[11px] text-neutral-600">
                    {evidence.sourceField}
                  </p>
                  {evidence.safeExcerpt ? (
                    <p className="mt-2 break-words text-xs leading-5 text-neutral-700">
                      {evidence.safeExcerpt}
                    </p>
                  ) : null}
                  <div className="mt-3">
                    <EvidenceInspector evidence={evidence} label="Inspect reference" />
                  </div>
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>
    </section>
  );
}

export function SessionXRay({ data }: { data: SessionXRayData }) {
  return (
    <div className="mx-auto min-w-0 w-full max-w-[96rem] space-y-6">
      <IdentityHeader data={data} />
      <PostureSummary data={data} />
      <Timeline events={data.events} />
      <CryptographyAndCertificate data={data} />
      <Findings data={data} />
      <ModelState data={data} />
      <EvidenceIndex data={data} />
      <Limitations data={data} />
      <footer className="flex items-center gap-2 border-t border-neutral-200 pt-5 text-xs leading-5 text-neutral-500">
        <CheckCircle2 className="size-4 shrink-0" aria-hidden />
        Session values come from the validated AnalysisDataSource result; this
        view does not re-analyze packets or derive cryptographic conclusions.
      </footer>
    </div>
  );
}
