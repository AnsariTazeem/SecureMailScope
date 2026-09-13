import Link from "next/link";
import {
  ArrowLeft,
  BrainCircuit,
  CircleAlert,
  Database,
  Info,
  ShieldAlert,
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
import { EvidenceRecords } from "./evidence-records";
import { SessionTabs } from "./session-tabs";
import { ProofMapGraph } from "../proof-map/proof-map-graph";
import type { ProofMapData } from "../proof-map/proof-map-view-model";
import { cn } from "@/lib/utils";

import { humanize } from "../sessions/session-formatters";
import { EvidenceInspector } from "./evidence-inspector";
import type {
  CryptoEntry,
  EvidenceState,
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
  const needsInterpretationWarning =
    data.analysisStatus !== "complete" ||
    data.captureCompleteness !== "complete" ||
    data.captureWarnings.length > 0;

  return (
    <header className="space-y-4">
      <div className="flex min-w-0 flex-col gap-4 md:flex-row md:items-end md:justify-between">
        <div className="min-w-0">
          <p className="text-[11px] font-bold uppercase tracking-[0.08em] text-neutral-500">
            Analysis / Sessions
          </p>
          <h1 className="mt-1 text-2xl font-semibold tracking-tight text-neutral-950 sm:text-3xl">
            Session investigation
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

      <div className="flex flex-wrap items-center gap-x-5 gap-y-2 rounded-lg border border-border bg-card p-4 text-sm">
        <span className="font-semibold">
          {data.protocol.toUpperCase()} · Stream {data.tcpStreamId}
        </span>
        <span className="break-all font-mono text-xs">
          {data.sourceEndpoint} → {data.destinationEndpoint}
        </span>
        <span className="text-muted-foreground">
          Analysis {humanize(data.analysisStatus)} · Capture{" "}
          {humanize(data.captureCompleteness)}
        </span>
        <Badge
          variant="outline"
          className={cn(
            "rounded-md",
            data.dataSource === "mock"
              ? "border-blue-200 bg-blue-50 text-blue-800"
              : "border-neutral-300 bg-neutral-50 text-neutral-700",
          )}
        >
          {data.dataSource === "mock"
            ? data.datasetLabel ?? "Prototype Analysis Dataset"
            : "Production API result"}
        </Badge>
      </div>
      {data.dataSource === "mock" ? (
        <Alert className="border-blue-200 bg-blue-50/70 px-4 py-3 text-blue-950">
          <Database className="size-4" aria-hidden />
          <AlertTitle>Prototype Analysis Dataset</AlertTitle>
          <AlertDescription className="text-blue-900/80">
            This is a labelled synthetic fixture, not a production analyzer
            run.
          </AlertDescription>
        </Alert>
      ) : null}
      {needsInterpretationWarning ? (
        <Alert className="border-amber-200 bg-amber-50/70 px-4 py-3 text-amber-950">
          <CircleAlert className="size-4" aria-hidden />
          <AlertTitle>Interpret this session with its source limits</AlertTitle>
          <AlertDescription className="text-amber-900/85">
            <p>
              Analysis status: {humanize(data.analysisStatus)}. Capture
              completeness: {humanize(data.captureCompleteness)}.
            </p>
            {data.captureWarnings.length > 0 ? (
              <ul className="mt-2 list-disc space-y-1 pl-5">
                {data.captureWarnings.map((warning, index) => (
                  <li key={`${index}:${warning}`}>{warning}</li>
                ))}
              </ul>
            ) : null}
          </AlertDescription>
        </Alert>
      ) : null}
      <details className="rounded-lg border border-border bg-card">
        <summary className="cursor-pointer px-4 py-3 text-sm font-medium focus-visible:outline-2">
          Session details · timing, frames and identifiers
        </summary>
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
              <MetadataItem label="Analysis status">
                <span className="font-mono text-xs">{data.analysisStatus}</span>
              </MetadataItem>
              <MetadataItem label="Policy engine status">
                <span className="font-mono text-xs">
                  {data.ruleEngineStatus}
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
                  value={
                    data.captureName ?? "Validated capture name unavailable"
                  }
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
      </details>
    </header>
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

function InlineLimitations({
  label,
  limitations,
}: {
  label: string;
  limitations: XRayEvent["limitations"];
}) {
  if (limitations.length === 0) return null;
  return (
    <details className="mt-3 border-t border-amber-200 pt-3">
      <summary className="cursor-pointer text-xs font-semibold text-amber-900 focus-visible:outline-2">
        {label} · {limitations.length}
      </summary>
      <ul className="mt-2 space-y-2">
        {limitations.map((limitation) => (
          <li
            key={`${limitation.code}:${limitation.summary}:${limitation.detail}`}
            className="text-xs leading-5 text-neutral-700"
          >
            <span className="font-medium">{limitation.summary}</span>
            <code className="mt-1 block break-all font-mono text-[11px] text-neutral-500">
              {limitation.code}
              {limitation.detail ? `: ${limitation.detail}` : ""}
            </code>
          </li>
        ))}
      </ul>
    </details>
  );
}

function Timeline({ data }: { data: SessionXRayData }) {
  const events = data.events;
  const upgradeCommand = data.protocol === "pop3" ? "STLS" : "STARTTLS";
  return (
    <section aria-labelledby="forensic-timeline-heading">
      <Card className="rounded-lg border-neutral-200 shadow-sm ring-0">
        <CardHeader className="border-b border-neutral-200">
          <CardTitle>
            <h2 id="forensic-timeline-heading">Session timeline</h2>
          </CardTitle>
          <CardDescription>
            Observed and inferred source records, in supplied sequence order.
            Missing records do not prove failure or that an event never occurred.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="mb-5 rounded-lg border border-dashed border-neutral-300 bg-neutral-50 p-4">
            <h3 className="text-sm font-semibold text-neutral-950">Reference milestones · not captured events</h3>
            <p className="mt-1 text-xs leading-5 text-neutral-600">
              A successful in-session upgrade can follow this sequence. It is a
              reading guide, not a checklist or an assessment of this capture.
              Implicit TLS starts with TLS negotiation instead.
            </p>
            {data.protocol === "unknown" ? (
              <p className="mt-3 text-sm text-neutral-700">Protocol-specific upgrade milestones unavailable: the source protocol is unknown.</p>
            ) : (
              <ol className="mt-3 grid gap-2 text-xs text-neutral-700 sm:grid-cols-2 xl:grid-cols-4">
                {[
                  `1. ${upgradeCommand} offered`,
                  `2. Client requests ${upgradeCommand}`,
                  "3. Server accepts the upgrade",
                  "4. TLS negotiation → establishment",
                ].map((milestone) => <li key={milestone} className="rounded-md border border-dashed border-neutral-300 p-3">{milestone}</li>)}
              </ol>
            )}
            <p className="mt-3 text-xs leading-5 text-neutral-600">Acceptance alone does not establish TLS. Certificate validation is a separate assessment.</p>
          </div>
          <VisibleLimitations label="Capture and session limitations" limitations={data.captureLimitations} />
          <h3 className="mb-3 text-sm font-semibold text-neutral-950">
            Observed and inferred events · {events.length}
          </h3>
          <p className="mb-4 text-xs leading-5 text-neutral-600">
            Ordered by sequence index, then original source-array occurrence for ties.
          </p>
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
                          Sequence {event.sequenceIndex}
                        </p>
                        <h4 className="mt-1 text-sm font-semibold text-neutral-950">
                          {event.title}
                        </h4>
                        <p className="mt-1 text-sm leading-6 text-neutral-600">
                          {event.description}
                        </p>
                      </div>
                      <StateBadge state={event.state} />
                    </div>
                    <p className="mt-3 break-all font-mono text-[11px] text-neutral-600">
                      <time dateTime={event.timestamp}>{event.timestamp}</time>
                      {" · "}{humanize(event.direction)}
                    </p>
                    <VisibleLimitations label="Event uncertainty" limitations={event.limitations} />
                    <EventEvidence event={event} />
                    <details className="mt-3 border-t border-neutral-100 pt-3">
                      <summary className="cursor-pointer text-xs font-semibold text-neutral-700 focus-visible:outline-2">Technical event details</summary>
                      <dl className="mt-4 grid min-w-0 gap-3 sm:grid-cols-2 xl:grid-cols-4">
                        <MetadataItem label="Event type"><ScrollableCode value={event.eventType} /></MetadataItem>
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
                        <MetadataItem
                          label="State transition"
                          className="sm:col-span-2"
                        >
                          <span className="font-mono text-xs">
                            {event.stateBefore} → {event.stateAfter}
                          </span>
                        </MetadataItem>
                        <MetadataItem label="Event ID" className="sm:col-span-2">
                          <ScrollableCode value={event.eventId} />
                        </MetadataItem>
                      </dl>
                    </details>
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

function VisibleLimitations({
  label,
  limitations,
}: {
  label: string;
  limitations: XRayEvent["limitations"];
}) {
  if (limitations.length === 0) return null;
  return (
    <div className="my-3 rounded-md border border-amber-200 bg-amber-50/70 p-3 text-amber-950">
      <p className="text-xs font-semibold">{label}</p>
      <ul className="mt-1 space-y-2 text-xs leading-5">
        {limitations.map((limitation) => (
          <li key={`${limitation.code}:${limitation.summary}:${limitation.detail}`}>
            <p className="break-words">{limitation.summary}</p>
            <details className="mt-1">
              <summary className="cursor-pointer text-xs focus-visible:outline-2">Exact limitation</summary>
              <ScrollableCode value={`${limitation.code}: ${limitation.detail}`} />
            </details>
          </li>
        ))}
      </ul>
    </div>
  );
}

function CryptoRow({ entry }: { entry: CryptoEntry }) {
  return (
    <article className="min-w-0 border-b border-neutral-100 py-4 first:pt-0 last:border-b-0 last:pb-0">
      <div className="flex min-w-0 flex-wrap items-start justify-between gap-3">
        <div className="min-w-0 flex-1 basis-48">
          <h3 className="text-xs font-semibold text-neutral-600">{entry.label}</h3>
          <p className="mt-1 max-w-full break-all font-mono text-sm font-semibold text-neutral-950">{entry.value}</p>
        </div>
        <StateBadge state={entry.state} />
      </div>
      {entry.technicalDetails === null ? <p className="mt-2 text-xs leading-5 text-neutral-600">{entry.detail}</p> : null}
      <VisibleLimitations label="Result limitations" limitations={entry.limitations} />
      {entry.technicalDetails !== null ? (
        <details className="mt-3 border-t border-neutral-100 pt-3">
          <summary className="cursor-pointer text-xs font-semibold text-neutral-700 focus-visible:outline-2">Technical source details</summary>
          <p className="mt-2 text-xs leading-5 text-neutral-600">{entry.detail}</p>
          <p className="mt-1 text-xs text-neutral-500">Badge describes evidence provenance or visibility, not whether the result passed validation.</p>
          <pre className="mt-3 max-w-full whitespace-pre-wrap break-all rounded-md bg-neutral-50 p-3 font-mono text-xs text-neutral-800">{entry.technicalDetails}</pre>
        </details>
      ) : null}
      {entry.evidenceRelationship !== "none" ? (
        <div className="mt-3">
          <p className="mb-2 text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
            {entry.evidenceRelationship === "through_sources" ? "Evidence through declared sources" : "Direct evidence references"}
          </p>
          <EvidenceActions evidence={entry.evidence} />
        </div>
      ) : null}
    </article>
  );
}

function CryptoSection({
  title,
  description,
  entries,
  children,
}: {
  title: string;
  description: string;
  entries: CryptoEntry[];
  children?: React.ReactNode;
}) {
  return (
    <section aria-label={title} className="min-w-0">
      <Card className="min-w-0 rounded-lg border-neutral-200 shadow-sm ring-0">
        <CardHeader className="border-b border-neutral-200">
          <CardTitle><h2>{title}</h2></CardTitle>
          <CardDescription>{description}</CardDescription>
        </CardHeader>
        <CardContent className="min-w-0">
          {children}
          {entries.map((entry) => <CryptoRow key={entry.id} entry={entry} />)}
        </CardContent>
      </Card>
    </section>
  );
}

function CryptographyAndCertificate({ data }: { data: SessionXRayData }) {
  const negotiated = data.cryptoEntries.filter((entry) => ["tls_negotiated_version", "selected_cipher_suite"].includes(entry.kind));
  const otherParameters = data.cryptoEntries.filter((entry) => !["tls_upgrade_completed", "tls_negotiated_version", "selected_cipher_suite"].includes(entry.kind));
  const certificateChecks = new Set([
    "certificate_structure_parsed", "certificate_signature_chain_checked",
    "certificate_trusted_path_validated", "certificate_service_identity_validated",
    "certificate_revocation_checked",
  ]);
  return (
    <div className="min-w-0 space-y-6">
      <CryptoSection title="TLS negotiation and outcome" description="Supplied transition records and completion assessment. TLS establishment does not establish certificate validity."
        entries={data.cryptoEntries.filter((entry) => entry.kind === "tls_upgrade_completed")}>
        {data.negotiationEvents.length === 0 ? (
          <p className="mb-4 text-sm text-neutral-600">No TLS transition records supplied. An absent record is not a failure verdict.</p>
        ) : (
          <ul className="mb-4 divide-y divide-neutral-100">
            {data.negotiationEvents.map((event) => (
              <li key={event.eventId} className="min-w-0 py-3 first:pt-0">
                <div className="flex flex-wrap items-start justify-between gap-2">
                  <p className="text-sm font-medium text-neutral-950">{event.title}</p>
                  <StateBadge state={event.state} />
                </div>
                <p className="mt-1 text-xs text-neutral-600">Sequence {event.sequenceIndex} · {humanize(event.stateBefore)} → {humanize(event.stateAfter)}</p>
                <VisibleLimitations label="Transition uncertainty" limitations={event.limitations} />
                <EventEvidence event={event} />
              </li>
            ))}
          </ul>
        )}
      </CryptoSection>
      <div className="grid min-w-0 gap-4 xl:grid-cols-2">
        <CryptoSection title="Negotiated parameters" description="Only explicitly supplied negotiated version and selected cipher results appear here." entries={negotiated}>
          {!negotiated.some((entry) => entry.kind === "tls_negotiated_version") ? <p className="mb-3 text-sm text-neutral-600">Negotiated TLS version: not supplied.</p> : null}
          {!negotiated.some((entry) => entry.kind === "selected_cipher_suite") ? <p className="mb-3 text-sm text-neutral-600">Selected cipher suite: not supplied.</p> : null}
        </CryptoSection>
        <CryptoSection title="Other TLS observations and assessment" description="Supported versions and legacy record versions are separate from negotiated results. Key-share or cipher presence alone is not a Forward Secrecy assessment." entries={otherParameters} />
      </div>
      <CryptoSection title="Certificate observations" description="Certificate presence and visibility are separate from trust, identity, time and revocation assessment. Unavailable information does not mean no certificate."
        entries={data.certificateEntries.filter((entry) => !certificateChecks.has(entry.kind))}>
        {data.certificateEntries.length === 0 ? <p className="mb-4 text-sm text-neutral-600">No certificate observation or visibility assessment supplied for this session. The reason is unavailable.</p> : null}
      </CryptoSection>
      <CryptoSection title="Certificate assessment" description="Each supplied check retains its own result. Observed describes the evidence; it does not mean trusted or valid."
        entries={data.certificateEntries.filter((entry) => certificateChecks.has(entry.kind))}>
        {!data.certificateEntries.some((entry) => certificateChecks.has(entry.kind)) ? <p className="mb-4 text-sm text-neutral-600">No certificate check results supplied. Trust, identity, validity and revocation remain unassessed in this view.</p> : null}
      </CryptoSection>
      <CryptoSection title="Assessment limitations" description="Result-specific limitations appear beside the affected observation or transition. Capture and broader analysis constraints remain relevant." entries={[]}>
        <VisibleLimitations label="Capture and session limitations" limitations={data.captureLimitations} />
        <VisibleLimitations label="Analysis-level limitations" limitations={data.analysisLimitations} />
        {data.captureLimitations.length === 0 && data.analysisLimitations.length === 0 ? <p className="text-sm text-neutral-600">No additional session or analysis limitation records supplied.</p> : null}
      </CryptoSection>
    </div>
  );
}

function FindingLimitations({
  limitations,
}: {
  limitations: SessionXRayData["findings"][number]["limitations"];
}) {
  if (limitations.length === 0) return null;
  return (
    <div className="mt-3 rounded-md border border-amber-200 bg-amber-50/70 p-3 text-amber-950">
      <p className="text-xs font-semibold">Finding-specific uncertainty</p>
      <ul className="mt-1 space-y-1 text-xs leading-5 text-amber-900/85">
        {limitations.map((limitation) => (
          <li
            key={`${limitation.code}:${limitation.summary}:${limitation.detail}`}
          >
            {limitation.summary}
          </li>
        ))}
      </ul>
    </div>
  );
}

function FindingsSummary({ data }: { data: SessionXRayData }) {
  const policyAssessmentComplete = data.ruleEngineStatus === "complete";
  const resultComplete =
    data.analysisStatus === "complete" &&
    data.captureCompleteness === "complete";

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
                <h2 id="linked-findings-heading">Finding summary</h2>
              </CardTitle>
              <CardDescription className="mt-1">
                Deterministic Policy Risk findings scoped to this session. ML
                Anomaly remains separate.
              </CardDescription>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {data.findings.length === 0 ? (
            <div className="rounded-lg border border-dashed border-neutral-300 bg-neutral-50 px-5 py-8 text-center">
              <Info
                className="mx-auto size-7 text-neutral-400"
                aria-hidden
              />
              <h3 className="mt-3 text-sm font-semibold text-neutral-950">
                {policyAssessmentComplete
                  ? "No reported findings for this session"
                  : "Finding assessment is incomplete"}
              </h3>
              <p className="mx-auto mt-2 max-w-xl text-sm leading-6 text-neutral-600">
                {policyAssessmentComplete && resultComplete
                  ? "The completed policy result reports no finding linked to this session. This does not establish that the session is secure."
                  : policyAssessmentComplete
                    ? "Policy evaluation completed, but the analysis or capture is partial. No linked finding is not a security conclusion."
                    : `Policy engine status is ${humanize(data.ruleEngineStatus)}. No finding conclusion is available for this session.`}
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
                  <p className="mt-4 break-words text-sm leading-6 text-neutral-700">
                    {finding.rationale}
                  </p>
                  <FindingLimitations limitations={finding.limitations} />
                  <div className="mt-4 flex flex-wrap items-center gap-3">
                    <Link
                      className="text-sm font-medium underline underline-offset-4"
                      href={`/analysis/${data.analysisId}/recommendations?session=${data.sessionId}#${finding.recommendationId}`}
                    >
                      View recommended action →
                    </Link>
                    <span className="text-xs text-neutral-500">
                      {finding.evidence.length} evidence reference
                      {finding.evidence.length === 1 ? "" : "s"}
                    </span>
                  </div>
                  <details className="mt-4 border-t border-neutral-200 pt-3">
                    <summary className="cursor-pointer text-xs font-semibold text-neutral-700 focus-visible:outline-2">
                      Technical rule and evidence details
                    </summary>
                    <dl className="mt-4 grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
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
                      <MetadataItem label="Finding ID" className="sm:col-span-2">
                        <ScrollableCode value={finding.findingId} />
                      </MetadataItem>
                      <MetadataItem
                        label="Recommendation ID"
                        className="sm:col-span-2"
                      >
                        <ScrollableCode value={finding.recommendationId} />
                      </MetadataItem>
                    </dl>
                    <div className="mt-4 grid gap-4 md:grid-cols-2">
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
                          Supplied recommendation summary
                        </p>
                        <p className="mt-1 break-words text-sm leading-6 text-neutral-700">
                          {finding.remediation}
                        </p>
                      </div>
                    </div>
                    {finding.limitations.length > 0 ? (
                      <div className="mt-4">
                        <p className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
                          Exact limitation details
                        </p>
                        <ul className="mt-2 space-y-2">
                          {finding.limitations.map((limitation) => (
                            <li key={`${limitation.code}:${limitation.detail}`}>
                              <ScrollableCode
                                value={`${limitation.code}: ${limitation.detail || limitation.summary}`}
                              />
                            </li>
                          ))}
                        </ul>
                      </div>
                    ) : null}
                    <div className="mt-4 border-t border-neutral-200 pt-4">
                      <p className="mb-2 text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
                        Direct evidence references
                      </p>
                      <EvidenceActions evidence={finding.evidence} />
                    </div>
                  </details>
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
                <h2 id="declared-limitations-heading">Declared limitations</h2>
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
                    <Badge
                      variant="outline"
                      className="rounded-md bg-white capitalize"
                    >
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
                      <span className="font-mono text-xs">
                        {anomaly.threshold}
                      </span>
                    </MetadataItem>
                  </dl>
                  <p className="mt-4 text-xs leading-5 text-neutral-600">
                    {anomaly.interpretationNote}
                  </p>
                  <InlineLimitations
                    label="Model-result limitations"
                    limitations={anomaly.limitations}
                  />
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

export function SessionXRay({
  data,
  proofData,
}: {
  data: SessionXRayData;
  proofData: ProofMapData;
}) {
  return (
    <div className="mx-auto min-w-0 w-full max-w-[96rem] space-y-6">
      <IdentityHeader data={data} />
      <SessionTabs
        timeline={<Timeline data={data} />}
        crypto={<CryptographyAndCertificate data={data} />}
        findings={
          <>
            <FindingsSummary data={data} />
            <section aria-labelledby="session-proof-map-heading">
              <div className="mb-3">
                <h2
                  id="session-proof-map-heading"
                  className="text-lg font-semibold text-neutral-950"
                >
                  Session proof map
                </h2>
                <p className="mt-1 text-sm text-neutral-600">
                  Evidence relationships scoped to this session.
                </p>
              </div>
              <ProofMapGraph data={proofData} lockedSessionId={data.sessionId} />
            </section>
            <section
              aria-labelledby="session-evidence-records-heading"
              className="rounded-lg border border-border bg-card"
            >
              <div className="border-b border-border px-4 py-3">
                <h2
                  id="session-evidence-records-heading"
                  className="text-sm font-semibold"
                >
                  Evidence records
                </h2>
                <p className="mt-1 text-xs text-muted-foreground">
                  Search {data.evidence.length} exact references for this
                  session. Open a record for full technical detail.
                </p>
              </div>
              <EvidenceRecords evidence={data.evidence} />
            </section>
            <Link
              href={`/analysis/${data.analysisId}/recommendations?session=${data.sessionId}`}
              className="inline-flex rounded-md border border-border bg-card px-4 py-2 text-sm font-medium underline-offset-4 hover:underline focus-visible:outline-2"
            >
              View recommendations for this session →
            </Link>
          </>
        }
      />
      <details className="rounded-lg border border-border bg-card">
        <summary className="cursor-pointer px-4 py-3 text-sm font-medium focus-visible:outline-2">
          ML status and declared limitations
        </summary>
        <ModelState data={data} />
        <Limitations data={data} />
      </details>
    </div>
  );
}
