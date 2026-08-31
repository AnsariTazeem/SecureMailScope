"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import {
  ArrowRight,
  ExternalLink,
  FileSearch,
  ShieldAlert,
} from "lucide-react";

import { Badge } from "@/components/ui/badge";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { SESSION_ID } from "@/lib/contracts/ids";
import { cn } from "@/lib/utils";
import { EvidenceInspector } from "@/components/analysis/session-xray/evidence-inspector";
import type { XRayEvidence } from "@/components/analysis/session-xray/session-xray-view-model";

import {
  categoryLabels,
  severityStyles,
  type FindingDetail,
  type FindingFactLink,
} from "./findings-view-model";

function MetadataRow({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div className="grid gap-1 border-b border-neutral-100 py-3 last:border-b-0 sm:grid-cols-[10rem_minmax(0,1fr)] sm:gap-4">
      <dt className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
        {label}
      </dt>
      <dd className="min-w-0 text-sm text-neutral-900">{children}</dd>
    </div>
  );
}

function IdCode({ value }: { value: string }) {
  return (
    <code
      className="block max-w-full break-all font-mono text-xs"
      title={value}
    >
      {value}
    </code>
  );
}

function EvidenceCard({
  evidence,
  relationship,
}: {
  evidence: XRayEvidence;
  relationship: "direct" | "through_source";
}) {
  return (
    <div className="rounded-lg border border-neutral-200 bg-neutral-50 p-3">
      <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0">
          <p className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
            {relationship === "direct"
              ? "Direct evidence relationship"
              : "Evidence through declared sources"}
          </p>
          <IdCode value={evidence.evidenceId} />
        </div>
        <Badge
          variant="outline"
          className={cn(
            "w-fit rounded-md font-mono text-[10px]",
            relationship === "direct"
              ? "border-emerald-300 bg-emerald-50 text-emerald-800"
              : "border-slate-300 bg-slate-50 text-slate-700",
          )}
        >
          {relationship === "direct" ? "Direct" : "Through sources"}
        </Badge>
      </div>
      <dl className="mt-2 grid gap-2 sm:grid-cols-2">
        <div>
          <dt className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
            Session
          </dt>
          <dd className="mt-0.5 font-mono text-[11px] text-neutral-700">
            {evidence.sessionId}
          </dd>
        </div>
        <div>
          <dt className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
            Frames
          </dt>
          <dd className="mt-0.5 font-mono text-[11px] text-neutral-700">
            {evidence.frameNumbers.join(", ")}
          </dd>
        </div>
        <div>
          <dt className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
            Source
          </dt>
          <dd className="mt-0.5 font-mono text-[11px] text-neutral-700">
            {evidence.sourceKind}: {evidence.sourceField}
          </dd>
        </div>
        <div>
          <dt className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
            Direction
          </dt>
          <dd className="mt-0.5 font-mono text-[11px] text-neutral-700">
            {evidence.direction}
          </dd>
        </div>
      </dl>
      <div className="mt-3 border-t border-neutral-200 pt-3">
        <EvidenceInspector evidence={evidence} label="Inspect safe evidence" />
      </div>
    </div>
  );
}

function FactCard({ fact }: { fact: FindingFactLink }) {
  return (
    <div className="rounded-lg border border-neutral-200 bg-neutral-50 p-3">
      <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0">
          <p className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
            Derived fact
          </p>
          <IdCode value={fact.factId} />
        </div>
        <Badge
          variant="outline"
          className="w-fit rounded-md font-mono text-[10px]"
        >
          {fact.factType}
        </Badge>
      </div>
      <dl className="mt-2 grid gap-2 sm:grid-cols-2">
        <div>
          <dt className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
            Observability
          </dt>
          <dd className="mt-0.5 font-mono text-[11px] text-neutral-700">
            {fact.observability}
          </dd>
        </div>
        <div>
          <dt className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
            Confidence
          </dt>
          <dd className="mt-0.5 font-mono text-[11px] text-neutral-700">
            {fact.confidenceLevel}
          </dd>
        </div>
      </dl>
    </div>
  );
}

export function FindingDetailInspector({
  finding,
  analysisId,
  open,
  onOpenChange,
  returnFocusRef,
}: {
  finding: FindingDetail | null;
  analysisId: string;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  returnFocusRef: React.RefObject<HTMLElement | null>;
}) {
  const [desktopSheet, setDesktopSheet] = useState(false);

  useEffect(() => {
    const media = window.matchMedia("(min-width: 768px)");
    const update = () => setDesktopSheet(media.matches);
    update();
    media.addEventListener("change", update);
    return () => media.removeEventListener("change", update);
  }, []);

  const handleOpenChange = useCallback(
    (nextOpen: boolean) => {
      onOpenChange(nextOpen);
      if (!nextOpen && returnFocusRef.current) {
        window.requestAnimationFrame(() => returnFocusRef.current?.focus());
      }
    },
    [onOpenChange, returnFocusRef],
  );

  if (!finding) return null;

  const hasXRayLink = SESSION_ID.test(finding.linkedSessions[0]?.sessionId ?? "");

  return (
    <Sheet open={open} onOpenChange={handleOpenChange}>
      <SheetContent
        side={desktopSheet ? "right" : "bottom"}
        className={cn(
          "w-full",
          desktopSheet
            ? "md:max-w-xl"
            : "max-h-[min(88svh,48rem)] rounded-t-xl",
        )}
        showCloseButton
      >
        <SheetHeader>
          <SheetTitle className="flex items-start gap-2">
            <ShieldAlert className="mt-0.5 size-4 shrink-0 text-orange-600" aria-hidden />
            <span className="break-words">Finding inspector</span>
          </SheetTitle>
          <SheetDescription>
            Validated deterministic policy finding metadata only. No values are
            derived or invented by the browser.
          </SheetDescription>
        </SheetHeader>

        <div className="flex-1 overflow-y-auto px-4 pb-4">
          <dl className="rounded-lg border border-neutral-200 px-4">
            <MetadataRow label="Finding ID">
              <IdCode value={finding.findingId} />
            </MetadataRow>
            <MetadataRow label="Stable key">
              <IdCode value={finding.stableFindingKey} />
            </MetadataRow>
            <MetadataRow label="Title">
              <span className="font-medium">{finding.title}</span>
            </MetadataRow>
            <MetadataRow label="Severity">
              <Badge
                variant="outline"
                className={cn(
                  "rounded-md uppercase",
                  severityStyles[finding.severity] ?? severityStyles.info,
                )}
              >
                {finding.severity}
              </Badge>
            </MetadataRow>
            <MetadataRow label="Policy Risk contribution">
              <span className="font-mono text-xs">
                {finding.policyRiskContribution}
              </span>
            </MetadataRow>
            <MetadataRow label="Category">
              <span className="font-mono text-xs">
                {categoryLabels[finding.category] ?? finding.category}
              </span>
            </MetadataRow>
            <MetadataRow label="Evidence confidence">
              <span className="font-mono text-xs">
                {finding.evidenceConfidence}
              </span>
            </MetadataRow>
            <MetadataRow label="Observability">
              <span className="font-mono text-xs">
                {finding.observability}
              </span>
            </MetadataRow>
          </dl>

          <div className="mt-4">
            <h3 className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
              Rule evaluation
            </h3>
            <dl className="mt-2 rounded-lg border border-neutral-200 px-4">
              <MetadataRow label="Rule ID">
                <IdCode value={finding.ruleId} />
              </MetadataRow>
              <MetadataRow label="Rule version">
                <IdCode value={finding.ruleVersion} />
              </MetadataRow>
              <MetadataRow label="Policy profile">
                <IdCode value={finding.profileId} />
              </MetadataRow>
              <MetadataRow label="Outcome / reason">
                <span className="font-mono text-xs">
                  {finding.ruleOutcome} / {finding.ruleReasonCode}
                </span>
              </MetadataRow>
            </dl>
          </div>

          <div className="mt-4 space-y-4">
            <div>
              <h3 className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
                Rationale
              </h3>
              <p className="mt-1 break-words text-sm leading-6 text-neutral-700">
                {finding.rationale}
              </p>
            </div>
            <div>
              <h3 className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
                Impact
              </h3>
              <p className="mt-1 break-words text-sm leading-6 text-neutral-700">
                {finding.impact}
              </p>
            </div>
          </div>

          {finding.recommendation ? (
            <div className="mt-4">
              <h3 className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
                Contract-declared recommendation
              </h3>
              <div className="mt-2 rounded-lg border border-neutral-200 bg-neutral-50 p-4">
                <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
                  <p className="break-words text-sm font-medium text-neutral-900">
                    {finding.recommendation.title}
                  </p>
                  <Badge
                    variant="outline"
                    className="w-fit rounded-md font-mono text-[10px]"
                  >
                    {finding.recommendation.priority}
                  </Badge>
                </div>
                <p className="mt-2 text-sm leading-6 text-neutral-600">
                  {finding.recommendation.summary}
                </p>
                {finding.recommendation.actionSteps.length > 0 ? (
                  <div className="mt-3">
                    <p className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
                      Action steps
                    </p>
                    <ul className="mt-1 list-inside list-disc space-y-1 text-sm text-neutral-700">
                      {finding.recommendation.actionSteps.map((step) => (
                        <li key={step} className="break-words">
                          {step}
                        </li>
                      ))}
                    </ul>
                  </div>
                ) : null}
                {finding.recommendation.verificationSteps.length > 0 ? (
                  <div className="mt-3">
                    <p className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
                      Verification steps
                    </p>
                    <ul className="mt-1 list-inside list-disc space-y-1 text-sm text-neutral-700">
                      {finding.recommendation.verificationSteps.map((step) => (
                        <li key={step} className="break-words">
                          {step}
                        </li>
                      ))}
                    </ul>
                  </div>
                ) : null}
                <dl className="mt-3 grid gap-2 sm:grid-cols-2">
                  <div>
                    <dt className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
                      Scope
                    </dt>
                    <dd className="mt-0.5 font-mono text-[11px] text-neutral-700">
                      {finding.recommendation.scope}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
                      Automation
                    </dt>
                    <dd className="mt-0.5 font-mono text-[11px] text-neutral-700">
                      {finding.recommendation.automationStatus}
                    </dd>
                  </div>
                </dl>
              </div>
            </div>
          ) : (
            <div className="mt-4">
              <h3 className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
                Recommendation
              </h3>
              <p className="mt-1 text-sm text-neutral-500">
                No recommendation declared for this finding.
              </p>
            </div>
          )}

          {finding.linkedSessions.length > 0 ? (
            <div className="mt-4">
              <h3 className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
                Explicit linked sessions
              </h3>
              <div className="mt-2 space-y-2">
                {finding.linkedSessions.map((session) => (
                  <div
                    key={session.sessionId}
                    className="rounded-lg border border-neutral-200 bg-neutral-50 p-3"
                  >
                    <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
                      <div className="min-w-0">
                        <p className="font-mono text-xs text-neutral-950">
                          {session.sessionId}
                        </p>
                        <p className="mt-0.5 text-[11px] text-neutral-500">
                          {session.captureName ?? "Capture unavailable"} &middot;{" "}
                          {session.protocol.toUpperCase()}
                        </p>
                        <p className="mt-0.5 font-mono text-[11px] text-neutral-600">
                          {session.sourceEndpoint} &rarr;{" "}
                          {session.destinationEndpoint}
                        </p>
                      </div>
                      {hasXRayLink ? (
                        <Link
                          href={`/analysis/${analysisId}/sessions/${session.sessionId}`}
                          className="inline-flex min-h-8 items-center gap-1.5 rounded-md border border-neutral-300 bg-white px-3 text-xs font-semibold text-neutral-900 outline-none hover:bg-neutral-50 focus-visible:ring-2 focus-visible:ring-neutral-950 focus-visible:ring-offset-2"
                          aria-label={`Open Session X-Ray for ${session.sessionId}`}
                        >
                          Open X-Ray
                          <ArrowRight className="size-3.5" aria-hidden />
                        </Link>
                      ) : null}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ) : null}

          {finding.directEvidence.length > 0 ? (
            <div className="mt-4">
              <h3 className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
                Direct evidence references
              </h3>
              <p className="mt-1 text-xs text-neutral-500">
                Evidence items directly linked to this finding by the validated
                contract.
              </p>
              <div className="mt-2 space-y-2">
                {finding.directEvidence.map((ev) => (
                  <EvidenceCard
                    key={ev.evidenceId}
                    evidence={ev}
                    relationship="direct"
                  />
                ))}
              </div>
            </div>
          ) : (
            <div className="mt-4">
              <h3 className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
                Direct evidence references
              </h3>
              <p className="mt-1 text-sm text-neutral-500">
                No direct evidence references declared.
              </p>
            </div>
          )}

          {finding.linkedFacts.length > 0 ? (
            <div className="mt-4">
              <h3 className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
                Linked derived facts
              </h3>
              <div className="mt-2 space-y-2">
                {finding.linkedFacts.map((fact) => (
                  <FactCard key={fact.factId} fact={fact} />
                ))}
              </div>
            </div>
          ) : null}

          {finding.evidenceThroughSources.length > 0 ? (
            <div className="mt-4">
              <h3 className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
                Evidence through declared sources
              </h3>
              <p className="mt-1 text-xs text-neutral-500">
                Evidence items reached through explicit fact source relationships.
                These are not direct finding-to-evidence links.
              </p>
              <div className="mt-2 space-y-2">
                {finding.evidenceThroughSources.map((ev) => (
                  <EvidenceCard
                    key={ev.evidenceId}
                    evidence={ev}
                    relationship="through_source"
                  />
                ))}
              </div>
            </div>
          ) : null}

          {finding.limitations.length > 0 ? (
            <div className="mt-4">
              <h3 className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
                Applicable limitations
              </h3>
              <div className="mt-2 space-y-2">
                {finding.limitations.map((lim) => (
                  <div
                    key={`${lim.code}:${lim.summary}`}
                    className="rounded-lg border border-neutral-200 bg-neutral-50 p-3"
                  >
                    <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
                      <p className="break-words text-sm font-medium text-neutral-900">
                        {lim.summary}
                      </p>
                      <Badge
                        variant="outline"
                        className="w-fit rounded-md border-neutral-300 bg-white font-mono text-[10px]"
                      >
                        {lim.code}
                      </Badge>
                    </div>
                    {lim.detail ? (
                      <p className="mt-1 break-all font-mono text-[11px] leading-5 text-neutral-500">
                        {lim.detail}
                      </p>
                    ) : null}
                  </div>
                ))}
              </div>
            </div>
          ) : null}

          <div className="mt-6 flex flex-wrap gap-2">
            {hasXRayLink ? (
              <Link
                href={`/analysis/${analysisId}/sessions/${finding.linkedSessions[0]?.sessionId}`}
                className="inline-flex min-h-9 items-center gap-2 rounded-md border border-neutral-300 bg-white px-4 text-sm font-medium text-neutral-800 outline-none hover:bg-neutral-50 focus-visible:ring-2 focus-visible:ring-neutral-950 focus-visible:ring-offset-2"
              >
                <FileSearch className="size-4" aria-hidden />
                Session X-Ray
              </Link>
            ) : null}
            <Link
              href={`/analysis/${analysisId}/proof-map`}
              className="inline-flex min-h-9 items-center gap-2 rounded-md border border-neutral-300 bg-white px-4 text-sm font-medium text-neutral-800 outline-none hover:bg-neutral-50 focus-visible:ring-2 focus-visible:ring-neutral-950 focus-visible:ring-offset-2"
            >
              <ExternalLink className="size-4" aria-hidden />
              Proof Map
            </Link>
          </div>
        </div>
      </SheetContent>
    </Sheet>
  );
}
