"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { Brain, ExternalLink, FileSearch } from "lucide-react";

import { EvidenceInspector } from "@/components/analysis/session-xray/evidence-inspector";
import { Badge } from "@/components/ui/badge";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { cn } from "@/lib/utils";

import type { AnomalyDetail } from "./findings-view-model";

function IdCode({ value }: { value: string }) {
  return (
    <code className="block max-w-full break-all font-mono text-xs" title={value}>
      {value}
    </code>
  );
}

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

export function MLAnomalyInspector({
  anomaly,
  analysisId,
  open,
  onOpenChange,
  returnFocusRef,
}: {
  anomaly: AnomalyDetail | null;
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

  if (!anomaly) return null;

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
      >
        <SheetHeader>
          <SheetTitle className="flex items-start gap-2">
            <Brain className="mt-0.5 size-4 shrink-0 text-blue-700" aria-hidden />
            ML anomaly inspector
          </SheetTitle>
          <SheetDescription>
            Validated model output and explicitly declared relationships only.
            Anomaly output is not a policy finding or proof of malicious activity.
          </SheetDescription>
        </SheetHeader>

        <div className="flex-1 overflow-y-auto px-4 pb-4">
          <dl className="rounded-lg border border-neutral-200 px-4">
            <MetadataRow label="Anomaly result ID">
              <IdCode value={anomaly.anomalyResultId} />
            </MetadataRow>
            <MetadataRow label="Band">
              <Badge variant="outline" className="rounded-md border-blue-300 bg-blue-50 text-blue-800">
                {anomaly.band}
              </Badge>
            </MetadataRow>
            <MetadataRow label="Normalized score">
              <span className="font-mono text-xs">{anomaly.normalizedScore}</span>
            </MetadataRow>
            <MetadataRow label="Raw score">
              <span className="font-mono text-xs">{anomaly.rawScore}</span>
            </MetadataRow>
            <MetadataRow label="Threshold">
              <span className="font-mono text-xs">{anomaly.threshold}</span>
            </MetadataRow>
            <MetadataRow label="Model">
              <IdCode value={`${anomaly.modelId} v${anomaly.modelVersion}`} />
            </MetadataRow>
            <MetadataRow label="Feature schema">
              <IdCode value={anomaly.featureSchemaVersion} />
            </MetadataRow>
          </dl>

          <section className="mt-4">
            <h3 className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
              Interpretation
            </h3>
            <p className="mt-1 text-sm leading-6 text-neutral-700">
              {anomaly.interpretationNote}
            </p>
          </section>

          <section className="mt-4">
            <h3 className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
              Unusual feature indicators
            </h3>
            {anomaly.unusualFeatureIndicators.length > 0 ? (
              <ul className="mt-2 space-y-2">
                {anomaly.unusualFeatureIndicators.map((indicator) => (
                  <li
                    key={indicator}
                    className="break-words rounded-md border border-neutral-200 bg-neutral-50 px-3 py-2 font-mono text-xs text-neutral-700"
                  >
                    {indicator}
                  </li>
                ))}
              </ul>
            ) : (
              <p className="mt-1 text-sm text-neutral-500">
                No unusual feature indicators were declared.
              </p>
            )}
          </section>

          <section className="mt-4">
            <h3 className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
              Explicit linked session
            </h3>
            <div className="mt-2 rounded-lg border border-neutral-200 bg-neutral-50 p-3">
              <IdCode value={anomaly.session.sessionId} />
              <p className="mt-1 font-mono text-[11px] text-neutral-600">
                {anomaly.session.sourceEndpoint} &rarr; {anomaly.session.destinationEndpoint}
              </p>
              <p className="mt-1 text-xs text-neutral-500">
                {anomaly.session.protocol.toUpperCase()}
              </p>
            </div>
          </section>

          <section className="mt-4">
            <h3 className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
              Explicit linked facts and observations
            </h3>
            <div className="mt-2 space-y-2">
              {anomaly.linkedFacts.map((fact) => (
                <div key={fact.factId} className="rounded-lg border border-neutral-200 bg-neutral-50 p-3">
                  <p className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
                    Derived fact
                  </p>
                  <IdCode value={fact.factId} />
                  <p className="mt-1 text-xs text-neutral-600">
                    {fact.factType} &middot; {fact.observability} &middot; confidence {fact.confidenceLevel}
                  </p>
                </div>
              ))}
              {anomaly.linkedObservations.map((observation) => (
                <div key={observation.observationId} className="rounded-lg border border-neutral-200 bg-neutral-50 p-3">
                  <p className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
                    Crypto observation
                  </p>
                  <IdCode value={observation.observationId} />
                  <p className="mt-1 text-xs text-neutral-600">
                    {observation.kind} &middot; {observation.observability}
                  </p>
                </div>
              ))}
              {anomaly.linkedFacts.length === 0 &&
              anomaly.linkedObservations.length === 0 ? (
                <p className="text-sm text-neutral-500">
                  No fact or observation relationship was declared.
                </p>
              ) : null}
            </div>
          </section>

          <section className="mt-4">
            <h3 className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
              Direct evidence relationship
            </h3>
            <div className="mt-2 space-y-2">
              {anomaly.directEvidence.map((evidence) => (
                <div key={evidence.evidenceId} className="rounded-lg border border-emerald-200 bg-emerald-50/50 p-3">
                  <IdCode value={evidence.evidenceId} />
                  <div className="mt-2">
                    <EvidenceInspector evidence={evidence} label="Inspect safe evidence" />
                  </div>
                </div>
              ))}
              {anomaly.directEvidence.length === 0 ? (
                <p className="text-sm text-neutral-500">
                  No direct ML-to-evidence relationship was declared.
                </p>
              ) : null}
            </div>
          </section>

          <section className="mt-4">
            <h3 className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
              Evidence through declared sources
            </h3>
            <p className="mt-1 text-xs text-neutral-500">
              These evidence items are reached only through declared linked facts
              or observations; they are not direct ML evidence edges.
            </p>
            <div className="mt-2 space-y-2">
              {anomaly.evidenceThroughSources.map((evidence) => (
                <div key={evidence.evidenceId} className="rounded-lg border border-slate-200 bg-slate-50 p-3">
                  <IdCode value={evidence.evidenceId} />
                  <div className="mt-2">
                    <EvidenceInspector evidence={evidence} label="Inspect safe evidence" />
                  </div>
                </div>
              ))}
              {anomaly.evidenceThroughSources.length === 0 ? (
                <p className="text-sm text-neutral-500">
                  No declared source path reaches additional evidence.
                </p>
              ) : null}
            </div>
          </section>

          {anomaly.limitations.length > 0 ? (
            <section className="mt-4">
              <h3 className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
                Applicable limitations
              </h3>
              <div className="mt-2 space-y-2">
                {anomaly.limitations.map((limitation) => (
                  <div key={`${limitation.code}:${limitation.summary}`} className="rounded-lg border border-neutral-200 bg-neutral-50 p-3">
                    <p className="text-sm font-medium text-neutral-900">{limitation.summary}</p>
                    <p className="mt-1 font-mono text-[11px] text-neutral-500">
                      {limitation.code}{limitation.detail ? ` · ${limitation.detail}` : ""}
                    </p>
                  </div>
                ))}
              </div>
            </section>
          ) : null}

          <div className="mt-6 flex flex-wrap gap-2">
            <Link
              href={`/analysis/${analysisId}/sessions/${anomaly.session.sessionId}`}
              className="inline-flex min-h-9 items-center gap-2 rounded-md border border-neutral-300 bg-white px-4 text-sm font-medium text-neutral-800 outline-none hover:bg-neutral-50 focus-visible:ring-2 focus-visible:ring-neutral-950 focus-visible:ring-offset-2"
            >
              <FileSearch className="size-4" aria-hidden />
              Session X-Ray
            </Link>
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
