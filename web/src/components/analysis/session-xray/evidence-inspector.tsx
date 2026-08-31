"use client";

import { Search } from "lucide-react";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";

import type { XRayEvidence } from "./session-xray-view-model";

function MetadataRow({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div className="grid gap-1 border-b border-neutral-100 py-3 last:border-b-0 sm:grid-cols-[9rem_minmax(0,1fr)] sm:gap-4">
      <dt className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
        {label}
      </dt>
      <dd className="min-w-0 text-sm text-neutral-900">{children}</dd>
    </div>
  );
}

function IdList({ values, empty }: { values: string[]; empty: string }) {
  if (values.length === 0) {
    return <span className="text-neutral-500">{empty}</span>;
  }
  return (
    <span className="flex min-w-0 flex-col gap-1">
      {values.map((value) => (
        <code
          key={value}
          className="block max-w-full break-all font-mono text-xs"
          title={value}
        >
          {value}
        </code>
      ))}
    </span>
  );
}

export function EvidenceInspector({
  evidence,
  label,
}: {
  evidence: XRayEvidence;
  label?: string;
}) {
  return (
    <Dialog>
      <DialogTrigger
        render={
          <Button
            type="button"
            variant="outline"
            size="sm"
            className="max-w-full font-mono text-[11px]"
            aria-label={`Inspect evidence ${evidence.evidenceId}`}
          />
        }
      >
        <Search className="size-3.5" aria-hidden />
        <span className="truncate">{label ?? evidence.evidenceId}</span>
      </DialogTrigger>
      <DialogContent className="max-h-[min(44rem,calc(100svh-2rem))] overflow-y-auto sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>Evidence inspector</DialogTitle>
          <DialogDescription>
            Contract-supported metadata only. Packet payloads, message bodies,
            credentials, decrypted content, and secrets are not displayed.
          </DialogDescription>
        </DialogHeader>

        <dl className="rounded-lg border border-neutral-200 px-4">
          <MetadataRow label="Evidence ID">
            <code
              className="block max-w-full break-all font-mono text-xs"
              title={evidence.evidenceId}
            >
              {evidence.evidenceId}
            </code>
          </MetadataRow>
          <MetadataRow label="Capture ID">
            <code
              className="block max-w-full break-all font-mono text-xs"
              title={evidence.captureId}
            >
              {evidence.captureId}
            </code>
          </MetadataRow>
          <MetadataRow label="Capture SHA-256">
            <code
              className="block max-w-full break-all font-mono text-xs"
              title={evidence.captureSha256}
            >
              {evidence.captureSha256}
            </code>
          </MetadataRow>
          <MetadataRow label="Session ID">
            <code
              className="block max-w-full break-all font-mono text-xs"
              title={evidence.sessionId}
            >
              {evidence.sessionId}
            </code>
          </MetadataRow>
          <MetadataRow label="Packet / frame">
            <span className="font-mono text-xs">
              {evidence.frameNumbers.join(", ")}
            </span>
          </MetadataRow>
          <MetadataRow label="Occurrence">
            <span className="font-mono text-xs">
              {evidence.occurrenceIndex}
            </span>
          </MetadataRow>
          <MetadataRow label="Timestamp">
            <span className="block max-w-full break-words font-mono text-xs">
              {evidence.timestampStart}
              {evidence.timestampEnd !== evidence.timestampStart
                ? ` — ${evidence.timestampEnd}`
                : ""}
            </span>
          </MetadataRow>
          <MetadataRow label="Direction">
            <code className="font-mono text-xs">{evidence.direction}</code>
          </MetadataRow>
          <MetadataRow label="Source type">
            <code className="font-mono text-xs">{evidence.sourceKind}</code>
          </MetadataRow>
          <MetadataRow label="Source field">
            <code className="block max-w-full break-all font-mono text-xs">
              {evidence.sourceField}
            </code>
          </MetadataRow>
          {evidence.safeExcerpt ? (
            <MetadataRow label="Safe excerpt">
              <code className="block max-w-full break-words font-mono text-xs leading-5">
                {evidence.safeExcerpt}
              </code>
            </MetadataRow>
          ) : null}
          <MetadataRow label="Display filter">
            <code className="block max-w-full break-all font-mono text-xs leading-5">
              {evidence.displayFilter}
            </code>
          </MetadataRow>
          <MetadataRow label="Observation state">
            {evidence.observability}
          </MetadataRow>
          <MetadataRow label="Redaction">
            <code className="font-mono text-xs">{evidence.redaction}</code>
          </MetadataRow>
          <MetadataRow label="Extractor version">
            <code className="break-all font-mono text-xs">
              {evidence.extractorVersion}
            </code>
          </MetadataRow>
          <MetadataRow label="Direct event references">
            <IdList values={evidence.eventIds} empty="No direct event link" />
          </MetadataRow>
          <MetadataRow label="Direct observation references">
            <IdList
              values={evidence.observationIds}
              empty="No direct observation link"
            />
          </MetadataRow>
          <MetadataRow label="Evidence through declared sources">
            <div className="space-y-1.5">
              <IdList
                values={evidence.factIdsThroughSources}
                empty="No declared fact-source path reaches this evidence"
              />
              {evidence.factIdsThroughSources.length > 0 ? (
                <p className="text-xs leading-5 text-neutral-500">
                  These fact IDs are structural reverse references through
                  explicit source events, observations, or facts. They are not
                  direct fact-to-evidence fields.
                </p>
              ) : null}
            </div>
          </MetadataRow>
          <MetadataRow label="Direct finding references">
            <IdList
              values={evidence.findingIds}
              empty="No direct finding link"
            />
          </MetadataRow>
        </dl>

        <DialogFooter showCloseButton />
      </DialogContent>
    </Dialog>
  );
}
