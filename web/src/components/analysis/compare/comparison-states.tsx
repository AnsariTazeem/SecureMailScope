import { AnalysisBreadcrumbs } from "@/components/layout/analysis-breadcrumbs";

import Link from "next/link";
import { AlertTriangle, GitCompareArrows } from "lucide-react";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";

function StateFrame({
  analysisId,
  title,
  description,
  children,
}: {
  analysisId: string;
  title: string;
  description: string;
  children?: React.ReactNode;
}) {
  return (
    <div className="mx-auto flex w-full max-w-4xl flex-col gap-6">
      <div>
        <AnalysisBreadcrumbs />
        <h1 className="mt-2 text-2xl font-semibold tracking-tight text-neutral-950">
          Session Comparison
        </h1>
      </div>
      <Alert className="border-amber-200 bg-amber-50/70 px-4 py-3 text-amber-950">
        <AlertTriangle className="size-4" aria-hidden />
        <AlertTitle>{title}</AlertTitle>
        <AlertDescription className="text-amber-900/80">
          {description}
        </AlertDescription>
      </Alert>
      {children}
      <dl className="overflow-hidden rounded-lg border border-neutral-200 bg-white px-5 py-4 shadow-sm">
        <div>
          <dt className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
            Analysis ID
          </dt>
          <dd className="mt-1 break-all font-mono text-xs text-neutral-950">
            {analysisId}
          </dd>
        </div>
      </dl>
      <div className="flex flex-wrap gap-3">
        <Link
          href={`/analysis/${analysisId}/sessions`}
          className="inline-flex min-h-9 items-center justify-center rounded-md bg-neutral-950 px-4 text-sm font-medium text-white outline-none hover:bg-neutral-800 focus-visible:ring-2 focus-visible:ring-neutral-950 focus-visible:ring-offset-2"
        >
          View sessions
        </Link>
        <Link
          href={`/analysis/${analysisId}/overview`}
          className="inline-flex min-h-9 items-center justify-center rounded-md border border-neutral-300 bg-white px-4 text-sm font-medium text-neutral-800 outline-none hover:bg-neutral-50 focus-visible:ring-2 focus-visible:ring-neutral-950 focus-visible:ring-offset-2"
        >
          Return to overview
        </Link>
      </div>
    </div>
  );
}

export function ComparisonDataSourceFailure({
  analysisId,
  message,
}: {
  analysisId: string;
  message: string;
}) {
  return (
    <StateFrame
      analysisId={analysisId}
      title="Comparison data is unavailable"
      description={message}
    />
  );
}

export function ComparisonSelectionFailure({
  analysisId,
  message,
}: {
  analysisId: string;
  message: string;
}) {
  return (
    <StateFrame
      analysisId={analysisId}
      title="Session selection is invalid or unavailable"
      description={message}
    />
  );
}

export function InsufficientSessionsState({
  analysisId,
  sessionCount,
}: {
  analysisId: string;
  sessionCount: number;
}) {
  return (
    <StateFrame
      analysisId={analysisId}
      title="Two reconstructed sessions are required"
      description={`The validated result contains ${sessionCount} reconstructed session${sessionCount === 1 ? "" : "s"}. No comparison was synthesized.`}
    >
      <div className="flex items-start gap-3 rounded-lg border border-neutral-200 bg-white p-5 text-sm leading-6 text-neutral-600 shadow-sm">
        <GitCompareArrows className="mt-1 size-4 shrink-0 text-neutral-500" aria-hidden />
        Compare becomes available only when the configured analysis source
        explicitly supplies at least two reconstructed session records.
      </div>
    </StateFrame>
  );
}
