import { AnalysisBreadcrumbs } from "@/components/layout/analysis-breadcrumbs";

import Link from "next/link";
import { CircleAlert } from "lucide-react";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";

export function ProofMapDataSourceFailure({
  analysisId,
  message,
}: {
  analysisId: string;
  message: string;
}) {
  return (
    <div className="mx-auto flex w-full max-w-3xl flex-1 items-center justify-center py-12 sm:py-20">
      <section className="w-full rounded-lg border border-neutral-200 bg-white p-6 shadow-sm sm:p-8">
        <AnalysisBreadcrumbs />
        <h1 className="mt-2 text-xl font-semibold text-neutral-950">
          Proof Map is unavailable
        </h1>
        <Alert variant="destructive" className="mt-5 border-red-200 bg-red-50 px-4 py-3">
          <CircleAlert className="size-4" aria-hidden />
          <AlertTitle>Validated relationships were not displayed</AlertTitle>
          <AlertDescription>{message}</AlertDescription>
        </Alert>
        <code className="mt-4 block max-w-full overflow-x-auto whitespace-nowrap font-mono text-xs text-neutral-500" title={analysisId}>
          {analysisId}
        </code>
        <div className="mt-6 flex flex-col gap-3 sm:flex-row">
          <Link
            href={`/analysis/${analysisId}/overview`}
            className="inline-flex min-h-9 items-center justify-center rounded-md bg-neutral-950 px-4 text-sm font-medium text-white outline-none hover:bg-neutral-800 focus-visible:ring-2 focus-visible:ring-neutral-950 focus-visible:ring-offset-2"
          >
            Return to Overview
          </Link>
          <Link
            href={`/analysis/${analysisId}/sessions`}
            className="inline-flex min-h-9 items-center justify-center rounded-md border border-neutral-300 bg-white px-4 text-sm font-medium text-neutral-900 outline-none hover:bg-neutral-50 focus-visible:ring-2 focus-visible:ring-neutral-950 focus-visible:ring-offset-2"
          >
            Open Sessions Explorer
          </Link>
        </div>
      </section>
    </div>
  );
}
