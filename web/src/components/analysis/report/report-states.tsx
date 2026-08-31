import Link from "next/link";
import { AlertTriangle } from "lucide-react";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";

export function ReportDataSourceFailure({
  analysisId,
  message,
}: {
  analysisId: string;
  message: string;
}) {
  return (
    <div className="mx-auto flex w-full max-w-5xl flex-col gap-6">
      <div>
        <p className="text-[11px] font-bold uppercase tracking-[0.08em] text-neutral-500">
          Analysis / Report
        </p>
        <h1 className="mt-2 text-2xl font-semibold tracking-tight text-neutral-950">
          SecureMailScope Assessment Report
        </h1>
      </div>
      <Alert className="border-red-200 bg-red-50/70 px-4 py-3 text-red-950">
        <AlertTriangle className="size-4" aria-hidden />
        <AlertTitle>Report data is unavailable</AlertTitle>
        <AlertDescription className="text-red-900/80">
          {message}
        </AlertDescription>
      </Alert>
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
          href="/analysis/new"
          className="inline-flex min-h-9 items-center justify-center rounded-md bg-neutral-950 px-4 text-sm font-medium text-white outline-none hover:bg-neutral-800 focus-visible:ring-2 focus-visible:ring-neutral-950 focus-visible:ring-offset-2"
        >
          Start a new analysis
        </Link>
        <Link
          href={`/analysis/${analysisId}/overview`}
          className="inline-flex min-h-9 items-center justify-center rounded-md border border-neutral-300 bg-white px-4 text-sm font-medium text-neutral-900 outline-none hover:bg-neutral-50 focus-visible:ring-2 focus-visible:ring-neutral-950 focus-visible:ring-offset-2"
        >
          Return to overview
        </Link>
      </div>
    </div>
  );
}
