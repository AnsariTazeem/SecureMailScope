import Link from "next/link";
import { CircleAlert, SearchX } from "lucide-react";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";

export function SessionXRayDataSourceFailure({
  analysisId,
  message,
}: {
  analysisId: string;
  message: string;
}) {
  return (
    <div className="mx-auto flex w-full max-w-3xl flex-1 items-center justify-center py-12 sm:py-20">
      <section className="w-full rounded-lg border border-neutral-200 bg-white p-6 shadow-sm sm:p-8">
        <p className="text-[11px] font-bold uppercase tracking-[0.08em] text-neutral-500">
          Analysis / Sessions / Session X-Ray
        </p>
        <h1 className="mt-2 text-xl font-semibold text-neutral-950">
          Session evidence is unavailable
        </h1>
        <Alert
          variant="destructive"
          className="mt-5 border-red-200 bg-red-50 px-4 py-3"
        >
          <CircleAlert className="size-4" aria-hidden />
          <AlertTitle>Validated result was not displayed</AlertTitle>
          <AlertDescription>{message}</AlertDescription>
        </Alert>
        <code
          className="mt-4 block max-w-full overflow-x-auto whitespace-nowrap font-mono text-xs text-neutral-500"
          title={analysisId}
        >
          {analysisId}
        </code>
        <div className="mt-6 flex flex-col gap-3 sm:flex-row">
          <Link
            href={`/analysis/${analysisId}/sessions`}
            className="inline-flex min-h-9 items-center justify-center rounded-md bg-neutral-950 px-4 text-sm font-medium text-white outline-none hover:bg-neutral-800 focus-visible:ring-2 focus-visible:ring-neutral-950 focus-visible:ring-offset-2"
          >
            Back to Sessions
          </Link>
          <Link
            href={`/analysis/${analysisId}/overview`}
            className="inline-flex min-h-9 items-center justify-center rounded-md border border-neutral-300 bg-white px-4 text-sm font-medium text-neutral-900 outline-none hover:bg-neutral-50 focus-visible:ring-2 focus-visible:ring-neutral-950 focus-visible:ring-offset-2"
          >
            Return to Overview
          </Link>
        </div>
      </section>
    </div>
  );
}

export function SessionRecordNotFound({
  analysisId,
  sessionId,
}: {
  analysisId: string;
  sessionId: string;
}) {
  return (
    <div className="mx-auto flex w-full max-w-3xl flex-1 items-center justify-center py-12 sm:py-20">
      <section className="w-full rounded-lg border border-neutral-200 bg-white p-6 text-center shadow-sm sm:p-8">
        <span className="mx-auto flex size-11 items-center justify-center rounded-full border border-amber-300 bg-amber-50 text-amber-800">
          <SearchX className="size-5" aria-hidden />
        </span>
        <p className="mt-4 text-[11px] font-bold uppercase tracking-[0.08em] text-neutral-500">
          Analysis / Sessions / Session X-Ray
        </p>
        <h1 className="mt-2 text-xl font-semibold text-neutral-950">
          Session not found
        </h1>
        <p className="mx-auto mt-2 max-w-lg text-sm leading-6 text-neutral-600">
          The analysis is valid, but its validated result contains no matching
          session record. No session or evidence was assumed.
        </p>
        <code
          className="mx-auto mt-4 block max-w-full overflow-x-auto whitespace-nowrap font-mono text-xs text-neutral-500"
          title={sessionId}
        >
          {sessionId}
        </code>
        <Link
          href={`/analysis/${analysisId}/sessions`}
          className="mt-6 inline-flex min-h-9 items-center justify-center rounded-md bg-neutral-950 px-4 text-sm font-medium text-white outline-none hover:bg-neutral-800 focus-visible:ring-2 focus-visible:ring-neutral-950 focus-visible:ring-offset-2"
        >
          Back to Sessions
        </Link>
      </section>
    </div>
  );
}
