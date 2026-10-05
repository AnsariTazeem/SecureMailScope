import { AnalysisBreadcrumbs } from "@/components/layout/analysis-breadcrumbs";

import Link from "next/link";
import { AlertTriangle, Database, ShieldX } from "lucide-react";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";

export function FindingsDataSourceFailure({
  analysisId,
  message,
}: {
  analysisId: string;
  message: string;
}) {
  return (
    <div className="mx-auto flex w-full max-w-5xl flex-col gap-6">
      <div>
        <AnalysisBreadcrumbs />
        <h1 className="mt-2 text-2xl font-semibold tracking-tight text-neutral-950">
          Findings
        </h1>
      </div>
      <Alert className="border-red-200 bg-red-50/70 px-4 py-3 text-red-950">
        <AlertTriangle className="size-4" aria-hidden />
        <AlertTitle>Data source failure</AlertTitle>
        <AlertDescription className="text-red-900/80">{message}</AlertDescription>
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
      <Link
        href="/analysis/new"
        className="inline-flex h-9 w-fit items-center gap-2 rounded-md border border-neutral-300 bg-white px-4 text-sm font-medium text-neutral-800 outline-none hover:bg-neutral-50 focus-visible:ring-2 focus-visible:ring-neutral-950 focus-visible:ring-offset-2"
      >
        Start a new analysis
      </Link>
    </div>
  );
}

export function PrototypeDatasetBanner({
  label,
}: {
  label: string | null;
}) {
  return (
    <Alert className="border-blue-200 bg-blue-50/70 px-4 py-3 text-blue-950">
      <Database className="size-4" aria-hidden />
      <AlertTitle>Prototype Analysis Dataset</AlertTitle>
      <AlertDescription className="text-blue-900/80">
        {label ?? "Prototype Analysis Dataset"} is a labelled, validated synthetic
        fixture. It does not represent production API integration or live capture
        analysis.
      </AlertDescription>
    </Alert>
  );
}

export function InvalidAnalysisState() {
  return (
    <div className="mx-auto flex w-full max-w-5xl flex-col items-center gap-4 py-16 text-center">
      <ShieldX className="size-10 text-neutral-400" aria-hidden />
      <h2 className="text-lg font-semibold text-neutral-950">
        Invalid analysis identifier
      </h2>
      <p className="max-w-xl text-sm leading-6 text-neutral-600">
        The analysis identifier does not match the expected format. No findings
        were loaded.
      </p>
      <Link
        href="/analysis/new"
        className="mt-2 inline-flex h-9 items-center gap-2 rounded-md border border-neutral-300 bg-white px-4 text-sm font-medium text-neutral-800 outline-none hover:bg-neutral-50 focus-visible:ring-2 focus-visible:ring-neutral-950 focus-visible:ring-offset-2"
      >
        Start a new analysis
      </Link>
    </div>
  );
}
