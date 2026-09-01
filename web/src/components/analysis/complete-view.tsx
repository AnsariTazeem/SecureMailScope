"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { CheckCircle2, CircleAlert, FileCheck2, LoaderCircle } from "lucide-react";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { getAnalysisDataSourceForId } from "@/lib/api/client";
import type { AnalysisResult } from "@/lib/contracts/analysis";
import { useAnalysisWorkflow } from "@/stores/analysis-workflow";

export function CompleteView() {
  const router = useRouter();
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const analysisId = useAnalysisWorkflow((state) => state.analysisId);
  const uploadedFileName = useAnalysisWorkflow((state) => state.uploadedFileName);
  const reset = useAnalysisWorkflow((state) => state.reset);

  useEffect(() => {
    if (!analysisId) return;
    const currentAnalysisId = analysisId;
    let cancelled = false;

    async function loadResult() {
      try {
        const nextResult = await getAnalysisDataSourceForId(
          currentAnalysisId,
        ).getResult(currentAnalysisId);
        if (!cancelled) setResult(nextResult);
      } catch (loadError) {
        if (cancelled) return;
        setError(
          loadError instanceof Error
            ? loadError.message
            : "The analysis result could not be loaded.",
        );
      }
    }

    void loadResult();
    return () => {
      cancelled = true;
    };
  }, [analysisId]);

  if (!analysisId) {
    return (
      <div className="mx-auto flex w-full max-w-2xl flex-1 items-center justify-center py-16">
        <section className="w-full rounded-lg border border-neutral-200 bg-white p-8 text-center shadow-sm">
          <CircleAlert className="mx-auto size-8 text-neutral-400" aria-hidden />
          <h1 className="mt-4 text-xl font-semibold text-neutral-950">No completed workflow found</h1>
          <p className="mx-auto mt-2 max-w-md text-sm leading-6 text-neutral-500">
            This page uses temporary in-memory workflow state and cannot recover
            a browser File after a refresh.
          </p>
          <Link
            href="/analysis/new"
            className="mt-6 inline-flex h-9 items-center justify-center rounded-md bg-neutral-950 px-4 text-sm font-medium text-white outline-none hover:bg-neutral-800 focus-visible:ring-2 focus-visible:ring-neutral-950 focus-visible:ring-offset-2"
          >
            Start an analysis
          </Link>
        </section>
      </div>
    );
  }

  if (error) {
    return (
      <div className="mx-auto w-full max-w-3xl py-10">
        <Alert variant="destructive" className="p-5">
          <CircleAlert aria-hidden />
          <AlertTitle>Result unavailable</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      </div>
    );
  }

  if (!result) {
    return (
      <div className="flex flex-1 items-center justify-center gap-3 py-20 text-sm text-neutral-500">
        <LoaderCircle className="size-4 animate-spin" aria-hidden />
        Validating the completed result boundary…
      </div>
    );
  }

  return (
    <div className="mx-auto flex w-full max-w-3xl flex-1 items-center justify-center py-8 lg:py-16">
      <section className="w-full overflow-hidden rounded-lg border border-neutral-200 bg-white shadow-sm">
        <div className="border-b border-neutral-200 bg-[#ecfdf3] px-6 py-8 text-center">
          <span className="mx-auto flex size-12 items-center justify-center rounded-full bg-[#027a48] text-white">
            <CheckCircle2 className="size-6" aria-hidden />
          </span>
          <h1 className="mt-4 text-2xl font-semibold tracking-tight text-neutral-950">
            Analysis workflow complete
          </h1>
          <p className="mx-auto mt-2 max-w-xl text-sm leading-6 text-neutral-600">
            {result.dataset_label
              ? "The deterministic Prototype Analysis Dataset passed the frontend runtime contract. This is not a claim that the selected capture was analyzed by a production backend."
              : "The production API result passed the frontend runtime contract."}
          </p>
        </div>

        <div className="space-y-5 p-6">
          <dl className="grid gap-4 rounded-lg border border-neutral-200 bg-neutral-50 p-4 sm:grid-cols-2">
            <div>
              <dt className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">Analysis ID</dt>
              <dd className="mt-1 break-all font-mono text-xs text-neutral-950">{analysisId}</dd>
            </div>
            <div>
              <dt className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">Source</dt>
              <dd className="mt-1 text-xs text-neutral-950">
                {result.dataset_label ?? "Production API"}
              </dd>
            </div>
            <div>
              <dt className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">Selected capture</dt>
              <dd className="mt-1 truncate text-xs text-neutral-950">
                {uploadedFileName ?? "Unavailable"}
              </dd>
            </div>
            <div>
              <dt className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">Chain contract</dt>
              <dd className="mt-1 text-xs text-neutral-950">
                v{result.chain.chain_schema_version}
              </dd>
            </div>
          </dl>

          <div className="flex gap-3 rounded-lg border border-neutral-200 p-4">
            <FileCheck2 className="mt-0.5 size-4 shrink-0 text-neutral-600" aria-hidden />
            <p className="text-xs leading-5 text-neutral-600">
              Explore the validated result through the implemented analysis
              workspace.
            </p>
          </div>

          <div className="flex flex-col gap-3 border-t border-neutral-200 pt-5 sm:flex-row sm:justify-end">
            <Button
              type="button"
              variant="outline"
              onClick={() => {
                reset();
                router.push("/analysis/new");
              }}
            >
              Analyze another capture
            </Button>
            <Link
              href={`/analysis/${analysisId}/overview`}
              className="inline-flex h-9 items-center justify-center rounded-md bg-neutral-950 px-4 text-sm font-medium text-white outline-none hover:bg-neutral-800 focus-visible:ring-2 focus-visible:ring-neutral-950 focus-visible:ring-offset-2"
            >
              Open Overview
            </Link>
          </div>
        </div>
      </section>
    </div>
  );
}
