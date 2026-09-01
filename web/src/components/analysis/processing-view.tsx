"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { CircleAlert, LoaderCircle, RotateCcw } from "lucide-react";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { getAnalysisDataSourceForId } from "@/lib/api/client";
import { useAnalysisWorkflow } from "@/stores/analysis-workflow";

export function ProcessingView() {
  const router = useRouter();
  const [loadingError, setLoadingError] = useState<string | null>(null);
  const analysisId = useAnalysisWorkflow((state) => state.analysisId);
  const uploadedFileName = useAnalysisWorkflow((state) => state.uploadedFileName);
  const usingPrototypeDataset = useAnalysisWorkflow(
    (state) => state.usingPrototypeDataset,
  );
  const setPhase = useAnalysisWorkflow((state) => state.setPhase);
  const setError = useAnalysisWorkflow((state) => state.setError);
  const reset = useAnalysisWorkflow((state) => state.reset);

  useEffect(() => {
    if (!analysisId) return;
    const currentAnalysisId = analysisId;
    let cancelled = false;

    async function validateCompletedResult() {
      try {
        await getAnalysisDataSourceForId(currentAnalysisId).getResult(
          currentAnalysisId,
        );
        if (cancelled) return;
        setPhase("complete");
        router.replace("/analysis/complete");
      } catch (error) {
        if (cancelled) return;
        const message =
          error instanceof Error
            ? error.message
            : "The completed analysis result could not be loaded.";
        setError(message);
        setLoadingError(message);
      }
    }

    void validateCompletedResult();
    return () => {
      cancelled = true;
    };
  }, [analysisId, router, setError, setPhase]);

  if (!analysisId) {
    return (
      <div className="mx-auto flex w-full max-w-2xl flex-1 items-center justify-center py-16">
        <section className="w-full rounded-lg border border-neutral-200 bg-white p-8 text-center shadow-sm">
          <CircleAlert className="mx-auto size-8 text-neutral-400" aria-hidden />
          <h1 className="mt-4 text-xl font-semibold text-neutral-950">
            No analysis is available
          </h1>
          <p className="mx-auto mt-2 max-w-md text-sm leading-6 text-neutral-500">
            File objects and capture contents are intentionally not persisted.
            Start a new upload or explore the labelled demo dataset.
          </p>
          <Link
            href="/analysis/new"
            className="mt-6 inline-flex h-9 items-center justify-center rounded-md bg-neutral-950 px-4 text-sm font-medium text-white outline-none hover:bg-neutral-800 focus-visible:ring-2 focus-visible:ring-neutral-950 focus-visible:ring-offset-2"
          >
            Return to Start Analysis
          </Link>
        </section>
      </div>
    );
  }

  if (loadingError) {
    return (
      <div className="mx-auto w-full max-w-3xl py-10">
        <Alert variant="destructive" className="p-5">
          <CircleAlert aria-hidden />
          <AlertTitle>Analysis result unavailable</AlertTitle>
          <AlertDescription>{loadingError}</AlertDescription>
        </Alert>
        <div className="mt-5 flex flex-wrap gap-3">
          <Button
            type="button"
            onClick={() => {
              reset();
              router.replace("/analysis/new");
            }}
          >
            <RotateCcw className="size-4" aria-hidden />
            Start again
          </Button>
        </div>
      </div>
    );
  }

  return (
    <div className="mx-auto flex w-full max-w-4xl flex-col gap-6 py-4 lg:py-10">
      <div className="text-center">
        <p className="text-[11px] font-bold uppercase tracking-[0.08em] text-neutral-500">
          {usingPrototypeDataset ? "Demo data" : "Offline analysis"}
        </p>
        <h1 className="mt-2 text-2xl font-semibold tracking-tight text-neutral-950">
          Loading completed analysis
        </h1>
        <p className="mx-auto mt-2 max-w-2xl text-sm leading-6 text-neutral-500">
          {usingPrototypeDataset
            ? "Loading the labelled Prototype Analysis Dataset. No capture is being analyzed."
            : "The synchronous backend request has completed. SecureMailScope is validating the authoritative analysis summary and Chain-of-Proof before opening the result."}
        </p>
      </div>

      <section className="overflow-hidden rounded-lg border border-neutral-200 bg-white shadow-sm">
        <div className="flex flex-col gap-2 border-b border-neutral-200 bg-neutral-50 px-5 py-4 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <p className="text-xs font-bold uppercase tracking-[0.06em] text-neutral-700">
              Analysis ID
            </p>
            <p className="mt-1 font-mono text-xs text-neutral-950">{analysisId}</p>
          </div>
          <div className="sm:text-right">
            <p className="text-xs font-bold uppercase tracking-[0.06em] text-neutral-700">
              Capture
            </p>
            <p className="mt-1 max-w-sm truncate text-xs text-neutral-600">
              {uploadedFileName ?? "Prototype Analysis Dataset"}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3 p-6 text-sm text-neutral-600">
          <LoaderCircle className="size-5 animate-spin" aria-hidden />
          Validating analysis summary and Chain-of-Proof…
        </div>
      </section>
    </div>
  );
}
