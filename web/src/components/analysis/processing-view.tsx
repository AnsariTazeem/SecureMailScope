"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Check, CircleAlert, LoaderCircle, RotateCcw } from "lucide-react";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import {
  Progress,
  ProgressLabel,
  ProgressValue,
} from "@/components/ui/progress";
import { getAnalysisDataSourceForId } from "@/lib/api/client";
import { cn } from "@/lib/utils";
import { PROTOTYPE_ANALYSIS_ID } from "@/mocks/load-prototype-dataset";
import { useAnalysisWorkflow } from "@/stores/analysis-workflow";

const DEMO_PROCESSING_STAGES = [
  "Preparing investigation workspace",
  "Reconstructing mail sessions",
  "Linking supporting evidence",
  "Evaluating security policy",
  "Scoring behavioural anomalies",
  "Preparing findings and recommendations",
] as const;

const DEMO_STAGE_DELAY_MS = 500;
const DEMO_COMPLETE_DELAY_MS = 400;

export function ProcessingView() {
  const router = useRouter();
  const [loadingError, setLoadingError] = useState<string | null>(null);
  const [completedDemoStages, setCompletedDemoStages] = useState(0);
  const analysisId = useAnalysisWorkflow((state) => state.analysisId);
  const uploadedFileName = useAnalysisWorkflow((state) => state.uploadedFileName);
  const usingPrototypeDataset = useAnalysisWorkflow(
    (state) => state.usingPrototypeDataset,
  );
  const setPhase = useAnalysisWorkflow((state) => state.setPhase);
  const setError = useAnalysisWorkflow((state) => state.setError);
  const reset = useAnalysisWorkflow((state) => state.reset);
  const isPrototypeWorkflow =
    usingPrototypeDataset && analysisId === PROTOTYPE_ANALYSIS_ID;
  const demoProgress = Math.round(
    (completedDemoStages / DEMO_PROCESSING_STAGES.length) * 100,
  );

  useEffect(() => {
    if (!analysisId || isPrototypeWorkflow) return;
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
  }, [analysisId, isPrototypeWorkflow, router, setError, setPhase]);

  useEffect(() => {
    if (!isPrototypeWorkflow) return;

    let completedStages = 0;
    let completeTimer: number | undefined;
    const stageTimer = window.setInterval(() => {
      completedStages += 1;
      setCompletedDemoStages(completedStages);

      if (completedStages === DEMO_PROCESSING_STAGES.length) {
        window.clearInterval(stageTimer);
        completeTimer = window.setTimeout(() => {
          setPhase("complete");
          router.replace("/analysis/complete");
        }, DEMO_COMPLETE_DELAY_MS);
      }
    }, DEMO_STAGE_DELAY_MS);

    return () => {
      window.clearInterval(stageTimer);
      if (completeTimer !== undefined) window.clearTimeout(completeTimer);
    };
  }, [isPrototypeWorkflow, router, setPhase]);

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

  if (isPrototypeWorkflow) {
    return (
      <div className="mx-auto flex w-full max-w-4xl flex-col gap-6 py-4 lg:py-10">
        <div className="text-center">
          <h1 className="mt-2 text-2xl font-semibold tracking-tight text-neutral-950">
            Preparing investigation
          </h1>
          <p className="mx-auto mt-2 max-w-2xl text-sm leading-6 text-neutral-500">
            Follow the investigation from mail sessions to evidence and review actions.
          </p>
        </div>

        <section className="overflow-hidden rounded-lg border border-neutral-200 bg-white shadow-sm">
          <div className="flex flex-col gap-2 border-b border-neutral-200 bg-neutral-50 px-5 py-4 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <p className="text-xs font-bold uppercase tracking-[0.06em] text-neutral-700">
                Analysis ID
              </p>
              <p className="mt-1 font-mono text-xs text-neutral-950">
                {analysisId}
              </p>
            </div>
            <p className="text-xs font-semibold text-neutral-600">
              Local walkthrough
            </p>
          </div>

          <div className="space-y-6 p-5 sm:p-6">
            <Progress
              value={demoProgress}
              aria-label="Simulated investigation progress"
            >
              <ProgressLabel>Investigation progress</ProgressLabel>
              <ProgressValue />
            </Progress>

            <ol className="space-y-3" aria-label="Simulated demo stages">
              {DEMO_PROCESSING_STAGES.map((stage, index) => {
                const complete = index < completedDemoStages;
                const active =
                  index === completedDemoStages &&
                  completedDemoStages < DEMO_PROCESSING_STAGES.length;

                return (
                  <li
                    key={stage}
                    className="flex items-center gap-3 rounded-md border border-neutral-200 px-3 py-3"
                  >
                    <span
                      className={cn(
                        "flex size-6 shrink-0 items-center justify-center rounded-full border text-[11px] font-bold",
                        complete &&
                          "border-[#027a48] bg-[#027a48] text-white",
                        active &&
                          "border-neutral-950 bg-neutral-950 text-white",
                        !complete &&
                          !active &&
                          "border-neutral-300 text-neutral-500",
                      )}
                    >
                      {complete ? (
                        <Check className="size-3.5" aria-hidden />
                      ) : active ? (
                        <LoaderCircle
                          className="size-3.5 animate-spin"
                          aria-hidden
                        />
                      ) : (
                        index + 1
                      )}
                    </span>
                    <span className="min-w-0 flex-1 text-sm font-medium text-neutral-800">
                      {stage}
                    </span>
                    <span className="text-xs text-neutral-500">
                      {complete ? "Complete" : active ? "Simulating" : "Pending"}
                    </span>
                  </li>
                );
              })}
            </ol>
          </div>
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
          Offline analysis
        </p>
        <h1 className="mt-2 text-2xl font-semibold tracking-tight text-neutral-950">
          Loading completed analysis
        </h1>
        <p className="mx-auto mt-2 max-w-2xl text-sm leading-6 text-neutral-500">
          The synchronous backend request has completed. SecureMailScope is
          validating the authoritative analysis summary and Chain-of-Proof
          before opening the result.
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
              {uploadedFileName ?? "Unavailable"}
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
