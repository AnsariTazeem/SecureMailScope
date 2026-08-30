"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import {
  Check,
  Circle,
  CircleAlert,
  LoaderCircle,
  RotateCcw,
} from "lucide-react";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import {
  Progress,
  ProgressLabel,
} from "@/components/ui/progress";
import { getAnalysisDataSource } from "@/lib/api/client";
import type { AnalysisStatus } from "@/lib/contracts/analysis";
import type { StageDiagnostic } from "@/lib/contracts/chain";
import { publicConfig } from "@/lib/config/env";
import { useAnalysisWorkflow } from "@/stores/analysis-workflow";

const stageLabels: Record<StageDiagnostic["stage"], string> = {
  intake: "Validate capture intake",
  capture_provenance: "Establish capture provenance",
  stream_reconstruction: "Reconstruct transport streams",
  event_reconstruction: "Order protocol events",
  tls_extraction: "Map observable TLS evidence",
  fact_derivation: "Build evidence-linked facts",
  policy_evaluation: "Evaluate policy rules",
  anomaly_scoring: "Evaluate ML anomaly signals",
  report_generation: "Generate report view",
  artifact_manifest: "Seal artifact manifest",
};

function StageIcon({ status }: { status: StageDiagnostic["status"] }) {
  if (status === "complete") {
    return (
      <span className="flex size-6 items-center justify-center rounded-full bg-[#027a48] text-white">
        <Check className="size-3.5" aria-hidden />
      </span>
    );
  }
  if (status === "partial") {
    return (
      <span className="flex size-6 items-center justify-center rounded-full bg-neutral-950 text-white">
        <LoaderCircle className="size-3.5 animate-spin" aria-hidden />
      </span>
    );
  }
  if (status === "failed") {
    return (
      <span className="flex size-6 items-center justify-center rounded-full bg-[#b42318] text-white">
        <CircleAlert className="size-3.5" aria-hidden />
      </span>
    );
  }
  return (
    <span className="flex size-6 items-center justify-center rounded-full border border-neutral-300 text-neutral-400">
      <Circle className="size-2.5" aria-hidden />
    </span>
  );
}

export function ProcessingView() {
  const router = useRouter();
  const [status, setStatus] = useState<AnalysisStatus | null>(null);
  const [pollingError, setPollingError] = useState<string | null>(null);
  const analysisId = useAnalysisWorkflow((state) => state.analysisId);
  const uploadedFileName = useAnalysisWorkflow((state) => state.uploadedFileName);
  const setPhase = useAnalysisWorkflow((state) => state.setPhase);
  const setError = useAnalysisWorkflow((state) => state.setError);
  const reset = useAnalysisWorkflow((state) => state.reset);

  useEffect(() => {
    if (!analysisId) return;
    const currentAnalysisId = analysisId;
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;

    async function poll() {
      try {
        const nextStatus = await getAnalysisDataSource().getStatus(currentAnalysisId);
        if (cancelled) return;
        setStatus(nextStatus);
        setPollingError(null);

        if (nextStatus.phase === "complete") {
          setPhase("complete");
          router.replace("/analysis/complete");
          return;
        }
        if (nextStatus.phase === "failed") {
          const message = nextStatus.error?.message ?? "Analysis failed.";
          setError(message);
          setPollingError(message);
          return;
        }
        timer = setTimeout(poll, 250);
      } catch (error) {
        if (cancelled) return;
        const message =
          error instanceof Error
            ? error.message
            : "Analysis status could not be loaded.";
        setError(message);
        setPollingError(message);
      }
    }

    void poll();
    return () => {
      cancelled = true;
      if (timer) clearTimeout(timer);
    };
  }, [analysisId, router, setError, setPhase]);

  if (!analysisId) {
    return (
      <div className="mx-auto flex w-full max-w-2xl flex-1 items-center justify-center py-16">
        <section className="w-full rounded-lg border border-neutral-200 bg-white p-8 text-center shadow-sm">
          <CircleAlert className="mx-auto size-8 text-neutral-400" aria-hidden />
          <h1 className="mt-4 text-xl font-semibold text-neutral-950">No analysis is in progress</h1>
          <p className="mx-auto mt-2 max-w-md text-sm leading-6 text-neutral-500">
            Temporary workflow state is intentionally not persisted. Select a
            capture or the prototype dataset to begin again.
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

  if (pollingError) {
    return (
      <div className="mx-auto w-full max-w-3xl py-10">
        <Alert variant="destructive" className="p-5">
          <CircleAlert aria-hidden />
          <AlertTitle>Analysis stopped</AlertTitle>
          <AlertDescription>{pollingError}</AlertDescription>
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
          {publicConfig.dataMode === "mock" ? "Prototype workflow" : "Offline analysis"}
        </p>
        <h1 className="mt-2 text-2xl font-semibold tracking-tight text-neutral-950">
          Preparing analysis results
        </h1>
        <p className="mx-auto mt-2 max-w-2xl text-sm leading-6 text-neutral-500">
          {publicConfig.dataMode === "mock"
            ? "These deterministic stages demonstrate the F1 journey and load the labelled prototype dataset. The selected file is not being analyzed by a production backend."
            : "The authorized capture is being processed by the configured production API."}
        </p>
      </div>

      <section className="overflow-hidden rounded-lg border border-neutral-200 bg-white shadow-sm">
        <div className="flex flex-col gap-2 border-b border-neutral-200 bg-neutral-50 px-5 py-4 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <p className="text-xs font-bold uppercase tracking-[0.06em] text-neutral-700">Analysis ID</p>
            <p className="mt-1 font-mono text-xs text-neutral-950">{analysisId}</p>
          </div>
          <div className="sm:text-right">
            <p className="text-xs font-bold uppercase tracking-[0.06em] text-neutral-700">Capture</p>
            <p className="mt-1 max-w-sm truncate text-xs text-neutral-600">
              {uploadedFileName ?? "Selected capture"}
            </p>
          </div>
        </div>

        <div className="space-y-6 p-5 sm:p-6">
          <Progress value={status?.percent ?? 0} aria-label="Analysis progress">
            <ProgressLabel>
              {status?.phase === "queued" ? "Queued" : "Processing"}
            </ProgressLabel>
            <span className="ml-auto text-sm tabular-nums text-neutral-500">
              {status?.percent ?? 0}%
            </span>
          </Progress>

          <ol className="divide-y divide-neutral-200 rounded-lg border border-neutral-200">
            {(status?.stages ?? []).map((stage) => (
              <li key={stage.stage} className="flex items-center gap-3 px-4 py-3">
                <StageIcon status={stage.status} />
                <div className="min-w-0 flex-1">
                  <p className="text-sm font-medium text-neutral-900">
                    {stageLabels[stage.stage]}
                  </p>
                  <p className="text-xs capitalize text-neutral-500">
                    {stage.status.replace("_", " ")}
                  </p>
                </div>
              </li>
            ))}
            {!status ? (
              <li className="flex items-center gap-3 px-4 py-3 text-sm text-neutral-500">
                <LoaderCircle className="size-4 animate-spin" aria-hidden />
                Loading deterministic stage status…
              </li>
            ) : null}
          </ol>
        </div>
      </section>
    </div>
  );
}
