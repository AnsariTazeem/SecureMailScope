"use client";

import { useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { CircleAlert, Database, Info, Play } from "lucide-react";

import { AnalysisStepIndicator } from "@/components/analysis/analysis-step-indicator";
import { AuthorizationConfirmation } from "@/components/analysis/authorization-confirmation";
import { CaptureDropzone } from "@/components/analysis/capture-dropzone";
import { CaptureValidationList } from "@/components/analysis/capture-validation-list";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { getRealAnalysisDataSource } from "@/lib/api/client";
import { DATASET_LABEL } from "@/lib/contracts/analysis";
import { useAnalysisWorkflow } from "@/stores/analysis-workflow";

export function StartAnalysisForm() {
  const router = useRouter();
  const [validationErrors, setValidationErrors] = useState<string[]>([]);
  const [submitting, setSubmitting] = useState(false);

  const selectedFile = useAnalysisWorkflow((state) => state.selectedFile);
  const authorizationConfirmed = useAnalysisWorkflow(
    (state) => state.authorizationConfirmed,
  );
  const lastError = useAnalysisWorkflow((state) => state.lastError);
  const setSelectedFile = useAnalysisWorkflow((state) => state.setSelectedFile);
  const selectPrototypeDataset = useAnalysisWorkflow(
    (state) => state.selectPrototypeDataset,
  );
  const setAuthorizationConfirmed = useAnalysisWorkflow(
    (state) => state.setAuthorizationConfirmed,
  );
  const setCreated = useAnalysisWorkflow((state) => state.setCreated);
  const setError = useAnalysisWorkflow((state) => state.setError);

  const hasInput = Boolean(selectedFile);
  const activeStep = !hasInput ? 0 : authorizationConfirmed ? 2 : 1;
  const canStart = hasInput && authorizationConfirmed && !submitting;

  const validationItems = useMemo(
    () => [
      {
        label: "Capture selection",
        detail: hasInput ? "Files ready" : "Waiting for selection",
        passed: hasInput,
      },
      {
        label: "Capture integrity",
        detail: hasInput ? "Format and size verified" : "Waiting for capture files",
        passed: hasInput,
      },
      {
        label: "Analysis authorization",
        detail: authorizationConfirmed ? "Confirmed by analyst" : "Confirmation required",
        passed: authorizationConfirmed,
      },
    ],
    [authorizationConfirmed, hasInput],
  );

  function handleFile(file: File) {
    setValidationErrors([]);
    setError(null);
    setSelectedFile(file);
  }

  function handlePrototypeSelection() {
    setValidationErrors([]);
    setError(null);
    selectPrototypeDataset();
    router.push("/analysis/processing");
  }

  async function handleStart() {
    if (!canStart) return;
    setSubmitting(true);
    setError(null);

    try {
      if (!selectedFile) return;
      const response = await getRealAnalysisDataSource().createAnalysis(
        selectedFile,
      );
      setCreated(response.analysis_id, response.original_filename);
      router.push("/analysis/processing");
    } catch (error) {
      const message =
        error instanceof Error
          ? error.message
          : "The analysis could not be started.";
      setError(message);
      setSubmitting(false);
    }
  }

  return (
    <div className="mx-auto flex w-full max-w-[1280px] flex-col gap-6">
      <div className="flex flex-col gap-2">
        <p className="text-[11px] font-bold uppercase tracking-[0.08em] text-neutral-600">
          Capture intake
        </p>
        <h1 className="text-2xl font-semibold tracking-tight text-neutral-950 sm:text-3xl">
          Start Analysis
        </h1>
      </div>

      <AnalysisStepIndicator activeStep={activeStep} />

      <section className="w-full overflow-hidden rounded-lg border border-neutral-200 bg-white shadow-sm">
        <div className="border-b border-neutral-200 bg-neutral-50 px-5 py-3">
          <h2 className="text-xs font-bold uppercase tracking-[0.06em] text-neutral-900">
            Capture selection
          </h2>
        </div>

        <div className="mx-auto w-full max-w-4xl space-y-6 p-5 sm:p-6">
          <p
            role="status"
            className="flex min-w-0 items-start gap-2 text-sm leading-5 text-neutral-950"
          >
            <CircleAlert
              className="mt-0.5 size-4 shrink-0 text-destructive"
              aria-hidden
            />
            <span>
              <span className="font-semibold text-destructive">
                Production backend development is in progress.
              </span>{" "}
              Explore Demo to review a sample analysis and see the full workflow.
            </span>
          </p>

          <CaptureDropzone
            selectedFile={selectedFile}
            errors={validationErrors}
            onSelect={handleFile}
            onReject={setValidationErrors}
            onRemove={() => {
              setValidationErrors([]);
              setSelectedFile(null);
            }}
          />

          <CaptureValidationList items={validationItems} />

          <AuthorizationConfirmation
            confirmed={authorizationConfirmed}
            onConfirmedChange={setAuthorizationConfirmed}
          />

          {lastError ? (
            <Alert variant="destructive">
              <Info aria-hidden />
              <AlertTitle>Analysis could not start</AlertTitle>
              <AlertDescription>{lastError}</AlertDescription>
            </Alert>
          ) : null}

          <div className="flex flex-col gap-3 border-t border-neutral-200 pt-5 sm:flex-row sm:items-center sm:justify-between">
            <p className="max-w-2xl text-xs leading-5 text-neutral-500">
              Start Analysis uploads the authorized capture to the configured analysis backend.
            </p>
            <Button
              type="button"
              size="lg"
              disabled={!canStart}
              onClick={handleStart}
              className="min-h-11 min-w-44"
            >
              <Play className="size-4" aria-hidden />
              {submitting ? "Starting…" : "Start Analysis"}
            </Button>
          </div>

          <div className="rounded-lg border border-neutral-200 bg-neutral-50 p-4">
            <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
              <div className="flex min-w-0 items-start gap-3">
                <Database className="mt-0.5 size-4 shrink-0 text-neutral-600" aria-hidden />
                <div>
                  <p className="text-sm font-semibold text-neutral-900">
                    Want to explore without a capture?
                  </p>
                  <p className="mt-1 text-xs leading-5 text-neutral-500">
                    {DATASET_LABEL} · No file upload required · Simulated demo
                    processing
                  </p>
                </div>
              </div>
              <Button
                type="button"
                variant="outline"
                className="min-h-11"
                disabled={submitting}
                onClick={handlePrototypeSelection}
              >
                Explore Demo
              </Button>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}
