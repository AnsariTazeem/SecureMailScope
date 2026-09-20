"use client";

import { useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { Database, Info, Play } from "lucide-react";

import { AnalysisStepIndicator } from "@/components/analysis/analysis-step-indicator";
import { AssessmentScopePanel } from "@/components/analysis/assessment-scope-panel";
import { AuthorizationConfirmation } from "@/components/analysis/authorization-confirmation";
import { CaptureDropzone } from "@/components/analysis/capture-dropzone";
import { CaptureValidationList } from "@/components/analysis/capture-validation-list";
import { EvidenceBoundaryNote } from "@/components/analysis/evidence-boundary-note";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { getRealAnalysisDataSource } from "@/lib/api/client";
import { publicConfig } from "@/lib/config/env";
import { formatByteLimit } from "@/lib/validation/capture-file";
import { useAnalysisWorkflow } from "@/stores/analysis-workflow";
import { useSubmissionCaptureGuard } from "@/components/analysis/submission-capture-guard";

export function StartAnalysisForm() {
  const router = useRouter();
  const { disclose, exploreDemo } = useSubmissionCaptureGuard();
  const liveAnalysis = publicConfig.liveAnalysis;
  const [validationErrors, setValidationErrors] = useState<string[]>([]);
  const [submitting, setSubmitting] = useState(false);

  const selectedFile = useAnalysisWorkflow((state) => state.selectedFile);
  const authorizationConfirmed = useAnalysisWorkflow(
    (state) => state.authorizationConfirmed,
  );
  const lastError = useAnalysisWorkflow((state) => state.lastError);
  const setSelectedFile = useAnalysisWorkflow((state) => state.setSelectedFile);
  const setAuthorizationConfirmed = useAnalysisWorkflow(
    (state) => state.setAuthorizationConfirmed,
  );
  const setCreated = useAnalysisWorkflow((state) => state.setCreated);
  const setError = useAnalysisWorkflow((state) => state.setError);

  const hasInput = Boolean(selectedFile);
  const activeStep = !hasInput ? 0 : authorizationConfirmed ? 2 : 1;
  const canStart = liveAnalysis && hasInput && authorizationConfirmed && !submitting;

  const validationItems = useMemo(
    () => [
      {
        label: "Capture format",
        detail: hasInput ? "PCAP/PCAPNG extension accepted" : "Waiting for selection",
        passed: hasInput,
      },
      {
        label: "File bounds",
        detail: hasInput
          ? `Non-empty and within ${formatByteLimit(publicConfig.maxCaptureBytes)}`
          : `Maximum ${formatByteLimit(publicConfig.maxCaptureBytes)}`,
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
    if (!liveAnalysis) { disclose(); return; }
    setValidationErrors([]);
    setError(null);
    setSelectedFile(file);
  }

  function handlePrototypeSelection() {
    setValidationErrors([]);
    setError(null);
    exploreDemo();
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
        <p className="text-[11px] font-bold uppercase tracking-[0.08em] text-neutral-500">
          Offline capture intake
        </p>
        <h1 className="text-2xl font-semibold tracking-tight text-neutral-950 sm:text-3xl">
          Start Analysis
        </h1>
        <p className="max-w-3xl text-sm leading-6 text-neutral-600">
          {liveAnalysis
            ? "Select an authorized packet capture for evidence-bound email transport assessment. The browser validates intake requirements before any analysis begins."
            : "Explore the curated demo to review the complete investigation workflow. Live capture analysis is not connected in this evaluation build."}
        </p>
      </div>

      {liveAnalysis ? <AnalysisStepIndicator activeStep={activeStep} /> : null}

      <div className="grid gap-6 xl:grid-cols-[minmax(0,2fr)_minmax(300px,0.82fr)]">
        <section className="overflow-hidden rounded-lg border border-neutral-200 bg-white shadow-sm">
          <div className="border-b border-neutral-200 bg-neutral-50 px-5 py-3">
            <h2 className="text-xs font-bold uppercase tracking-[0.06em] text-neutral-900">
              Capture selection
            </h2>
          </div>

          <div className="space-y-6 p-5 sm:p-6">
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

            {liveAnalysis ? <CaptureValidationList items={validationItems} /> : null}

            {liveAnalysis ? <AuthorizationConfirmation
              confirmed={authorizationConfirmed}
              onConfirmedChange={setAuthorizationConfirmed}
            /> : null}

            {lastError ? (
              <Alert variant="destructive">
                <Info aria-hidden />
                <AlertTitle>Analysis could not start</AlertTitle>
                <AlertDescription>{lastError}</AlertDescription>
              </Alert>
            ) : null}

            {liveAnalysis ? <div className="flex flex-col gap-3 border-t border-neutral-200 pt-5 sm:flex-row sm:items-center sm:justify-between">
              <p className="text-xs leading-5 text-neutral-500">
                Start Analysis uploads the authorized capture to the configured
                production backend. Explore Demo never uploads a capture.
              </p>
              <Button
                type="button"
                size="lg"
                disabled={!canStart}
                onClick={handleStart}
                className="min-w-48"
              >
                <Play className="size-4" aria-hidden />
                {submitting ? "Starting…" : "Start offline analysis"}
              </Button>
            </div> : null}

            <div className="rounded-lg border border-neutral-200 bg-neutral-50 p-4">
              <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                <div className="flex min-w-0 items-start gap-3">
                  <Database className="mt-0.5 size-4 shrink-0 text-neutral-600" aria-hidden />
                  <div>
                    <p className="text-sm font-semibold text-neutral-900">
                      Want to explore without a capture?
                    </p>
                    <p className="mt-1 text-xs leading-5 text-neutral-500">
                      Follow mail sessions, supporting evidence, findings and review actions. No file upload required.
                    </p>
                  </div>
                </div>
                <Button
                  type="button"
                  variant={liveAnalysis ? "outline" : "default"}
                  disabled={submitting}
                  onClick={handlePrototypeSelection}
                >
                  Open complete demo
                </Button>
              </div>
            </div>
          </div>
        </section>

        <aside className="space-y-4 xl:sticky xl:top-24 xl:self-start">
          <AssessmentScopePanel />
          <EvidenceBoundaryNote />
        </aside>
      </div>
    </div>
  );
}
