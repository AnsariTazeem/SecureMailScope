"use client";

import { useMemo, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { Info, Play } from "lucide-react";

import { AnalysisStepIndicator } from "@/components/analysis/analysis-step-indicator";
import { AuthorizationConfirmation } from "@/components/analysis/authorization-confirmation";
import { CaptureDropzone } from "@/components/analysis/capture-dropzone";
import { CaptureValidationList } from "@/components/analysis/capture-validation-list";
import { PreparedCaptureDropzone } from "@/components/analysis/prepared-capture-dropzone";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { getRealAnalysisDataSource } from "@/lib/api/client";
import { publicConfig } from "@/lib/config/env";
import { formatByteLimit } from "@/lib/validation/capture-file";
import {
  PREPARED_CAPTURE_BUNDLE,
  verifyPreparedCaptureBundle,
} from "@/lib/walkthrough/capture-bundle";
import { useAnalysisWorkflow } from "@/stores/analysis-workflow";

type BundleStatus = "idle" | "checking" | "valid" | "invalid";

export function CaptureAnalysisForm() {
  const router = useRouter();
  const liveAnalysis = publicConfig.liveAnalysis;
  const verificationSequence = useRef(0);
  const [preparedFiles, setPreparedFiles] = useState<File[]>([]);
  const [bundleStatus, setBundleStatus] = useState<BundleStatus>("idle");
  const [preparedDisplayNames, setPreparedDisplayNames] = useState<string[]>([]);
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

  const hasInput = liveAnalysis
    ? Boolean(selectedFile)
    : preparedFiles.length > 0;
  const inputValid = liveAnalysis
    ? Boolean(selectedFile)
    : bundleStatus === "valid";
  const activeStep = !hasInput ? 0 : inputValid && authorizationConfirmed ? 2 : 1;
  const canStart = inputValid && authorizationConfirmed && !submitting;

  const validationItems = useMemo(() => {
    if (liveAnalysis) {
      return [
        {
          label: "Capture format",
          detail: hasInput
            ? "PCAP/PCAPNG extension accepted"
            : "Waiting for selection",
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
          detail: authorizationConfirmed
            ? "Confirmed by analyst"
            : "Confirmation required",
          passed: authorizationConfirmed,
        },
      ];
    }

    return [
      {
        label: "Capture selection",
        detail:
          preparedFiles.length === 0
            ? "Waiting for selection"
            : preparedFiles.length === PREPARED_CAPTURE_BUNDLE.length
              ? "Files ready"
              : "Selection incomplete",
        passed: preparedFiles.length === PREPARED_CAPTURE_BUNDLE.length,
      },
      {
        label: "Capture integrity",
        detail:
          bundleStatus === "checking"
            ? "Verifying file integrity…"
            : bundleStatus === "valid"
              ? "Integrity verified"
              : bundleStatus === "invalid"
                ? "Integrity check failed"
                : "Waiting for capture files",
        passed: bundleStatus === "valid",
      },
      {
        label: "Analysis authorization",
        detail: authorizationConfirmed
          ? "Confirmed by analyst"
          : "Confirmation required",
        passed: authorizationConfirmed,
      },
    ];
  }, [
    authorizationConfirmed,
    bundleStatus,
    hasInput,
    liveAnalysis,
    preparedFiles.length,
  ]);

  function handleFile(file: File) {
    setValidationErrors([]);
    setError(null);
    setSelectedFile(file);
  }

  async function updatePreparedFiles(files: File[]) {
    const sequence = ++verificationSequence.current;
    setPreparedFiles(files);
    setPreparedDisplayNames(files.map(() => "Capture file"));
    setValidationErrors([]);
    setError(null);

    if (files.length === 0) {
      setBundleStatus("idle");
      setPreparedDisplayNames([]);
      return;
    }

    setBundleStatus("checking");
    const verification = await verifyPreparedCaptureBundle(files);
    if (verificationSequence.current !== sequence) return;

    if (verification.valid) {
      setBundleStatus("valid");
      setPreparedDisplayNames(verification.canonicalFilenames);
      return;
    }

    setBundleStatus("invalid");
    setValidationErrors(verification.errors);
  }

  async function handleStart() {
    if (!canStart) return;
    setSubmitting(true);
    setError(null);

    try {
      if (liveAnalysis) {
        if (!selectedFile) return;
        const response = await getRealAnalysisDataSource().createAnalysis(
          selectedFile,
        );
        setCreated(response.analysis_id, response.original_filename);
      } else {
        const captureNames = PREPARED_CAPTURE_BUNDLE.map(
          (capture) => capture.filename,
        ).join(" + ");
        selectPrototypeDataset(captureNames);
      }
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
          {liveAnalysis ? (
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
          ) : (
            <PreparedCaptureDropzone
              selectedFiles={preparedFiles}
              displayNames={preparedDisplayNames}
              errors={validationErrors}
              onSelect={(files) => void updatePreparedFiles(files)}
              onReject={(errors) => {
                setBundleStatus("invalid");
                setValidationErrors(errors);
              }}
              onRemove={(file) =>
                void updatePreparedFiles(
                  preparedFiles.filter((selected) => selected !== file),
                )
              }
            />
          )}

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
              {liveAnalysis
                ? "Start Analysis uploads the authorized capture to the configured analysis backend."
                : "Selected files are verified locally and matched to the available analysis record. Capture contents are not uploaded."}
            </p>
            <Button
              type="button"
              size="lg"
              disabled={!canStart}
              onClick={handleStart}
              className="min-w-44"
            >
              <Play className="size-4" aria-hidden />
              {submitting ? "Starting…" : "Start Analysis"}
            </Button>
          </div>
        </div>
      </section>
    </div>
  );
}
