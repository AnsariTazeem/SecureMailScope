"use client";

import { useEffect, useState } from "react";
import { Download, LoaderCircle, Printer } from "lucide-react";

import { Button } from "@/components/ui/button";
import {
  ExportDownloadError,
  createDemoChainDownload,
  fetchFindingArtifactDownload,
  fetchRealChainDownload,
  type DownloadFile,
  type FindingArtifactFormat,
} from "@/lib/api/export-downloads";
import type { ChainOfProof } from "@/lib/contracts/chain";

function startBrowserDownload(file: DownloadFile): void {
  const url = URL.createObjectURL(file.blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = file.filename;
  anchor.hidden = true;
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1_000);
}

function safeErrorMessage(error: unknown): string {
  return error instanceof ExportDownloadError
    ? error.message
    : "The download could not be prepared. No file was downloaded.";
}

type ReportExportActionsProps = {
  analysisId: string;
  dataSource: "api" | "mock";
  demoChain: ChainOfProof | null;
};

export function ReportExportActions({
  analysisId,
  dataSource,
  demoChain,
}: ReportExportActionsProps) {
  const [downloading, setDownloading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [includeAppendix, setIncludeAppendix] = useState(false);

  useEffect(() => {
    const root = document.querySelector<HTMLElement>("[data-assessment-report]");
    if (!root) return;
    root.dataset.includeAppendix = String(includeAppendix);
    let closedDetails: HTMLDetailsElement[] = [];
    const preparePrint = () => {
      closedDetails = Array.from(root.querySelectorAll<HTMLDetailsElement>("details[data-report-print-expand]:not([open])"))
        .filter((details) => includeAppendix || !details.closest("[data-report-appendix]"));
      for (const details of closedDetails) details.open = true;
    };
    const restoreScreen = () => {
      for (const details of closedDetails) details.open = false;
      closedDetails = [];
    };
    window.addEventListener("beforeprint", preparePrint);
    window.addEventListener("afterprint", restoreScreen);
    return () => {
      restoreScreen();
      window.removeEventListener("beforeprint", preparePrint);
      window.removeEventListener("afterprint", restoreScreen);
    };
  }, [includeAppendix]);


  const downloadChain = async () => {
    setDownloading(true);
    setError(null);
    try {
      let file: DownloadFile;
      if (dataSource === "mock") {
        if (!demoChain) {
          throw new ExportDownloadError(
            "The Prototype Analysis Dataset Chain is unavailable. No file was downloaded.",
          );
        }
        file = createDemoChainDownload(analysisId, demoChain);
      } else {
        file = await fetchRealChainDownload(analysisId);
      }
      startBrowserDownload(file);
    } catch (downloadError) {
      setError(safeErrorMessage(downloadError));
    } finally {
      setDownloading(false);
    }
  };

  return (
    <div data-print-hide className="max-w-full sm:max-w-xl">
      <div className="flex flex-wrap justify-start gap-2 sm:justify-end">
        <Button
          type="button"
          variant="outline"
          size="lg"
          onClick={downloadChain}
          disabled={downloading}
          aria-busy={downloading}
        >
          {downloading ? (
            <LoaderCircle className="animate-spin" aria-hidden />
          ) : (
            <Download aria-hidden />
          )}
          Download Chain JSON
        </Button>
        <Button
          type="button"
          variant="outline"
          size="lg"
          onClick={() => window.print()}
        >
          <Printer aria-hidden />
          Print / Save as PDF
        </Button>
      </div>
      <label className="mt-3 flex min-h-9 items-center gap-2 text-xs leading-5 text-neutral-600 sm:justify-end">
        <input
          type="checkbox"
          checked={includeAppendix}
          onChange={(event) => setIncludeAppendix(event.target.checked)}
          className="size-4 shrink-0 accent-neutral-950"
        />
        Include technical appendix when printing
      </label>
      {error ? (
        <p
          role="alert"
          className="mt-2 text-left text-xs leading-5 text-red-700 sm:text-right"
        >
          {error}
        </p>
      ) : null}
    </div>
  );
}

export function FindingArtifactActions({
  analysisId,
  findingId,
}: {
  analysisId: string;
  findingId: string;
}) {
  const [downloading, setDownloading] =
    useState<FindingArtifactFormat | null>(null);
  const [error, setError] = useState<string | null>(null);

  const downloadArtifact = async (format: FindingArtifactFormat) => {
    setDownloading(format);
    setError(null);
    try {
      startBrowserDownload(
        await fetchFindingArtifactDownload(analysisId, findingId, format),
      );
    } catch (downloadError) {
      setError(safeErrorMessage(downloadError));
    } finally {
      setDownloading(null);
    }
  };

  return (
    <div data-print-hide className="max-w-full">
      <div className="flex flex-wrap gap-2 sm:justify-end">
        {(["pdf", "html"] as const).map((format) => (
          <Button
            key={format}
            type="button"
            variant="outline"
            size="sm"
            onClick={() => downloadArtifact(format)}
            disabled={downloading !== null}
            aria-busy={downloading === format}
          >
            {downloading === format ? (
              <LoaderCircle className="animate-spin" aria-hidden />
            ) : (
              <Download aria-hidden />
            )}
            Download {format.toUpperCase()}
          </Button>
        ))}
      </div>
      {error ? (
        <p
          role="alert"
          className="mt-2 max-w-md text-left text-xs leading-5 text-red-700 sm:text-right"
        >
          {error}
        </p>
      ) : null}
    </div>
  );
}
