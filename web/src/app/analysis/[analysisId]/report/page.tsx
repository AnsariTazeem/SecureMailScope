import type { Metadata } from "next";
import { notFound } from "next/navigation";
import { cache } from "react";

import {
  FindingsIntegrityError,
  validateFindingsIntegrity,
} from "@/components/analysis/findings/findings-integrity";
import { ReportDataSourceFailure } from "@/components/analysis/report/report-states";
import { buildReportPageData } from "@/components/analysis/report/report-view-model";
import { ReportWorkspace } from "@/components/analysis/report/report-workspace";
import { getAnalysisDataSource } from "@/lib/api/client";
import { AnalysisNotFoundError, DataSourceError } from "@/lib/api/errors";
import {
  DATASET_LABEL,
  analysisResultSchema,
  type AnalysisResult,
} from "@/lib/contracts/analysis";
import { ANALYSIS_ID } from "@/lib/contracts/ids";

const loadAnalysisResult = cache(async (analysisId: string) => {
  try {
    const result = analysisResultSchema.parse(
      await getAnalysisDataSource().getResult(analysisId),
    );
    validateFindingsIntegrity(result);
    return { status: "success" as const, result };
  } catch (error) {
    if (error instanceof AnalysisNotFoundError) {
      return { status: "not_found" as const };
    }
    if (error instanceof FindingsIntegrityError) {
      return {
        status: "failure" as const,
        message:
          "The validated result contains duplicate, unresolved, contradictory, cyclic, or cross-boundary Chain-of-Proof references. No report was displayed.",
      };
    }
    return {
      status: "failure" as const,
      message:
        error instanceof DataSourceError
          ? error.message
          : "The analysis source did not return a result that satisfies the validated Chain-of-Proof contract. No report was displayed.",
    };
  }
});

function hasConsistentResultSource(result: AnalysisResult): boolean {
  return result.data_source === "mock"
    ? result.dataset_kind === "prototype_analysis_dataset" &&
        result.dataset_label === DATASET_LABEL
    : result.dataset_kind === "production_analysis_result" &&
        result.dataset_label === null;
}

type ReportRouteProps = {
  params: Promise<{ analysisId: string }>;
};

export async function generateMetadata({
  params,
}: ReportRouteProps): Promise<Metadata> {
  const { analysisId } = await params;
  const baseMetadata: Metadata = {
    title: "SecureMailScope Assessment Report",
  };
  if (!ANALYSIS_ID.test(analysisId)) {
    return { ...baseMetadata, robots: { index: false, follow: false } };
  }

  const loaded = await loadAnalysisResult(analysisId);
  const valid =
    loaded.status === "success" &&
    hasConsistentResultSource(loaded.result) &&
    loaded.result.chain.analysis.analysis_id === analysisId;
  return valid
    ? baseMetadata
    : { ...baseMetadata, robots: { index: false, follow: false } };
}

export default async function ReportPage({ params }: ReportRouteProps) {
  const { analysisId } = await params;
  if (!ANALYSIS_ID.test(analysisId)) notFound();

  const loaded = await loadAnalysisResult(analysisId);
  if (loaded.status === "not_found") notFound();
  if (loaded.status === "failure") {
    return (
      <ReportDataSourceFailure
        analysisId={analysisId}
        message={loaded.message}
      />
    );
  }
  if (!hasConsistentResultSource(loaded.result)) {
    return (
      <ReportDataSourceFailure
        analysisId={analysisId}
        message="The validated envelope contains a contradictory dataset kind, label, or data-source mode. No report was displayed."
      />
    );
  }
  if (loaded.result.chain.analysis.analysis_id !== analysisId) {
    return (
      <ReportDataSourceFailure
        analysisId={analysisId}
        message="The validated result belongs to a different analysis identifier. No report was displayed."
      />
    );
  }

  return <ReportWorkspace data={buildReportPageData(loaded.result)} />;
}
