import type { Metadata } from "next";
import { notFound } from "next/navigation";

import {
  AnalysisOverview,
  OverviewDataSourceFailure,
} from "@/components/analysis/overview/analysis-overview";
import { getAnalysisDataSource } from "@/lib/api/client";
import {
  AnalysisNotFoundError,
  DataSourceError,
} from "@/lib/api/errors";
import { analysisResultSchema } from "@/lib/contracts/analysis";
import { ANALYSIS_ID } from "@/lib/contracts/ids";

export const metadata: Metadata = {
  title: "Analysis Overview",
};

async function loadAnalysisResult(analysisId: string) {
  try {
    return {
      status: "success" as const,
      result: analysisResultSchema.parse(
        await getAnalysisDataSource().getResult(analysisId),
      ),
    };
  } catch (error) {
    if (error instanceof AnalysisNotFoundError) {
      return { status: "not_found" as const };
    }

    return {
      status: "failure" as const,
      message:
        error instanceof DataSourceError
          ? error.message
          : "The analysis source did not return a result that satisfies the validated Chain-of-Proof contract. No result was displayed.",
    };
  }
}

export default async function OverviewPage({
  params,
}: {
  params: Promise<{ analysisId: string }>;
}) {
  const { analysisId } = await params;
  if (!ANALYSIS_ID.test(analysisId)) notFound();

  const loaded = await loadAnalysisResult(analysisId);
  if (loaded.status === "not_found") notFound();
  if (loaded.status === "failure") {
    return (
      <OverviewDataSourceFailure
        analysisId={analysisId}
        message={loaded.message}
      />
    );
  }

  if (loaded.result.chain.analysis.analysis_id !== analysisId) {
    return (
      <OverviewDataSourceFailure
        analysisId={analysisId}
        message="The validated result belongs to a different analysis identifier. No result was displayed."
      />
    );
  }

  return <AnalysisOverview result={loaded.result} />;
}
