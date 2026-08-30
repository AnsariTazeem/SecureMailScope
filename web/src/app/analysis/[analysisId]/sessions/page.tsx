import type { Metadata } from "next";
import { notFound } from "next/navigation";

import { SessionsExplorer } from "@/components/analysis/sessions/sessions-explorer";
import { SessionsDataSourceFailure } from "@/components/analysis/sessions/sessions-states";
import { buildSessionsExplorerData } from "@/components/analysis/sessions/session-view-model";
import { getAnalysisDataSource } from "@/lib/api/client";
import {
  AnalysisNotFoundError,
  DataSourceError,
} from "@/lib/api/errors";
import { analysisResultSchema } from "@/lib/contracts/analysis";
import { ANALYSIS_ID } from "@/lib/contracts/ids";

export const metadata: Metadata = {
  title: "Sessions Explorer",
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
          : "The analysis source did not return a result that satisfies the validated Chain-of-Proof contract. No sessions were displayed.",
    };
  }
}

export default async function SessionsPage({
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
      <SessionsDataSourceFailure
        analysisId={analysisId}
        message={loaded.message}
      />
    );
  }

  if (loaded.result.chain.analysis.analysis_id !== analysisId) {
    return (
      <SessionsDataSourceFailure
        analysisId={analysisId}
        message="The validated result belongs to a different analysis identifier. No sessions were displayed."
      />
    );
  }

  return (
    <SessionsExplorer data={buildSessionsExplorerData(loaded.result)} />
  );
}
