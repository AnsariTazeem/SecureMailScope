import type { Metadata } from "next";
import { notFound } from "next/navigation";
import { cache } from "react";

import {
  ComparisonDataSourceFailure,
  ComparisonSelectionFailure,
  InsufficientSessionsState,
} from "@/components/analysis/compare/comparison-states";
import { buildComparisonPageData } from "@/components/analysis/compare/comparison-view-model";
import { ComparisonWorkspace } from "@/components/analysis/compare/comparison-workspace";
import {
  FindingsIntegrityError,
  validateFindingsIntegrity,
} from "@/components/analysis/findings/findings-integrity";
import { getAnalysisDataSource } from "@/lib/api/client";
import { AnalysisNotFoundError, DataSourceError } from "@/lib/api/errors";
import {
  DATASET_LABEL,
  analysisResultSchema,
  type AnalysisResult,
} from "@/lib/contracts/analysis";
import { ANALYSIS_ID, SESSION_ID } from "@/lib/contracts/ids";

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
          "The validated result contains duplicate, unresolved, contradictory, or cross-boundary Chain-of-Proof references. No comparison was displayed.",
      };
    }
    return {
      status: "failure" as const,
      message:
        error instanceof DataSourceError
          ? error.message
          : "The analysis source did not return a result that satisfies the validated Chain-of-Proof contract. No comparison was displayed.",
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

type CompareSearchParams = {
  a?: string | string[];
  b?: string | string[];
};

type CompareRouteProps = {
  params: Promise<{ analysisId: string }>;
  searchParams: Promise<CompareSearchParams>;
};

function singleSearchValue(value: string | string[] | undefined): string | null {
  return typeof value === "string" ? value : null;
}

function isValidSelection(
  value: string | null,
  sessionIds: Set<string>,
): value is string {
  return value !== null && SESSION_ID.test(value) && sessionIds.has(value);
}

export async function generateMetadata({
  params,
  searchParams,
}: CompareRouteProps): Promise<Metadata> {
  const { analysisId } = await params;
  const query = await searchParams;
  const baseMetadata: Metadata = { title: "Session Comparison" };
  if (!ANALYSIS_ID.test(analysisId)) {
    return { ...baseMetadata, robots: { index: false, follow: false } };
  }

  const loaded = await loadAnalysisResult(analysisId);
  if (
    loaded.status !== "success" ||
    !hasConsistentResultSource(loaded.result) ||
    loaded.result.chain.analysis.analysis_id !== analysisId ||
    loaded.result.chain.sessions.length < 2
  ) {
    return { ...baseMetadata, robots: { index: false, follow: false } };
  }

  const sessionIds = new Set(
    loaded.result.chain.sessions.map((session) => session.session_id),
  );
  const selectedA = singleSearchValue(query.a);
  const selectedB = singleSearchValue(query.b);
  const invalidSelection =
    (query.a !== undefined && !isValidSelection(selectedA, sessionIds)) ||
    (query.b !== undefined && !isValidSelection(selectedB, sessionIds));

  return invalidSelection
    ? { ...baseMetadata, robots: { index: false, follow: false } }
    : baseMetadata;
}

export default async function ComparePage({
  params,
  searchParams,
}: CompareRouteProps) {
  const { analysisId } = await params;
  const query = await searchParams;
  if (!ANALYSIS_ID.test(analysisId)) notFound();

  const loaded = await loadAnalysisResult(analysisId);
  if (loaded.status === "not_found") notFound();
  if (loaded.status === "failure") {
    return (
      <ComparisonDataSourceFailure
        analysisId={analysisId}
        message={loaded.message}
      />
    );
  }
  if (!hasConsistentResultSource(loaded.result)) {
    return (
      <ComparisonDataSourceFailure
        analysisId={analysisId}
        message="The validated envelope contains a contradictory dataset kind, label, or data-source mode. No comparison was displayed."
      />
    );
  }
  if (loaded.result.chain.analysis.analysis_id !== analysisId) {
    return (
      <ComparisonDataSourceFailure
        analysisId={analysisId}
        message="The validated result belongs to a different analysis identifier. No comparison was displayed."
      />
    );
  }

  const sessions = [...loaded.result.chain.sessions].sort((left, right) =>
    left.session_id.localeCompare(right.session_id),
  );
  if (sessions.length < 2) {
    return (
      <InsufficientSessionsState
        analysisId={analysisId}
        sessionCount={sessions.length}
      />
    );
  }

  const sessionIds = new Set(sessions.map((session) => session.session_id));
  const requestedA = singleSearchValue(query.a);
  const requestedB = singleSearchValue(query.b);
  if (
    (query.a !== undefined && !isValidSelection(requestedA, sessionIds)) ||
    (query.b !== undefined && !isValidSelection(requestedB, sessionIds))
  ) {
    return (
      <ComparisonSelectionFailure
        analysisId={analysisId}
        message="Each supplied selector must be one available reconstructed session ID in the validated result. No fallback pair was substituted."
      />
    );
  }

  const selectedA = requestedA ?? sessions[0].session_id;
  const selectedB = requestedB ?? sessions[1].session_id;
  return (
    <ComparisonWorkspace
      data={buildComparisonPageData(loaded.result, selectedA, selectedB)}
    />
  );
}
