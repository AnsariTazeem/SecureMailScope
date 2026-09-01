import type { Metadata } from "next";
import { notFound } from "next/navigation";
import { cache } from "react";

import { SessionXRay } from "@/components/analysis/session-xray/session-xray";
import {
  SessionRecordNotFound,
  SessionXRayDataSourceFailure,
} from "@/components/analysis/session-xray/session-xray-states";
import { SessionXRayIntegrityError } from "@/components/analysis/session-xray/session-xray-integrity";
import { buildSessionXRayData } from "@/components/analysis/session-xray/session-xray-view-model";
import { getAnalysisDataSourceForId } from "@/lib/api/client";
import {
  AnalysisNotFoundError,
  DataSourceError,
} from "@/lib/api/errors";
import {
  DATASET_LABEL,
  analysisResultSchema,
  type AnalysisResult,
} from "@/lib/contracts/analysis";
import { ANALYSIS_ID, SESSION_ID } from "@/lib/contracts/ids";

const loadAnalysisResult = cache(async (analysisId: string) => {
  try {
    return {
      status: "success" as const,
      result: analysisResultSchema.parse(
        await getAnalysisDataSourceForId(analysisId).getResult(analysisId),
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
          : "The analysis source did not return a result that satisfies the validated Chain-of-Proof contract. No session evidence was displayed.",
    };
  }
});

type SessionRouteProps = {
  params: Promise<{ analysisId: string; sessionId: string }>;
};

function hasConsistentResultSource(result: AnalysisResult): boolean {
  return result.data_source === "mock"
    ? result.dataset_kind === "prototype_analysis_dataset" &&
        result.dataset_label === DATASET_LABEL
    : result.dataset_kind === "production_analysis_result" &&
        result.dataset_label === null;
}

export async function generateMetadata({
  params,
}: SessionRouteProps): Promise<Metadata> {
  const { analysisId, sessionId } = await params;
  const baseMetadata: Metadata = { title: "Session X-Ray" };

  if (!ANALYSIS_ID.test(analysisId) || !SESSION_ID.test(sessionId)) {
    return { ...baseMetadata, robots: { index: false, follow: false } };
  }

  const loaded = await loadAnalysisResult(analysisId);
  const hasSession =
    loaded.status === "success" &&
    hasConsistentResultSource(loaded.result) &&
    loaded.result.chain.analysis.analysis_id === analysisId &&
    loaded.result.chain.sessions.some(
      (session) => session.session_id === sessionId,
    );

  return hasSession
    ? baseMetadata
    : { ...baseMetadata, robots: { index: false, follow: false } };
}

export default async function SessionDetailPage({
  params,
}: SessionRouteProps) {
  const { analysisId, sessionId } = await params;
  if (!ANALYSIS_ID.test(analysisId) || !SESSION_ID.test(sessionId)) notFound();

  const loaded = await loadAnalysisResult(analysisId);
  if (loaded.status === "not_found") notFound();
  if (loaded.status === "failure") {
    return (
      <SessionXRayDataSourceFailure
        analysisId={analysisId}
        message={loaded.message}
      />
    );
  }

  if (!hasConsistentResultSource(loaded.result)) {
    return (
      <SessionXRayDataSourceFailure
        analysisId={analysisId}
        message="The validated envelope contains a contradictory dataset kind, label, or data-source mode. No session evidence was displayed."
      />
    );
  }

  if (loaded.result.chain.analysis.analysis_id !== analysisId) {
    return (
      <SessionXRayDataSourceFailure
        analysisId={analysisId}
        message="The validated result belongs to a different analysis identifier. No session evidence was displayed."
      />
    );
  }

  let data;
  try {
    data = buildSessionXRayData(loaded.result, sessionId);
  } catch (error) {
    if (error instanceof SessionXRayIntegrityError) {
      return (
        <SessionXRayDataSourceFailure
          analysisId={analysisId}
          message="The validated result contains duplicate, unresolved, contradictory, or cross-boundary Chain-of-Proof references. No session evidence was displayed."
        />
      );
    }
    throw error;
  }
  if (!data) {
    return (
      <SessionRecordNotFound
        analysisId={analysisId}
        sessionId={sessionId}
      />
    );
  }

  return <SessionXRay data={data} />;
}
