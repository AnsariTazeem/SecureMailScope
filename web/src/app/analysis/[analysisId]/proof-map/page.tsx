import type { Metadata } from "next";
import { notFound } from "next/navigation";
import { cache } from "react";

import { ProofMap } from "@/components/analysis/proof-map/proof-map";
import { ProofMapIntegrityError } from "@/components/analysis/proof-map/proof-map-integrity";
import { ProofMapDataSourceFailure } from "@/components/analysis/proof-map/proof-map-states";
import { buildProofMapData } from "@/components/analysis/proof-map/proof-map-view-model";
import { getAnalysisDataSourceForId } from "@/lib/api/client";
import { AnalysisNotFoundError, DataSourceError } from "@/lib/api/errors";
import {
  DATASET_LABEL,
  analysisResultSchema,
  type AnalysisResult,
} from "@/lib/contracts/analysis";
import { ANALYSIS_ID } from "@/lib/contracts/ids";

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
          : "The analysis source did not return a result that satisfies the validated Chain-of-Proof contract. No Proof Map was displayed.",
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

type ProofMapRouteProps = {
  params: Promise<{ analysisId: string }>;
};

export async function generateMetadata({
  params,
}: ProofMapRouteProps): Promise<Metadata> {
  const { analysisId } = await params;
  const baseMetadata: Metadata = { title: "Proof Map" };
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

export default async function ProofMapPage({
  params,
}: ProofMapRouteProps) {
  const { analysisId } = await params;
  if (!ANALYSIS_ID.test(analysisId)) notFound();

  const loaded = await loadAnalysisResult(analysisId);
  if (loaded.status === "not_found") notFound();
  if (loaded.status === "failure") {
    return <ProofMapDataSourceFailure analysisId={analysisId} message={loaded.message} />;
  }
  if (!hasConsistentResultSource(loaded.result)) {
    return (
      <ProofMapDataSourceFailure
        analysisId={analysisId}
        message="The validated envelope contains a contradictory dataset kind, label, or data-source mode. No Proof Map was displayed."
      />
    );
  }
  if (loaded.result.chain.analysis.analysis_id !== analysisId) {
    return (
      <ProofMapDataSourceFailure
        analysisId={analysisId}
        message="The validated result belongs to a different analysis identifier. No Proof Map was displayed."
      />
    );
  }

  let data;
  try {
    data = buildProofMapData(loaded.result);
  } catch (error) {
    if (error instanceof ProofMapIntegrityError) {
      return (
        <ProofMapDataSourceFailure
          analysisId={analysisId}
          message="The validated result contains duplicate, unresolved, contradictory, cyclic, or cross-boundary Chain-of-Proof references. No Proof Map was displayed."
        />
      );
    }
    throw error;
  }

  return <ProofMap data={data} />;
}
