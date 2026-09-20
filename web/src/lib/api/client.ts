import { ApiAnalysisDataSource } from "@/lib/api/api-analysis-data-source";
import { MockAnalysisDataSource } from "@/lib/api/mock-analysis-data-source";
import type {
  AnalysisDataSource,
  AnalysisSubmissionDataSource,
} from "@/lib/contracts/analysis";
import { PROTOTYPE_ANALYSIS_ID } from "@/mocks/load-prototype-dataset";
import { applicationCapabilities } from "@/lib/config/env";
import { SubmissionModeDisabledError } from "@/lib/api/errors";

let realInstance: AnalysisSubmissionDataSource | null = null;
let demoInstance: AnalysisDataSource | null = null;

export function getRealAnalysisDataSource(): AnalysisSubmissionDataSource {
  if (!applicationCapabilities.liveAnalysis) throw new SubmissionModeDisabledError();
  realInstance ??= new ApiAnalysisDataSource();
  return realInstance;
}

export function getDemoAnalysisDataSource(): AnalysisDataSource {
  demoInstance ??= new MockAnalysisDataSource();
  return demoInstance;
}

export function getAnalysisDataSourceForId(
  analysisId: string,
): AnalysisDataSource {
  return analysisId === PROTOTYPE_ANALYSIS_ID
    ? getDemoAnalysisDataSource()
    : getRealAnalysisDataSource();
}

export function resetAnalysisDataSourceForTests(): void {
  realInstance = null;
  demoInstance = null;
}
