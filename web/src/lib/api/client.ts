import { ApiAnalysisDataSource } from "@/lib/api/api-analysis-data-source";
import { MockAnalysisDataSource } from "@/lib/api/mock-analysis-data-source";
import type {
  AnalysisDataSource,
  AnalysisSubmissionDataSource,
} from "@/lib/contracts/analysis";
import { PROTOTYPE_ANALYSIS_ID } from "@/mocks/load-prototype-dataset";

let realInstance: AnalysisSubmissionDataSource | null = null;
let demoInstance: AnalysisDataSource | null = null;

export function getRealAnalysisDataSource(): AnalysisSubmissionDataSource {
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
