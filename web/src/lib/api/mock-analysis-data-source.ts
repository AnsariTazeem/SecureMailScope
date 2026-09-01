import {
  loadPrototypeAnalysisDataset,
  PROTOTYPE_ANALYSIS_ID,
} from "@/mocks/load-prototype-dataset";
import type { AnalysisDataSource } from "@/lib/contracts/analysis";
import { ANALYSIS_ID } from "@/lib/contracts/ids";
import { AnalysisNotFoundError } from "@/lib/api/errors";

function assertKnownAnalysis(analysisId: string): void {
  if (!ANALYSIS_ID.test(analysisId)) {
    throw new AnalysisNotFoundError(analysisId);
  }
  if (analysisId !== PROTOTYPE_ANALYSIS_ID) {
    throw new AnalysisNotFoundError(analysisId);
  }
}

export class MockAnalysisDataSource implements AnalysisDataSource {
  async getResult(analysisId: string) {
    assertKnownAnalysis(analysisId);
    return loadPrototypeAnalysisDataset();
  }
}
