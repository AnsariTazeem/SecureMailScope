import type { AnalysisResult } from "@/lib/contracts/analysis";
import { analysisResultSchema } from "@/lib/contracts/analysis";

import prototypeDataset from "@/mocks/prototype-analysis-dataset.json";

export const PROTOTYPE_ANALYSIS_ID = "ana_c0ffee0000000001";

export function loadPrototypeAnalysisDataset(): AnalysisResult {
  return analysisResultSchema.parse(prototypeDataset);
}
