import { publicConfig } from "@/lib/config/env";
import type { AnalysisDataSource } from "@/lib/contracts/analysis";
import { ApiAnalysisDataSource } from "@/lib/api/api-analysis-data-source";
import { MockAnalysisDataSource } from "@/lib/api/mock-analysis-data-source";

let instance: AnalysisDataSource | null = null;

export function getAnalysisDataSource(): AnalysisDataSource {
  if (instance) return instance;
  instance =
    publicConfig.dataMode === "api"
      ? new ApiAnalysisDataSource()
      : new MockAnalysisDataSource();
  return instance;
}

export function resetAnalysisDataSourceForTests(): void {
  instance = null;
}
