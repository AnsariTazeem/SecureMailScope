import { z } from "zod";

import { chainOfProofSchema } from "./chain";
import { ANALYSIS_ID } from "./ids";

export const DATASET_LABEL = "Prototype Analysis Dataset";

export const createAnalysisResponseSchema = z.object({
  api_version: z.literal("v1"),
  analysis_id: z.string().regex(ANALYSIS_ID),
  analysis_status: z.enum(["complete", "partial", "failed"]),
  original_filename: z.string(),
  data_source: z.literal("api"),
});

export const analysisResultSchema = z.object({
  dataset_label: z.literal(DATASET_LABEL).nullable(),
  dataset_kind: z.enum([
    "prototype_analysis_dataset",
    "production_analysis_result",
  ]),
  data_source: z.enum(["mock", "api"]),
  chain: chainOfProofSchema,
});

export type CreateAnalysisResponse = z.infer<
  typeof createAnalysisResponseSchema
>;
export type AnalysisResult = z.infer<typeof analysisResultSchema>;

export interface AnalysisDataSource {
  getResult(analysisId: string): Promise<AnalysisResult>;
}

export interface AnalysisSubmissionDataSource extends AnalysisDataSource {
  createAnalysis(file: File): Promise<CreateAnalysisResponse>;
}
