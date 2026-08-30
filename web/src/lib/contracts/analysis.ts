import { z } from "zod";

import { chainOfProofSchema, stageDiagnosticSchema } from "./chain";
import { ANALYSIS_ID } from "./ids";

export const DATASET_LABEL = "Prototype Analysis Dataset";

export const createAnalysisResponseSchema = z.object({
  analysis_id: z.string().regex(ANALYSIS_ID),
  accepted_filename: z.string(),
  dataset_label: z.literal(DATASET_LABEL).nullable(),
  data_source: z.enum(["mock", "api"]),
});

export const analysisPhaseSchema = z.enum([
  "queued",
  "processing",
  "complete",
  "failed",
]);

export const analysisStatusSchema = z.object({
  analysis_id: z.string().regex(ANALYSIS_ID),
  phase: analysisPhaseSchema,
  current_stage: z.string().nullable(),
  percent: z.number().min(0).max(100),
  stages: z.array(stageDiagnosticSchema),
  error: z
    .object({
      code: z.string(),
      message: z.string(),
    })
    .nullable(),
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
export type AnalysisStatus = z.infer<typeof analysisStatusSchema>;
export type AnalysisResult = z.infer<typeof analysisResultSchema>;

export interface AnalysisDataSource {
  createAnalysis(file: File): Promise<CreateAnalysisResponse>;
  getStatus(analysisId: string): Promise<AnalysisStatus>;
  getResult(analysisId: string): Promise<AnalysisResult>;
}
