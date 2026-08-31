import type {
  AnalysisDataSource,
  AnalysisResult,
  AnalysisStatus,
  CreateAnalysisResponse,
} from "@/lib/contracts/analysis";
import {
  analysisResultSchema,
  analysisStatusSchema,
  createAnalysisResponseSchema,
} from "@/lib/contracts/analysis";
import { ANALYSIS_ID } from "@/lib/contracts/ids";
import { publicConfig } from "@/lib/config/env";
import {
  AnalysisNotFoundError,
  ApiRequestError,
} from "@/lib/api/errors";
import { z } from "zod";

const apiCreateResponseSchema = z.object({
  analysis_id: z.string().regex(ANALYSIS_ID),
  accepted_filename: z.string().optional(),
});

function endpoint(path: string): string {
  const base = publicConfig.apiBaseUrl.endsWith("/")
    ? publicConfig.apiBaseUrl
    : `${publicConfig.apiBaseUrl}/`;
  return new URL(path, base).toString();
}

async function requestJson(
  url: string,
  init?: RequestInit,
  analysisId?: string,
): Promise<unknown> {
  let response: Response;
  try {
    response = await fetch(url, init);
  } catch {
    throw new ApiRequestError(
      "The production analysis API could not be reached. No result was created.",
    );
  }

  if (response.status === 404 && analysisId) {
    throw new AnalysisNotFoundError(analysisId);
  }

  if (!response.ok) {
    throw new ApiRequestError(
      `The production analysis API returned HTTP ${response.status}. No successful result was assumed.`,
    );
  }

  try {
    return await response.json();
  } catch {
    throw new ApiRequestError(
      "The production analysis API returned an invalid JSON response.",
    );
  }
}

/**
 * Reserved for the future production HTTP API.
 *
 * This class models the future FastAPI boundary and only reports data that
 * validates at runtime. Network, HTTP, and contract failures remain failures.
 */
export class ApiAnalysisDataSource implements AnalysisDataSource {
  async createAnalysis(file: File): Promise<CreateAnalysisResponse> {
    const formData = new FormData();
    formData.append("capture", file, file.name);
    formData.append("authorized", "true");

    const payload = apiCreateResponseSchema.parse(
      await requestJson(endpoint("api/v1/analyses"), {
        method: "POST",
        body: formData,
      }),
    );

    return createAnalysisResponseSchema.parse({
      analysis_id: payload.analysis_id,
      accepted_filename: payload.accepted_filename ?? file.name,
      dataset_label: null,
      data_source: "api",
    });
  }

  async getStatus(analysisId: string): Promise<AnalysisStatus> {
    return analysisStatusSchema.parse(
      await requestJson(
        endpoint(
          `api/v1/analyses/${encodeURIComponent(analysisId)}/status`,
        ),
        undefined,
        analysisId,
      ),
    );
  }

  async getResult(analysisId: string): Promise<AnalysisResult> {
    return analysisResultSchema.parse(
      await requestJson(
        endpoint(
          `api/v1/analyses/${encodeURIComponent(analysisId)}/result`,
        ),
        undefined,
        analysisId,
      ),
    );
  }
}
