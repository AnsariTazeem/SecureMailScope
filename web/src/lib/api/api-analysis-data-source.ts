import { z } from "zod";

import {
  AnalysisNotFoundError,
  ApiRequestError,
  CaptureValidationError,
} from "@/lib/api/errors";
import { publicConfig } from "@/lib/config/env";
import {
  analysisResultSchema,
  createAnalysisResponseSchema,
  type AnalysisResult,
  type AnalysisSubmissionDataSource,
  type CreateAnalysisResponse,
} from "@/lib/contracts/analysis";
import {
  analysisLimitationSchema,
  chainOfProofSchema,
  type ChainOfProof,
} from "@/lib/contracts/chain";
import {
  analysisStatusSchema,
  engineStatusSchema,
} from "@/lib/contracts/enums";
import { ANALYSIS_ID } from "@/lib/contracts/ids";
import { validateCaptureFile } from "@/lib/validation/capture-file";

const apiCreateResponseSchema = z.strictObject({
  api_version: z.literal("v1"),
  analysis_id: z.string().regex(ANALYSIS_ID),
  analysis_status: analysisStatusSchema,
});

const apiPolicyRiskSummarySchema = z.strictObject({
  policy_risk_id: z.string(),
  profile_id: z.string(),
  uncapped_score: z.number().int().min(0),
  capped_score: z.number().int().min(0).max(100),
  available: z.boolean(),
});

const apiAnalysisSummarySchema = z.strictObject({
  api_version: z.literal("v1"),
  chain_schema_version: z.literal("1.0.0"),
  analysis_id: z.string().regex(ANALYSIS_ID),
  analyzer_version: z.string(),
  analysis_status: analysisStatusSchema,
  rule_engine_status: engineStatusSchema,
  ml_engine_status: engineStatusSchema,
  capture_ids: z.array(z.string()),
  session_ids: z.array(z.string()),
  finding_ids: z.array(z.string()),
  capture_count: z.number().int().min(0),
  session_count: z.number().int().min(0),
  evidence_count: z.number().int().min(0),
  protocol_event_count: z.number().int().min(0),
  derived_fact_count: z.number().int().min(0),
  rule_evaluation_count: z.number().int().min(0),
  finding_count: z.number().int().min(0),
  recommendation_count: z.number().int().min(0),
  policy_risk: apiPolicyRiskSummarySchema.nullable(),
  limitations: z.array(analysisLimitationSchema),
});

const apiErrorEnvelopeSchema = z.strictObject({
  error: z.strictObject({
    code: z.string(),
    message: z.string(),
  }),
});

type ApiAnalysisSummary = z.infer<typeof apiAnalysisSummarySchema>;

function endpoint(path: string): string {
  const base = publicConfig.apiBaseUrl.endsWith("/")
    ? publicConfig.apiBaseUrl
    : `${publicConfig.apiBaseUrl}/`;
  return new URL(path, base).toString();
}

function parsePayload<T>(
  schema: z.ZodType<T>,
  payload: unknown,
  message: string,
): T {
  const parsed = schema.safeParse(payload);
  if (!parsed.success) {
    throw new ApiRequestError(message, "api_contract_invalid");
  }
  return parsed.data;
}

function errorMessageFor(
  status: number,
  code: string | null,
  method: string,
): string {
  if (status === 413) {
    return method === "POST"
      ? "The uploaded capture exceeds the backend size limit. Choose a smaller PCAP or PCAPNG file."
      : "The analysis result exceeds the backend response limit and cannot be displayed.";
  }
  if (status === 415) {
    return "The backend does not support this capture format. Choose a .pcap or .pcapng file.";
  }
  if (status === 422) {
    return code === "empty_upload"
      ? "The selected capture is empty. Choose a non-empty PCAP or PCAPNG file."
      : "The backend rejected the capture as invalid or malformed. No analysis result was created.";
  }
  if (status === 409) {
    return "This capture conflicts with an analysis already held by the backend. No duplicate result was created.";
  }
  if (status === 503) {
    return "Analysis capacity is currently unavailable. Try again after backend capacity is restored.";
  }
  if (status === 500) {
    return "The backend could not complete or return this analysis. No successful result was assumed.";
  }
  return `The production analysis API rejected the request (HTTP ${status}). No successful result was assumed.`;
}

async function requestJson(
  url: string,
  init?: RequestInit,
  analysisId?: string,
): Promise<unknown> {
  let response: Response;
  try {
    response = await fetch(url, { cache: "no-store", ...init });
  } catch {
    throw new ApiRequestError(
      "The production backend is unavailable. Check the configured API URL and backend service, then try again.",
      "backend_unavailable",
    );
  }

  if (!response.ok) {
    let code: string | null = null;
    try {
      const envelope = apiErrorEnvelopeSchema.safeParse(await response.json());
      if (envelope.success) code = envelope.data.error.code;
    } catch {
      // Status-based mapping remains safe when the response is not JSON.
    }

    if (response.status === 404 && analysisId) {
      throw new AnalysisNotFoundError(analysisId);
    }
    throw new ApiRequestError(
      errorMessageFor(response.status, code, init?.method ?? "GET"),
      code ?? `http_${response.status}`,
    );
  }

  try {
    return await response.json();
  } catch {
    throw new ApiRequestError(
      "The production backend returned an invalid JSON response. No result was displayed.",
      "api_invalid_json",
    );
  }
}

function assertSummaryMatchesChain(
  summary: ApiAnalysisSummary,
  chain: ChainOfProof,
): void {
  const sameIds = (summaryIds: string[], chainIds: string[]) =>
    summaryIds.length === chainIds.length &&
    summaryIds.every((id, index) => id === chainIds[index]);

  const valid =
    summary.analysis_id === chain.analysis.analysis_id &&
    summary.chain_schema_version === chain.chain_schema_version &&
    summary.analysis_status === chain.analysis.analysis_status &&
    summary.analyzer_version === chain.analysis.analyzer_version &&
    summary.rule_engine_status === chain.analysis.rule_engine_status &&
    summary.ml_engine_status === chain.analysis.ml_engine_status &&
    sameIds(
      summary.capture_ids,
      chain.captures.map((capture) => capture.capture_id).sort(),
    ) &&
    sameIds(
      summary.session_ids,
      chain.sessions.map((session) => session.session_id).sort(),
    ) &&
    sameIds(
      summary.finding_ids,
      chain.findings.map((finding) => finding.finding_id).sort(),
    ) &&
    summary.capture_count === chain.captures.length &&
    summary.session_count === chain.sessions.length &&
    summary.evidence_count === chain.evidence.length &&
    summary.protocol_event_count === chain.protocol_events.length &&
    summary.derived_fact_count === chain.derived_facts.length &&
    summary.rule_evaluation_count === chain.rule_evaluations.length &&
    summary.finding_count === chain.findings.length &&
    summary.recommendation_count === chain.recommendations.length;

  if (!valid) {
    throw new ApiRequestError(
      "The backend analysis summary and Chain-of-Proof response are inconsistent. No result was displayed.",
      "api_contract_inconsistent",
    );
  }
}

export class ApiAnalysisDataSource implements AnalysisSubmissionDataSource {
  async createAnalysis(file: File): Promise<CreateAnalysisResponse> {
    const validation = validateCaptureFile(file);
    if (!validation.success) {
      throw new CaptureValidationError(validation.error.issues[0].message);
    }

    const formData = new FormData();
    formData.append("capture", file, file.name);

    const payload = parsePayload(
      apiCreateResponseSchema,
      await requestJson(endpoint("api/v1/analyses"), {
        method: "POST",
        body: formData,
      }),
      "The backend returned an invalid analysis submission response. No successful result was assumed.",
    );

    return createAnalysisResponseSchema.parse({
      ...payload,
      original_filename: file.name,
      data_source: "api",
    });
  }

  async getResult(analysisId: string): Promise<AnalysisResult> {
    const encodedId = encodeURIComponent(analysisId);
    const [summaryPayload, chainPayload] = await Promise.all([
      requestJson(
        endpoint(`api/v1/analyses/${encodedId}`),
        undefined,
        analysisId,
      ),
      requestJson(
        endpoint(`api/v1/analyses/${encodedId}/chain`),
        undefined,
        analysisId,
      ),
    ]);

    const summary = parsePayload(
      apiAnalysisSummarySchema,
      summaryPayload,
      "The backend returned an invalid analysis summary. No result was displayed.",
    );
    const chain = parsePayload(
      chainOfProofSchema,
      chainPayload,
      "The backend returned an invalid Chain-of-Proof response. No result was displayed.",
    );
    assertSummaryMatchesChain(summary, chain);

    return analysisResultSchema.parse({
      dataset_label: null,
      dataset_kind: "production_analysis_result",
      data_source: "api",
      chain,
    });
  }
}
