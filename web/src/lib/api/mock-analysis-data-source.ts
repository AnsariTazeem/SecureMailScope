import {
  loadPrototypeAnalysisDataset,
  PROTOTYPE_ANALYSIS_ID,
} from "@/mocks/load-prototype-dataset";
import type {
  AnalysisDataSource,
  AnalysisStatus,
  CreateAnalysisResponse,
} from "@/lib/contracts/analysis";
import { DATASET_LABEL } from "@/lib/contracts/analysis";
import { ANALYSIS_ID } from "@/lib/contracts/ids";
import {
  AnalysisNotFoundError,
  CaptureValidationError,
} from "@/lib/api/errors";
import { validateCaptureFile } from "@/lib/validation/capture-file";

const PROCESSING_MS = 2400;
const MOCK_STAGE_IDS = [
  "intake",
  "capture_provenance",
  "stream_reconstruction",
  "event_reconstruction",
  "tls_extraction",
  "fact_derivation",
] as const;

type Job = {
  createdAt: number;
  filename: string;
  forceFailure: boolean;
};

const jobs = new Map<string, Job>();

export function assertAcceptedCapture(file: File): void {
  const result = validateCaptureFile(file);
  if (!result.success) {
    throw new CaptureValidationError(result.error.issues[0].message);
  }
}

function assertKnownAnalysis(analysisId: string): void {
  if (!ANALYSIS_ID.test(analysisId)) {
    throw new AnalysisNotFoundError(analysisId);
  }
  if (analysisId !== PROTOTYPE_ANALYSIS_ID && !jobs.has(analysisId)) {
    throw new AnalysisNotFoundError(analysisId);
  }
}

export class MockAnalysisDataSource implements AnalysisDataSource {
  async createAnalysis(file: File): Promise<CreateAnalysisResponse> {
    assertAcceptedCapture(file);
    const analysisId = PROTOTYPE_ANALYSIS_ID;
    jobs.set(analysisId, {
      createdAt: Date.now(),
      filename: file.name,
      forceFailure: file.name.toLowerCase().includes("force-failure"),
    });
    return {
      analysis_id: analysisId,
      accepted_filename: file.name,
      dataset_label: DATASET_LABEL,
      data_source: "mock",
    };
  }

  async getStatus(analysisId: string): Promise<AnalysisStatus> {
    assertKnownAnalysis(analysisId);
    const job = jobs.get(analysisId);
    const elapsed = job ? Date.now() - job.createdAt : PROCESSING_MS;
    const stageDuration = PROCESSING_MS / MOCK_STAGE_IDS.length;
    const activeStageIndex = Math.min(
      MOCK_STAGE_IDS.length - 1,
      Math.floor(elapsed / stageDuration),
    );
    const stages = MOCK_STAGE_IDS.map((stage, index) => ({
      stage,
      status:
        elapsed >= PROCESSING_MS || index < activeStageIndex
          ? ("complete" as const)
          : index === activeStageIndex
            ? ("partial" as const)
            : ("not_run" as const),
      limitation: null,
      runtime_seconds: 0,
    }));

    if (job?.forceFailure) {
      return {
        analysis_id: analysisId,
        phase: "failed",
        current_stage: "intake",
        percent: 0,
        stages: stages.map((stage, index) => ({
          ...stage,
          status: index === 0 ? ("failed" as const) : ("not_run" as const),
        })),
        error: {
          code: "intake_failed",
          message:
            "Mock intake failed because the filename requested a forced failure. No cryptographic conclusion was produced.",
        },
      };
    }

    if (elapsed < stageDuration) {
      return {
        analysis_id: analysisId,
        phase: "queued",
        current_stage: MOCK_STAGE_IDS[0],
        percent: Math.max(5, Math.round((elapsed / PROCESSING_MS) * 100)),
        stages,
        error: null,
      };
    }
    if (elapsed < PROCESSING_MS) {
      return {
        analysis_id: analysisId,
        phase: "processing",
        current_stage: MOCK_STAGE_IDS[activeStageIndex],
        percent: Math.min(95, Math.round((elapsed / PROCESSING_MS) * 100)),
        stages,
        error: null,
      };
    }
    return {
      analysis_id: analysisId,
      phase: "complete",
      current_stage: null,
      percent: 100,
      stages,
      error: null,
    };
  }

  async getResult(analysisId: string) {
    const status = await this.getStatus(analysisId);
    if (status.phase === "failed") {
      throw new CaptureValidationError(
        status.error?.message ?? "Analysis failed.",
      );
    }
    if (status.phase !== "complete") {
      throw new CaptureValidationError(
        "The prototype analysis is still processing. Results are not available yet.",
      );
    }
    return loadPrototypeAnalysisDataset();
  }
}
