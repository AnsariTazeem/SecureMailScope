import { publicConfig } from "@/lib/config/env";
import {
  chainOfProofSchema,
  type ChainOfProof,
} from "@/lib/contracts/chain";
import { ANALYSIS_ID, FINDING_ID } from "@/lib/contracts/ids";

export type FindingArtifactFormat = "html" | "pdf";

export type DownloadFile = {
  blob: Blob;
  filename: string;
};

export class ExportDownloadError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ExportDownloadError";
  }
}

function endpoint(path: string): string {
  const base = publicConfig.apiBaseUrl.endsWith("/")
    ? publicConfig.apiBaseUrl
    : `${publicConfig.apiBaseUrl}/`;
  return new URL(path, base).toString();
}

function invalidResponseMessage(kind: "artifact" | "chain"): string {
  return kind === "chain"
    ? "The backend returned an invalid Chain JSON response. No file was downloaded."
    : "The backend returned an invalid finding artifact. No file was downloaded.";
}

async function requestDownload(
  url: string,
  kind: "artifact" | "chain",
): Promise<Response> {
  let response: Response;
  try {
    response = await fetch(url, {
      cache: "no-store",
      signal: AbortSignal.timeout(30_000),
    });
  } catch (error) {
    throw new ExportDownloadError(
      error instanceof Error && error.name === "TimeoutError"
        ? "The backend download timed out. No file was downloaded. Try again when the service is available."
        : "The production backend is unavailable. Check the configured API URL and backend service, then try again.",
    );
  }

  if (response.ok) return response;

  if (response.status === 404) {
    throw new ExportDownloadError(
      kind === "chain"
        ? "The authoritative Chain is no longer available for this analysis. No demo content was substituted."
        : "The requested finding artifact was not found. It may no longer be available from the backend.",
    );
  }
  if (response.status === 413) {
    throw new ExportDownloadError(
      kind === "chain"
        ? "The authoritative Chain exceeds the backend response limit and cannot be downloaded."
        : "The requested finding artifact exceeds the backend response limit and cannot be downloaded.",
    );
  }
  if (response.status === 500) {
    throw new ExportDownloadError(
      kind === "chain"
        ? "The backend could not return the authoritative Chain. No file was downloaded."
        : "The backend could not render the requested finding artifact. No file was downloaded.",
    );
  }

  throw new ExportDownloadError(
    `The production backend rejected the ${kind} download (HTTP ${response.status}). No file was downloaded.`,
  );
}

function filenameFromDisposition(
  response: Response,
  fallback: string,
  extension: string,
): string {
  const disposition = response.headers.get("content-disposition");
  const candidate = disposition?.match(/filename="?([^";]+)"?/i)?.[1];
  return candidate &&
    /^[A-Za-z0-9._-]+$/.test(candidate) &&
    candidate.toLowerCase().endsWith(extension)
    ? candidate
    : fallback;
}

export function createDemoChainDownload(
  analysisId: string,
  chain: ChainOfProof,
): DownloadFile {
  const parsed = chainOfProofSchema.safeParse(chain);
  if (
    !ANALYSIS_ID.test(analysisId) ||
    !parsed.success ||
    parsed.data.analysis.analysis_id !== analysisId
  ) {
    throw new ExportDownloadError(
      "The Prototype Analysis Dataset Chain is invalid. No file was downloaded.",
    );
  }

  return {
    blob: new Blob([`${JSON.stringify(parsed.data, null, 2)}\n`], {
      type: "application/json",
    }),
    filename: `${analysisId}.demo-chain.json`,
  };
}

export async function fetchRealChainDownload(
  analysisId: string,
): Promise<DownloadFile> {
  if (!ANALYSIS_ID.test(analysisId)) {
    throw new ExportDownloadError(
      "The analysis identifier is invalid. No file was downloaded.",
    );
  }

  const response = await requestDownload(
    endpoint(`api/v1/analyses/${encodeURIComponent(analysisId)}/chain`),
    "chain",
  );
  const contentType = response.headers.get("content-type")?.toLowerCase() ?? "";
  const blob = await response.blob();
  if (!contentType.includes("application/json") || blob.size === 0) {
    throw new ExportDownloadError(invalidResponseMessage("chain"));
  }

  let payload: unknown;
  try {
    payload = JSON.parse(await blob.text());
  } catch {
    throw new ExportDownloadError(invalidResponseMessage("chain"));
  }
  const parsed = chainOfProofSchema.safeParse(payload);
  if (!parsed.success || parsed.data.analysis.analysis_id !== analysisId) {
    throw new ExportDownloadError(invalidResponseMessage("chain"));
  }

  return {
    blob,
    filename: filenameFromDisposition(
      response,
      `${analysisId}.chain.json`,
      ".json",
    ),
  };
}

export async function fetchFindingArtifactDownload(
  analysisId: string,
  findingId: string,
  format: FindingArtifactFormat,
): Promise<DownloadFile> {
  if (!ANALYSIS_ID.test(analysisId) || !FINDING_ID.test(findingId)) {
    throw new ExportDownloadError(
      "The analysis or finding identifier is invalid. No file was downloaded.",
    );
  }

  const response = await requestDownload(
    endpoint(
      `api/v1/analyses/${encodeURIComponent(analysisId)}/findings/${encodeURIComponent(findingId)}/artifacts/${format}`,
    ),
    "artifact",
  );
  const contentType = response.headers.get("content-type")?.toLowerCase() ?? "";
  const blob = await response.blob();
  const validMediaType =
    format === "pdf"
      ? contentType.includes("application/pdf")
      : contentType.includes("text/html");
  const validPdfSignature =
    format !== "pdf" || (await blob.slice(0, 5).text()) === "%PDF-";
  if (!validMediaType || !validPdfSignature || blob.size === 0) {
    throw new ExportDownloadError(invalidResponseMessage("artifact"));
  }

  const extension = `.${format}`;
  return {
    blob,
    filename: filenameFromDisposition(
      response,
      `${findingId}.finding${extension}`,
      extension,
    ),
  };
}
