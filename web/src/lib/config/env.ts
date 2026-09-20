import { SubmissionModeDisabledError } from "@/lib/api/errors";

const BACKEND_DEFAULT_MAX_CAPTURE_BYTES = 512 * 1024 * 1024;

export type ApplicationMode = "submission_demo" | "backend_connected";

function parseMode(value: string | undefined): ApplicationMode {
  if (value === undefined) return "submission_demo";
  if (value === "submission_demo" || value === "backend_connected") return value;
  throw new Error("Invalid NEXT_PUBLIC_SECUREMAILSCOPE_MODE: expected submission_demo or backend_connected.");
}

const mode = parseMode(process.env.NEXT_PUBLIC_SECUREMAILSCOPE_MODE);
const configuredApiUrl = process.env.NEXT_PUBLIC_API_BASE_URL;

function requireApiUrl(value: string | undefined): string {
  try {
    if (!value || !/^https?:\/\//i.test(value)) throw new Error();
    const url = new URL(value);
    if (!url.hostname || url.username || url.password || url.search || url.hash) throw new Error();
    return url.toString();
  } catch {
    throw new Error("backend_connected requires an explicit absolute HTTP(S) NEXT_PUBLIC_API_BASE_URL without credentials, query, or fragment.");
  }
}

const apiBaseUrl = mode === "backend_connected" ? requireApiUrl(configuredApiUrl) : null;

export const applicationCapabilities = Object.freeze({
  mode,
  liveAnalysis: mode === "backend_connected",
});

function parsePositiveInteger(
  value: string | undefined,
  fallback: number,
): number {
  if (!value) return fallback;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : fallback;
}

// Direct public env references are inlined by Next.js at build time.
export const publicConfig = Object.freeze({
  ...applicationCapabilities,
  get apiBaseUrl(): string {
    // Both existing API transports resolve this before fetch, including exports.
    if (apiBaseUrl === null) throw new SubmissionModeDisabledError();
    return apiBaseUrl;
  },
  maxCaptureBytes: parsePositiveInteger(
    process.env.NEXT_PUBLIC_MAX_CAPTURE_BYTES,
    BACKEND_DEFAULT_MAX_CAPTURE_BYTES,
  ),
});
