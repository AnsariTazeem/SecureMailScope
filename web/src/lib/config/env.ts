export const DATA_MODES = ["mock", "api"] as const;

const BACKEND_DEFAULT_MAX_CAPTURE_BYTES = 512 * 1024 * 1024;

export type DataMode = (typeof DATA_MODES)[number];

function parseDataMode(value: string | undefined): DataMode {
  return value === "api" ? "api" : "mock";
}

function parsePositiveInteger(
  value: string | undefined,
  fallback: number,
): number {
  if (!value) return fallback;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : fallback;
}

/**
 * Public frontend configuration.
 *
 * Defaults match the F1 contract:
 *   NEXT_PUBLIC_DATA_MODE=mock
 *   NEXT_PUBLIC_API_BASE_URL=http://localhost:8000
 *   NEXT_PUBLIC_MAX_CAPTURE_BYTES=536870912
 *
 * `api` mode is reserved. It must not invent a successful backend integration.
 */
export const publicConfig = {
  dataMode: parseDataMode(process.env.NEXT_PUBLIC_DATA_MODE),
  apiBaseUrl:
    process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000",
  maxCaptureBytes: parsePositiveInteger(
    process.env.NEXT_PUBLIC_MAX_CAPTURE_BYTES,
    BACKEND_DEFAULT_MAX_CAPTURE_BYTES,
  ),
} as const;
