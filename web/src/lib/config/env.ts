const BACKEND_DEFAULT_MAX_CAPTURE_BYTES = 512 * 1024 * 1024;

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
 * Defaults match the production intake contract:
 *   NEXT_PUBLIC_API_BASE_URL=http://localhost:8000
 *   NEXT_PUBLIC_MAX_CAPTURE_BYTES=536870912
 */
export const publicConfig = {
  apiBaseUrl:
    process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000",
  maxCaptureBytes: parsePositiveInteger(
    process.env.NEXT_PUBLIC_MAX_CAPTURE_BYTES,
    BACKEND_DEFAULT_MAX_CAPTURE_BYTES,
  ),
} as const;
