import { z } from "zod";

import { publicConfig } from "@/lib/config/env";

export const ACCEPTED_CAPTURE_EXTENSIONS = [".pcap", ".pcapng"] as const;

function hasAcceptedExtension(filename: string): boolean {
  const normalized = filename.trim().toLowerCase();
  return ACCEPTED_CAPTURE_EXTENSIONS.some((extension) =>
    normalized.endsWith(extension),
  );
}

export function formatByteLimit(bytes: number): string {
  const mebibytes = bytes / (1024 * 1024);
  return `${Number.isInteger(mebibytes) ? mebibytes : mebibytes.toFixed(1)} MiB`;
}

export const captureFileSchema = z
  .custom<File>(
    (value) => typeof File !== "undefined" && value instanceof File,
    "Select a readable capture file.",
  )
  .refine((file) => hasAcceptedExtension(file.name), {
    message: "Unsupported file type. Choose a .pcap or .pcapng capture.",
  })
  .refine((file) => file.size > 0, {
    message: "The capture is empty. Choose a non-empty PCAP or PCAPNG file.",
  })
  .refine((file) => file.size <= publicConfig.maxCaptureBytes, {
    message: `The capture exceeds the ${formatByteLimit(publicConfig.maxCaptureBytes)} intake limit.`,
  });

export function validateCaptureFile(file: File) {
  return captureFileSchema.safeParse(file);
}
