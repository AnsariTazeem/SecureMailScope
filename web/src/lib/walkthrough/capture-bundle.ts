import { validateCaptureFile } from "@/lib/validation/capture-file";

export const PREPARED_CAPTURE_BUNDLE = [
  {
    filename: "secure-chain.pcapng",
    sha256: "7f519c11f650392819e3d3d78dba5e1d286a08bc8b6375252c0097c898033a76",
  },
  {
    filename: "insecure-chain.pcapng",
    sha256: "def0ffe96f4da89bf98d7192644b0caa4f590114fac2bec4612e6bd0de4c6743",
  },
] as const;

export type CaptureBundleVerification =
  | { valid: true; canonicalFilenames: string[] }
  | { valid: false; errors: string[] };

async function sha256(file: File): Promise<string> {
  if (!globalThis.crypto?.subtle) {
    throw new Error("SHA-256 verification is unavailable in this browser.");
  }

  const digest = await globalThis.crypto.subtle.digest(
    "SHA-256",
    await file.arrayBuffer(),
  );

  return Array.from(new Uint8Array(digest), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
}

export async function verifyPreparedCaptureBundle(
  files: readonly File[],
): Promise<CaptureBundleVerification> {
  if (files.length !== PREPARED_CAPTURE_BUNDLE.length) {
    return {
      valid: false,
      errors: [
        "The required capture selection is incomplete.",
      ],
    };
  }

  const fileErrors = files.flatMap((file) => {
    const result = validateCaptureFile(file);
    return result.success
      ? []
      : result.error.issues.map((issue) => `${file.name}: ${issue.message}`);
  });

  if (fileErrors.length > 0) {
    return { valid: false, errors: fileErrors };
  }

  try {
    const hashes = await Promise.all(files.map(sha256));
    const expectedHashes = new Set(
      PREPARED_CAPTURE_BUNDLE.map((capture) => capture.sha256),
    );
    const receivedHashes = new Set(hashes);
    const exactMatch =
      receivedHashes.size === PREPARED_CAPTURE_BUNDLE.length &&
      [...expectedHashes].every((hash) => receivedHashes.has(hash));

    if (!exactMatch) {
      return {
        valid: false,
        errors: [
          "The selected capture files could not be verified for this analysis.",
        ],
      };
    }

    return {
      valid: true,
      canonicalFilenames: hashes.map((hash) => {
        const capture = PREPARED_CAPTURE_BUNDLE.find(
          (candidate) => candidate.sha256 === hash,
        );
        if (!capture) throw new Error("Verified capture identity is missing.");
        return capture.filename;
      }),
    };
  } catch (error) {
    return {
      valid: false,
      errors: [
        error instanceof Error
          ? error.message
          : "The capture files could not be verified.",
      ],
    };
  }
}
