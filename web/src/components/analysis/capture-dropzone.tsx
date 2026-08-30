"use client";

import { useCallback } from "react";
import { FileUp } from "lucide-react";
import {
  type FileError,
  type FileRejection,
  useDropzone,
} from "react-dropzone";

import { Button } from "@/components/ui/button";
import { SelectedCaptureCard } from "@/components/analysis/selected-capture-card";
import { cn } from "@/lib/utils";
import {
  formatByteLimit,
  validateCaptureFile,
} from "@/lib/validation/capture-file";
import { publicConfig } from "@/lib/config/env";

function zodFileValidator(file: File): FileError | null {
  const result = validateCaptureFile(file);
  if (result.success) return null;
  return {
    code: "capture-invalid",
    message: result.error.issues[0].message,
  };
}

type CaptureDropzoneProps = {
  selectedFile: File | null;
  errors: readonly string[];
  onSelect: (file: File) => void;
  onReject: (errors: string[]) => void;
  onRemove: () => void;
};

export function CaptureDropzone({
  selectedFile,
  errors,
  onSelect,
  onReject,
  onRemove,
}: CaptureDropzoneProps) {
  const onDrop = useCallback(
    (acceptedFiles: File[], fileRejections: FileRejection[]) => {
      if (fileRejections.length > 0) {
        onReject(
          fileRejections.flatMap((rejection) =>
            rejection.errors.map((error) => error.message),
          ),
        );
        return;
      }
      const file = acceptedFiles[0];
      if (file) onSelect(file);
    },
    [onReject, onSelect],
  );

  const {
    getRootProps,
    getInputProps,
    isDragActive,
    isDragAccept,
    isDragReject,
    open,
  } = useDropzone({
    accept: {
      "application/octet-stream": [".pcap", ".pcapng"],
      "application/vnd.tcpdump.pcap": [".pcap"],
      "application/x-pcapng": [".pcapng"],
    },
    multiple: false,
    maxFiles: 1,
    noClick: true,
    validator: zodFileValidator,
    onDrop,
  });

  return (
    <div className="space-y-3">
      <div
        {...getRootProps({
          role: "group",
          "aria-label": "PCAP or PCAPNG file selection",
        })}
        className={cn(
          "flex min-h-56 flex-col items-center justify-center rounded-lg border border-dashed bg-neutral-50 px-6 py-8 text-center transition-colors",
          isDragActive && "border-neutral-500 bg-neutral-100",
          isDragAccept && "border-[#027a48] bg-[#ecfdf3]",
          isDragReject && "border-[#b42318] bg-[#fef3f2]",
          errors.length > 0 && "border-[#b42318]",
        )}
      >
        <input
          {...getInputProps({
            "aria-label": "Choose one PCAP or PCAPNG capture",
          })}
        />
        <span className="mb-4 flex size-11 items-center justify-center rounded-full border border-neutral-200 bg-white text-neutral-700 shadow-xs">
          <FileUp className="size-5" aria-hidden />
        </span>
        <p className="text-sm font-semibold text-neutral-950">
          {isDragReject
            ? "This capture cannot be accepted"
            : isDragActive
              ? "Drop the capture to validate it"
              : "Drag and drop a capture here"}
        </p>
        <p className="mt-1 max-w-md text-xs leading-5 text-neutral-500">
          One .pcap or .pcapng file, up to{" "}
          {formatByteLimit(publicConfig.maxCaptureBytes)}. Selection does not
          modify the original capture.
        </p>
        <Button type="button" variant="outline" className="mt-5" onClick={open}>
          Choose file
        </Button>
      </div>

      {selectedFile ? (
        <SelectedCaptureCard
          file={selectedFile}
          onReplace={open}
          onRemove={onRemove}
        />
      ) : null}

      {errors.length > 0 ? (
        <div
          role="alert"
          className="rounded-lg border border-[#fecdca] bg-[#fef3f2] px-4 py-3 text-sm text-[#b42318]"
        >
          <p className="font-semibold">Capture validation failed</p>
          <ul className="mt-1 list-disc space-y-1 pl-5 text-xs">
            {[...new Set(errors)].map((error) => (
              <li key={error}>{error}</li>
            ))}
          </ul>
        </div>
      ) : null}
    </div>
  );
}
