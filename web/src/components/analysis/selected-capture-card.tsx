import { FileCheck2, RefreshCw, Trash2 } from "lucide-react";

import { Button } from "@/components/ui/button";

function formatFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
}

type SelectedCaptureCardProps = {
  file: File;
  onReplace?: () => void;
  displayName?: string;
  onRemove: () => void;
};

export function SelectedCaptureCard({
  file,
  onReplace,
  displayName,
  onRemove,
}: SelectedCaptureCardProps) {
  return (
    <div className="flex flex-col gap-3 rounded-lg border border-neutral-200 bg-white p-4 sm:flex-row sm:items-center sm:justify-between">
      <div className="flex min-w-0 items-center gap-3">
        <span className="flex size-9 shrink-0 items-center justify-center rounded-md bg-[#ecfdf3] text-[#027a48]">
          <FileCheck2 className="size-4" aria-hidden />
        </span>
        <div className="min-w-0">
          <p className="truncate text-sm font-semibold text-neutral-950">
            {displayName ?? file.name}
          </p>
          <p className="text-xs text-neutral-500">
            {formatFileSize(file.size)} · ready for intake validation
          </p>
        </div>
      </div>
      <div className="flex items-center gap-2">
        {onReplace ? (
          <Button type="button" variant="outline" onClick={onReplace}>
            <RefreshCw className="size-3.5" aria-hidden />
            Replace
          </Button>
        ) : null}
        <Button type="button" variant="ghost" onClick={onRemove}>
          <Trash2 className="size-3.5" aria-hidden />
          Remove
        </Button>
      </div>
    </div>
  );
}
