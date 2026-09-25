"use client";

import { useEffect, useState } from "react";
import { Check, LoaderCircle } from "lucide-react";

import { cn } from "@/lib/utils";

const PROCESSING_STAGES = [
  "Capture integrity verified",
  "Analysis contract validated",
  "Sessions and evidence indexed",
  "Findings prioritized",
  "Recommendations linked",
  "Investigation workspace prepared",
] as const;

const STAGE_INTERVAL_MS = 450;
const COMPLETION_PAUSE_MS = 350;

export function ProcessingStageList({
  onComplete,
}: {
  onComplete: () => void;
}) {
  const [completedStages, setCompletedStages] = useState(0);
  const progress = Math.round(
    (completedStages / PROCESSING_STAGES.length) * 100,
  );

  useEffect(() => {
    const stageTimers = PROCESSING_STAGES.map((_, index) =>
      window.setTimeout(
        () => setCompletedStages(index + 1),
        (index + 1) * STAGE_INTERVAL_MS,
      ),
    );
    const completionTimer = window.setTimeout(
      onComplete,
      PROCESSING_STAGES.length * STAGE_INTERVAL_MS + COMPLETION_PAUSE_MS,
    );

    return () => {
      stageTimers.forEach(window.clearTimeout);
      window.clearTimeout(completionTimer);
    };
  }, [onComplete]);

  return (
    <div className="space-y-5 p-5 sm:p-6">
      <div>
        <div className="flex items-center justify-between gap-4 text-xs">
          <span className="font-semibold text-neutral-700">
            Analysis progress
          </span>
          <span
            className="tabular-nums text-neutral-500"
            aria-live="polite"
          >
            {progress}%
          </span>
        </div>
        <div
          className="mt-2 h-1.5 overflow-hidden rounded-full bg-neutral-100"
          role="progressbar"
          aria-label="Analysis preparation progress"
          aria-valuemin={0}
          aria-valuemax={100}
          aria-valuenow={progress}
        >
          <div
            className="h-full rounded-full bg-neutral-950 transition-[width] duration-300 ease-out"
            style={{ width: `${progress}%` }}
          />
        </div>
      </div>

      <ol className="space-y-2.5" aria-label="Analysis preparation stages">
        {PROCESSING_STAGES.map((stage, index) => {
          const complete = index < completedStages;
          const active =
            index === completedStages &&
            completedStages < PROCESSING_STAGES.length;

          return (
            <li
              key={stage}
              className={cn(
                "flex items-center gap-3 rounded-lg border px-3.5 py-3 transition-colors",
                complete && "border-[#abefc6] bg-[#f6fef9]",
                active && "border-neutral-300 bg-neutral-50",
                !complete && !active && "border-neutral-200 bg-white",
              )}
            >
              <span
                className={cn(
                  "flex size-7 shrink-0 items-center justify-center rounded-full border text-[11px] font-bold",
                  complete && "border-[#027a48] bg-[#027a48] text-white",
                  active && "border-neutral-950 bg-neutral-950 text-white",
                  !complete &&
                    !active &&
                    "border-neutral-300 bg-white text-neutral-500",
                )}
              >
                {complete ? (
                  <Check className="size-4" aria-hidden />
                ) : active ? (
                  <LoaderCircle className="size-4 animate-spin" aria-hidden />
                ) : (
                  index + 1
                )}
              </span>

              <span
                className={cn(
                  "min-w-0 flex-1 text-sm font-medium",
                  complete || active
                    ? "text-neutral-950"
                    : "text-neutral-500",
                )}
              >
                {stage}
              </span>

              <span
                className={cn(
                  "text-xs",
                  complete ? "text-[#027a48]" : "text-neutral-500",
                )}
              >
                {complete ? "Complete" : active ? "In progress" : "Pending"}
              </span>
            </li>
          );
        })}
      </ol>
    </div>
  );
}
