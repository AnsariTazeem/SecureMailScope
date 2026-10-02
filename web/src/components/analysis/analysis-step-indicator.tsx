import { Check } from "lucide-react";

import { cn } from "@/lib/utils";

const steps = ["Select capture", "Validate", "Analyze"] as const;

export function AnalysisStepIndicator({ activeStep }: { activeStep: number }) {
  return (
    <ol
      aria-label="Analysis progress"
      className="grid grid-cols-3 overflow-hidden rounded-lg border border-neutral-200 bg-white shadow-xs"
    >
      {steps.map((step, index) => {
        const complete = index < activeStep;
        const active = index === activeStep;

        return (
          <li
            key={step}
            aria-current={active ? "step" : undefined}
            className={cn(
              "relative flex min-w-0 flex-col items-center gap-2 border-r border-neutral-200 px-2 py-3 last:border-r-0 sm:flex-row sm:px-4",
              active && "bg-neutral-50",
            )}
          >
            <span
              className={cn(
                "flex size-6 shrink-0 items-center justify-center rounded-full border text-[11px] font-bold",
                complete && "border-[#027a48] bg-[#027a48] text-white",
                active && "border-neutral-950 bg-neutral-950 text-white",
                !complete && !active && "border-neutral-300 text-neutral-500",
              )}
            >
              {complete ? <Check className="size-3.5" aria-hidden /> : index + 1}
            </span>
            <span
              className={cn(
                "text-center text-[10px] font-bold uppercase tracking-[0.06em] sm:text-left sm:text-xs",
                active || complete ? "text-neutral-950" : "text-neutral-500",
              )}
            >
              {step}
            </span>
          </li>
        );
      })}
    </ol>
  );
}
