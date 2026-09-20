"use client";

import { usePathname } from "next/navigation";

import { Badge } from "@/components/ui/badge";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { PROTOTYPE_ANALYSIS_ID } from "@/mocks/load-prototype-dataset";
import { useAnalysisWorkflow } from "@/stores/analysis-workflow";

export function DatasetBanner() {
  const pathname = usePathname();
  const workflowAnalysisId = useAnalysisWorkflow((state) => state.analysisId);
  const routeAnalysisId =
    pathname.match(/^\/analysis\/(ana_[0-9a-f]{16})(?:\/|$)/)?.[1] ?? null;
  const isTransientWorkflowRoute =
    pathname === "/analysis/processing" || pathname === "/analysis/complete";
  const activeAnalysisId = routeAnalysisId ??
    (isTransientWorkflowRoute ? workflowAnalysisId : null);

  if (activeAnalysisId !== PROTOTYPE_ANALYSIS_ID) return null;

  return (
    <Tooltip>
      <TooltipTrigger
        render={
          <Badge
            tabIndex={0}
            aria-label="Sample analysis: Demonstration results. No uploaded file was analyzed."
            variant="outline"
            className="rounded-md border-neutral-400 bg-neutral-50 font-medium text-neutral-900"
          />
        }
      >
        Sample analysis
      </TooltipTrigger>
      <TooltipContent>
        Demonstration results. No uploaded file was analyzed.
      </TooltipContent>
    </Tooltip>
  );
}
