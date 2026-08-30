import { Badge } from "@/components/ui/badge";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { DATASET_LABEL } from "@/lib/contracts/analysis";
import { publicConfig } from "@/lib/config/env";

export function DatasetBanner() {
  if (publicConfig.dataMode !== "mock") return null;

  return (
    <Tooltip>
      <TooltipTrigger
        render={
          <Badge
            variant="outline"
            className="rounded-md border-neutral-400 bg-neutral-50 font-medium text-neutral-900"
          />
        }
      >
        {DATASET_LABEL}
      </TooltipTrigger>
      <TooltipContent>
        Contract fixtures assembled for prototype UI work. Not a production
        analyzer run, live capture, or verified API result.
      </TooltipContent>
    </Tooltip>
  );
}
