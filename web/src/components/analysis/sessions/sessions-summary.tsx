import {
  BrainCircuit,
  Database,
  Network,
  ShieldCheck,
  TableProperties,
} from "lucide-react";

import { Card, CardContent } from "@/components/ui/card";

import { humanize, pluralize } from "./session-formatters";
import type { SessionsExplorerData } from "./session-view-model";

function MetricCard({
  label,
  value,
  detail,
  icon: Icon,
}: {
  label: string;
  value: string;
  detail: string;
  icon: typeof Network;
}) {
  return (
    <Card className="rounded-lg border-neutral-200 shadow-sm ring-0">
      <CardContent className="flex h-full items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
            {label}
          </p>
          <p className="mt-2 break-words text-xl font-semibold tracking-tight text-neutral-950">
            {value}
          </p>
          <p className="mt-2 text-xs leading-5 text-neutral-600">{detail}</p>
        </div>
        <span className="flex size-9 shrink-0 items-center justify-center rounded-md border border-neutral-200 bg-neutral-50 text-neutral-600">
          <Icon className="size-4" aria-hidden />
        </span>
      </CardContent>
    </Card>
  );
}

export function SessionsSummary({ data }: { data: SessionsExplorerData }) {
  const notComplete =
    data.captureIncompleteSessions + data.insufficientSessions;
  const protocolSummary = data.protocolCounts.length
    ? data.protocolCounts
        .map(({ protocol, count }) => `${protocol.toUpperCase()} ${count}`)
        .join(" · ")
    : "No protocol records";
  const mlValue = humanize(data.mlEngineStatus);
  const mlDetail = (() => {
    if (data.mlEngineStatus === "not_run") {
      return "Anomaly scoring was not run; no ML value is implied.";
    }
    if (
      data.mlEngineStatus === "failed" ||
      data.mlEngineStatus === "unavailable"
    ) {
      return `The engine reported ${humanize(data.mlEngineStatus)}; no anomaly value is inferred.`;
    }
    return `${pluralize(data.anomalyResultCount, "validated anomaly result")} available; Policy Risk remains separate.`;
  })();

  return (
    <section aria-labelledby="sessions-summary-heading">
      <div className="mb-3 flex items-end justify-between gap-4">
        <div>
          <p className="text-[10px] font-bold uppercase tracking-[0.08em] text-neutral-500">
            Validated result
          </p>
          <h2
            id="sessions-summary-heading"
            className="mt-1 text-base font-semibold text-neutral-950"
          >
            Session summary
          </h2>
        </div>
      </div>
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
        <MetricCard
          label="Reconstructed"
          value={data.totalSessions.toLocaleString("en")}
          detail="Validated session records in this analysis."
          icon={Network}
        />
        <MetricCard
          label="Completeness"
          value={`${data.completeSessions} complete`}
          detail={`${notComplete} not complete: ${data.captureIncompleteSessions} capture incomplete, ${data.insufficientSessions} insufficient.`}
          icon={TableProperties}
        />
        <MetricCard
          label="Protocols"
          value={data.protocolCounts.length.toLocaleString("en")}
          detail={protocolSummary}
          icon={Database}
        />
        <MetricCard
          label="Linked policy findings"
          value={data.sessionsWithFindings.toLocaleString("en")}
          detail="Sessions with at least one validated finding link; no severity is inferred here."
          icon={ShieldCheck}
        />
        <MetricCard
          label="ML anomaly state"
          value={mlValue}
          detail={mlDetail}
          icon={BrainCircuit}
        />
      </div>
    </section>
  );
}
