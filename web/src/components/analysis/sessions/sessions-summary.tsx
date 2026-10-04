import { Database, Network, ShieldCheck, TableProperties } from "lucide-react";

import { Card, CardContent } from "@/components/ui/card";

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
      <CardContent className="flex h-full items-start justify-between gap-3 p-4">
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
  return (
    <section aria-labelledby="sessions-summary-heading">
      <div className="mb-3 flex items-end justify-between gap-4">
        <div>
          <h2
            id="sessions-summary-heading"
            className="text-base font-semibold text-neutral-950"
          >
            Session summary
          </h2>
        </div>
      </div>
      <div className="grid grid-cols-2 gap-3 xl:grid-cols-4">
        <MetricCard
          label="Reconstructed"
          value={data.totalSessions.toLocaleString("en")}
          detail="Sessions reconstructed from the supplied capture records."
          icon={Network}
        />
        <MetricCard
          label="Completeness"
          value={`${data.completeSessions} complete`}
          detail={
            notComplete === 0
              ? "All reconstructed sessions are complete."
              : `${notComplete} session${notComplete === 1 ? "" : "s"} need completeness review.`
          }
          icon={TableProperties}
        />
        <MetricCard
          label="Protocols"
          value={data.protocolCounts.length.toLocaleString("en")}
          detail={protocolSummary}
          icon={Database}
        />
        <MetricCard
          label="Sessions with findings"
          value={data.sessionsWithFindings.toLocaleString("en")}
          detail="Open these sessions first to review the linked evidence."
          icon={ShieldCheck}
        />
      </div>
    </section>
  );
}
