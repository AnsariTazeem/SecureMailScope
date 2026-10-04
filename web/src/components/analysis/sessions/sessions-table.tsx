"use client";

import { useMemo } from "react";
import Link from "next/link";
import {
  createColumnHelper,
  createSortedRowModel,
  rowSortingFeature,
  sortFn_alphanumeric,
  sortFn_text,
  tableFeatures,
  useTable,
} from "@tanstack/react-table";
import {
  ArrowDown,
  ArrowRight,
  ArrowUp,
  ArrowUpDown,
} from "lucide-react";

import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { SESSION_ID } from "@/lib/contracts/ids";
import { cn } from "@/lib/utils";

import { formatEndpoint, humanize } from "./session-formatters";
import {
  completenessLabels,
  tlsTransitionLabels,
  type SessionExplorerRow,
} from "./session-view-model";

const tableFeatureSet = tableFeatures({
  rowSortingFeature,
  sortedRowModel: createSortedRowModel(),
  sortFns: {
    alphanumeric: sortFn_alphanumeric,
    text: sortFn_text,
  },
});

const columnHelper = createColumnHelper<
  typeof tableFeatureSet,
  SessionExplorerRow
>();

const severityStyles: Record<string, string> = {
  critical: "border-red-300 bg-red-50 text-red-800",
  high: "border-orange-300 bg-orange-50 text-orange-800",
  medium: "border-amber-300 bg-amber-50 text-amber-800",
  low: "border-neutral-300 bg-neutral-50 text-neutral-700",
  info: "border-blue-300 bg-blue-50 text-blue-800",
};

function SessionLink({
  analysisId,
  sessionId,
  compact = false,
  label = "Open X-Ray",
}: {
  analysisId: string;
  sessionId: string;
  compact?: boolean;
  label?: string;
}) {
  if (!SESSION_ID.test(sessionId)) {
    return (
      <span className="text-xs text-neutral-500" title="Invalid session ID">
        Link unavailable
      </span>
    );
  }

  return (
    <Link
      href={`/analysis/${analysisId}/sessions/${sessionId}`}
      className={cn(
        "inline-flex min-h-9 items-center justify-center gap-1.5 rounded-md border border-neutral-300 bg-white px-3 text-xs font-semibold text-neutral-900 outline-none hover:bg-neutral-50 focus-visible:ring-2 focus-visible:ring-neutral-950 focus-visible:ring-offset-2",
        compact && "w-full sm:w-auto",
      )}
      aria-label={`Open Session X-Ray for ${sessionId}`}
    >
      {label}
      <ArrowRight className="size-3.5" aria-hidden />
    </Link>
  );
}

function TransitionEvidence({ row }: { row: SessionExplorerRow }) {
  if (row.transitionEvidenceStates.length === 0) {
    return <span className="text-neutral-500">Not available</span>;
  }

  return (
    <span className="text-neutral-700">
      {row.transitionEvidenceStates
        .map(
          ({ eventStatus, observability }) =>
            `${humanize(eventStatus)} / ${humanize(observability)}`,
        )
        .join(" · ")}
    </span>
  );
}

function EndpointsCell({ row }: { row: SessionExplorerRow }) {
  const source = formatEndpoint(row.sourceIp, row.sourcePort);
  const destination = formatEndpoint(row.destinationIp, row.destinationPort);

  return (
    <div className="min-w-0 space-y-0.5 font-mono text-[11px] leading-4 text-neutral-900">
      <div className="flex min-w-0 gap-1.5">
        <span className="w-6 shrink-0 font-sans text-[10px] font-semibold uppercase tracking-wide text-neutral-500">
          Src
        </span>
        <span className="min-w-0 break-all">{source}</span>
      </div>
      <div className="flex min-w-0 gap-1.5">
        <ArrowRight
          className="mt-0.5 size-3 shrink-0 text-neutral-500"
          aria-hidden
        />
        <span className="w-6 shrink-0 font-sans text-[10px] font-semibold uppercase tracking-wide text-neutral-500">
          Dst
        </span>
        <span className="min-w-0 break-all">{destination}</span>
      </div>
    </div>
  );
}

export function SessionsTable({
  rows,
  analysisId,
}: {
  rows: SessionExplorerRow[];
  analysisId: string;
}) {
  const columns = useMemo(
    () =>
      columnHelper.columns([
        columnHelper.accessor("protocol", {
          header: "Protocol",
          sortFn: "text",
          cell: ({ getValue }) => (
            <Badge
              variant="outline"
              className="rounded-md border-neutral-300 bg-neutral-50 font-mono uppercase"
            >
              {getValue()}
            </Badge>
          ),
        }),
        columnHelper.accessor(
          (row) =>
            `${formatEndpoint(row.sourceIp, row.sourcePort)} → ${formatEndpoint(
              row.destinationIp,
              row.destinationPort,
            )}`,
          {
            id: "endpoints",
            header: "Affected endpoints",
            sortFn: "alphanumeric",
            cell: ({ row }) => <EndpointsCell row={row.original} />,
          },
        ),
        columnHelper.accessor("tlsTransition", {
          header: "Encryption transition",
          sortFn: "text",
          cell: ({ getValue, row }) => (
            <div className="space-y-1 text-xs leading-4">
              <span className="block font-medium text-neutral-950">
                {tlsTransitionLabels[getValue()]}
              </span>
              <span className="block text-[11px] leading-4 text-neutral-600">
                <TransitionEvidence row={row.original} />
              </span>
            </div>
          ),
        }),
        columnHelper.accessor("highestFindingSeverity", {
          header: "Risk",
          sortFn: (left, right) => {
            const order: Record<string, number> = {
              critical: 0,
              high: 1,
              medium: 2,
              low: 3,
              info: 4,
            };
            return (
              (order[left.original.highestFindingSeverity ?? ""] ?? 99) -
              (order[right.original.highestFindingSeverity ?? ""] ?? 99)
            );
          },
          cell: ({ row }) =>
            row.original.highestFindingSeverity ? (
              <div className="space-y-1">
                <Badge
                  variant="outline"
                  className={cn(
                    "rounded-md uppercase",
                    severityStyles[row.original.highestFindingSeverity] ??
                      severityStyles.info,
                  )}
                >
                  {row.original.highestFindingSeverity}
                </Badge>
                <span className="block text-[11px] text-neutral-600">
                  {row.original.linkedFindingCount} linked finding
                  {row.original.linkedFindingCount === 1 ? "" : "s"}
                </span>
              </div>
            ) : (
              <span className="text-neutral-600">No linked finding</span>
            ),
        }),
        columnHelper.accessor("evidenceConfidence", {
          header: "Evidence",
          sortFn: "text",
          cell: ({ getValue, row }) => (
            <div className="text-xs leading-4">
              <span className="font-medium text-neutral-950">
                {getValue() ? `${humanize(getValue()!)} confidence` : "Not supplied"}
              </span>
              <span className="mt-1 block text-[11px] text-neutral-600">
                {completenessLabels[row.original.completeness]}
              </span>
            </div>
          ),
        }),
        columnHelper.display({
          id: "open",
          header: "Action",
          cell: ({ row }) => (
            <SessionLink
              analysisId={analysisId}
              sessionId={row.original.sessionId}
              label="Investigate"
            />
          ),
        }),
      ]),
    [analysisId],
  );

  const table = useTable({
    features: tableFeatureSet,
    columns,
    data: rows,
    getRowId: (row) => row.sessionId,
    initialState: {
      sorting: [
        { id: "highestFindingSeverity", desc: false },
        { id: "protocol", desc: false },
      ],
    },
    enableSortingRemoval: false,
  });
  const tableRows = table.getRowModel().rows;

  return (
    <>
      <div className="hidden overflow-hidden rounded-lg border border-neutral-200 bg-white shadow-sm xl:block">
        <Table
          aria-label="Filtered reconstructed sessions"
          className="w-full table-fixed text-xs"
        >
          <colgroup>
            <col className="w-[10%]" />
            <col className="w-[27%]" />
            <col className="w-[25%]" />
            <col className="w-[13%]" />
            <col className="w-[13%]" />
            <col className="w-[12%]" />
          </colgroup>
          <TableHeader className="bg-neutral-50">
            {table.getHeaderGroups().map((headerGroup) => (
              <TableRow key={headerGroup.id}>
                {headerGroup.headers.map((header) => {
                  const sorted = header.column.getIsSorted();
                  const canSort = header.column.getCanSort();
                  return (
                    <TableHead
                      key={header.id}
                      aria-sort={
                        canSort
                          ? sorted === "asc"
                            ? "ascending"
                            : sorted === "desc"
                              ? "descending"
                              : "none"
                          : undefined
                      }
                      className="px-2 text-[10px] font-bold uppercase tracking-[0.06em] whitespace-normal text-neutral-600"
                    >
                      {header.isPlaceholder ? null : canSort ? (
                        <button
                          type="button"
                          onClick={header.column.getToggleSortingHandler()}
                          className="inline-flex min-h-9 items-center gap-1.5 rounded-md outline-none hover:text-neutral-950 focus-visible:ring-2 focus-visible:ring-neutral-950 focus-visible:ring-offset-2"
                        >
                          <table.FlexRender header={header} />
                          {sorted === "asc" ? (
                            <ArrowUp className="size-3.5" aria-hidden />
                          ) : sorted === "desc" ? (
                            <ArrowDown className="size-3.5" aria-hidden />
                          ) : (
                            <ArrowUpDown className="size-3.5" aria-hidden />
                          )}
                        </button>
                      ) : (
                        <table.FlexRender header={header} />
                      )}
                    </TableHead>
                  );
                })}
              </TableRow>
            ))}
          </TableHeader>
          <TableBody>
            {tableRows.map((row) => (
              <TableRow key={row.id}>
                {row.getAllCells().map((cell) => (
                  <TableCell
                    key={cell.id}
                    className="min-w-0 px-2 py-3 text-xs whitespace-normal"
                  >
                    <table.FlexRender cell={cell} />
                  </TableCell>
                ))}
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>

      <div className="grid gap-3 xl:hidden">
        {tableRows.map((tableRow) => {
          const row = tableRow.original;
          return (
            <article
              key={row.sessionId}
              className="min-w-0 rounded-lg border border-neutral-200 bg-white p-4 shadow-sm"
            >
              <div className="flex min-w-0 items-start justify-between gap-3">
                <div className="min-w-0">
                  <Badge
                    variant="outline"
                    className="rounded-md border-neutral-300 bg-neutral-50 font-mono uppercase"
                  >
                    {row.protocol}
                  </Badge>
                  <p className="mt-2 break-all font-mono text-xs leading-5 text-neutral-800">
                    {formatEndpoint(row.sourceIp, row.sourcePort)} →{" "}
                    {formatEndpoint(row.destinationIp, row.destinationPort)}
                  </p>
                </div>
                {row.highestFindingSeverity ? (
                  <Badge
                    variant="outline"
                    className={cn(
                      "rounded-md uppercase",
                      severityStyles[row.highestFindingSeverity] ??
                        severityStyles.info,
                    )}
                  >
                    {row.highestFindingSeverity}
                  </Badge>
                ) : null}
              </div>
              <dl className="mt-4 grid min-w-0 gap-4 sm:grid-cols-2">
                <div>
                  <dt className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
                    Encryption transition
                  </dt>
                  <dd className="mt-1 text-xs leading-5 text-neutral-950">
                    {tlsTransitionLabels[row.tlsTransition]}
                  </dd>
                </div>
                <div>
                  <dt className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
                    Findings
                  </dt>
                  <dd className="mt-1 text-xs text-neutral-950">
                    {row.linkedFindingCount > 0
                      ? `${row.linkedFindingCount} linked · ${humanize(row.evidenceConfidence ?? "unknown")} confidence`
                      : "No linked finding"}
                  </dd>
                </div>
              </dl>
              <details className="mt-4 rounded-md border border-neutral-200 bg-neutral-50 px-3 py-2">
                <summary className="cursor-pointer text-xs font-medium text-neutral-700">
                  Technical session details
                </summary>
                <dl className="mt-3 grid gap-3 text-xs sm:grid-cols-2">
                  <div>
                    <dt className="text-neutral-500">Session ID</dt>
                    <dd className="break-all font-mono">{row.sessionId}</dd>
                  </div>
                  <div>
                    <dt className="text-neutral-500">TCP stream</dt>
                    <dd className="font-mono">{row.tcpStreamId}</dd>
                  </div>
                  <div>
                    <dt className="text-neutral-500">Completeness</dt>
                    <dd>{completenessLabels[row.completeness]}</dd>
                  </div>
                  <div>
                    <dt className="text-neutral-500">Capture</dt>
                    <dd className="break-all">
                      {row.captureName ?? "Not supplied"}
                    </dd>
                  </div>
                </dl>
              </details>
              <div className="mt-4 border-t border-neutral-200 pt-4">
                <SessionLink
                  analysisId={analysisId}
                  sessionId={row.sessionId}
                  compact
                  label="Investigate session"
                />
              </div>
            </article>
          );
        })}
      </div>
    </>
  );
}
