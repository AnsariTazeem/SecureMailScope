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
        columnHelper.accessor("sessionId", {
          header: "Session ID",
          sortFn: "alphanumeric",
          cell: ({ getValue }) => (
            <span className="font-mono text-xs text-neutral-950">
              {getValue()}
            </span>
          ),
        }),
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
            header: "Endpoints",
            sortFn: "alphanumeric",
            cell: ({ row }) => <EndpointsCell row={row.original} />,
          },
        ),
        columnHelper.accessor("tcpStreamId", {
          header: "TCP stream",
          cell: ({ getValue }) => (
            <span className="font-mono text-xs">{getValue()}</span>
          ),
        }),
        columnHelper.accessor("completeness", {
          header: "Completeness",
          sortFn: "text",
          cell: ({ getValue }) => completenessLabels[getValue()],
        }),
        columnHelper.accessor("tlsTransition", {
          header: "TLS upgrade transition",
          sortFn: "text",
          cell: ({ getValue, row }) => (
            <div className="space-y-1 text-xs leading-4">
              <span className="block text-neutral-950">
                {tlsTransitionLabels[getValue()]}
              </span>
              <span className="block text-[11px] leading-4 text-neutral-600">
                <TransitionEvidence row={row.original} />
              </span>
            </div>
          ),
        }),
        columnHelper.accessor("linkedFindingCount", {
          header: "Linked findings",
          cell: ({ getValue }) =>
            getValue() > 0 ? `${getValue()} linked` : "None linked",
        }),
        columnHelper.display({
          id: "open",
          header: "Open",
          cell: ({ row }) => (
            <SessionLink
              analysisId={analysisId}
              sessionId={row.original.sessionId}
              label="Open"
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
      sorting: [{ id: "sessionId", desc: false }],
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
            <col className="w-[15%]" />
            <col className="w-[8%]" />
            <col className="w-[25%]" />
            <col className="w-[7%]" />
            <col className="w-[10%]" />
            <col className="w-[20%]" />
            <col className="w-[7%]" />
            <col className="w-[8%]" />
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
              <div className="flex min-w-0 flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
                <div className="min-w-0">
                  <p className="break-all font-mono text-xs font-semibold text-neutral-950">
                    {row.sessionId}
                  </p>
                  <p className="mt-1 break-all text-xs text-neutral-500">
                    {row.captureName ?? "Capture record unavailable"}
                  </p>
                </div>
                <Badge
                  variant="outline"
                  className="rounded-md border-neutral-300 bg-neutral-50 font-mono uppercase"
                >
                  {row.protocol}
                </Badge>
              </div>
              <dl className="mt-4 grid min-w-0 gap-4 sm:grid-cols-2">
                <div className="min-w-0">
                  <dt className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
                    Source endpoint
                  </dt>
                  <dd className="mt-1 break-all font-mono text-xs text-neutral-950">
                    {formatEndpoint(row.sourceIp, row.sourcePort)}
                  </dd>
                </div>
                <div className="min-w-0">
                  <dt className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
                    Destination endpoint
                  </dt>
                  <dd className="mt-1 break-all font-mono text-xs text-neutral-950">
                    {formatEndpoint(
                      row.destinationIp,
                      row.destinationPort,
                    )}
                  </dd>
                </div>
                <div>
                  <dt className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
                    TCP stream
                  </dt>
                  <dd className="mt-1 font-mono text-xs text-neutral-950">
                    {row.tcpStreamId}
                  </dd>
                </div>
                <div>
                  <dt className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
                    Completeness
                  </dt>
                  <dd className="mt-1 text-xs text-neutral-950">
                    {completenessLabels[row.completeness]}
                  </dd>
                </div>
                <div>
                  <dt className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
                    TLS upgrade transition
                  </dt>
                  <dd className="mt-1 text-xs leading-5 text-neutral-950">
                    {tlsTransitionLabels[row.tlsTransition]}
                  </dd>
                </div>
                <div>
                  <dt className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
                    Policy findings
                  </dt>
                  <dd className="mt-1 text-xs text-neutral-950">
                    {row.linkedFindingCount > 0
                      ? `${row.linkedFindingCount} linked`
                      : "None linked"}
                  </dd>
                </div>
                <div className="sm:col-span-2">
                  <dt className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
                    Evidence / observability
                  </dt>
                  <dd className="mt-1 text-xs leading-5 text-neutral-950">
                    <TransitionEvidence row={row} />
                  </dd>
                </div>
              </dl>
              <div className="mt-4 border-t border-neutral-200 pt-4">
                <SessionLink
                  analysisId={analysisId}
                  sessionId={row.sessionId}
                  compact
                />
              </div>
            </article>
          );
        })}
      </div>
    </>
  );
}
