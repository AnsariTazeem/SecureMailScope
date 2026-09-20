"use client";

import Link from "next/link";
import { useMemo, useState, type ReactNode } from "react";
import { FilterX, Search, TableProperties } from "lucide-react";

import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";

import { pluralize } from "./session-formatters";
import {
  completenessLabels,
  tlsTransitionLabels,
  type SessionsExplorerData,
} from "./session-view-model";
import { SessionsSummary } from "./sessions-summary";
import { SessionsTable } from "./sessions-table";

const filterSelectClassName =
  "h-9 w-full min-w-0 rounded-lg border border-input bg-white px-2.5 text-sm text-neutral-900 outline-none transition-colors focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50";

function EmptyDataset() {
  return (
    <section className="rounded-lg border border-dashed border-neutral-300 bg-white px-5 py-12 text-center shadow-sm">
      <TableProperties
        className="mx-auto size-8 text-neutral-400"
        aria-hidden
      />
      <h2 className="mt-4 text-base font-semibold text-neutral-950">
        No reconstructed sessions
      </h2>
      <p className="mx-auto mt-2 max-w-xl text-sm leading-6 text-neutral-600">
        The validated analysis result contains an empty sessions collection. No
        session records or conclusions were synthesized.
      </p>
    </section>
  );
}

function FilterField({
  id,
  label,
  value,
  onChange,
  children,
}: {
  id: string;
  label: string;
  value: string;
  onChange: (value: string) => void;
  children: ReactNode;
}) {
  return (
    <div className="min-w-0">
      <label
        htmlFor={id}
        className="mb-1.5 block text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500"
      >
        {label}
      </label>
      <select
        id={id}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className={filterSelectClassName}
      >
        {children}
      </select>
    </div>
  );
}

export function SessionsExplorer({ data }: { data: SessionsExplorerData }) {
  const [search, setSearch] = useState("");
  const [protocolFilter, setProtocolFilter] = useState("all");
  const [captureFilter, setCaptureFilter] = useState("all");
  const [completenessFilter, setCompletenessFilter] = useState("all");
  const [transitionFilter, setTransitionFilter] = useState("all");
  const [findingFilter, setFindingFilter] = useState("all");

  const completenessOptions = useMemo(
    () => [...new Set(data.rows.map((row) => row.completeness))].sort(),
    [data.rows],
  );
  const transitionOptions = useMemo(
    () =>
      [...new Set(data.rows.map((row) => row.tlsTransition))].sort(
        (left, right) =>
          tlsTransitionLabels[left].localeCompare(tlsTransitionLabels[right]),
      ),
    [data.rows],
  );
  const filteredRows = useMemo(() => {
    const query = search.trim().toLocaleLowerCase("en-US");

    return data.rows.filter((row) => {
      const matchesSearch =
        query.length === 0 ||
        [
          row.sessionId,
          row.sourceIp,
          String(row.sourcePort),
          row.destinationIp,
          String(row.destinationPort),
          row.protocol,
        ].some((value) => value.toLocaleLowerCase("en-US").includes(query));
      const matchesProtocol =
        protocolFilter === "all" || row.protocol === protocolFilter;
      const matchesCapture =
        captureFilter === "all" || row.captureId === captureFilter;
      const matchesCompleteness =
        completenessFilter === "all" || row.completeness === completenessFilter;
      const matchesTransition =
        transitionFilter === "all" || row.tlsTransition === transitionFilter;
      const matchesFindings =
        findingFilter === "all" ||
        (findingFilter === "with" && row.linkedFindingCount > 0) ||
        (findingFilter === "without" && row.linkedFindingCount === 0);

      return (
        matchesSearch &&
        matchesProtocol &&
        matchesCapture &&
        matchesCompleteness &&
        matchesTransition &&
        matchesFindings
      );
    });
  }, [
    captureFilter,
    completenessFilter,
    data.rows,
    findingFilter,
    protocolFilter,
    search,
    transitionFilter,
  ]);
  const hasActiveControls =
    search !== "" ||
    protocolFilter !== "all" ||
    captureFilter !== "all" ||
    completenessFilter !== "all" ||
    transitionFilter !== "all" ||
    findingFilter !== "all";

  function clearAll() {
    setSearch("");
    setProtocolFilter("all");
    setCaptureFilter("all");
    setCompletenessFilter("all");
    setTransitionFilter("all");
    setFindingFilter("all");
  }

  return (
    <div className="mx-auto min-w-0 w-full max-w-[96rem] space-y-6">
      <div className="flex justify-end">
        {data.rows.length >= 2 ? (
          <Link
            href={`/analysis/${data.analysisId}/compare`}
            className="rounded-md border border-border bg-card px-4 py-2 text-sm font-medium focus-visible:outline-2"
          >
            Compare sessions
          </Link>
        ) : null}
      </div>
      <header className="flex min-w-0 flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
        <div className="min-w-0">
          <p className="text-[11px] font-bold uppercase tracking-[0.08em] text-neutral-500">
            Analysis / Sessions
          </p>
          <h1 className="mt-1 text-2xl font-semibold tracking-tight text-neutral-950 sm:text-3xl">
            Sessions Explorer
          </h1>
          <p className="mt-2 max-w-3xl text-sm leading-6 text-neutral-600">
            Investigate validated reconstructed-session metadata. Ports support
            navigation and search; they are not treated as protocol proof.
          </p>
        </div>
        <dl className="w-full min-w-0 rounded-lg border border-neutral-200 bg-white px-4 py-3 shadow-sm sm:w-80 sm:shrink-0">
          <div>
            <dt className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
              Analysis ID
            </dt>
            <dd
              className="mt-1 block truncate font-mono text-xs text-neutral-950"
              title={data.analysisId}
            >
              {data.analysisId}
            </dd>
          </div>
          <div className="mt-2 border-t border-neutral-100 pt-2">
            <dt className="sr-only">Total validated sessions</dt>
            <dd className="text-xs text-neutral-600">
              {pluralize(data.totalSessions, "validated session")}
            </dd>
          </div>
        </dl>
      </header>

      <SessionsSummary data={data} />

      {data.totalSessions === 0 ? (
        <EmptyDataset />
      ) : (
        <section
          aria-labelledby="session-inventory-heading"
          className="min-w-0"
        >
          <Card className="rounded-lg border-neutral-200 shadow-sm ring-0">
            <CardHeader className="border-b border-neutral-200">
              <CardTitle>
                <h2 id="session-inventory-heading">Session inventory</h2>
              </CardTitle>
              <CardDescription>
                Search and filter only validated session metadata and explicit
                record relationships.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-5">
              <div className="space-y-4">
                <div className="min-w-0">
                  <label
                    htmlFor="session-search"
                    className="mb-1.5 block text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500"
                  >
                    Search sessions
                  </label>
                  <div className="relative">
                    <Search
                      className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-neutral-400"
                      aria-hidden
                    />
                    <Input
                      id="session-search"
                      type="search"
                      value={search}
                      onChange={(event) => setSearch(event.target.value)}
                      placeholder="ID, IP, port, or protocol"
                      className="h-9 bg-white pl-8"
                      aria-describedby="session-search-help"
                    />
                  </div>
                  <p id="session-search-help" className="sr-only">
                    Case-insensitive search across session ID, source and
                    destination IP addresses and ports, and protocol.
                  </p>
                </div>
                <fieldset>
                  <legend className="mb-2 text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
                    Filters
                  </legend>
                  <div className="grid min-w-0 gap-3 sm:grid-cols-2 md:grid-cols-3 xl:grid-cols-5">
                    <FilterField
                      id="protocol-filter"
                      label="Protocol"
                      value={protocolFilter}
                      onChange={setProtocolFilter}
                    >
                      <option value="all">All protocols</option>
                      {data.protocolCounts.map(({ protocol, count }) => (
                        <option key={protocol} value={protocol}>
                          {protocol.toUpperCase()} ({count})
                        </option>
                      ))}
                    </FilterField>
                    <FilterField
                      id="capture-filter"
                      label="Capture record"
                      value={captureFilter}
                      onChange={setCaptureFilter}
                    >
                      <option value="all">All captures</option>
                      {data.captureOptions.map(({ captureId, captureName }) => (
                        <option key={captureId} value={captureId}>
                          {captureName ?? `Unavailable record (${captureId})`}
                        </option>
                      ))}
                    </FilterField>
                    <FilterField
                      id="completeness-filter"
                      label="Completeness"
                      value={completenessFilter}
                      onChange={setCompletenessFilter}
                    >
                      <option value="all">All states</option>
                      {completenessOptions.map((value) => (
                        <option key={value} value={value}>
                          {completenessLabels[value]}
                        </option>
                      ))}
                    </FilterField>
                    <FilterField
                      id="transition-filter"
                      label="TLS transition"
                      value={transitionFilter}
                      onChange={setTransitionFilter}
                    >
                      <option value="all">All states</option>
                      {transitionOptions.map((value) => (
                        <option key={value} value={value}>
                          {tlsTransitionLabels[value]}
                        </option>
                      ))}
                    </FilterField>
                    <FilterField
                      id="finding-filter"
                      label="Policy findings"
                      value={findingFilter}
                      onChange={setFindingFilter}
                    >
                      <option value="all">All sessions</option>
                      <option value="with">With linked findings</option>
                      <option value="without">Without linked findings</option>
                    </FilterField>
                  </div>
                </fieldset>
              </div>

              <div className="flex flex-col gap-3 border-t border-neutral-200 pt-4 sm:flex-row sm:items-center sm:justify-between">
                <p
                  className="text-sm text-neutral-600"
                  role="status"
                  aria-live="polite"
                >
                  Showing {filteredRows.length.toLocaleString("en")} of{" "}
                  {data.totalSessions.toLocaleString("en")} validated sessions
                </p>
                <Button
                  type="button"
                  variant="outline"
                  size="lg"
                  onClick={clearAll}
                  disabled={!hasActiveControls}
                  className="w-full sm:w-auto"
                >
                  <FilterX className="size-4" aria-hidden />
                  Clear all
                </Button>
              </div>

              {filteredRows.length === 0 ? (
                <div className="rounded-lg border border-dashed border-neutral-300 bg-neutral-50 px-5 py-10 text-center">
                  <h3 className="text-sm font-semibold text-neutral-950">
                    No sessions match
                  </h3>
                  <p className="mx-auto mt-2 max-w-xl text-sm leading-6 text-neutral-600">
                    No validated session matches the current search and filter
                    combination. Clear the controls to restore the full result.
                  </p>
                  <Button
                    type="button"
                    variant="outline"
                    size="lg"
                    onClick={clearAll}
                    className="mt-4"
                  >
                    Clear search and filters
                  </Button>
                </div>
              ) : (
                <SessionsTable
                  rows={filteredRows}
                  analysisId={data.analysisId}
                />
              )}
            </CardContent>
          </Card>
        </section>
      )}
    </div>
  );
}
