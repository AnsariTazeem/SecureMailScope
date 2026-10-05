"use client";

import { AnalysisBreadcrumbs } from "@/components/layout/analysis-breadcrumbs";

import { useCallback, useMemo, useRef, useState } from "react";
import Link from "next/link";
import { usePathname, useSearchParams, useRouter } from "next/navigation";
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
  ArrowUp,
  ArrowUpDown,
  Brain,
  ExternalLink,
  FileSearch,
  FilterX,
  ListChecks,
  Search,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
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

import { FindingDetailInspector } from "./finding-detail-inspector";
import {
  categoryLabels,
  engineStatusLabels,
  severityOrder,
  severityStyles,
  type AnomalyFindingsData,
  type FindingDetail,
  type PolicyFindingsData,
} from "./findings-view-model";
import { MLAnomalyExplorer } from "./ml-anomaly-explorer";

const filterSelectClassName =
  "h-9 w-full min-w-0 rounded-lg border border-input bg-white px-2.5 text-sm text-neutral-900 outline-none transition-colors focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50";

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
  FindingDetail
>();

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
  children: React.ReactNode;
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

function PolicyRiskPostureCard({
  policyRisk,
}: {
  policyRisk: PolicyFindingsData["policyRisk"];
}) {
  if (!policyRisk) {
    return (
      <Card className="rounded-lg border-neutral-200 shadow-sm ring-0">
        <CardContent className="flex h-full items-start justify-between gap-4 p-4">
          <div className="min-w-0">
            <p className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
              Policy Risk
            </p>
            <p className="mt-2 text-2xl font-semibold tracking-tight text-neutral-950">
              Not available
            </p>
            <p className="mt-2 text-xs leading-5 text-neutral-600">
              Policy risk summary not present in the validated result.
            </p>
          </div>
          <span className="flex size-9 shrink-0 items-center justify-center rounded-md border border-neutral-200 bg-neutral-50 text-neutral-600">
            <ShieldAlert className="size-4" aria-hidden />
          </span>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="rounded-lg border-neutral-200 shadow-sm ring-0">
      <CardContent className="flex h-full items-start justify-between gap-4 p-4">
        <div className="min-w-0">
          <p className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
            Policy Risk
          </p>
          <p className="mt-2 break-words text-2xl font-semibold tracking-tight text-neutral-950">
            {policyRisk.cappedScore}
            <span className="ml-1 text-sm font-normal text-neutral-500">
              / 100
            </span>
          </p>
          <p className="mt-2 text-xs leading-5 text-neutral-600">
            Higher means more deterministic policy risk ·{" "}
            {policyRisk.affectedSessionCount} affected session
            {policyRisk.affectedSessionCount !== 1 ? "s" : ""}
          </p>
        </div>
        <span className="flex size-9 shrink-0 items-center justify-center rounded-md border border-neutral-200 bg-neutral-50 text-neutral-600">
          <ShieldAlert className="size-4" aria-hidden />
        </span>
      </CardContent>
    </Card>
  );
}

function MLAnomalyPostureCard({
  anomaly,
}: {
  anomaly: AnomalyFindingsData;
}) {
  const statusLabel =
    engineStatusLabels[anomaly.mlEngineStatus] ?? anomaly.mlEngineStatus;
  const bands = [...new Set(anomaly.results.map((result) => result.band))];
  const resultLabel =
    bands.length > 0
      ? bands.map((band) => band.replaceAll("_", " ")).join(", ")
      : statusLabel;

  return (
    <Card className="rounded-lg border-neutral-200 shadow-sm ring-0">
      <CardContent className="flex h-full items-start justify-between gap-4 p-4">
        <div className="min-w-0">
          <p className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
            ML Anomaly
          </p>
          <p className="mt-2 text-2xl font-semibold tracking-tight text-neutral-950">
            {resultLabel}
          </p>
          <p className="mt-2 text-xs leading-5 text-neutral-600">
            {anomaly.resultCount} result
            {anomaly.resultCount !== 1 ? "s" : ""} · Kept separate from Policy
            Risk.
          </p>
        </div>
        <span className="flex size-9 shrink-0 items-center justify-center rounded-md border border-neutral-200 bg-neutral-50 text-neutral-600">
          <Brain className="size-4" aria-hidden />
        </span>
      </CardContent>
    </Card>
  );
}

function EmptyFindingsState() {
  return (
    <div className="rounded-lg border border-dashed border-neutral-300 bg-white px-5 py-12 text-center shadow-sm">
      <ShieldCheck
        className="mx-auto size-8 text-neutral-400"
        aria-hidden
      />
      <h2 className="mt-4 text-base font-semibold text-neutral-950">
        No validated policy findings
      </h2>
      <p className="mx-auto mt-2 max-w-xl text-sm leading-6 text-neutral-600">
        The validated analysis result contains no deterministic policy findings.
        No findings were synthesized or invented.
      </p>
    </div>
  );
}

function NoFilterResultsState({ onClear }: { onClear: () => void }) {
  return (
    <div className="rounded-lg border border-dashed border-neutral-300 bg-neutral-50 px-5 py-10 text-center">
      <h3 className="text-sm font-semibold text-neutral-950">
        No findings match
      </h3>
      <p className="mx-auto mt-2 max-w-xl text-sm leading-6 text-neutral-600">
        No validated finding matches the current search and filter combination.
        Clear the controls to restore the full result.
      </p>
      <Button
        type="button"
        variant="outline"
        size="lg"
        onClick={onClear}
        className="mt-4"
      >
        Clear search and filters
      </Button>
    </div>
  );
}

function FindingDesktopTable({
  rows,
  onSelect,
}: {
  rows: FindingDetail[];
  onSelect: (finding: FindingDetail, trigger: HTMLElement) => void;
}) {
  const columns = useMemo(
    () =>
      columnHelper.columns([
        columnHelper.accessor("title", {
          header: "Finding",
          sortFn: (left, right) =>
            left.original.title.localeCompare(right.original.title) ||
            left.original.findingId.localeCompare(right.original.findingId),
          cell: ({ row }) => (
            <div className="min-w-0">
              <p className="break-words text-sm font-medium text-neutral-950">
                {row.original.title}
              </p>
              <p className="mt-1 text-[11px] text-neutral-500">
                {categoryLabels[row.original.category] ?? row.original.category}
              </p>
            </div>
          ),
        }),
        columnHelper.accessor("severity", {
          header: "Priority",
          sortFn: (left, right) =>
            (severityOrder[left.original.severity] ?? 99) -
            (severityOrder[right.original.severity] ?? 99),
          cell: ({ getValue, row }) => (
            <div>
              <Badge
                variant="outline"
                className={cn(
                  "rounded-md uppercase",
                  severityStyles[getValue()] ?? severityStyles.info,
                )}
              >
                {getValue()}
              </Badge>
              <p className="mt-1 text-[10px] text-neutral-500">
                {row.original.evidenceConfidence} confidence
              </p>
            </div>
          ),
        }),
        columnHelper.accessor("impact", {
          header: "Why it matters",
          sortFn: "text",
          cell: ({ getValue }) => (
            <p className="line-clamp-3 text-xs leading-5 text-neutral-700">
              {getValue()}
            </p>
          ),
        }),
        columnHelper.accessor("linkedSessions", {
          header: "Affected scope",
          sortFn: (a, b) =>
            a.original.linkedSessions.length -
            b.original.linkedSessions.length,
          cell: ({ getValue }) => {
            const sessions = getValue();
            const primary = sessions[0];
            return primary ? (
              <div className="text-xs leading-5">
                <span className="font-medium uppercase">{primary.protocol}</span>
                <span className="block break-all font-mono text-[11px] text-neutral-600">
                  {primary.sourceEndpoint} → {primary.destinationEndpoint}
                </span>
                {sessions.length > 1 ? (
                  <span className="block text-[11px] text-neutral-500">
                    +{sessions.length - 1} more session
                    {sessions.length === 2 ? "" : "s"}
                  </span>
                ) : null}
              </div>
            ) : (
              <span className="text-neutral-500">No linked session</span>
            );
          },
        }),
        columnHelper.display({
          id: "evidence",
          header: "Evidence",
          cell: ({ row }) => (
            <div className="text-xs">
              <span className="font-medium text-neutral-950">
                {row.original.directEvidence.length} direct reference
                {row.original.directEvidence.length === 1 ? "" : "s"}
              </span>
              <span className="mt-1 block text-[10px] text-neutral-500">
                {row.original.linkedFacts.length} linked fact
                {row.original.linkedFacts.length === 1 ? "" : "s"}
              </span>
            </div>
          ),
        }),
        columnHelper.display({
          id: "open",
          header: "Action",
          cell: ({ row }) => (
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={(event) => onSelect(row.original, event.currentTarget)}
              aria-label={`Inspect finding ${row.original.title}`}
            >
              <Search className="size-3.5" aria-hidden />
              Inspect
            </Button>
          ),
        }),
      ]),
    [onSelect],
  );

  const table = useTable({
    features: tableFeatureSet,
    columns,
    data: rows,
    getRowId: (row) => row.findingId,
    initialState: {
      sorting: [
        { id: "severity", desc: false },
        { id: "title", desc: false },
      ],
    },
    enableSortingRemoval: false,
  });
  const tableRows = table.getRowModel().rows;

  return (
    <>
      <div className="hidden overflow-hidden rounded-lg border border-neutral-200 bg-white shadow-sm lg:block">
        <Table
          aria-label="Validated policy findings"
          className="w-full table-fixed text-xs"
        >
          <colgroup>
            <col className="w-[21%]" />
            <col className="w-[10%]" />
            <col className="w-[25%]" />
            <col className="w-[22%]" />
            <col className="w-[12%]" />
            <col className="w-[10%]" />
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
                      className="px-3 text-[10px] font-bold uppercase tracking-[0.06em] whitespace-normal text-neutral-600"
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
              <TableRow
                key={row.id}
                className="cursor-pointer hover:bg-neutral-50"
                tabIndex={0}
                onClick={(event) => onSelect(row.original, event.currentTarget)}
                onKeyDown={(event) => {
                  if (event.key === "Enter" || event.key === " ") {
                    event.preventDefault();
                    onSelect(row.original, event.currentTarget);
                  }
                }}
              >
                {row.getAllCells().map((cell) => (
                  <TableCell
                    key={cell.id}
                    className="min-w-0 px-3 py-3 text-xs whitespace-normal"
                  >
                    <table.FlexRender cell={cell} />
                  </TableCell>
                ))}
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>

      <div className="grid gap-3 lg:hidden">
        {tableRows.map((tableRow) => {
          const finding = tableRow.original;
          const primarySession = finding.linkedSessions[0];
          return (
            <article
              key={finding.findingId}
              className="min-w-0 rounded-lg border border-neutral-200 bg-white p-4 shadow-sm"
            >
              <div className="flex min-w-0 items-start justify-between gap-3">
                <div className="min-w-0">
                  <p className="break-words text-sm font-semibold text-neutral-950">
                    {finding.title}
                  </p>
                  <p className="mt-1 text-[11px] text-neutral-500">
                    {categoryLabels[finding.category] ?? finding.category}
                  </p>
                </div>
                <Badge
                  variant="outline"
                  className={cn(
                    "w-fit rounded-md uppercase",
                    severityStyles[finding.severity] ?? severityStyles.info,
                  )}
                >
                  {finding.severity}
                </Badge>
              </div>
              <p className="mt-3 text-sm leading-6 text-neutral-700">
                <strong className="text-neutral-950">Why it matters:</strong>{" "}
                {finding.impact}
              </p>
              <dl className="mt-4 grid min-w-0 gap-3 sm:grid-cols-2">
                <div>
                  <dt className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
                    Affected scope
                  </dt>
                  <dd className="mt-1 text-xs leading-5 text-neutral-950">
                    {primarySession ? (
                      <>
                        <span className="uppercase">{primarySession.protocol}</span>
                        <span className="block break-all font-mono text-[11px]">
                          {primarySession.sourceEndpoint} →{" "}
                          {primarySession.destinationEndpoint}
                        </span>
                      </>
                    ) : (
                      "No linked session"
                    )}
                  </dd>
                </div>
                <div>
                  <dt className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
                    Evidence
                  </dt>
                  <dd className="mt-1 text-xs leading-5 text-neutral-950">
                    {finding.evidenceConfidence} confidence ·{" "}
                    {finding.directEvidence.length} direct reference
                    {finding.directEvidence.length === 1 ? "" : "s"}
                  </dd>
                </div>
              </dl>
              <div className="mt-4 border-t border-neutral-200 pt-4">
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={(event) => onSelect(finding, event.currentTarget)}
                  className="w-full sm:w-auto"
                  aria-label={`Inspect finding ${finding.title}`}
                >
                  <Search className="size-3.5" aria-hidden />
                  Inspect finding
                </Button>
              </div>
            </article>
          );
        })}
      </div>
    </>
  );
}

export function FindingsWorkspace({
  policyData,
  anomalyData,
}: {
  policyData: PolicyFindingsData;
  anomalyData: AnomalyFindingsData;
}) {
  const searchParams = useSearchParams();
  const pathname = usePathname();
  const router = useRouter();

  const viewParam = searchParams.get("view");
  const activeView: "policy" | "ml" =
    viewParam === "ml" ? "ml" : "policy";

  const setView = useCallback(
    (view: "policy" | "ml") => {
      const params = new URLSearchParams(searchParams.toString());
      params.set("view", view);
      const qs = params.toString();
      router.push(qs ? `${pathname}?${qs}` : pathname, { scroll: false });
    },
    [pathname, router, searchParams],
  );

  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [categoryFilter, setCategoryFilter] = useState("all");
  const [sessionFilter, setSessionFilter] = useState("all");
  const [selectedFinding, setSelectedFinding] =
    useState<FindingDetail | null>(null);
  const [inspectorOpen, setInspectorOpen] = useState(false);
  const returnFocusRef = useRef<HTMLElement | null>(null);

  const handleSelect = useCallback((finding: FindingDetail, trigger: HTMLElement) => {
    returnFocusRef.current = trigger;
    setSelectedFinding(finding);
    setInspectorOpen(true);
  }, []);

  const filteredFindings = useMemo(() => {
    const query = search.trim().toLocaleLowerCase("en-US");
    return policyData.findings.filter((finding) => {
      const matchesSearch =
        query.length === 0 ||
        [
          finding.title,
          finding.findingId,
          finding.ruleId,
          finding.category,
        ].some((value) =>
          value.toLocaleLowerCase("en-US").includes(query),
        );
      const matchesSeverity =
        severityFilter === "all" || finding.severity === severityFilter;
      const matchesCategory =
        categoryFilter === "all" || finding.category === categoryFilter;
      const matchesSession =
        sessionFilter === "all" ||
        finding.linkedSessions.some((s) => s.sessionId === sessionFilter);
      return (
        matchesSearch &&
        matchesSeverity &&
        matchesCategory &&
        matchesSession
      );
    });
  }, [
    policyData.findings,
    search,
    severityFilter,
    categoryFilter,
    sessionFilter,
  ]);

  const hasActiveControls =
    search !== "" ||
    severityFilter !== "all" ||
    categoryFilter !== "all" ||
    sessionFilter !== "all";

  function clearAll() {
    setSearch("");
    setSeverityFilter("all");
    setCategoryFilter("all");
    setSessionFilter("all");
  }

  return (
    <div className="mx-auto min-w-0 w-full max-w-[96rem] space-y-6">
      <header className="min-w-0">
        <div className="min-w-0">
          <AnalysisBreadcrumbs />
          <h1 className="mt-1 text-2xl font-semibold tracking-tight text-neutral-950 sm:text-3xl">
            Findings
          </h1>
          <p className="mt-2 max-w-3xl text-sm leading-6 text-neutral-600">
            Review deterministic policy findings and anomaly results without
            combining them into one score.
          </p>
          <p className="mt-2 text-xs text-neutral-500">
            Analysis ID:{" "}
            <code className="break-all font-mono">{policyData.analysisId}</code>
          </p>
        </div>
      </header>

      <nav aria-label="Findings view" className="flex gap-1">
        <Button
          type="button"
          variant={activeView === "policy" ? "default" : "outline"}
          onClick={() => setView("policy")}
          aria-pressed={activeView === "policy"}
          className="gap-2"
        >
          <ShieldAlert className="size-4" aria-hidden />
          Policy Risk
        </Button>
        <Button
          type="button"
          variant={activeView === "ml" ? "default" : "outline"}
          onClick={() => setView("ml")}
          aria-pressed={activeView === "ml"}
          className="gap-2"
        >
          <Brain className="size-4" aria-hidden />
          ML Anomaly
        </Button>
      </nav>

      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        <PolicyRiskPostureCard policyRisk={policyData.policyRisk} />
        <MLAnomalyPostureCard anomaly={anomalyData} />
      </div>

      {activeView === "policy" ? (
        <section aria-labelledby="policy-findings-heading" className="min-w-0">
          <Card className="rounded-lg border-neutral-200 shadow-sm ring-0">
            <CardHeader className="border-b border-neutral-200">
              <div className="flex items-start gap-3">
                <span className="flex size-9 shrink-0 items-center justify-center rounded-md border border-neutral-200 bg-neutral-50 text-neutral-700">
                  <ListChecks className="size-4" aria-hidden />
                </span>
                <div>
                  <CardTitle>
                    <h2 id="policy-findings-heading">
                      Policy findings
                    </h2>
                  </CardTitle>
                  <CardDescription className="mt-1">
                    Prioritized policy issues with linked sessions and evidence.
                  </CardDescription>
                </div>
              </div>
            </CardHeader>
            <CardContent className="space-y-5">
              {policyData.findings.length === 0 ? (
                <EmptyFindingsState />
              ) : (
                <>
                  <details className="rounded-lg border border-neutral-200 bg-neutral-50/60">
                    <summary className="cursor-pointer px-4 py-3 text-sm font-medium text-neutral-800 outline-none hover:bg-neutral-50 focus-visible:ring-2 focus-visible:ring-neutral-950 focus-visible:ring-inset">
                      Search and filter findings
                    </summary>
                    <div className="space-y-4 border-t border-neutral-200 p-4">
                    <div className="min-w-0">
                      <label
                        htmlFor="finding-search"
                        className="mb-1.5 block text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500"
                      >
                        Search findings
                      </label>
                      <div className="relative">
                        <Search
                          className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-neutral-400"
                          aria-hidden
                        />
                        <Input
                          id="finding-search"
                          type="search"
                          value={search}
                          onChange={(event) => setSearch(event.target.value)}
                          placeholder="Title, finding ID, rule ID, or category"
                          className="h-9 bg-white pl-8"
                          aria-describedby="finding-search-help"
                        />
                      </div>
                      <p id="finding-search-help" className="sr-only">
                        Case-insensitive search across finding title, finding ID,
                        rule ID, and category.
                      </p>
                    </div>
                    <fieldset>
                      <legend className="mb-2 text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
                        Filters
                      </legend>
                      <div className="grid min-w-0 gap-3 sm:grid-cols-3">
                        <FilterField
                          id="severity-filter"
                          label="Severity"
                          value={severityFilter}
                          onChange={setSeverityFilter}
                        >
                          <option value="all">All severities</option>
                          {policyData.severities.map(({ key, label, count }) => (
                            <option key={key} value={key}>
                              {label} ({count})
                            </option>
                          ))}
                        </FilterField>
                        <FilterField
                          id="category-filter"
                          label="Category"
                          value={categoryFilter}
                          onChange={setCategoryFilter}
                        >
                          <option value="all">All categories</option>
                          {policyData.categories.map(
                            ({ key, label, count }) => (
                              <option key={key} value={key}>
                                {label} ({count})
                              </option>
                            ),
                          )}
                        </FilterField>
                        <FilterField
                          id="session-filter"
                          label="Session"
                          value={sessionFilter}
                          onChange={setSessionFilter}
                        >
                          <option value="all">All sessions</option>
                          {policyData.sessions.map((s) => (
                            <option key={s.sessionId} value={s.sessionId}>
                              {s.sessionId}
                            </option>
                          ))}
                        </FilterField>
                      </div>
                    </fieldset>
                      <div className="flex flex-col gap-3 border-t border-neutral-200 pt-4 sm:flex-row sm:items-center sm:justify-between">
                        <p
                          className="text-sm text-neutral-600"
                          role="status"
                          aria-live="polite"
                        >
                          Showing {filteredFindings.length.toLocaleString("en")} of{" "}
                          {policyData.totalFindings.toLocaleString("en")} findings
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
                    </div>
                  </details>

                  {filteredFindings.length === 0 ? (
                    <NoFilterResultsState onClear={clearAll} />
                  ) : (
                    <FindingDesktopTable
                      rows={filteredFindings}
                      onSelect={handleSelect}
                    />
                  )}
                </>
              )}
            </CardContent>
          </Card>

          {policyData.findings.length > 0 ? (
            <div className="mt-4 flex flex-wrap gap-3">
              <Link
                href={`/analysis/${policyData.analysisId}/proof-map`}
                className="inline-flex min-h-9 items-center gap-2 rounded-md border border-neutral-300 bg-white px-4 text-sm font-medium text-neutral-800 outline-none hover:bg-neutral-50 focus-visible:ring-2 focus-visible:ring-neutral-950 focus-visible:ring-offset-2"
              >
                <ExternalLink className="size-4" aria-hidden />
                Proof Map
              </Link>
              {policyData.findings[0]?.linkedSessions[0]?.sessionId &&
              SESSION_ID.test(
                policyData.findings[0].linkedSessions[0].sessionId,
              ) ? (
                <Link
                  href={`/analysis/${policyData.analysisId}/sessions/${policyData.findings[0].linkedSessions[0].sessionId}`}
                  className="inline-flex min-h-9 items-center gap-2 rounded-md border border-neutral-300 bg-white px-4 text-sm font-medium text-neutral-800 outline-none hover:bg-neutral-50 focus-visible:ring-2 focus-visible:ring-neutral-950 focus-visible:ring-offset-2"
                >
                  <FileSearch className="size-4" aria-hidden />
                  Linked Session X-Ray
                </Link>
              ) : null}
            </div>
          ) : null}
        </section>
      ) : (
        <section aria-labelledby="ml-anomaly-heading" className="min-w-0">
          <Card className="rounded-lg border-neutral-200 shadow-sm ring-0">
            <CardHeader className="border-b border-neutral-200">
              <div className="flex items-start gap-3">
                <span className="flex size-9 shrink-0 items-center justify-center rounded-md border border-neutral-200 bg-neutral-50 text-neutral-700">
                  <Brain className="size-4" aria-hidden />
                </span>
                <div>
                  <CardTitle>
                    <h2 id="ml-anomaly-heading">ML Anomaly results</h2>
                  </CardTitle>
                  <CardDescription className="mt-1">
                    Unusual session behavior for analyst review. This is not a
                    policy score.
                  </CardDescription>
                </div>
              </div>
            </CardHeader>
            <CardContent className="space-y-4">
              <MLAnomalyExplorer data={anomalyData} />
            </CardContent>
          </Card>
        </section>
      )}

      <FindingDetailInspector
        finding={selectedFinding}
        analysisId={policyData.analysisId}
        open={inspectorOpen}
        onOpenChange={setInspectorOpen}
        returnFocusRef={returnFocusRef}
      />
    </div>
  );
}
