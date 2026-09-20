"use client";

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
        <CardContent className="flex h-full items-start justify-between gap-4">
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
      <CardContent className="flex h-full items-start justify-between gap-4">
        <div className="min-w-0">
          <p className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
            Policy Risk
          </p>
          <p className="mt-2 break-words text-2xl font-semibold tracking-tight text-neutral-950">
            {policyRisk.cappedScore}
            <span className="ml-1 text-sm font-normal text-neutral-500">
              (uncapped: {policyRisk.uncappedScore})
            </span>
          </p>
          <p className="mt-2 text-xs leading-5 text-neutral-600">
            Profile: {policyRisk.profileId} &middot;{" "}
            {policyRisk.contributionCount} contribution
            {policyRisk.contributionCount !== 1 ? "s" : ""} &middot;{" "}
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

  return (
    <Card className="rounded-lg border-neutral-200 shadow-sm ring-0">
      <CardContent className="flex h-full items-start justify-between gap-4">
        <div className="min-w-0">
          <p className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
            ML Anomaly
          </p>
          <p className="mt-2 text-2xl font-semibold tracking-tight text-neutral-950">
            {statusLabel}
          </p>
          <p className="mt-2 text-xs leading-5 text-neutral-600">
            {anomaly.resultCount} result
            {anomaly.resultCount !== 1 ? "s" : ""}
            {anomaly.modelId ? ` · Model: ${anomaly.modelId}` : ""}
            {anomaly.modelVersion
              ? ` v${anomaly.modelVersion}`
              : ""}
            {". "}
            Independent of Policy Risk.
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
              <code
                className="mt-0.5 block max-w-full break-all font-mono text-[11px] text-neutral-500"
                title={row.original.findingId}
              >
                {row.original.findingId}
              </code>
            </div>
          ),
        }),
        columnHelper.accessor("severity", {
          header: "Severity",
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
                Confidence: {row.original.evidenceConfidence}
              </p>
            </div>
          ),
        }),
        columnHelper.accessor("category", {
          header: "Category",
          sortFn: "text",
          cell: ({ getValue }) => (
            <span className="font-mono text-xs">
              {categoryLabels[getValue()] ?? getValue()}
            </span>
          ),
        }),
        columnHelper.accessor("policyRiskContribution", {
          header: "Contribution",
          sortFn: "alphanumeric",
          cell: ({ getValue }) => (
            <span className="font-mono text-xs">{getValue()}</span>
          ),
        }),
        columnHelper.accessor("ruleId", {
          header: "Rule",
          sortFn: "alphanumeric",
          cell: ({ getValue, row }) => (
            <div className="min-w-0">
              <code
                className="block max-w-full break-all font-mono text-[11px]"
                title={getValue()}
              >
                {getValue()}
              </code>
              <span className="text-[11px] text-neutral-500">
                v{row.original.ruleVersion} · {row.original.profileId}
              </span>
              <span className="block text-[10px] text-neutral-500">
                {row.original.ruleOutcome} / {row.original.ruleReasonCode}
              </span>
            </div>
          ),
        }),
        columnHelper.accessor("linkedSessions", {
          header: "Sessions",
          sortFn: (a, b) =>
            a.original.linkedSessions.length -
            b.original.linkedSessions.length,
          cell: ({ getValue, row }) => {
            const count = getValue().length;
            return (
              <div className="text-xs">
                <span>{count > 0 ? `${count} linked` : "None"}</span>
                <span className="mt-1 block text-[10px] text-neutral-500">
                  {row.original.directEvidence.length} evidence · {row.original.linkedFacts.length} facts
                </span>
              </div>
            );
          },
        }),
        columnHelper.display({
          id: "open",
          header: "Inspect",
          cell: ({ row }) => (
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={(event) => onSelect(row.original, event.currentTarget)}
              aria-label={`Inspect finding ${row.original.title}`}
              className="font-mono text-[11px]"
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
        { id: "policyRiskContribution", desc: true },
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
            <col className="w-[26%]" />
            <col className="w-[9%]" />
            <col className="w-[14%]" />
            <col className="w-[10%]" />
            <col className="w-[18%]" />
            <col className="w-[8%]" />
            <col className="w-[15%]" />
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

      <div className="grid gap-3 lg:hidden">
        {tableRows.map((tableRow) => {
          const finding = tableRow.original;
          return (
            <article
              key={finding.findingId}
              className="min-w-0 rounded-lg border border-neutral-200 bg-white p-4 shadow-sm"
            >
              <div className="flex min-w-0 flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
                <div className="min-w-0">
                  <p className="break-words text-sm font-semibold text-neutral-950">
                    {finding.title}
                  </p>
                  <code
                    className="mt-1 block max-w-full break-all font-mono text-[11px] text-neutral-500"
                    title={finding.findingId}
                  >
                    {finding.findingId}
                  </code>
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
                <p className="text-[10px] text-neutral-500">
                  Confidence: {finding.evidenceConfidence}
                </p>
              </div>
              <dl className="mt-4 grid min-w-0 gap-3 sm:grid-cols-2">
                <div>
                  <dt className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
                    Category
                  </dt>
                  <dd className="mt-1 font-mono text-xs text-neutral-950">
                    {categoryLabels[finding.category] ?? finding.category}
                  </dd>
                </div>
                <div>
                  <dt className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
                    Contribution
                  </dt>
                  <dd className="mt-1 font-mono text-xs text-neutral-950">
                    {finding.policyRiskContribution}
                  </dd>
                </div>
                <div>
                  <dt className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
                    Rule
                  </dt>
                  <dd className="mt-1 font-mono text-[11px] text-neutral-950">
                    {finding.ruleId} v{finding.ruleVersion}
                    <span className="block text-neutral-500">
                      {finding.profileId} · {finding.ruleOutcome} / {finding.ruleReasonCode}
                    </span>
                  </dd>
                </div>
                <div>
                  <dt className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
                    Sessions
                  </dt>
                  <dd className="mt-1 text-xs text-neutral-950">
                    {finding.linkedSessions.length > 0
                      ? `${finding.linkedSessions.length} linked`
                      : "None"}
                    <span className="block text-[10px] text-neutral-500">
                      {finding.directEvidence.length} evidence · {finding.linkedFacts.length} facts
                    </span>
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
  const [profileFilter, setProfileFilter] = useState("all");
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
      const matchesProfile =
        profileFilter === "all" || finding.profileId === profileFilter;
      return (
        matchesSearch &&
        matchesSeverity &&
        matchesCategory &&
        matchesSession &&
        matchesProfile
      );
    });
  }, [
    policyData.findings,
    search,
    severityFilter,
    categoryFilter,
    sessionFilter,
    profileFilter,
  ]);

  const hasActiveControls =
    search !== "" ||
    severityFilter !== "all" ||
    categoryFilter !== "all" ||
    sessionFilter !== "all" ||
    profileFilter !== "all";

  function clearAll() {
    setSearch("");
    setSeverityFilter("all");
    setCategoryFilter("all");
    setSessionFilter("all");
    setProfileFilter("all");
  }

  return (
    <div className="mx-auto min-w-0 w-full max-w-[96rem] space-y-6">
      <header className="flex min-w-0 flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
        <div className="min-w-0">
          <p className="text-[11px] font-bold uppercase tracking-[0.08em] text-neutral-500">
            Analysis / Findings
          </p>
          <h1 className="mt-1 text-2xl font-semibold tracking-tight text-neutral-950 sm:text-3xl">
            Findings
          </h1>
          <p className="mt-2 max-w-3xl text-sm leading-6 text-neutral-600">
            Deterministic Policy Risk and ML Anomaly remain independent. This
            workspace renders only validated contract fields; no scores,
            severities, or evidence are generated in the browser.
          </p>
        </div>
        <dl className="w-full min-w-0 rounded-lg border border-neutral-200 bg-white px-4 py-3 shadow-sm sm:w-80 sm:shrink-0">
          <div>
            <dt className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
              Analysis ID
            </dt>
            <dd
              className="mt-1 block truncate font-mono text-xs text-neutral-950"
              title={policyData.analysisId}
            >
              {policyData.analysisId}
            </dd>
          </div>
          <div className="mt-2 border-t border-neutral-100 pt-2">
            <dt className="sr-only">Analysis status</dt>
            <dd className="text-xs text-neutral-600">
              {policyData.analysisStatus === "complete"
                ? "Analysis complete"
                : `Status: ${policyData.analysisStatus}`}
            </dd>
          </div>
        </dl>
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

      <div className="grid gap-4 sm:grid-cols-2">
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
                      Validated policy findings
                    </h2>
                  </CardTitle>
                  <CardDescription className="mt-1">
                    Deterministic findings from the validated Chain-of-Proof
                    contract. Severity and contribution come directly from the
                    contract; they are never derived in the browser.
                  </CardDescription>
                </div>
              </div>
            </CardHeader>
            <CardContent className="space-y-5">
              {policyData.findings.length === 0 ? (
                <EmptyFindingsState />
              ) : (
                <>
                  <div className="space-y-4">
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
                      <div className="grid min-w-0 gap-3 sm:grid-cols-2 md:grid-cols-3 xl:grid-cols-5">
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
                        <FilterField
                          id="profile-filter"
                          label="Policy profile"
                          value={profileFilter}
                          onChange={setProfileFilter}
                        >
                          <option value="all">All profiles</option>
                          {policyData.profiles.map(({ key, count }) => (
                            <option key={key} value={key}>
                              {key} ({count})
                            </option>
                          ))}
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
                      Showing {filteredFindings.length.toLocaleString("en")} of{" "}
                      {policyData.totalFindings.toLocaleString("en")} validated
                      findings
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
                    Independent ML engine output. This remains separate from
                    deterministic Policy Risk; no combined score is presented.
                  </CardDescription>
                </div>
              </div>
            </CardHeader>
            <CardContent className="space-y-4">
              <MLAnomalyExplorer data={anomalyData} />

              <div className="mt-4 rounded-lg border border-neutral-200 px-4">
                <dl>
                  <div className="grid gap-1 border-b border-neutral-100 py-3 sm:grid-cols-[10rem_minmax(0,1fr)] sm:gap-4">
                    <dt className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
                      Engine status
                    </dt>
                    <dd className="text-sm text-neutral-900">
                      {engineStatusLabels[anomalyData.mlEngineStatus] ??
                        anomalyData.mlEngineStatus}
                    </dd>
                  </div>
                  {anomalyData.modelId ? (
                    <div className="grid gap-1 border-b border-neutral-100 py-3 sm:grid-cols-[10rem_minmax(0,1fr)] sm:gap-4">
                      <dt className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
                        Model
                      </dt>
                      <dd className="font-mono text-xs text-neutral-900">
                        {anomalyData.modelId}
                        {anomalyData.modelVersion
                          ? ` v${anomalyData.modelVersion}`
                          : ""}
                      </dd>
                    </div>
                  ) : null}
                  <div className="grid gap-1 py-3 sm:grid-cols-[10rem_minmax(0,1fr)] sm:gap-4">
                    <dt className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
                      Result count
                    </dt>
                    <dd className="font-mono text-xs text-neutral-900">
                      {anomalyData.resultCount}
                    </dd>
                  </div>
                </dl>
              </div>

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
