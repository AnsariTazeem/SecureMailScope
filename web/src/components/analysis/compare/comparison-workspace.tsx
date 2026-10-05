"use client";

import { AnalysisBreadcrumbs } from "@/components/layout/analysis-breadcrumbs";

import Link from "next/link";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import {
  ArrowLeft,
  ArrowRight,
  BrainCircuit,
  GitCompareArrows,
  GitFork,
  Info,
  ListChecks,
  Repeat2,
  ShieldAlert,
} from "lucide-react";

import { EvidenceInspector } from "@/components/analysis/session-xray/evidence-inspector";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { cn } from "@/lib/utils";

import type {
  ComparisonCell,
  ComparisonCategory,
  ComparisonPageData,
  ComparisonSessionSummary,
} from "./comparison-view-model";

const selectClassName =
  "h-10 w-full min-w-0 rounded-md border border-neutral-300 bg-white px-3 font-mono text-xs text-neutral-950 outline-none focus-visible:ring-2 focus-visible:ring-neutral-950 focus-visible:ring-offset-2";

function stateClassName(state: string): string {
  if (state.includes("policy")) {
    return "border-violet-200 bg-violet-50 text-violet-800";
  }
  if (
    state.includes("not_observable") ||
    state.includes("session_secrets_required") ||
    state.includes("unknown")
  ) {
    return "border-amber-200 bg-amber-50 text-amber-900";
  }
  if (state.includes("incomplete") || state.includes("failed")) {
    return "border-orange-200 bg-orange-50 text-orange-900";
  }
  if (state.includes("observed") || state === "complete") {
    return "border-emerald-200 bg-emerald-50 text-emerald-800";
  }
  if (state.includes("derived")) {
    return "border-blue-200 bg-blue-50 text-blue-800";
  }
  return "border-neutral-300 bg-neutral-50 text-neutral-700";
}

function StateBadge({ state }: { state: string | null }) {
  if (!state) return null;
  return (
    <Badge
      variant="outline"
      className={cn(
        "max-w-full rounded-md font-mono text-[9px] break-all whitespace-normal",
        stateClassName(state),
      )}
    >
      {state}
    </Badge>
  );
}

function CellEvidence({ cell }: { cell: ComparisonCell }) {
  if (cell.evidence.length === 0) return null;
  return (
    <details className="mt-3 rounded-md border border-neutral-200 bg-neutral-50 px-3 py-2">
      <summary className="cursor-pointer text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-600 outline-none focus-visible:ring-2 focus-visible:ring-neutral-950">
        {cell.evidenceRelationship === "through_sources"
          ? "Evidence through declared sources"
          : "Direct evidence references"}{" "}
        · {cell.evidence.length}
      </summary>
      <div className="mt-3 flex flex-wrap gap-2">
        {cell.evidence.map((evidence) => (
          <EvidenceInspector
            key={evidence.evidenceId}
            evidence={evidence}
            label={evidence.evidenceId}
          />
        ))}
      </div>
    </details>
  );
}

function ComparisonValue({ cell }: { cell: ComparisonCell }) {
  return (
    <div className="min-w-0">
      <div className="flex min-w-0 flex-col items-start gap-2">
        <code className="max-w-full break-all font-mono text-xs font-semibold leading-5 text-neutral-950">
          {cell.value}
        </code>
        <StateBadge state={cell.state} />
      </div>
      {cell.detail.length > 0 ? (
        <ul className="mt-2 space-y-1 text-[11px] leading-5 text-neutral-600">
          {cell.detail.map((detail, index) => (
            <li key={`${detail}:${index}`} className="break-words">
              {detail}
            </li>
          ))}
        </ul>
      ) : null}
      <CellEvidence cell={cell} />
    </div>
  );
}

function Selectors({ data }: { data: ComparisonPageData }) {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();

  function navigate(sessionA: string, sessionB: string) {
    const next = new URLSearchParams(searchParams.toString());
    next.set("a", sessionA);
    next.set("b", sessionB);
    router.push(`${pathname}?${next.toString()}`, { scroll: false });
  }

  return (
    <section
      aria-labelledby="compare-selectors-heading"
      className="rounded-lg border border-neutral-200 bg-white p-4 shadow-sm sm:p-5"
    >
      <div className="mb-4">
        <h2 id="compare-selectors-heading" className="text-sm font-semibold text-neutral-950">
          Select reconstructed sessions
        </h2>
        <p className="mt-1 text-xs leading-5 text-neutral-600">
          Selections are stored in the URL. Each pair is rebuilt on the server
          from the validated result.
        </p>
      </div>
      <div className="grid min-w-0 gap-3 lg:grid-cols-[minmax(0,1fr)_auto_minmax(0,1fr)] lg:items-end">
        <label className="grid min-w-0 gap-1.5">
          <span className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
            Session A
          </span>
          <select
            value={data.selectedA}
            onChange={(event) => navigate(event.target.value, data.selectedB)}
            className={selectClassName}
            aria-label="Select Session A"
          >
            {data.options.map((option) => (
              <option key={option.sessionId} value={option.sessionId}>
                {option.protocol.toUpperCase()} · stream {option.tcpStreamId} · {option.sessionId}
              </option>
            ))}
          </select>
        </label>
        <Button
          type="button"
          variant="outline"
          size="lg"
          onClick={() => navigate(data.selectedB, data.selectedA)}
          className="w-full lg:w-auto"
          aria-label="Swap Session A and Session B"
          data-compare-swap
        >
          <Repeat2 className="size-4" aria-hidden />
          Swap
        </Button>
        <label className="grid min-w-0 gap-1.5">
          <span className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
            Session B
          </span>
          <select
            value={data.selectedB}
            onChange={(event) => navigate(data.selectedA, event.target.value)}
            className={selectClassName}
            aria-label="Select Session B"
          >
            {data.options.map((option) => (
              <option key={option.sessionId} value={option.sessionId}>
                {option.protocol.toUpperCase()} · stream {option.tcpStreamId} · {option.sessionId}
              </option>
            ))}
          </select>
        </label>
      </div>
    </section>
  );
}

function SessionSummaryCard({
  label,
  summary,
}: {
  label: "Session A" | "Session B";
  summary: ComparisonSessionSummary;
}) {
  return (
    <Card className="min-w-0 rounded-lg border-neutral-200 shadow-sm ring-0">
      <CardHeader className="border-b border-neutral-200 bg-neutral-50/70">
        <div className="flex min-w-0 flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
          <div className="min-w-0">
            <p className="text-[10px] font-bold uppercase tracking-[0.08em] text-neutral-500">
              {label}
            </p>
            <CardTitle className="mt-1 break-all font-mono text-sm">
              {summary.sessionId}
            </CardTitle>
            <CardDescription className="mt-1 break-all">
              {summary.captureName} · {summary.captureId}
            </CardDescription>
          </div>
          <Link
            href={summary.xrayHref}
            className="inline-flex min-h-8 shrink-0 items-center justify-center gap-1.5 rounded-md border border-neutral-300 bg-white px-3 text-xs font-semibold text-neutral-900 outline-none hover:bg-neutral-100 focus-visible:ring-2 focus-visible:ring-neutral-950 focus-visible:ring-offset-2"
          >
            Session X-Ray
            <ArrowRight className="size-3.5" aria-hidden />
          </Link>
        </div>
      </CardHeader>
      <CardContent>
        <dl className="grid min-w-0 gap-px overflow-hidden rounded-lg border border-neutral-200 bg-neutral-200 sm:grid-cols-2 xl:grid-cols-1 2xl:grid-cols-2">
          {summary.highlights.map((item) => (
            <div key={item.label} className="min-w-0 bg-white p-3">
              <dt className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
                {item.label}
              </dt>
              <dd className="mt-1 min-w-0">
                <code className="block break-all font-mono text-xs leading-5 text-neutral-950">
                  {item.value}
                </code>
                <div className="mt-1.5">
                  <StateBadge state={item.state} />
                </div>
              </dd>
            </div>
          ))}
        </dl>
        <div className="mt-3 rounded-md border border-neutral-200 bg-neutral-50 p-3">
          <p className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
            Capture SHA-256
          </p>
          <code className="mt-1 block break-all font-mono text-[10px] leading-4 text-neutral-700">
            {summary.captureSha256}
          </code>
        </div>
      </CardContent>
    </Card>
  );
}

function AssessmentBoundary({ data }: { data: ComparisonPageData }) {
  return (
    <section
      aria-label="Separate assessment context"
      className="grid gap-3 md:grid-cols-2"
    >
      <Card className="rounded-lg border-violet-200 bg-violet-50/30 shadow-sm ring-0">
        <CardContent>
          <div className="flex items-start gap-3">
            <ShieldAlert className="mt-0.5 size-4 shrink-0 text-violet-700" aria-hidden />
            <div>
              <p className="text-[10px] font-bold uppercase tracking-[0.06em] text-violet-700">
                Analysis-wide Policy Risk
              </p>
              <p className="mt-1 font-mono text-sm font-semibold text-violet-950">
                {data.policyRisk.status === "available"
                  ? `capped ${data.policyRisk.cappedScore} · uncapped ${data.policyRisk.uncappedScore}`
                  : "not_present"}
              </p>
              <p className="mt-1 text-xs leading-5 text-violet-900/80">
                {data.policyRisk.status === "available"
                  ? `Profile ${data.policyRisk.profileId}. Per-session rows show declared contributions, not a browser-derived score.`
                  : "No Policy Risk summary was supplied by the validated result."}
              </p>
            </div>
          </div>
        </CardContent>
      </Card>
      <Card className="rounded-lg border-blue-200 bg-blue-50/30 shadow-sm ring-0">
        <CardContent>
          <div className="flex items-start gap-3">
            <BrainCircuit className="mt-0.5 size-4 shrink-0 text-blue-700" aria-hidden />
            <div>
              <p className="text-[10px] font-bold uppercase tracking-[0.06em] text-blue-700">
                ML Anomaly
              </p>
              <p className="mt-1 font-mono text-sm font-semibold text-blue-950">
                {data.mlAnomaly.engineStatus}
              </p>
              <p className="mt-1 text-xs leading-5 text-blue-900/80">
                {data.mlAnomaly.resultCount} explicit result
                {data.mlAnomaly.resultCount === 1 ? "" : "s"} supplied. No zero
                score or relationship is invented, and anomaly is not proof of attack.
              </p>
            </div>
          </div>
        </CardContent>
      </Card>
    </section>
  );
}

function DifferenceBadge({ differs }: { differs: boolean }) {
  return (
    <Badge
      variant="outline"
      className={cn(
        "rounded-md",
        differs
          ? "border-amber-200 bg-amber-50 text-amber-900"
          : "border-neutral-300 bg-neutral-50 text-neutral-600",
      )}
    >
      {differs ? "Different" : "Same"}
    </Badge>
  );
}

function ComparisonCategorySection({
  category,
}: {
  category: ComparisonCategory;
}) {
  return (
    <section
      aria-labelledby={`comparison-${category.key}`}
      className="overflow-hidden rounded-lg border border-neutral-200 bg-white shadow-sm"
      data-comparison-category={category.key}
    >
      <div className="border-b border-neutral-200 bg-neutral-50 px-4 py-4 sm:px-5">
        <h2 id={`comparison-${category.key}`} className="text-sm font-semibold text-neutral-950">
          {category.title}
        </h2>
        <p className="mt-1 max-w-4xl text-xs leading-5 text-neutral-600">
          {category.description}
        </p>
      </div>

      {category.rows.length === 0 ? (
        <div className="p-6 text-center" data-empty-comparison-category>
          <p className="text-sm font-semibold text-neutral-950">
            Empty comparison category
          </p>
          <p className="mt-1 text-xs leading-5 text-neutral-600">
            The validated result supplies no display-safe fields for this category.
            No values were synthesized.
          </p>
        </div>
      ) : (
        <>
          <div className="hidden xl:block" data-comparison-layout="desktop">
            <Table aria-label={`${category.title} comparison`} className="table-fixed text-xs">
              <colgroup>
                <col className="w-[18%]" />
                <col className="w-[36%]" />
                <col className="w-[36%]" />
                <col className="w-[10%]" />
              </colgroup>
              <TableHeader>
                <TableRow>
                  <TableHead className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
                    Attribute
                  </TableHead>
                  <TableHead className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
                    Session A
                  </TableHead>
                  <TableHead className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
                    Session B
                  </TableHead>
                  <TableHead className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
                    Exact match
                  </TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {category.rows.map((comparison) => (
                  <TableRow
                    key={comparison.key}
                    data-comparison-row={comparison.key}
                    data-differs={comparison.differs}
                    className={comparison.differs ? "bg-amber-50/20" : undefined}
                  >
                    <TableCell className="align-top text-xs font-semibold text-neutral-800 whitespace-normal">
                      {comparison.label}
                    </TableCell>
                    <TableCell className="align-top whitespace-normal">
                      <ComparisonValue cell={comparison.sessionA} />
                    </TableCell>
                    <TableCell className="align-top whitespace-normal">
                      <ComparisonValue cell={comparison.sessionB} />
                    </TableCell>
                    <TableCell className="align-top whitespace-normal">
                      <DifferenceBadge differs={comparison.differs} />
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>

          <div className="grid gap-3 p-3 xl:hidden" data-comparison-layout="mobile">
            {category.rows.map((comparison) => (
              <article
                key={comparison.key}
                className="min-w-0 rounded-lg border border-neutral-200 bg-white p-4"
                data-comparison-row={comparison.key}
                data-differs={comparison.differs}
              >
                <div className="flex items-start justify-between gap-3">
                  <h3 className="text-sm font-semibold text-neutral-950">
                    {comparison.label}
                  </h3>
                  <DifferenceBadge differs={comparison.differs} />
                </div>
                <div className="mt-4 grid min-w-0 gap-3 md:grid-cols-2">
                  <div className="min-w-0 rounded-md border border-neutral-200 bg-neutral-50 p-3">
                    <p className="mb-2 text-[10px] font-bold uppercase tracking-[0.08em] text-neutral-500">
                      Session A
                    </p>
                    <ComparisonValue cell={comparison.sessionA} />
                  </div>
                  <div className="min-w-0 rounded-md border border-neutral-200 bg-neutral-50 p-3">
                    <p className="mb-2 text-[10px] font-bold uppercase tracking-[0.08em] text-neutral-500">
                      Session B
                    </p>
                    <ComparisonValue cell={comparison.sessionB} />
                  </div>
                </div>
              </article>
            ))}
          </div>
        </>
      )}
    </section>
  );
}

export function ComparisonWorkspace({ data }: { data: ComparisonPageData }) {
  return (
    <div
      className="mx-auto min-w-0 w-full max-w-[100rem] space-y-6"
      data-session-a={data.selectedA}
      data-session-b={data.selectedB}
      data-difference-count={data.differenceCount}
    >
      <header className="space-y-4">
        <div className="flex min-w-0 flex-col gap-4 md:flex-row md:items-end md:justify-between">
          <div className="min-w-0">
            <AnalysisBreadcrumbs />
            <h1 className="mt-1 text-2xl font-semibold tracking-tight text-neutral-950 sm:text-3xl">
              Session Comparison
            </h1>
            <p className="mt-2 max-w-3xl text-sm leading-6 text-neutral-600">
              Compare declared session posture and evidence side by side. A
              difference means only that validated values or states differ.
            </p>
          </div>
          <Link
            href={data.overviewHref}
            className="inline-flex min-h-9 w-full shrink-0 items-center justify-center gap-2 rounded-md border border-neutral-300 bg-white px-4 text-sm font-semibold text-neutral-900 outline-none hover:bg-neutral-50 focus-visible:ring-2 focus-visible:ring-neutral-950 focus-visible:ring-offset-2 md:w-auto"
          >
            <ArrowLeft className="size-4" aria-hidden />
            Overview
          </Link>
        </div>

        <div className="grid gap-px overflow-hidden rounded-lg border border-neutral-200 bg-neutral-200 sm:grid-cols-3">
          <div className="bg-white px-4 py-3">
            <p className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
              Analysis ID
            </p>
            <code className="mt-1 block break-all font-mono text-xs text-neutral-950">
              {data.analysisId}
            </code>
          </div>
          <div className="bg-white px-4 py-3">
            <p className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
              Analysis status
            </p>
            <code className="mt-1 block font-mono text-xs text-neutral-950">
              {data.analysisStatus}
            </code>
          </div>
          <div className="bg-white px-4 py-3">
            <p className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
              Exact displayed differences
            </p>
            <code className="mt-1 block font-mono text-xs text-neutral-950">
              {data.differenceCount}
            </code>
          </div>
        </div>
      </header>

      <Selectors data={data} />

      <section aria-labelledby="posture-summary-heading">
        <div className="mb-3">
          <p className="text-[10px] font-bold uppercase tracking-[0.08em] text-neutral-500">
            Selected pair
          </p>
          <h2 id="posture-summary-heading" className="mt-1 text-lg font-semibold text-neutral-950">
            Side-by-side declared posture
          </h2>
        </div>
        <div className="grid min-w-0 gap-4 xl:grid-cols-2">
          <SessionSummaryCard label="Session A" summary={data.sessionA} />
          <SessionSummaryCard label="Session B" summary={data.sessionB} />
        </div>
      </section>

      <AssessmentBoundary data={data} />

      <Alert className="border-amber-200 bg-amber-50/60 text-amber-950">
        <GitCompareArrows className="size-4" aria-hidden />
        <AlertTitle>Difference is not an attack conclusion</AlertTitle>
        <AlertDescription className="text-amber-900/85">
          Highlighting uses exact server-built display values and declared states.
          It does not label a session malicious, attacked, safe, or secure.
        </AlertDescription>
      </Alert>

      <div className="space-y-4" aria-label="Exact comparison matrix">
        {data.categories.map((category) => (
          <ComparisonCategorySection key={category.key} category={category} />
        ))}
      </div>

      <nav
        aria-label="Comparison investigation links"
        className="grid gap-3 rounded-lg border border-neutral-200 bg-white p-4 shadow-sm sm:grid-cols-2 xl:grid-cols-4"
      >
        <Link
          href={data.sessionA.xrayHref}
          className="inline-flex min-h-10 items-center justify-center gap-2 rounded-md border border-neutral-300 bg-white px-3 text-xs font-semibold text-neutral-900 outline-none hover:bg-neutral-50 focus-visible:ring-2 focus-visible:ring-neutral-950 focus-visible:ring-offset-2"
        >
          Session A X-Ray
          <ArrowRight className="size-3.5" aria-hidden />
        </Link>
        <Link
          href={data.sessionB.xrayHref}
          className="inline-flex min-h-10 items-center justify-center gap-2 rounded-md border border-neutral-300 bg-white px-3 text-xs font-semibold text-neutral-900 outline-none hover:bg-neutral-50 focus-visible:ring-2 focus-visible:ring-neutral-950 focus-visible:ring-offset-2"
        >
          Session B X-Ray
          <ArrowRight className="size-3.5" aria-hidden />
        </Link>
        <Link
          href={data.proofMapHref}
          className="inline-flex min-h-10 items-center justify-center gap-2 rounded-md border border-neutral-300 bg-white px-3 text-xs font-semibold text-neutral-900 outline-none hover:bg-neutral-50 focus-visible:ring-2 focus-visible:ring-neutral-950 focus-visible:ring-offset-2"
        >
          <GitFork className="size-4" aria-hidden />
          Proof Map
        </Link>
        <Link
          href={data.policyFindingsHref}
          className="inline-flex min-h-10 items-center justify-center gap-2 rounded-md bg-neutral-950 px-3 text-xs font-semibold text-white outline-none hover:bg-neutral-800 focus-visible:ring-2 focus-visible:ring-neutral-950 focus-visible:ring-offset-2"
        >
          <ListChecks className="size-4" aria-hidden />
          Policy Findings
        </Link>
      </nav>

      <footer className="flex items-start gap-2 border-t border-neutral-200 pt-5 text-xs leading-5 text-neutral-500">
        <Info className="mt-0.5 size-4 shrink-0" aria-hidden />
        Comparison values were built on the server from the revalidated
        AnalysisDataSource result. The browser only changes URL-backed session
        selections and renders the supplied display model.
      </footer>
    </div>
  );
}
