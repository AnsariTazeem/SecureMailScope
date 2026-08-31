"use client";

import { useMemo, useRef, useState } from "react";
import { AlertTriangle, Brain, FilterX, Search, ShieldCheck } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

import { MLAnomalyInspector } from "./ml-anomaly-inspector";
import {
  engineStatusLabels,
  type AnomalyDetail,
  type AnomalyFindingsData,
} from "./findings-view-model";

const selectClassName =
  "h-9 w-full min-w-0 rounded-lg border border-input bg-white px-2.5 text-sm text-neutral-900 outline-none transition-colors focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50";

function EngineState({
  title,
  description,
  tone,
}: {
  title: string;
  description: string;
  tone: "neutral" | "success" | "failure";
}) {
  const Icon = tone === "failure" ? AlertTriangle : tone === "success" ? ShieldCheck : Brain;
  return (
    <div className="rounded-lg border border-dashed border-neutral-300 bg-neutral-50 px-5 py-10 text-center">
      <Icon
        className={tone === "failure" ? "mx-auto size-8 text-red-600" : "mx-auto size-8 text-neutral-400"}
        aria-hidden
      />
      <h3 className="mt-3 text-sm font-semibold text-neutral-950">{title}</h3>
      <p className="mx-auto mt-2 max-w-xl text-sm leading-6 text-neutral-600">
        {description}
      </p>
    </div>
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
  children: React.ReactNode;
}) {
  return (
    <div className="min-w-0">
      <label htmlFor={id} className="mb-1.5 block text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
        {label}
      </label>
      <select id={id} value={value} onChange={(event) => onChange(event.target.value)} className={selectClassName}>
        {children}
      </select>
    </div>
  );
}

export function MLAnomalyExplorer({ data }: { data: AnomalyFindingsData }) {
  const [search, setSearch] = useState("");
  const [band, setBand] = useState("all");
  const [session, setSession] = useState("all");
  const [model, setModel] = useState("all");
  const [sort, setSort] = useState("score_desc");
  const [selected, setSelected] = useState<AnomalyDetail | null>(null);
  const [inspectorOpen, setInspectorOpen] = useState(false);
  const returnFocusRef = useRef<HTMLElement | null>(null);

  const filtered = useMemo(() => {
    const query = search.trim().toLocaleLowerCase("en-US");
    const rows = data.results.filter((result) => {
      const matchesSearch =
        query.length === 0 ||
        [
          result.anomalyResultId,
          result.session.sessionId,
          result.modelId,
          result.modelVersion,
          result.band,
          ...result.unusualFeatureIndicators,
        ].some((value) => value.toLocaleLowerCase("en-US").includes(query));
      return (
        matchesSearch &&
        (band === "all" || result.band === band) &&
        (session === "all" || result.session.sessionId === session) &&
        (model === "all" ||
          JSON.stringify([result.modelId, result.modelVersion]) === model)
      );
    });
    return [...rows].sort((left, right) => {
      if (sort === "score_asc") {
        return left.normalizedScore - right.normalizedScore || left.anomalyResultId.localeCompare(right.anomalyResultId);
      }
      if (sort === "band") {
        return left.band.localeCompare(right.band) || left.anomalyResultId.localeCompare(right.anomalyResultId);
      }
      if (sort === "id") return left.anomalyResultId.localeCompare(right.anomalyResultId);
      return right.normalizedScore - left.normalizedScore || left.anomalyResultId.localeCompare(right.anomalyResultId);
    });
  }, [band, data.results, model, search, session, sort]);

  function clearAll() {
    setSearch("");
    setBand("all");
    setSession("all");
    setModel("all");
    setSort("score_desc");
  }

  function inspect(result: AnomalyDetail, trigger: HTMLElement) {
    returnFocusRef.current = trigger;
    setSelected(result);
    setInspectorOpen(true);
  }

  if (data.mlEngineStatus === "not_run") {
    return (
      <EngineState
        title="ML anomaly engine was not run"
        description="The validated result contains no anomaly score, anomaly result, or ML evidence edge. Policy Risk remains available independently; no combined score is presented."
        tone="neutral"
      />
    );
  }

  if (data.mlEngineStatus === "failed" || data.mlEngineStatus === "unavailable") {
    return (
      <EngineState
        title={`ML anomaly engine ${engineStatusLabels[data.mlEngineStatus]?.toLocaleLowerCase("en-US") ?? data.mlEngineStatus}`}
        description="No anomaly conclusion is available. Deterministic Policy Risk findings remain unchanged and independent."
        tone="failure"
      />
    );
  }

  if (data.mlEngineStatus === "complete" && data.resultCount === 0) {
    return (
      <EngineState
        title="ML completed with zero results"
        description="The engine completed but the validated result declares no anomaly results. No anomaly score or evidence relationship is displayed."
        tone="success"
      />
    );
  }

  return (
    <div className="space-y-5">
      {data.mlEngineStatus === "partial" ? (
        <div className="rounded-lg border border-amber-300 bg-amber-50 px-4 py-3 text-sm text-amber-900">
          ML anomaly processing is incomplete. Only validated results and declared relationships currently present are shown.
        </div>
      ) : null}

      <div className="space-y-4">
        <div>
          <label htmlFor="ml-result-search" className="mb-1.5 block text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
            Search ML results
          </label>
          <div className="relative">
            <Search className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-neutral-400" aria-hidden />
            <Input
              id="ml-result-search"
              type="search"
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Result ID, session, model, band, or indicator"
              className="h-9 bg-white pl-8"
            />
          </div>
        </div>
        <fieldset>
          <legend className="mb-2 text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">ML result controls</legend>
          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
            <FilterField id="ml-band-filter" label="Band" value={band} onChange={setBand}>
              <option value="all">All bands</option>
              {data.bands.map((item) => (
                <option key={item.key} value={item.key}>{item.key} ({item.count})</option>
              ))}
            </FilterField>
            <FilterField id="ml-session-filter" label="Session" value={session} onChange={setSession}>
              <option value="all">All sessions</option>
              {data.sessions.map((item) => (
                <option key={item.sessionId} value={item.sessionId}>{item.sessionId}</option>
              ))}
            </FilterField>
            <FilterField id="ml-model-filter" label="Model" value={model} onChange={setModel}>
              <option value="all">All models</option>
              {data.models.map((item) => (
                <option key={item.key} value={item.key}>{item.label} ({item.count})</option>
              ))}
            </FilterField>
            <FilterField id="ml-sort" label="Sort" value={sort} onChange={setSort}>
              <option value="score_desc">Score: high to low</option>
              <option value="score_asc">Score: low to high</option>
              <option value="band">Band</option>
              <option value="id">Result ID</option>
            </FilterField>
          </div>
        </fieldset>
      </div>

      <div className="flex flex-col gap-3 border-t border-neutral-200 pt-4 sm:flex-row sm:items-center sm:justify-between">
        <p className="text-sm text-neutral-600" role="status" aria-live="polite">
          Showing {filtered.length.toLocaleString("en")} of {data.resultCount.toLocaleString("en")} validated anomaly results
        </p>
        <Button
          type="button"
          variant="outline"
          size="lg"
          onClick={clearAll}
          disabled={
            search === "" &&
            band === "all" &&
            session === "all" &&
            model === "all" &&
            sort === "score_desc"
          }
        >
          <FilterX className="size-4" aria-hidden />
          Clear all
        </Button>
      </div>

      {filtered.length === 0 ? (
        <EngineState
          title="No ML results match"
          description="No validated anomaly result matches the current search and filter combination."
          tone="neutral"
        />
      ) : (
        <div className="grid gap-3 lg:grid-cols-2">
          {filtered.map((result) => (
            <article key={result.anomalyResultId} className="min-w-0 rounded-lg border border-neutral-200 bg-white p-4 shadow-sm">
              <div className="flex min-w-0 flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
                <div className="min-w-0">
                  <p className="text-sm font-semibold text-neutral-950">ML anomaly result</p>
                  <code className="mt-1 block break-all font-mono text-[11px] text-neutral-500">{result.anomalyResultId}</code>
                </div>
                <Badge variant="outline" className="w-fit rounded-md border-blue-300 bg-blue-50 text-blue-800">{result.band}</Badge>
              </div>
              <dl className="mt-4 grid gap-3 sm:grid-cols-2">
                <div>
                  <dt className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">Normalized score</dt>
                  <dd className="mt-1 font-mono text-xs text-neutral-950">{result.normalizedScore}</dd>
                </div>
                <div>
                  <dt className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">Threshold</dt>
                  <dd className="mt-1 font-mono text-xs text-neutral-950">{result.threshold}</dd>
                </div>
                <div>
                  <dt className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">Session</dt>
                  <dd className="mt-1 break-all font-mono text-[11px] text-neutral-950">{result.session.sessionId}</dd>
                </div>
                <div>
                  <dt className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">Model</dt>
                  <dd className="mt-1 break-all font-mono text-[11px] text-neutral-950">{result.modelId} v{result.modelVersion}</dd>
                </div>
              </dl>
              <div className="mt-4 border-t border-neutral-200 pt-4">
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={(event) => inspect(result, event.currentTarget)}
                  aria-label={`Inspect anomaly result ${result.anomalyResultId}`}
                >
                  <Search className="size-3.5" aria-hidden />
                  Inspect result
                </Button>
              </div>
            </article>
          ))}
        </div>
      )}

      <MLAnomalyInspector
        anomaly={selected}
        analysisId={data.analysisId}
        open={inspectorOpen}
        onOpenChange={setInspectorOpen}
        returnFocusRef={returnFocusRef}
      />
    </div>
  );
}
