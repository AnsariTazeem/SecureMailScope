import Link from "next/link";
import {
  ArrowLeft,
  ArrowRight,
  BrainCircuit,
  CircleAlert,
  Database,
  FileKey2,
  GitBranch,
  Info,
  Network,
  ShieldAlert,
} from "lucide-react";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { cn } from "@/lib/utils";

import { ProofMapGraph } from "./proof-map-graph";
import type {
  ProofMapData,
  ProofRelationship,
  ProofSession,
} from "./proof-map-view-model";

const relationshipStyles: Record<
  ProofRelationship["relationshipType"],
  string
> = {
  structural: "border-neutral-300 bg-neutral-50 text-neutral-700",
  direct_evidence: "border-emerald-200 bg-emerald-50 text-emerald-800",
  declared_source: "border-slate-300 bg-slate-100 text-slate-800",
  policy: "border-violet-200 bg-violet-50 text-violet-800",
  anomaly: "border-blue-200 bg-blue-50 text-blue-800",
};

function RelationshipLedger({ session }: { session: ProofSession }) {
  return (
    <details className="rounded-lg border border-neutral-200 bg-white">
      <summary className="cursor-pointer rounded-lg px-4 py-3 text-sm font-semibold text-neutral-950 outline-none hover:bg-neutral-50 focus-visible:ring-2 focus-visible:ring-neutral-950 focus-visible:ring-inset">
        Exact relationship ledger · {session.sessionId} · {session.relationships.length}
      </summary>
      <div className="border-t border-neutral-200 p-4">
        <ul className="space-y-2">
          {session.relationships.map((relationship) => (
            <li
              key={relationship.relationshipId}
              className="grid min-w-0 gap-2 rounded-md border border-neutral-200 bg-neutral-50 p-3 text-[11px] md:grid-cols-[minmax(0,1fr)_auto_minmax(0,1fr)] md:items-center"
            >
              <span className="min-w-0">
                <span className="block text-[9px] font-bold uppercase tracking-[0.06em] text-neutral-500">
                  {relationship.fromKind}
                </span>
                <code className="block break-all font-mono text-neutral-900">
                  {relationship.fromId}
                </code>
              </span>
              <span className="min-w-0 text-left md:text-center">
                <Badge
                  variant="outline"
                  className={cn(
                    "max-w-full rounded-md font-mono text-[9px]",
                    relationshipStyles[relationship.relationshipType],
                  )}
                >
                  {relationship.contractField}
                </Badge>
              </span>
              <span className="min-w-0 md:text-right">
                <span className="block text-[9px] font-bold uppercase tracking-[0.06em] text-neutral-500">
                  {relationship.toKind}
                </span>
                <code className="block break-all font-mono text-neutral-900">
                  {relationship.toId}
                </code>
              </span>
            </li>
          ))}
        </ul>
      </div>
    </details>
  );
}

function Header({ data }: { data: ProofMapData }) {
  return (
    <header className="space-y-4">
      <div className="flex min-w-0 flex-col gap-4 md:flex-row md:items-end md:justify-between">
        <div className="min-w-0">
          <p className="text-[11px] font-bold uppercase tracking-[0.08em] text-neutral-500">
            Analysis / Proof Map
          </p>
          <h1 className="mt-1 text-2xl font-semibold tracking-tight text-neutral-950 sm:text-3xl">
            Chain-of-Proof Explorer
          </h1>
          <p className="mt-2 max-w-3xl text-sm leading-6 text-neutral-600">
            Follow only contract-declared capture, session, evidence, event,
            observation, fact, and deterministic policy relationships.
          </p>
        </div>
        <div className="flex w-full flex-col gap-2 sm:flex-row md:w-auto">
          <Link
            href={data.overviewHref}
            className="inline-flex min-h-9 items-center justify-center gap-2 rounded-md border border-neutral-300 bg-white px-4 text-sm font-semibold text-neutral-900 outline-none hover:bg-neutral-50 focus-visible:ring-2 focus-visible:ring-neutral-950 focus-visible:ring-offset-2"
          >
            <ArrowLeft className="size-4" aria-hidden />
            Overview
          </Link>
          <Link
            href={data.sessionsHref}
            className="inline-flex min-h-9 items-center justify-center gap-2 rounded-md bg-neutral-950 px-4 text-sm font-semibold text-white outline-none hover:bg-neutral-800 focus-visible:ring-2 focus-visible:ring-neutral-950 focus-visible:ring-offset-2"
          >
            Sessions Explorer
            <ArrowRight className="size-4" aria-hidden />
          </Link>
        </div>
      </div>

      {data.dataSource === "mock" ? (
        <Alert className="border-blue-200 bg-blue-50/70 px-4 py-3 text-blue-950">
          <Database className="size-4" aria-hidden />
          <AlertTitle>Prototype Analysis Dataset</AlertTitle>
          <AlertDescription className="text-blue-900/80">
            {data.datasetLabel ?? "Prototype Analysis Dataset"} is a labelled,
            validated synthetic fixture. It is not a production analyzer run.
          </AlertDescription>
        </Alert>
      ) : (
        <Alert className="border-neutral-300 bg-neutral-50 px-4 py-3 text-neutral-950">
          <Database className="size-4" aria-hidden />
          <AlertTitle>Production API source</AlertTitle>
          <AlertDescription className="text-neutral-700">
            This result was supplied and validated through the configured API
            data source. No prototype fallback was used.
          </AlertDescription>
        </Alert>
      )}
    </header>
  );
}

function Summary({ data }: { data: ProofMapData }) {
  return (
    <section aria-labelledby="proof-map-summary-heading">
      <h2 id="proof-map-summary-heading" className="sr-only">
        Proof Map summary
      </h2>
      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
        <Card className="rounded-lg border-neutral-200 shadow-sm ring-0">
          <CardContent>
            <FileKey2 className="size-4 text-neutral-500" aria-hidden />
            <p className="mt-3 text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
              Declared relationships
            </p>
            <p className="mt-1 font-mono text-2xl font-semibold text-neutral-950">
              {data.relationshipCount}
            </p>
            <p className="mt-1 text-xs leading-5 text-neutral-600">
              {data.directEvidenceRelationshipCount} direct evidence ·{" "}
              {data.declaredSourceRelationshipCount} declared fact source
            </p>
          </CardContent>
        </Card>
        <Card className="rounded-lg border-neutral-200 shadow-sm ring-0">
          <CardContent>
            <Network className="size-4 text-neutral-500" aria-hidden />
            <p className="mt-3 text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
              Sessions / contract
            </p>
            <p className="mt-1 font-mono text-2xl font-semibold text-neutral-950">
              {data.sessions.length}
            </p>
            <p className="mt-1 text-xs leading-5 text-neutral-600">
              Analysis {data.analysisStatus} · Chain v{data.chainSchemaVersion}
            </p>
          </CardContent>
        </Card>
        <Card className="rounded-lg border-violet-200 bg-violet-50/40 shadow-sm ring-0">
          <CardContent>
            <ShieldAlert className="size-4 text-violet-700" aria-hidden />
            <p className="mt-3 text-[10px] font-bold uppercase tracking-[0.06em] text-violet-700">
              Policy Risk
            </p>
            <p className="mt-1 font-mono text-2xl font-semibold text-violet-950">
              {data.policyRisk.status === "available"
                ? data.policyRisk.cappedScore
                : "not_present"}
            </p>
            <p className="mt-1 text-xs leading-5 text-violet-900/80">
              {data.policyRisk.findingCount} finding
              {data.policyRisk.findingCount === 1 ? "" : "s"} · deterministic
              policy only
            </p>
          </CardContent>
        </Card>
        <Card className="rounded-lg border-blue-200 bg-blue-50/40 shadow-sm ring-0">
          <CardContent>
            <BrainCircuit className="size-4 text-blue-700" aria-hidden />
            <p className="mt-3 text-[10px] font-bold uppercase tracking-[0.06em] text-blue-700">
              ML Anomaly
            </p>
            <p className="mt-1 font-mono text-2xl font-semibold text-blue-950">
              {data.mlAnomaly.engineStatus}
            </p>
            <p className="mt-1 text-xs leading-5 text-blue-900/80">
              {data.mlAnomaly.resultCount} result
              {data.mlAnomaly.resultCount === 1 ? "" : "s"} · no combined score
            </p>
          </CardContent>
        </Card>
      </div>
    </section>
  );
}

function Legend() {
  const states = ["unknown", "not_present", "not_assessed", "not_observable"];
  return (
    <Card className="rounded-lg border-neutral-200 shadow-sm ring-0">
      <CardHeader className="border-b border-neutral-200">
        <CardTitle>
          <h2>Path and state legend</h2>
        </CardTitle>
        <CardDescription>
          Solid green edges are direct evidence references. Dashed slate edges
          are transitive evidence reached only through declared fact sources.
        </CardDescription>
      </CardHeader>
      <CardContent className="grid gap-4 lg:grid-cols-2">
        <div className="space-y-2 text-xs text-neutral-700">
          <p className="border-l-2 border-emerald-600 pl-3">
            <strong>Direct evidence relationship</strong> — an explicit evidence
            ID is present on the session, event, observation, finding, or anomaly
            record.
          </p>
          <p className="border-l-2 border-dashed border-slate-500 pl-3">
            <strong>Evidence through declared sources</strong> — evidence is
            reached by following only a fact&apos;s source event, observation, or
            fact IDs.
          </p>
          <p className="border-l-2 border-violet-600 pl-3">
            <strong>Policy relationship</strong> — an explicit deterministic
            finding or rule reference, kept separate from ML Anomaly output.
          </p>
        </div>
        <div>
          <p className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
            Distinct absence and uncertainty vocabulary
          </p>
          <div className="mt-2 flex flex-wrap gap-2">
            {states.map((state) => (
              <Badge
                key={state}
                variant="outline"
                className="rounded-md font-mono text-[10px]"
              >
                {state}
              </Badge>
            ))}
          </div>
          <p className="mt-2 text-xs leading-5 text-neutral-600">
            These contract states are never collapsed into a single unknown or
            success state. TLS 1.3 certificate contents remain not_observable
            when passive evidence does not expose them.
          </p>
        </div>
      </CardContent>
    </Card>
  );
}

function SeparateAssessmentState({ data }: { data: ProofMapData }) {
  return (
    <section
      className="grid gap-4 lg:grid-cols-2"
      aria-label="Separate assessment outputs"
    >
      <Card className="rounded-lg border-violet-200 shadow-sm ring-0">
        <CardHeader className="border-b border-violet-100 bg-violet-50/40">
          <CardTitle>
            <h2>Policy Risk relationships</h2>
          </CardTitle>
          <CardDescription>
            Deterministic finding and contribution references only.
          </CardDescription>
        </CardHeader>
        <CardContent className="text-sm leading-6 text-neutral-700">
          {data.policyRisk.status === "available" ? (
            <dl className="grid gap-3 sm:grid-cols-2">
              <div>
                <dt className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
                  Policy Risk ID
                </dt>
                <dd className="break-all font-mono text-xs">
                  {data.policyRisk.policyRiskId}
                </dd>
              </div>
              <div>
                <dt className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
                  Profile
                </dt>
                <dd className="break-all font-mono text-xs">
                  {data.policyRisk.profileId}
                </dd>
              </div>
              <div>
                <dt className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
                  Capped / uncapped
                </dt>
                <dd className="font-mono text-xs">
                  {data.policyRisk.cappedScore} / {data.policyRisk.uncappedScore}
                </dd>
              </div>
              <div>
                <dt className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
                  Contributions
                </dt>
                <dd className="font-mono text-xs">
                  {data.policyRisk.contributionCount}
                </dd>
              </div>
            </dl>
          ) : (
            <p>
              <code className="font-mono">not_present</code> — no Policy Risk
              summary was supplied.
            </p>
          )}
        </CardContent>
      </Card>
      <Card className="rounded-lg border-blue-200 shadow-sm ring-0">
        <CardHeader className="border-b border-blue-100 bg-blue-50/40">
          <CardTitle>
            <h2>ML Anomaly relationships</h2>
          </CardTitle>
          <CardDescription>
            Kept outside the deterministic Policy Risk chain.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <dl className="grid gap-3 sm:grid-cols-2">
            <div>
              <dt className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
                Engine status
              </dt>
              <dd className="font-mono text-xs">{data.mlAnomaly.engineStatus}</dd>
            </div>
            <div>
              <dt className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
                Results
              </dt>
              <dd className="font-mono text-xs">{data.mlAnomaly.resultCount}</dd>
            </div>
            <div>
              <dt className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
                Explicit evidence IDs
              </dt>
              <dd className="font-mono text-xs">
                {data.mlAnomaly.explicitEvidenceCount}
              </dd>
            </div>
            <div>
              <dt className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
                Explicit linked facts / observations
              </dt>
              <dd className="font-mono text-xs">
                {data.mlAnomaly.explicitLinkedFactCount} /{" "}
                {data.mlAnomaly.explicitLinkedObservationCount}
              </dd>
            </div>
          </dl>
          <p className="mt-4 text-xs leading-5 text-neutral-600">
            No anomaly edge or evidence is inferred from timestamps, labels,
            frame numbers, text similarity, or Policy Risk output.
          </p>
        </CardContent>
      </Card>
    </section>
  );
}

function Limitations({ data }: { data: ProofMapData }) {
  if (data.limitations.length === 0) return null;
  return (
    <section aria-labelledby="proof-limitations-heading">
      <Card className="rounded-lg border-neutral-200 shadow-sm ring-0">
        <CardHeader className="border-b border-neutral-200">
          <CardTitle>
            <h2 id="proof-limitations-heading">Declared limitations</h2>
          </CardTitle>
          <CardDescription>
            Exact limitation codes stay distinct; missing data is not converted
            into an edge.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <ul className="grid gap-3 lg:grid-cols-2">
            {data.limitations.map((limitation, index) => (
              <li
                key={`${limitation.scope}:${limitation.code}:${index}`}
                className="rounded-lg border border-neutral-200 bg-neutral-50 p-4"
              >
                <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
                  <code className="font-mono text-xs font-semibold text-neutral-950">
                    {limitation.code}
                  </code>
                  <span className="break-all text-[10px] text-neutral-500">
                    {limitation.scope}
                  </span>
                </div>
                <p className="mt-2 text-sm font-medium text-neutral-900">
                  {limitation.summary}
                </p>
                {limitation.detail ? (
                  <p className="mt-1 break-words text-xs leading-5 text-neutral-600">
                    {limitation.detail}
                  </p>
                ) : null}
              </li>
            ))}
          </ul>
        </CardContent>
      </Card>
    </section>
  );
}

export function ProofMap({ data }: { data: ProofMapData }) {
  return (
    <div className="mx-auto w-full min-w-0 max-w-[100rem] space-y-6 overflow-x-clip">
      <Header data={data} />
      <Summary data={data} />
      <Legend />

      {data.partial ? (
        <Alert className="border-amber-200 bg-amber-50">
          <CircleAlert className="size-4" aria-hidden />
          <AlertTitle>
            Proof graph contains incomplete or partial relationships
          </AlertTitle>
          <AlertDescription>
            The graph stops at the last contract-declared relationship. It does
            not fill gaps from timestamps, array position, frame numbers,
            matching labels, or text.
          </AlertDescription>
        </Alert>
      ) : null}

      {data.empty ? (
        <Card className="rounded-lg border-neutral-200 shadow-sm ring-0">
          <CardContent className="py-12 text-center">
            <GitBranch className="mx-auto size-8 text-neutral-400" aria-hidden />
            <h2 className="mt-3 text-base font-semibold text-neutral-950">
              Empty proof graph
            </h2>
            <p className="mx-auto mt-2 max-w-xl text-sm leading-6 text-neutral-600">
              The validated result contains no session records, so no
              capture-to-session proof graph can be rendered. No nodes or edges
              were invented.
            </p>
          </CardContent>
        </Card>
      ) : (
        <ProofMapGraph data={data} />
      )}

      <SeparateAssessmentState data={data} />

      {!data.empty ? (
        <section aria-labelledby="relationship-ledger-heading">
          <div className="mb-3">
            <h2
              id="relationship-ledger-heading"
              className="text-lg font-semibold text-neutral-950"
            >
              Exact relationship ledger
            </h2>
            <p className="mt-1 text-xs leading-5 text-neutral-600">
              Secondary, collapsed, and accessible. Every declared relationship
              names its exact backing contract field, including policy-evaluation
              references that are not duplicated as main-canvas nodes.
            </p>
          </div>
          <div className="space-y-3">
            {data.sessions.map((session) => (
              <RelationshipLedger
                key={`ledger:${session.sessionId}`}
                session={session}
              />
            ))}
          </div>
        </section>
      ) : null}

      <Limitations data={data} />
      <footer className="flex items-start gap-2 border-t border-neutral-200 pt-5 text-xs leading-5 text-neutral-500">
        <Info className="mt-0.5 size-4 shrink-0" aria-hidden />
        Proof nodes come from the revalidated AnalysisDataSource result. A
        displayed edge shows a declared contract relationship; it does not create
        an independent security conclusion.
      </footer>
    </div>
  );
}
