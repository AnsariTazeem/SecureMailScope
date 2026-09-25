"use client";

import { useLayoutEffect } from "react";
import Link from "next/link";
import { usePathname, useRouter, useSearchParams } from "next/navigation";

import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

import {
  severityStyles,
  type AnomalyFindingsData,
  type FindingSessionLink,
  type PolicyFindingsData,
} from "../findings/findings-view-model";
import { MLInvestigationGuidance } from "./ml-investigation-guidance";
import {
  selectRecommendations,
  type RecommendationGroup,
} from "./recommendations-view-model";

function countLabel(count: number, singular: string, plural = `${singular}s`) {
  return `${count.toLocaleString("en")} ${count === 1 ? singular : plural}`;
}

function SessionContext({ session }: { session: FindingSessionLink }) {
  return (
    <div className="min-w-0">
      <p className="break-words text-sm text-neutral-800">
        {session.protocol.toUpperCase()} · stream {session.tcpStreamId} · {session.sourceEndpoint} → {session.destinationEndpoint}
      </p>
    </div>
  );
}

function useRecommendationAnchor() {
  useLayoutEffect(() => {
    function revealTarget() {
      const hash = window.location.hash.slice(1);
      if (!hash) return;

      let targetId: string;
      try {
        targetId = decodeURIComponent(hash);
      } catch {
        return;
      }

      const target = document.getElementById(targetId);
      if (!(target instanceof HTMLElement)) return;
      if (target.dataset.recommendationAnchor !== "true") return;

      target.scrollIntoView({ block: "start" });
      target
        .querySelector<HTMLElement>("[data-recommendation-heading]")
        ?.focus({ preventScroll: true });
    }

    revealTarget();
    window.addEventListener("hashchange", revealTarget);
    return () => window.removeEventListener("hashchange", revealTarget);
  }, []);
}

function RecommendationNavigation({
  analysisId,
  group,
}: {
  analysisId: string;
  group: RecommendationGroup;
}) {
  if (group.linkedSessions.length === 1) {
    const session = group.linkedSessions[0];
    return (
      <Link
        href={`/analysis/${analysisId}/sessions/${session.sessionId}?tab=findings`}
        className="text-sm font-medium underline underline-offset-4"
      >
        Back to session
      </Link>
    );
  }

  if (group.linkedSessions.length > 1) {
    return (
      <div className="space-y-2">
        <p className="text-xs font-semibold text-muted-foreground">
          Open an affected session
        </p>
        <div className="flex flex-wrap gap-x-4 gap-y-2">
          {group.linkedSessions.map((session) => (
            <Link
              key={session.sessionId}
              href={`/analysis/${analysisId}/sessions/${session.sessionId}?tab=findings`}
              className="text-sm font-medium underline underline-offset-4"
            >
              {session.protocol.toUpperCase()} stream {session.tcpStreamId}
              <span className="sr-only"> ({session.sessionId})</span>
            </Link>
          ))}
        </div>
      </div>
    );
  }

  return null;
}

function EmptyRecommendations({
  data,
  filterState,
  selectedSession,
}: {
  data: PolicyFindingsData;
  filterState: "all" | "valid" | "invalid";
  selectedSession: FindingSessionLink | null;
}) {
  const incomplete =
    data.analysisStatus !== "complete" ||
    data.ruleEngineStatus !== "complete" ||
    (filterState === "valid"
      ? selectedSession?.captureCompleteness !== "complete"
      : data.hasIncompleteSessions);
  const title =
    filterState === "invalid"
      ? "Session filter is unavailable"
      : filterState === "valid"
        ? "No recommendations for the selected session"
        : incomplete
          ? "Recommendation results are incomplete"
          : "No recommendations supplied for this analysis";
  const description =
    filterState === "invalid"
      ? "The requested session does not belong to this analysis. No unfiltered recommendations are shown. Clear the filter or return to Sessions."
      : filterState === "valid"
        ? incomplete
          ? "No recommendation linked to this session is available in the current partial result. Review the source status and evidence limitations before drawing a conclusion."
          : "The completed result supplies no recommendation linked to this session. This does not establish that the session is secure."
        : incomplete
          ? `Analysis status is ${data.analysisStatus.replaceAll("_", " ")} and policy engine status is ${data.ruleEngineStatus.replaceAll("_", " ")}. Only supplied results can be shown; absence is not a security conclusion.`
          : "The completed analysis supplies no policy recommendations. This does not establish that the capture or its sessions are secure.";

  return (
    <div className="rounded-xl border border-dashed border-border bg-card p-8 text-center">
      <h2 className="font-semibold">{title}</h2>
      <p className="mx-auto mt-2 max-w-2xl text-sm leading-6 text-muted-foreground">
        {description}
      </p>
    </div>
  );
}

export function RecommendationsWorkspace({
  policyData,
  anomalyData,
}: {
  policyData: PolicyFindingsData;
  anomalyData: AnomalyFindingsData;
}) {
  const params = useSearchParams();
  const pathname = usePathname();
  const router = useRouter();
  const requestedSessionId = params.get("session");
  const activeView = params.get("view") === "ml" ? "anomalies" : "remediation";
  const selection = selectRecommendations(policyData, requestedSessionId);
  useRecommendationAnchor();

  return (
    <div className="mx-auto w-full max-w-6xl space-y-6">
      <header>
        <p className="text-xs text-muted-foreground">Analysis / Recommendations</p>
        <h1 className="mt-2 text-3xl font-semibold tracking-tight">Recommendations</h1>
        <p className="mt-2 text-sm text-muted-foreground">
          See what to fix, why it matters, and how to verify the change.
        </p>
      </header>

      <Tabs
        value={activeView}
        onValueChange={(value) => {
          const next = new URLSearchParams(params.toString());
          if (value === "anomalies") next.set("view", "ml");
          else next.delete("view");
          const query = next.toString();
          router.push(query ? `${pathname}?${query}` : pathname, {
            scroll: false,
          });
        }}
        className="gap-6"
      >
        <TabsList variant="line" className="h-auto flex-wrap gap-2" aria-label="Recommendation type">
          <TabsTrigger value="remediation" className="px-3">Policy recommendations</TabsTrigger>
          <TabsTrigger value="anomalies" className="px-3">
            ML investigation guidance
          </TabsTrigger>
        </TabsList>

        <TabsContent value="remediation" className="space-y-5">
          {requestedSessionId ? (
            <section
              aria-label="Active session filter"
              className="flex flex-col gap-3 rounded-lg border border-border bg-card p-4 sm:flex-row sm:items-center sm:justify-between"
            >
              <div className="min-w-0">
                <p className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">Active session filter</p>
                {selection.selectedSession ? (
                  <SessionContext session={selection.selectedSession} />
                ) : (
                  <p className="mt-1 text-sm text-red-700">
                    Session <code className="break-all font-mono text-xs">{requestedSessionId}</code> is not available in this analysis.
                  </p>
                )}
              </div>
              <Link
                href={`/analysis/${policyData.analysisId}/recommendations`}
                className="shrink-0 text-sm font-medium underline underline-offset-4"
              >
                Clear session filter
              </Link>
            </section>
          ) : null}

          <p className="text-sm text-muted-foreground" role="status">
            {countLabel(selection.groups.length, "recommendation")} · {countLabel(selection.findings.length, "linked policy finding")}
          </p>

          {selection.groups.map((group) => {
            const { recommendation, linkedFindings } = group;
            const severities = [...new Set(linkedFindings.map((finding) => finding.severity))];
            return (
              <article
                key={recommendation.recommendationId}
                id={recommendation.recommendationId}
                data-recommendation-anchor="true"
                aria-labelledby={`${recommendation.recommendationId}-heading`}
                className="scroll-mt-24 rounded-xl border border-border bg-card p-5 sm:p-6"
              >
                <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
                  <div className="min-w-0">
                    <h2
                      id={`${recommendation.recommendationId}-heading`}
                      data-recommendation-heading
                      tabIndex={-1}
                      className="break-words text-lg font-semibold focus-visible:outline-2"
                    >
                      {recommendation.title}
                    </h2>
                    <p className="mt-2 text-sm leading-6 text-muted-foreground">{recommendation.summary}</p>
                  </div>
                  <div className="flex shrink-0 flex-wrap gap-2">
                    <Badge variant="outline" className="capitalize">{recommendation.priority} priority</Badge>
                    {severities.map((severity) => (
                      <Badge key={severity} variant="outline" className={severityStyles[severity]}>
                        {severity} severity
                      </Badge>
                    ))}
                  </div>
                </div>

                <section className="mt-5 border-t border-border pt-4">
                  <h3 className="text-sm font-semibold">{countLabel(linkedFindings.length, "Linked finding")}</h3>
                  <div className="mt-3 space-y-3">
                    {linkedFindings.map((finding) => (
                      <div key={finding.findingId} className="rounded-lg bg-muted/40 p-4">
                        <div className="flex flex-wrap items-center gap-2">
                          <p className="font-medium">{finding.title}</p>
                          <Badge variant="outline" className={severityStyles[finding.severity]}>{finding.severity}</Badge>
                        </div>
                        <div className="mt-3 space-y-3">
                          {finding.linkedSessions.map((session) => <SessionContext key={session.sessionId} session={session} />)}
                        </div>
                      </div>
                    ))}
                    {linkedFindings.length === 0 ? (
                      <p className="text-sm text-muted-foreground">
                        No affected finding or session relationship was supplied for this action.
                      </p>
                    ) : null}
                  </div>
                  <div className="mt-4"><RecommendationNavigation analysisId={policyData.analysisId} group={group} /></div>
                </section>

                <div className="mt-5 grid gap-6 border-t border-border pt-5 md:grid-cols-2">
                  <section>
                    <h3 className="text-sm font-semibold">Remediation steps</h3>
                    <ol className="mt-3 list-decimal space-y-2 pl-5 text-sm leading-6">
                      {recommendation.actionSteps.map((step, index) => <li key={index}>{step}</li>)}
                    </ol>
                  </section>
                  <section>
                    <h3 className="text-sm font-semibold">Verification steps</h3>
                    <ol className="mt-3 list-decimal space-y-2 pl-5 text-sm leading-6">
                      {recommendation.verificationSteps.map((step, index) => <li key={index}>{step}</li>)}
                    </ol>
                  </section>
                </div>

                <section className="mt-5 border-t border-border pt-4">
                  <h3 className="text-sm font-semibold">Supporting evidence</h3>
                  <div className="mt-3 space-y-3">
                    {linkedFindings.map((finding) => {
                      const session = finding.linkedSessions[0];
                      const evidenceCount = finding.directEvidence.length + finding.evidenceThroughSources.length;
                      return (
                        <div key={finding.findingId} className="flex flex-col gap-2 text-sm sm:flex-row sm:items-center sm:justify-between">
                          <span>{finding.title}: {countLabel(evidenceCount, "evidence reference")}</span>
                          {session ? (
                            <Link
                              href={`/analysis/${policyData.analysisId}/sessions/${session.sessionId}?tab=findings#session-evidence-records-heading`}
                              className="shrink-0 font-medium underline underline-offset-4"
                            >
                              View session evidence
                            </Link>
                          ) : null}
                        </div>
                      );
                    })}
                    {linkedFindings.length === 0 ? (
                      <p className="text-sm text-muted-foreground">
                        No supporting finding or evidence relationship was supplied.
                      </p>
                    ) : null}
                  </div>
                </section>

                <details className="mt-5 border-t border-border pt-4">
                  <summary className="cursor-pointer text-sm font-semibold focus-visible:outline-2">Technical details</summary>
                  <dl className="mt-4 grid gap-4 text-sm sm:grid-cols-2">
                    <div>
                      <dt className="text-xs font-semibold text-muted-foreground">Recommendation ID</dt>
                      <dd><code className="break-all font-mono text-xs">{recommendation.recommendationId}</code></dd>
                    </div>
                    <div>
                      <dt className="text-xs font-semibold text-muted-foreground">Scope / automation</dt>
                      <dd className="capitalize">{recommendation.scope.replaceAll("_", " ")} · {recommendation.automationStatus.replaceAll("_", " ")}</dd>
                    </div>
                    <div className="sm:col-span-2">
                      <dt className="text-xs font-semibold text-muted-foreground">Standards references</dt>
                      <dd className="mt-1 text-muted-foreground">
                        {recommendation.standardsReferences.map((reference) =>
                          reference.section
                            ? `${reference.id} § ${reference.section}`
                            : reference.id,
                        ).join(", ") || "None supplied"}
                      </dd>
                    </div>
                    {linkedFindings.map((finding) => (
                      <div key={finding.findingId} className="sm:col-span-2">
                        <dt className="text-xs font-semibold text-muted-foreground">{finding.title}</dt>
                        <dd className="mt-1 space-y-2 text-muted-foreground">
                          <p className="break-all font-mono text-[11px]">
                            Finding ID: {finding.findingId}
                          </p>
                          <p>{finding.rationale}</p>
                          <p><span className="font-medium text-foreground">Impact:</span> {finding.impact}</p>
                          <p className="break-all font-mono text-[11px]">Direct evidence: {finding.directEvidence.map((item) => item.evidenceId).join(", ") || "none supplied"}</p>
                          <p className="break-all font-mono text-[11px]">Evidence through sources: {finding.evidenceThroughSources.map((item) => item.evidenceId).join(", ") || "none supplied"}</p>
                        </dd>
                      </div>
                    ))}
                  </dl>
                </details>
              </article>
            );
          })}

          {selection.groups.length === 0 ? (
            <EmptyRecommendations
              data={policyData}
              filterState={selection.filterState}
              selectedSession={selection.selectedSession}
            />
          ) : null}
        </TabsContent>

        <TabsContent value="anomalies" className="space-y-5">
          <MLInvestigationGuidance data={anomalyData} sessionId={requestedSessionId} />
        </TabsContent>
      </Tabs>
    </div>
  );
}
