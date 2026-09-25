import Link from "next/link";
import { Badge } from "@/components/ui/badge";
import type { AnomalyFindingsData } from "../findings/findings-view-model";

/** Advisory presentation of validated anomaly records; never a policy remediation. */
export function MLInvestigationGuidance({ data, sessionId }: {
  data: AnomalyFindingsData;
  sessionId: string | null;
}) {
  const results = data.results.filter(result => !sessionId || result.session.sessionId === sessionId);
  return (
    <section aria-labelledby="ml-guidance-heading" className="space-y-4">
      <h2 id="ml-guidance-heading" className="text-lg font-semibold">ML investigation guidance</h2>
      <p className="text-sm text-muted-foreground">Analyst review of unusual behaviour, separate from deterministic policy remediation.</p>
      {results.map(result => {
        const evidenceCount = new Set([...result.directEvidence, ...result.evidenceThroughSources].map(item => item.evidenceId)).size;
        return (
          <article key={result.anomalyResultId} className="space-y-4 rounded-xl border border-border bg-card p-5">
            <div className="flex flex-wrap items-center gap-2">
              <h3 className="break-all font-semibold">{result.session.sessionId}</h3>
              <Badge variant="outline">{result.band} · {result.normalizedScore}</Badge>
            </div>
            <p className="break-words text-sm">{result.session.protocol.toUpperCase()} · {result.session.sourceEndpoint} → {result.session.destinationEndpoint}</p>
            <p className="text-sm">{evidenceCount} linked evidence records</p>
            <ul className="list-disc space-y-2 pl-5 text-sm">
              {result.unusualFeatureIndicators.map((indicator, i) => <li key={i}>{indicator}</li>)}
            </ul>
            <ol className="list-decimal space-y-2 pl-5 text-sm">
              <li>Review the linked session.</li>
              <li>Compare this behaviour with the organization’s expected mail-flow baseline.</li>
              <li>Validate the unusual indicators before taking action.</li>
            </ol>
            <p className="text-sm text-muted-foreground">{result.interpretationNote}</p>
            <Link className="inline-block text-sm font-medium underline underline-offset-4" href={`/analysis/${data.analysisId}/findings?view=ml#ml-anomaly-heading`}>Review anomaly result in Findings</Link>
          </article>
        );
      })}
      {results.length === 0 ? <p className="text-sm text-muted-foreground">No validated anomaly results are available for this selection.</p> : null}
    </section>
  );
}
