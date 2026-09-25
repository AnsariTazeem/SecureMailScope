import Link from "next/link";
import { Construction, Database, Info } from "lucide-react";


type FutureRoutePlaceholderProps = {
  analysisId: string;
  title: string;
  description: string;
  sessionId?: string;
};

export function FutureRoutePlaceholder({
  analysisId,
  title,
  description,
  sessionId,
}: FutureRoutePlaceholderProps) {
  return (
    <div className="mx-auto flex w-full max-w-5xl flex-col gap-6">
      <div>
        <p className="text-[11px] font-bold uppercase tracking-[0.08em] text-neutral-500">
          Analysis / {title}
        </p>
        <h1 className="mt-2 text-2xl font-semibold tracking-tight text-neutral-950">{title}</h1>
        <p className="mt-2 max-w-3xl text-sm leading-6 text-neutral-600">{description}</p>
      </div>

      <section className="overflow-hidden rounded-lg border border-neutral-200 bg-white shadow-sm">
        <div className="flex flex-col gap-3 border-b border-neutral-200 bg-neutral-50 px-5 py-4 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <p className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">Analysis ID</p>
            <p className="mt-1 font-mono text-xs text-neutral-950">{analysisId}</p>
          </div>
        </div>
        <div className="flex min-h-80 flex-col items-center justify-center px-6 py-12 text-center">
          <span className="flex size-12 items-center justify-center rounded-full border border-neutral-200 bg-neutral-50 text-neutral-600">
            <Construction className="size-5" aria-hidden />
          </span>
          <h2 className="mt-4 text-lg font-semibold text-neutral-950">Reserved for a later frontend milestone</h2>
          <p className="mt-2 max-w-xl text-sm leading-6 text-neutral-500">
            F1 establishes the route and shared shell only. This placeholder does
            not calculate, summarize, or invent analysis findings.
          </p>
          {sessionId ? (
            <p className="mt-4 rounded-md bg-neutral-100 px-3 py-1.5 font-mono text-xs text-neutral-700">
              Session: {sessionId}
            </p>
          ) : null}
          <div className="mt-6 flex max-w-xl items-start gap-2 rounded-lg border border-neutral-200 bg-neutral-50 p-3 text-left">
            <Info className="mt-0.5 size-4 shrink-0 text-neutral-500" aria-hidden />
            <p className="text-xs leading-5 text-neutral-600">
              Future content must render canonical Chain-of-Proof state. Policy
              Risk and ML Anomaly will remain separate, and unavailable evidence
              will remain explicitly unavailable.
            </p>
          </div>
          <Link
            href="/analysis/new"
            className="mt-6 inline-flex h-9 items-center gap-2 rounded-md border border-neutral-300 bg-white px-4 text-sm font-medium text-neutral-800 outline-none hover:bg-neutral-50 focus-visible:ring-2 focus-visible:ring-neutral-950 focus-visible:ring-offset-2"
          >
            <Database className="size-4" aria-hidden />
            Start a new analysis
          </Link>
        </div>
      </section>
    </div>
  );
}
