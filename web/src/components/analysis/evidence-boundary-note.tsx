import { FileCheck2 } from "lucide-react";

export function EvidenceBoundaryNote() {
  return (
    <section className="rounded-lg border border-neutral-300 bg-neutral-50 p-5">
      <div className="flex gap-3">
        <FileCheck2 className="mt-0.5 size-4 shrink-0 text-neutral-600" aria-hidden />
        <div>
          <h2 className="text-sm font-semibold text-neutral-900">Evidence boundary</h2>
          <p className="mt-1 text-xs leading-5 text-neutral-600">
            The interface presents supplied analysis records and never derives
            TLS, certificate, Policy Risk, or ML Anomaly conclusions in the
            browser.
          </p>
        </div>
      </div>
    </section>
  );
}
