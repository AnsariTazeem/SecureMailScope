import { FileCheck2 } from "lucide-react";
import { applicationCapabilities } from "@/lib/config/env";

export function EvidenceBoundaryNote() {
  return (
    <section className="rounded-lg border border-neutral-300 bg-neutral-50 p-5">
      <div className="flex gap-3">
        <FileCheck2 className="mt-0.5 size-4 shrink-0 text-neutral-600" aria-hidden />
        <div>
          <h2 className="text-sm font-semibold text-neutral-900">Evidence boundary</h2>
          <p className="mt-1 text-xs leading-5 text-neutral-600">
            {applicationCapabilities.liveAnalysis
              ? "The frontend validates file intake only. It never derives TLS, certificate, Policy Risk, or ML Anomaly conclusions."
              : "This evaluation build presents the curated Prototype Analysis Dataset. It does not analyze uploaded captures or derive TLS, certificate, Policy Risk, or ML Anomaly conclusions."}
          </p>
        </div>
      </div>
    </section>
  );
}
