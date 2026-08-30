import { EyeOff, LockKeyhole, ShieldCheck } from "lucide-react";

export function AssessmentScopePanel() {
  return (
    <section className="overflow-hidden rounded-lg border border-neutral-200 bg-white shadow-sm">
      <div className="border-b border-neutral-200 bg-neutral-50 px-5 py-3">
        <h2 className="text-xs font-bold uppercase tracking-[0.06em] text-neutral-900">
          Assessment scope
        </h2>
      </div>
      <div className="space-y-5 p-5">
        <div className="flex gap-3">
          <ShieldCheck className="mt-0.5 size-4 shrink-0 text-[#027a48]" aria-hidden />
          <div>
            <p className="text-sm font-semibold text-neutral-900">Evidence preserved</p>
            <p className="mt-1 text-xs leading-5 text-neutral-500">
              Capture provenance, SHA-256 identity, and observable packet
              references remain the source of truth.
            </p>
          </div>
        </div>
        <div className="flex gap-3">
          <LockKeyhole className="mt-0.5 size-4 shrink-0 text-neutral-600" aria-hidden />
          <div>
            <p className="text-sm font-semibold text-neutral-900">Passive assessment</p>
            <p className="mt-1 text-xs leading-5 text-neutral-500">
              The workflow does not alter infrastructure, decrypt message bodies,
              or perform live capture.
            </p>
          </div>
        </div>
        <div className="flex gap-3">
          <EyeOff className="mt-0.5 size-4 shrink-0 text-neutral-600" aria-hidden />
          <div>
            <p className="text-sm font-semibold text-neutral-900">Unknown stays unknown</p>
            <p className="mt-1 text-xs leading-5 text-neutral-500">
              Missing or protected evidence is reported as unavailable or not
              observable—not silently interpreted as safe or failed.
            </p>
          </div>
        </div>
      </div>
    </section>
  );
}
