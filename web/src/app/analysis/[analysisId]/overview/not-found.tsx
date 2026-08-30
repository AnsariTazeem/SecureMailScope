import Link from "next/link";
import { CircleAlert } from "lucide-react";

export default function OverviewNotFound() {
  return (
    <div className="mx-auto flex w-full max-w-2xl flex-1 items-center justify-center py-12 sm:py-20">
      <section className="w-full rounded-lg border border-neutral-200 bg-white p-6 text-center shadow-sm sm:p-8">
        <span className="mx-auto flex size-11 items-center justify-center rounded-full border border-amber-300 bg-amber-50 text-amber-800">
          <CircleAlert className="size-5" aria-hidden />
        </span>
        <p className="mt-4 text-[11px] font-bold uppercase tracking-[0.08em] text-neutral-500">
          Analysis / Overview
        </p>
        <h1 className="mt-2 text-xl font-semibold text-neutral-950">
          Analysis ID is invalid or unavailable
        </h1>
        <p className="mx-auto mt-2 max-w-lg text-sm leading-6 text-neutral-600">
          The identifier does not match the validated analysis-ID format, or
          the configured data source has no analysis with that identifier. No
          result was assumed.
        </p>
        <Link
          href="/analysis/new"
          className="mt-6 inline-flex h-9 items-center justify-center rounded-md bg-neutral-950 px-4 text-sm font-medium text-white outline-none hover:bg-neutral-800 focus-visible:ring-2 focus-visible:ring-neutral-950 focus-visible:ring-offset-2"
        >
          Start a new analysis
        </Link>
      </section>
    </div>
  );
}
