import { AnalysisBreadcrumbs } from "@/components/layout/analysis-breadcrumbs";

import Link from "next/link";
import { CircleAlert } from "lucide-react";

export default function SessionsNotFound() {
  return (
    <div className="mx-auto flex w-full max-w-2xl flex-1 items-center justify-center py-12 sm:py-20">
      <section className="w-full rounded-lg border border-neutral-200 bg-white p-6 text-center shadow-sm sm:p-8">
        <span className="mx-auto flex size-11 items-center justify-center rounded-full border border-amber-300 bg-amber-50 text-amber-800">
          <CircleAlert className="size-5" aria-hidden />
        </span>
        <AnalysisBreadcrumbs className="mt-4" />
        <h1 className="mt-2 text-xl font-semibold text-neutral-950">
          Analysis or session is invalid or unavailable
        </h1>
        <p className="mx-auto mt-2 max-w-lg text-sm leading-6 text-neutral-600">
          The route identifier is invalid, or the configured data source has no
          matching validated record. No analysis or session was assumed.
        </p>
        <Link
          href="/analysis/new"
          className="mt-6 inline-flex min-h-9 items-center justify-center rounded-md bg-neutral-950 px-4 text-sm font-medium text-white outline-none hover:bg-neutral-800 focus-visible:ring-2 focus-visible:ring-neutral-950 focus-visible:ring-offset-2"
        >
          Start a new analysis
        </Link>
      </section>
    </div>
  );
}
