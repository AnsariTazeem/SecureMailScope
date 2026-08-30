import { Skeleton } from "@/components/ui/skeleton";

export default function OverviewLoading() {
  return (
    <div
      className="mx-auto w-full max-w-7xl space-y-6"
      aria-label="Loading analysis overview"
      aria-busy="true"
    >
      <div className="space-y-3">
        <Skeleton className="h-3 w-36" />
        <Skeleton className="h-8 w-72 max-w-full" />
        <Skeleton className="h-4 w-full max-w-2xl" />
      </div>
      <Skeleton className="h-44 w-full" />
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        {Array.from({ length: 4 }, (_, index) => (
          <Skeleton key={index} className="h-36 w-full" />
        ))}
      </div>
      <div className="grid gap-6 xl:grid-cols-[minmax(0,1.6fr)_minmax(18rem,0.8fr)]">
        <Skeleton className="h-80 w-full" />
        <Skeleton className="h-80 w-full" />
      </div>
      <span className="sr-only">Validating the analysis result…</span>
    </div>
  );
}
