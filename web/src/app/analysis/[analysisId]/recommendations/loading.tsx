import { Skeleton } from "@/components/ui/skeleton";

export default function RecommendationsLoading() {
  return (
    <div
      className="mx-auto w-full max-w-6xl space-y-6"
      aria-label="Loading recommendations"
      aria-busy="true"
    >
      <div className="space-y-3">
        <Skeleton className="h-3 w-48" />
        <Skeleton className="h-8 w-64 max-w-full" />
        <Skeleton className="h-4 w-full max-w-2xl" />
      </div>
      <div className="flex gap-4">
        <Skeleton className="h-10 w-28" />
        <Skeleton className="h-10 w-36" />
      </div>
      <Skeleton className="h-[32rem] w-full" />
      <span className="sr-only">Validating recommendation results…</span>
    </div>
  );
}
