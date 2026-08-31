import { Skeleton } from "@/components/ui/skeleton";

export default function FindingsLoading() {
  return (
    <div
      className="mx-auto w-full max-w-[96rem] space-y-6"
      aria-label="Loading findings"
      aria-busy="true"
    >
      <div className="space-y-3">
        <Skeleton className="h-3 w-36" />
        <Skeleton className="h-8 w-48 max-w-full" />
        <Skeleton className="h-4 w-full max-w-2xl" />
      </div>
      <div className="flex gap-1">
        <Skeleton className="h-9 w-32" />
        <Skeleton className="h-9 w-32" />
      </div>
      <div className="grid gap-4 sm:grid-cols-2">
        <Skeleton className="h-28 w-full" />
        <Skeleton className="h-28 w-full" />
      </div>
      <Skeleton className="h-96 w-full" />
      <span className="sr-only">Validating the analysis result…</span>
    </div>
  );
}
