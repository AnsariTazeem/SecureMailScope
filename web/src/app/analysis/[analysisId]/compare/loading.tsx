import { Skeleton } from "@/components/ui/skeleton";

export default function CompareLoading() {
  return (
    <div
      className="mx-auto w-full max-w-[100rem] space-y-6"
      aria-label="Loading session comparison"
      aria-busy="true"
    >
      <div className="space-y-3">
        <Skeleton className="h-3 w-36" />
        <Skeleton className="h-9 w-72 max-w-full" />
        <Skeleton className="h-4 w-full max-w-3xl" />
      </div>
      <Skeleton className="h-32 w-full" />
      <div className="grid gap-4 xl:grid-cols-2">
        <Skeleton className="h-72 w-full" />
        <Skeleton className="h-72 w-full" />
      </div>
      <Skeleton className="h-96 w-full" />
      <span className="sr-only">
        Validating the selected sessions and their evidence…
      </span>
    </div>
  );
}
