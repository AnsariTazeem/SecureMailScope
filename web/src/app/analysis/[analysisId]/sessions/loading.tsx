import { Skeleton } from "@/components/ui/skeleton";

export default function SessionsLoading() {
  return (
    <div
      className="mx-auto w-full max-w-[96rem] space-y-6"
      aria-label="Loading Sessions Explorer"
      aria-busy="true"
    >
      <div className="space-y-3">
        <Skeleton className="h-3 w-36" />
        <Skeleton className="h-9 w-72 max-w-full" />
        <Skeleton className="h-4 w-full max-w-3xl" />
      </div>
      <Skeleton className="h-16 w-full" />
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
        {Array.from({ length: 5 }, (_, index) => (
          <Skeleton key={index} className="h-36 w-full" />
        ))}
      </div>
      <Skeleton className="h-24 w-full" />
      <Skeleton className="h-96 w-full" />
      <span className="sr-only">Validating reconstructed sessions…</span>
    </div>
  );
}
