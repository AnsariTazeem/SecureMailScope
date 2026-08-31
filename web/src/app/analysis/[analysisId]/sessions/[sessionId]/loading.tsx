import { Skeleton } from "@/components/ui/skeleton";

export default function SessionXRayLoading() {
  return (
    <div
      className="mx-auto w-full max-w-[96rem] space-y-6"
      aria-label="Loading Session X-Ray"
      aria-busy="true"
    >
      <div className="space-y-3">
        <Skeleton className="h-3 w-52 max-w-full" />
        <Skeleton className="h-9 w-64 max-w-full" />
        <Skeleton className="h-4 w-full max-w-3xl" />
      </div>
      <Skeleton className="h-16 w-full" />
      <Skeleton className="h-72 w-full" />
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
        {Array.from({ length: 6 }, (_, index) => (
          <Skeleton key={index} className="h-36 w-full" />
        ))}
      </div>
      <Skeleton className="h-96 w-full" />
      <span className="sr-only">
        Validating session events and evidence…
      </span>
    </div>
  );
}
