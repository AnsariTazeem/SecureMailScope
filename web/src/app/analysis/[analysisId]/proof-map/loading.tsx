import { Skeleton } from "@/components/ui/skeleton";

export default function ProofMapLoading() {
  return (
    <div
      className="mx-auto w-full max-w-[100rem] space-y-6"
      aria-label="Loading Proof Map"
      aria-busy="true"
    >
      <div className="space-y-3">
        <Skeleton className="h-3 w-36" />
        <Skeleton className="h-8 w-80 max-w-full" />
        <Skeleton className="h-4 w-full max-w-3xl" />
      </div>
      <Skeleton className="h-20 w-full" />
      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
        {Array.from({ length: 4 }, (_, index) => (
          <Skeleton key={index} className="h-32 w-full" />
        ))}
      </div>
      <Skeleton className="h-96 w-full" />
      <span className="sr-only">Validating declared Chain-of-Proof relationships…</span>
    </div>
  );
}
