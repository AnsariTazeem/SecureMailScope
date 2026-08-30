import { notFound } from "next/navigation";

import { FutureRoutePlaceholder } from "@/components/analysis/future-route-placeholder";
import { ANALYSIS_ID } from "@/lib/contracts/ids";

export default async function ComparePage({
  params,
}: {
  params: Promise<{ analysisId: string }>;
}) {
  const { analysisId } = await params;
  if (!ANALYSIS_ID.test(analysisId)) notFound();

  return (
    <FutureRoutePlaceholder
      analysisId={analysisId}
      title="Compare"
      description="Cross-analysis comparison is a future capability. F1 does not duplicate or transform canonical analysis facts."
    />
  );
}
