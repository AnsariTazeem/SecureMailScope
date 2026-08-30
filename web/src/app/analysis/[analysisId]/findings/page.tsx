import { notFound } from "next/navigation";

import { FutureRoutePlaceholder } from "@/components/analysis/future-route-placeholder";
import { ANALYSIS_ID } from "@/lib/contracts/ids";

export default async function FindingsPage({
  params,
}: {
  params: Promise<{ analysisId: string }>;
}) {
  const { analysisId } = await params;
  if (!ANALYSIS_ID.test(analysisId)) notFound();

  return (
    <FutureRoutePlaceholder
      analysisId={analysisId}
      title="Findings"
      description="Versioned policy findings and their evidence references are not part of F1 and are not inferred by this frontend."
    />
  );
}
