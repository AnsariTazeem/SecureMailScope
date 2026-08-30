import { notFound } from "next/navigation";

import { FutureRoutePlaceholder } from "@/components/analysis/future-route-placeholder";
import { ANALYSIS_ID } from "@/lib/contracts/ids";

export default async function OverviewPage({
  params,
}: {
  params: Promise<{ analysisId: string }>;
}) {
  const { analysisId } = await params;
  if (!ANALYSIS_ID.test(analysisId)) notFound();

  return (
    <FutureRoutePlaceholder
      analysisId={analysisId}
      title="Overview"
      description="The production analysis overview will summarize only canonical, evidence-backed state. Its content is outside Frontend Milestone F1."
    />
  );
}
