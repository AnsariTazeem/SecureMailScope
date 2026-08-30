import { notFound } from "next/navigation";

import { FutureRoutePlaceholder } from "@/components/analysis/future-route-placeholder";
import { ANALYSIS_ID } from "@/lib/contracts/ids";

export default async function ReportPage({
  params,
}: {
  params: Promise<{ analysisId: string }>;
}) {
  const { analysisId } = await params;
  if (!ANALYSIS_ID.test(analysisId)) notFound();

  return (
    <FutureRoutePlaceholder
      analysisId={analysisId}
      title="Report"
      description="Report rendering is excluded from F1. PDF export remains outside the currently authorized product scope."
    />
  );
}
