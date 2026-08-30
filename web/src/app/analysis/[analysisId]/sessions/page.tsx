import { notFound } from "next/navigation";

import { FutureRoutePlaceholder } from "@/components/analysis/future-route-placeholder";
import { ANALYSIS_ID } from "@/lib/contracts/ids";

export default async function SessionsPage({
  params,
}: {
  params: Promise<{ analysisId: string }>;
}) {
  const { analysisId } = await params;
  if (!ANALYSIS_ID.test(analysisId)) notFound();

  return (
    <FutureRoutePlaceholder
      analysisId={analysisId}
      title="Sessions"
      description="Session inventory and evidence-backed filtering are reserved for the next authorized frontend milestone."
    />
  );
}
