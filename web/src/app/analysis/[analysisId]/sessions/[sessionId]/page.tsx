import { notFound } from "next/navigation";

import { FutureRoutePlaceholder } from "@/components/analysis/future-route-placeholder";
import { ANALYSIS_ID, SESSION_ID } from "@/lib/contracts/ids";

export default async function SessionDetailPage({
  params,
}: {
  params: Promise<{ analysisId: string; sessionId: string }>;
}) {
  const { analysisId, sessionId } = await params;
  if (!ANALYSIS_ID.test(analysisId) || !SESSION_ID.test(sessionId)) notFound();

  return (
    <FutureRoutePlaceholder
      analysisId={analysisId}
      sessionId={sessionId}
      title="Session detail"
      description="The evidence timeline and cryptographic observation views are intentionally not implemented in F1."
    />
  );
}
