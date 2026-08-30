import type { Metadata } from "next";

import { CompleteView } from "@/components/analysis/complete-view";

export const metadata: Metadata = {
  title: "Analysis Complete",
};

export default function CompletePage() {
  return <CompleteView />;
}
