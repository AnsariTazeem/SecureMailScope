import type { Metadata } from "next";

import { ProcessingView } from "@/components/analysis/processing-view";

export const metadata: Metadata = {
  title: "Processing Analysis",
};

export default function ProcessingPage() {
  return <ProcessingView />;
}
