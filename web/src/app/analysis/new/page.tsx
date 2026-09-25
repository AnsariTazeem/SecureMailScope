import type { Metadata } from "next";

import { CaptureAnalysisForm } from "@/components/analysis/capture-analysis-form";

export const metadata: Metadata = {
  title: "Start Analysis",
};

export default function NewAnalysisPage() {
  return <CaptureAnalysisForm />;
}
