import type { Metadata } from "next";

import { StartAnalysisForm } from "@/components/analysis/start-analysis-form";

export const metadata: Metadata = {
  title: "Start Analysis",
};

export default function NewAnalysisPage() {
  return <StartAnalysisForm />;
}
