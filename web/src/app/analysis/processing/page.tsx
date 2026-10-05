import { AnalysisBreadcrumbs } from "@/components/layout/analysis-breadcrumbs";

import type { Metadata } from "next";

import { ProcessingView } from "@/components/analysis/processing-view";

export const metadata: Metadata = {
  title: "Processing Analysis",
};

export default function ProcessingPage() {
  return (
    <>
      <div className="mx-auto mb-6 w-full max-w-4xl">
        <AnalysisBreadcrumbs />
      </div>
      <ProcessingView />
    </>
  );
}
