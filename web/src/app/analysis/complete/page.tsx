import { AnalysisBreadcrumbs } from "@/components/layout/analysis-breadcrumbs";

import type { Metadata } from "next";

import { CompleteView } from "@/components/analysis/complete-view";

export const metadata: Metadata = {
  title: "Analysis Complete",
};

export default function CompletePage() {
  return (
    <>
      <div className="mx-auto mb-6 w-full max-w-3xl">
        <AnalysisBreadcrumbs />
      </div>
      <CompleteView />
    </>
  );
}
