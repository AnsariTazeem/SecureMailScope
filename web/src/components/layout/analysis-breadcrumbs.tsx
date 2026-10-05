"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { Fragment } from "react";

import { ANALYSIS_ID } from "@/lib/contracts/ids";
import { cn } from "@/lib/utils";

import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from "@/components/ui/breadcrumb";

type Crumb = {
  label: string;
  href?: string;
};

const sectionLabels: Record<string, string> = {
  overview: "Overview",
  sessions: "Sessions",
  findings: "Findings",
  "proof-map": "Proof Map",
  recommendations: "Recommendations",
  report: "Report",
  compare: "Compare",
};

function crumbsForPath(pathname: string): Crumb[] {
  const parts = pathname.split("/").filter(Boolean);
  if (parts[0] !== "analysis") return [];

  if (parts[1] === "new") {
    return [{ label: "Analysis", href: "/analysis/new" }, { label: "New analysis" }];
  }
  if (parts[1] === "processing") {
    return [{ label: "Analysis", href: "/analysis/new" }, { label: "Processing" }];
  }
  if (parts[1] === "complete") {
    return [{ label: "Analysis", href: "/analysis/new" }, { label: "Complete" }];
  }

  const analysisId = parts[1];
  if (!analysisId) return [];
  const validAnalysisId = ANALYSIS_ID.test(analysisId);

  const section = parts[2] ?? "overview";
  const crumbs: Crumb[] = [
    { label: "Analysis", href: validAnalysisId ? `/analysis/${analysisId}/overview` : "/analysis/new" },
  ];

  if (section === "sessions" && parts[3]) {
    crumbs.push({
      label: "Sessions",
      href: validAnalysisId ? `/analysis/${analysisId}/sessions` : "/analysis/new",
    });
    crumbs.push({ label: "Session X-Ray" });
    return crumbs;
  }

  if (section === "compare") {
    crumbs.push({
      label: "Sessions",
      href: validAnalysisId ? `/analysis/${analysisId}/sessions` : "/analysis/new",
    });
    crumbs.push({ label: "Compare" });
    return crumbs;
  }

  crumbs.push({ label: sectionLabels[section] ?? "Workspace" });
  return crumbs;
}

export function AnalysisBreadcrumbs({ className }: { className?: string }) {
  const pathname = usePathname();
  const crumbs = crumbsForPath(pathname);
  if (crumbs.length === 0) return null;

  return (
    <Breadcrumb className={cn("min-w-0", className)}>
      <BreadcrumbList className="flex-nowrap overflow-hidden text-xs">
        {crumbs.map((crumb, index) => (
          <Fragment key={`${crumb.label}:${index}`}>
            {index > 0 ? <BreadcrumbSeparator /> : null}
            <BreadcrumbItem className="min-w-0">
              {crumb.href && index < crumbs.length - 1 ? (
                <BreadcrumbLink
                  render={<Link href={crumb.href} />}
                  className="rounded-sm focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-neutral-950"
                >
                  {crumb.label}
                </BreadcrumbLink>
              ) : (
                <BreadcrumbPage className="truncate">
                  {crumb.label}
                </BreadcrumbPage>
              )}
            </BreadcrumbItem>
          </Fragment>
        ))}
      </BreadcrumbList>
    </Breadcrumb>
  );
}
