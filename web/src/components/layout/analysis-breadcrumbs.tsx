"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { Fragment } from "react";

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
  if (!analysisId?.startsWith("ana_")) return [];

  const section = parts[2] ?? "overview";
  const crumbs: Crumb[] = [
    { label: "Analysis", href: `/analysis/${analysisId}/overview` },
  ];

  if (section === "sessions" && parts[3]) {
    crumbs.push({
      label: "Sessions",
      href: `/analysis/${analysisId}/sessions`,
    });
    crumbs.push({ label: "Session X-Ray" });
    return crumbs;
  }

  if (section === "compare") {
    crumbs.push({
      label: "Sessions",
      href: `/analysis/${analysisId}/sessions`,
    });
    crumbs.push({ label: "Compare" });
    return crumbs;
  }

  crumbs.push({ label: sectionLabels[section] ?? "Workspace" });
  return crumbs;
}

export function AnalysisBreadcrumbs() {
  const pathname = usePathname();
  const crumbs = crumbsForPath(pathname);
  if (crumbs.length === 0) return null;

  return (
    <Breadcrumb className="min-w-0">
      <BreadcrumbList className="flex-nowrap overflow-hidden text-xs">
        {crumbs.map((crumb, index) => (
          <Fragment key={`${crumb.label}:${index}`}>
            {index > 0 ? <BreadcrumbSeparator /> : null}
            <BreadcrumbItem className="min-w-0">
              {crumb.href && index < crumbs.length - 1 ? (
                <BreadcrumbLink render={<Link href={crumb.href} />}>
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
