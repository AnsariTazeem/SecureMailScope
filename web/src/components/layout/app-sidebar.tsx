"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Activity,
  ClipboardCheck,
  FileSearch,
  Files,
  GitCompareArrows,
  GitFork,
  ListChecks,
  Menu,
  PlayCircle,
  Shield,
} from "lucide-react";

import { DatasetBanner } from "@/components/layout/dataset-banner";
import { Button } from "@/components/ui/button";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
} from "@/components/ui/sheet";
import { cn } from "@/lib/utils";
import { useAnalysisWorkflow } from "@/stores/analysis-workflow";

const navigationItems = [
  { label: "Start analysis", segment: null, icon: PlayCircle },
  { label: "Overview", segment: "overview", icon: Activity },
  { label: "Sessions", segment: "sessions", icon: Files },
  { label: "Proof Map", segment: "proof-map", icon: GitFork },
  { label: "Findings", segment: "findings", icon: ListChecks },
  { label: "Recommendations", segment: "recommendations", icon: ClipboardCheck },
  { label: "Compare", segment: "compare", icon: GitCompareArrows },
  { label: "Report", segment: "report", icon: FileSearch },
] as const;

function analysisIdFromPath(pathname: string): string | null {
  return pathname.match(/^\/analysis\/(ana_[0-9a-f]{16})(?:\/|$)/)?.[1] ?? null;
}

function ApplicationIdentity({ onNavigate }: { onNavigate?: () => void }) {
  return (
    <Link
      href="/analysis/new"
      onClick={onNavigate}
      className="flex items-center gap-2 rounded-md outline-none focus-visible:ring-2 focus-visible:ring-neutral-950 focus-visible:ring-offset-2"
    >
      <Shield className="size-5 fill-neutral-950" aria-hidden />
      <span className="text-[17px] font-bold tracking-tight text-neutral-950">
        SecureMailScope
      </span>
    </Link>
  );
}

type AnalysisNavigationProps = {
  ariaLabel: string;
  className?: string;
  onNavigate?: () => void;
};

function AnalysisNavigation({
  ariaLabel,
  className,
  onNavigate,
}: AnalysisNavigationProps) {
  const pathname = usePathname();
  const workflowAnalysisId = useAnalysisWorkflow((state) => state.analysisId);
  const analysisId = analysisIdFromPath(pathname) ?? workflowAnalysisId;

  return (
    <nav
      aria-label={ariaLabel}
      className={cn("flex flex-1 flex-col gap-1 p-4", className)}
    >
      {navigationItems.map((item, index) => {
        const href = item.segment
          ? analysisId
            ? `/analysis/${analysisId}/${item.segment}`
            : null
          : "/analysis/new";
        const active = href
          ? pathname === href ||
            (item.segment === "sessions" && pathname.startsWith(`${href}/`))
          : false;
        const Icon = item.icon;

        return (
          <div key={item.label}>
            {index === 1 ? (
              <div
                role="separator"
                aria-orientation="horizontal"
                className="my-3 border-t border-neutral-200"
              />
            ) : null}

            {href ? (
              <Link
                href={href}
                onClick={onNavigate}
                aria-current={active ? "page" : undefined}
                className={cn(
                  "flex items-center gap-3 rounded-md border-l-2 px-3 py-2.5 text-xs font-bold uppercase tracking-[0.05em] outline-none transition-colors focus-visible:ring-2 focus-visible:ring-neutral-950 focus-visible:ring-offset-2",
                  active
                    ? "border-neutral-950 bg-neutral-100 text-neutral-950"
                    : "border-transparent text-neutral-600 hover:bg-neutral-100 hover:text-neutral-950",
                )}
              >
                <Icon className="size-5" aria-hidden />
                {item.label}
              </Link>
            ) : (
              <span
                aria-disabled="true"
                title="Start or select an analysis to enable this route"
                className="flex cursor-not-allowed items-center gap-3 rounded-md border-l-2 border-transparent px-3 py-2.5 text-xs font-bold uppercase tracking-[0.05em] text-neutral-400"
              >
                <Icon className="size-5" aria-hidden />
                {item.label}
              </span>
            )}
          </div>
        );
      })}
    </nav>
  );
}

export function AppSidebar() {
  return (
    <aside
      data-print-hide
      className="hidden w-60 shrink-0 border-r border-neutral-200 bg-[#fcfafa] lg:flex lg:flex-col"
    >
      <div className="border-b border-neutral-200 px-5 py-6">
        <ApplicationIdentity />
        <p className="mt-2 text-xs text-neutral-500">Forensic Analysis Suite</p>
      </div>

      <AnalysisNavigation ariaLabel="Primary" />

      <div className="border-t border-neutral-200 p-4 text-[11px] leading-5 text-neutral-500">
        Passive analysis only. Evidence limitations remain explicit.
      </div>
    </aside>
  );
}

export function AppMobileNavigation() {
  const [open, setOpen] = useState(false);

  useEffect(() => {
    const desktopQuery = window.matchMedia("(min-width: 64rem)");
    const closeAtDesktop = (event: MediaQueryListEvent) => {
      if (event.matches) setOpen(false);
    };

    desktopQuery.addEventListener("change", closeAtDesktop);
    return () => desktopQuery.removeEventListener("change", closeAtDesktop);
  }, []);

  return (
    <Sheet open={open} onOpenChange={setOpen}>
      <SheetTrigger
        render={
          <Button
            type="button"
            variant="ghost"
            size="icon-lg"
            aria-label="Open navigation menu"
            className="lg:hidden"
          />
        }
      >
        <Menu className="size-5" aria-hidden />
      </SheetTrigger>

      <SheetContent
        side="left"
        className="w-[min(20rem,calc(100vw-3rem))] gap-0 bg-[#fcfafa] p-0 sm:max-w-80 lg:hidden"
      >
        <SheetHeader className="border-b border-neutral-200 px-5 py-6 pr-12">
          <SheetTitle className="sr-only">SecureMailScope navigation</SheetTitle>
          <ApplicationIdentity onNavigate={() => setOpen(false)} />
          <SheetDescription className="mt-2 text-xs">
            Forensic Analysis Suite
          </SheetDescription>
        </SheetHeader>

        <AnalysisNavigation
          ariaLabel="Mobile primary"
          onNavigate={() => setOpen(false)}
        />

        <div className="mt-auto border-t border-neutral-200 p-4">
          <DatasetBanner />
          <p className="mt-3 text-[11px] leading-5 text-neutral-500">
            Passive analysis only. Evidence limitations remain explicit.
          </p>
        </div>
      </SheetContent>
    </Sheet>
  );
}
