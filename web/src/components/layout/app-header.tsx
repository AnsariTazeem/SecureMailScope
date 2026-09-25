import Link from "next/link";
import { PanelLeftClose, PanelLeftOpen, Shield } from "lucide-react";

import { AnalysisBreadcrumbs } from "@/components/layout/analysis-breadcrumbs";
import { AppMobileNavigation } from "@/components/layout/app-sidebar";
import { Button } from "@/components/ui/button";

export function AppHeader({
  isAnalysis,
  sidebarOpen,
  onToggleSidebar,
}: {
  isAnalysis: boolean;
  sidebarOpen: boolean;
  onToggleSidebar: () => void;
}) {
  return (
    <header
      data-print-hide
      className="sticky top-0 z-30 border-b border-neutral-200 bg-white/95 backdrop-blur-sm"
    >
      <div className="flex min-h-16 items-center justify-between gap-3 px-4 sm:px-6">
        <div className="flex min-w-0 items-center gap-2">
          {isAnalysis ? <AppMobileNavigation /> : null}
          {isAnalysis ? (
            <Button
              type="button"
              variant="ghost"
              size="icon-lg"
              onClick={onToggleSidebar}
              aria-label={sidebarOpen ? "Hide sidebar" : "Show sidebar"}
              aria-expanded={sidebarOpen}
              className="hidden lg:inline-flex"
            >
              {sidebarOpen ? (
                <PanelLeftClose className="size-5" aria-hidden />
              ) : (
                <PanelLeftOpen className="size-5" aria-hidden />
              )}
            </Button>
          ) : null}
          <Link
            href="/analysis/new"
            className={`${isAnalysis ? "hidden sm:flex lg:hidden" : "flex"} items-center gap-2 rounded-md text-sm font-semibold tracking-tight outline-none focus-visible:ring-2 focus-visible:ring-ring`}
          >
            {!isAnalysis ? <Shield className="size-5" aria-hidden /> : null}
            <span>SecureMailScope</span>
          </Link>
          {isAnalysis ? <AnalysisBreadcrumbs /> : null}
        </div>
      </div>
    </header>
  );
}
