import Link from "next/link";
import { Shield } from "lucide-react";
import { DatasetBanner } from "@/components/layout/dataset-banner";
import { AppMobileNavigation } from "@/components/layout/app-sidebar";

export function AppHeader({ isAnalysis }: { isAnalysis: boolean }) {
  return (
    <header
      data-print-hide
      className="sticky top-0 z-30 border-b border-neutral-200 bg-white/95 backdrop-blur-sm"
    >
      <div className="flex min-h-16 items-center justify-between gap-3 px-4 sm:px-6">
        <div className="flex min-w-0 items-center gap-2">
          {isAnalysis ? <AppMobileNavigation /> : null}
          <Link
            href="/analysis/new"
            className={`${isAnalysis ? "hidden sm:flex lg:hidden" : "flex"} items-center gap-2 rounded-md text-sm font-semibold tracking-tight outline-none focus-visible:ring-2 focus-visible:ring-ring`}
          >
            {!isAnalysis ? <Shield className="size-5" aria-hidden /> : null}
            <span>SecureMailScope</span>
          </Link>
          {isAnalysis ? (
            <p className="hidden text-sm text-muted-foreground lg:block">
              Email security analysis
            </p>
          ) : null}
        </div>
        <DatasetBanner />
      </div>
    </header>
  );
}
