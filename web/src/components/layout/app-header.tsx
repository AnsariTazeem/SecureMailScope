import Link from "next/link";
import { FilePlus2 } from "lucide-react";

import { DatasetBanner } from "@/components/layout/dataset-banner";
import { AppMobileNavigation } from "@/components/layout/app-sidebar";

export function AppHeader() {
  return (
    <header className="sticky top-0 z-30 border-b border-neutral-200 bg-white/95 backdrop-blur-sm">
      <div className="flex min-h-16 items-center justify-between gap-4 px-4 sm:px-6">
        <div className="flex min-w-0 items-center gap-2 lg:hidden">
          <AppMobileNavigation />
          <Link
            href="/analysis/new"
            className="min-w-0 rounded-md outline-none focus-visible:ring-2 focus-visible:ring-neutral-950 focus-visible:ring-offset-2"
          >
            <span className="block truncate text-sm font-semibold tracking-tight text-neutral-950">
              SecureMailScope
            </span>
            <span className="block truncate text-[11px] text-muted-foreground">
              Forensic Analysis Suite
            </span>
          </Link>
        </div>
        <p className="hidden text-sm font-semibold text-neutral-900 lg:block">
          Analysis workspace
        </p>
        <div className="flex min-w-0 items-center justify-end gap-2">
          <div className="hidden sm:block">
            <DatasetBanner />
          </div>
          <Link
            href="/analysis/new"
            className="hidden h-9 items-center gap-2 rounded-md border border-neutral-300 bg-white px-3 text-sm font-medium text-neutral-800 shadow-xs transition-colors hover:bg-neutral-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-neutral-950 focus-visible:ring-offset-2 sm:flex"
          >
            <FilePlus2 className="size-4" aria-hidden />
            New analysis
          </Link>
        </div>
      </div>
    </header>
  );
}
