"use client";

import { usePathname } from "next/navigation";

import { AppHeader } from "@/components/layout/app-header";
import { AppSidebar } from "@/components/layout/app-sidebar";

export function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const isUploadPage = pathname === "/" || pathname === "/analysis/new";

  return (
    <div data-app-shell className="flex min-h-svh bg-[#f5f6f8]">
      {isUploadPage ? (
        <a
          href="#main-content"
          className="sr-only rounded-md bg-white text-sm font-semibold text-neutral-950 focus:not-sr-only focus:fixed focus:left-4 focus:top-4 focus:z-50 focus:px-4 focus:py-3 focus:outline-2 focus:outline-offset-2 focus:outline-neutral-950"
        >
          Skip to content
        </a>
      ) : null}
      {isUploadPage ? null : <AppSidebar />}
      <div data-app-content className="flex min-w-0 flex-1 flex-col">
        <AppHeader isUploadPage={isUploadPage} />
        <main
          id="main-content"
          tabIndex={-1}
          data-app-main
          className="flex w-full flex-1 flex-col px-4 py-6 sm:px-6 lg:px-8 lg:py-8"
        >
          {children}
        </main>
      </div>
    </div>
  );
}
