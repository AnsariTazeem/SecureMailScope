"use client";

import { usePathname } from "next/navigation";
import { useState } from "react";
import { AppHeader } from "@/components/layout/app-header";
import { AppSidebar } from "@/components/layout/app-sidebar";

export function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const isAnalysis = /^\/analysis\/ana_[0-9a-f]{16}(?:\/|$)/.test(pathname);
  const [sidebarOpen, setSidebarOpen] = useState(true);
  return (
    <div data-app-shell className="flex min-h-svh bg-[#f5f6f8]">
      <a
        href="#main-content"
        className="sr-only z-50 rounded-md bg-primary px-4 py-3 text-primary-foreground focus:not-sr-only focus:fixed focus:left-4 focus:top-4"
      >
        Skip to content
      </a>
      {isAnalysis && sidebarOpen ? <AppSidebar /> : null}
      <div data-app-content className="flex min-w-0 flex-1 flex-col">
        <AppHeader
          isAnalysis={isAnalysis}
          sidebarOpen={sidebarOpen}
          onToggleSidebar={() => setSidebarOpen((current) => !current)}
        />
        <main
          id="main-content"
          tabIndex={-1}
          data-app-main
          className="flex w-full flex-1 flex-col px-4 py-6 outline-none sm:px-6 lg:px-8 lg:py-8"
        >
          {children}
        </main>
      </div>
    </div>
  );
}
