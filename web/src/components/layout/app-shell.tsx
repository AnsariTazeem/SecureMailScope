import { AppHeader } from "@/components/layout/app-header";
import { AppSidebar } from "@/components/layout/app-sidebar";

export function AppShell({ children }: { children: React.ReactNode }) {
  return (
    <div data-app-shell className="flex min-h-svh bg-[#f5f6f8]">
      <AppSidebar />
      <div data-app-content className="flex min-w-0 flex-1 flex-col">
        <AppHeader />
        <main
          data-app-main
          className="flex w-full flex-1 flex-col px-4 py-6 sm:px-6 lg:px-8 lg:py-8"
        >
          {children}
        </main>
      </div>
    </div>
  );
}
