"use client";

import type { ReactNode } from "react";
import { useSearchParams } from "next/navigation";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

export function SessionTabs({
  timeline,
  crypto,
  findings,
}: {
  timeline: ReactNode;
  crypto: ReactNode;
  findings: ReactNode;
}) {
  const params = useSearchParams();
  const requested = params.get("tab");
  const active =
    requested === "crypto" || requested === "findings" ? requested : "timeline";
  return (
    <Tabs
      value={active}
      onValueChange={(value) => {
        const url = new URL(window.location.href);
        url.searchParams.set("tab", String(value));
        window.history.pushState(null, "", url);
      }}
      className="gap-6"
    >
      <div className="overflow-x-auto border-b border-border pb-2">
        <TabsList
          variant="line"
          aria-label="Session investigation"
          className="h-11 gap-4"
        >
          <TabsTrigger value="timeline" className="px-3">
            Timeline
          </TabsTrigger>
          <TabsTrigger value="crypto" className="px-3">
            TLS &amp; Certificates
          </TabsTrigger>
          <TabsTrigger value="findings" className="px-3">
            Findings &amp; Evidence
          </TabsTrigger>
        </TabsList>
      </div>
      <TabsContent
        value="timeline"
        keepMounted
        className="space-y-6 data-[hidden]:hidden"
      >
        {timeline}
      </TabsContent>
      <TabsContent
        value="crypto"
        keepMounted
        className="space-y-6 data-[hidden]:hidden"
      >
        {crypto}
      </TabsContent>
      <TabsContent
        value="findings"
        keepMounted
        className="space-y-6 data-[hidden]:hidden"
      >
        {findings}
      </TabsContent>
    </Tabs>
  );
}
