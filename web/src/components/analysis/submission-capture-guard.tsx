"use client";

import { createContext, useCallback, useContext, useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { applicationCapabilities } from "@/lib/config/env";
import { useAnalysisWorkflow } from "@/stores/analysis-workflow";

export function isFileTransfer(transfer: DataTransfer | null): boolean {
  return Boolean(transfer && (
    Array.from(transfer.types).some(type => type === "Files" || type === "application/x-moz-file") ||
    Array.from(transfer.items ?? []).some(item => item.kind === "file")
  ));
}

const CaptureGuardContext = createContext<{
  disclose: (initiator?: HTMLElement | null) => void;
  exploreDemo: () => void;
} | null>(null);

export function useSubmissionCaptureGuard() {
  const context = useContext(CaptureGuardContext);
  if (!context) throw new Error("Submission capture guard is missing.");
  return context;
}

export function SubmissionCaptureGuard({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const selectPrototypeDataset = useAnalysisWorkflow(state => state.selectPrototypeDataset);
  const [open, setOpen] = useState(false);
  const openRef = useRef(false);
  const returnFocus = useRef<HTMLElement | null>(null);
  const primaryAction = useRef<HTMLButtonElement | null>(null);

  const disclose = useCallback((initiator?: HTMLElement | null) => {
    if (applicationCapabilities.liveAnalysis) return;
    document.querySelectorAll<HTMLInputElement>("[data-submission-capture-zone] input[type=file]").forEach(input => { input.value = ""; });
    if (openRef.current) return;
    const active = document.activeElement;
    returnFocus.current = initiator ?? (
      active instanceof HTMLElement && active !== document.body
        ? active
        : document.getElementById("main-content")
    );
    openRef.current = true;
    setOpen(true);
  }, []);

  const exploreDemo = useCallback(() => {
    openRef.current = false;
    setOpen(false);
    selectPrototypeDataset();
    router.push("/analysis/processing");
  }, [router, selectPrototypeDataset]);

  useEffect(() => {
    if (applicationCapabilities.liveAnalysis) return;
    const dragOver = (event: DragEvent) => {
      if (isFileTransfer(event.dataTransfer)) event.preventDefault();
    };
    const drop = (event: DragEvent) => {
      if (!isFileTransfer(event.dataTransfer)) return;
      event.preventDefault();
      // The zone owns its disclosure and focus target; all other drops use this one.
      if (event.target instanceof Element && event.target.closest("[data-submission-capture-zone]")) return;
      disclose();
    };
    document.addEventListener("dragover", dragOver, true);
    document.addEventListener("drop", drop, true);
    document.dispatchEvent(new Event("submission-guard-ready"));
    return () => {
      document.removeEventListener("dragover", dragOver, true);
      document.removeEventListener("drop", drop, true);
    };
  }, [disclose]);

  return (
    <CaptureGuardContext.Provider value={{ disclose, exploreDemo }}>
      {children}
      {!applicationCapabilities.liveAnalysis ? (
        <Dialog open={open} onOpenChange={next => { openRef.current = next; setOpen(next); }}>
          <DialogContent showCloseButton={false} initialFocus={primaryAction} finalFocus={() =>
            returnFocus.current?.isConnected ? returnFocus.current : document.getElementById("main-content")
          }>
            <DialogHeader>
              <DialogTitle>Backend integration in progress</DialogTitle>
              <DialogDescription>File upload analysis is unavailable in this evaluation build. No file was uploaded, stored or analyzed. You can explore the complete demo instead.</DialogDescription>
            </DialogHeader>
            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => { openRef.current = false; setOpen(false); }}>Cancel</Button>
              <Button ref={primaryAction} type="button" onClick={exploreDemo}>Open Complete Demo</Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      ) : null}
    </CaptureGuardContext.Provider>
  );
}
