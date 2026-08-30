import { create } from "zustand";

type WorkflowPhase = "idle" | "processing" | "complete" | "failed";

type AnalysisWorkflowState = {
  selectedFile: File | null;
  authorizationConfirmed: boolean;
  usingPrototypeDataset: boolean;
  analysisId: string | null;
  uploadedFileName: string | null;
  phase: WorkflowPhase;
  lastError: string | null;
  setSelectedFile: (file: File | null) => void;
  selectPrototypeDataset: () => void;
  setAuthorizationConfirmed: (confirmed: boolean) => void;
  setCreated: (analysisId: string, uploadedFileName: string) => void;
  setPhase: (phase: WorkflowPhase) => void;
  setError: (message: string | null) => void;
  reset: () => void;
};

export const useAnalysisWorkflow = create<AnalysisWorkflowState>((set) => ({
  selectedFile: null,
  authorizationConfirmed: false,
  usingPrototypeDataset: false,
  analysisId: null,
  uploadedFileName: null,
  phase: "idle",
  lastError: null,
  setSelectedFile: (selectedFile) =>
    set({
      selectedFile,
      usingPrototypeDataset: false,
      analysisId: null,
      phase: "idle",
      lastError: null,
    }),
  selectPrototypeDataset: () =>
    set({
      selectedFile: null,
      usingPrototypeDataset: true,
      analysisId: null,
      uploadedFileName: "prototype-analysis-dataset.pcapng",
      phase: "idle",
      lastError: null,
    }),
  setAuthorizationConfirmed: (authorizationConfirmed) =>
    set({ authorizationConfirmed }),
  setCreated: (analysisId, uploadedFileName) =>
    set({
      analysisId,
      uploadedFileName,
      phase: "processing",
      lastError: null,
    }),
  setPhase: (phase) => set({ phase }),
  setError: (message) =>
    set({ lastError: message, phase: message ? "failed" : "idle" }),
  reset: () =>
    set({
      selectedFile: null,
      authorizationConfirmed: false,
      usingPrototypeDataset: false,
      analysisId: null,
      uploadedFileName: null,
      phase: "idle",
      lastError: null,
    }),
}));
