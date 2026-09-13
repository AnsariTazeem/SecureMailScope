"use client";

import "@xyflow/react/dist/style.css";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Background,
  BackgroundVariant,
  Controls,
  Handle,
  MarkerType,
  MiniMap,
  Position,
  ReactFlow,
  ReactFlowProvider,
  useReactFlow,
  type Edge,
  type Node,
  type NodeProps,
} from "@xyflow/react";
import { ArrowRight, Filter, Focus, RotateCcw } from "lucide-react";

import { EvidenceInspector } from "@/components/analysis/session-xray/evidence-inspector";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Sheet,
  SheetContent,
  SheetClose,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { cn } from "@/lib/utils";
import {
  buildFindingInvestigation,
  investigationVisibility,
  type FindingInvestigation,
  type FindingInvestigationVisibility,
} from "./proof-map-investigation";
import { proofGeometry, readableToken } from "./proof-map-presentation";
import { useInitialProofMapFit } from "./use-initial-proof-map-fit";

import type {
  ProofGraphNode,
  ProofGraphNodeKind,
  ProofMapData,
  ProofRelationship,
} from "./proof-map-view-model";

type GraphNodeData = ProofGraphNode & {
  highlighted: boolean;
  dimmed: boolean;
  onInspect: () => void;
};

type GraphEdgeData = {
  relationship: ProofRelationship;
};

type CanvasNode = Node<GraphNodeData, "proofNode">;
type CanvasEdge = Edge<GraphEdgeData>;

type InspectorSelection =
  | { kind: "node"; id: string }
  | { kind: "edge"; id: string }
  | null;

const NODE_WIDTH = proofGeometry.width;
const NODE_HEIGHT = proofGeometry.height;
const ROW_GAP = NODE_HEIGHT + proofGeometry.rowGap;

const kindPresentation: Record<
  ProofGraphNodeKind,
  { label: string; x: number; className: string; dot: string }
> = {
  capture: {
    label: "Capture",
    x: 0 * (NODE_WIDTH + proofGeometry.columnGap),
    className: "border-neutral-300 bg-white",
    dot: "#737373",
  },
  session: {
    label: "Session",
    x: 1 * (NODE_WIDTH + proofGeometry.columnGap),
    className: "border-neutral-400 bg-neutral-50",
    dot: "#404040",
  },
  evidence: {
    label: "Evidence",
    x: 2 * (NODE_WIDTH + proofGeometry.columnGap),
    className: "border-emerald-300 bg-emerald-50/80",
    dot: "#15803d",
  },
  event: {
    label: "Transition event",
    x: 3 * (NODE_WIDTH + proofGeometry.columnGap),
    className: "border-teal-300 bg-teal-50/70",
    dot: "#0f766e",
  },
  observation: {
    label: "Observation",
    x: 4 * (NODE_WIDTH + proofGeometry.columnGap),
    className: "border-sky-300 bg-sky-50/70",
    dot: "#0369a1",
  },
  fact: {
    label: "Derived fact",
    x: 5 * (NODE_WIDTH + proofGeometry.columnGap),
    className: "border-slate-400 bg-slate-50",
    dot: "#475569",
  },
  finding: {
    label: "Policy finding",
    x: 6 * (NODE_WIDTH + proofGeometry.columnGap),
    className: "border-violet-300 bg-violet-50/80",
    dot: "#7c3aed",
  },
};

const kindOrder: ProofGraphNodeKind[] = [
  "capture",
  "session",
  "evidence",
  "event",
  "observation",
  "fact",
  "finding",
];

const stateOptions = [
  "observed",
  "derived",
  "policy_inferred",
  "not_observable",
  "session_secrets_required",
  "incomplete_capture",
  "not_applicable",
];

export function ProofNodeCard({ data }: NodeProps<CanvasNode>) {
  const presentation = kindPresentation[data.kind];
  return (
    <article
      style={{ width: NODE_WIDTH, height: NODE_HEIGHT }}
      className={cn("relative rounded-lg border px-3 py-2 shadow-sm", presentation.className,
        data.highlighted && "ring-2 ring-neutral-950 ring-offset-2", data.dimmed && "opacity-25")}
      data-proof-node-kind={data.kind} data-proof-node-id={data.id}
    >
      <Handle type="target" position={Position.Left} className="!size-2 !border-white !bg-neutral-500" />
      <Handle type="source" position={Position.Right} className="!size-2 !border-white !bg-neutral-500" />
      <button type="button" onClick={data.onInspect}
        className="nodrag nopan flex h-full w-full flex-col text-left outline-none focus-visible:ring-2 focus-visible:ring-neutral-950 focus-visible:ring-offset-2"
        aria-label={"Inspect " + data.title + ". Value: " + data.value + ". Provenance: " + readableToken(data.stateLabel)}
      >
        <span className="text-[10px] font-semibold uppercase tracking-wide text-neutral-600">{presentation.label}</span>
        <h3 className="mt-1 line-clamp-2 w-full break-words text-sm font-semibold leading-4 text-neutral-950" title={data.title}>{data.title}</h3>
        <p className="mt-1 line-clamp-2 w-full break-words text-sm leading-4 text-neutral-800" title={data.value}>{data.value}</p>
        <span className="mt-auto block w-full border-t border-neutral-300/60 pt-1 text-[11px] leading-4 text-neutral-700" title={data.stateLabel}>
          Provenance: {readableToken(data.stateLabel)}
        </span>
      </button>
    </article>
  );
}

const nodeTypes = { proofNode: ProofNodeCard };

function relationshipColor(type: ProofRelationship["relationshipType"]): string {
  if (type === "direct_evidence") return "#15803d";
  if (type === "declared_source") return "#64748b";
  if (type === "policy") return "#7c3aed";
  if (type === "anomaly") return "#2563eb";
  return "#a3a3a3";
}

function relationshipLabel(relationship: ProofRelationship): string | undefined {
  if (relationship.relationshipType === "declared_source") {
    return "Evidence through declared sources";
  }
  if (relationship.relationshipType === "direct_evidence") {
    return "Direct evidence";
  }
  if (relationship.relationshipType === "policy") return "Policy";
  if (relationship.relationshipType === "anomaly") return "ML Anomaly";
  return undefined;
}

function compareNodes(left: ProofGraphNode, right: ProofGraphNode): number {
  return left.order - right.order || left.id.localeCompare(right.id);
}

export function layoutNodes(
  nodes: ProofGraphNode[],
  selectedSessionIds: string[],
): Array<ProofGraphNode & { position: { x: number; y: number } }> {
  const positions = new Map<string, { x: number; y: number }>();
  let groupTop = 0;

  for (const sessionId of selectedSessionIds) {
    const owned = nodes.filter(
      (node) =>
        node.sessionIds.includes(sessionId) &&
        node.sessionIds
          .filter((candidate) => selectedSessionIds.includes(candidate))
          .sort()[0] === sessionId,
    );
    const byKind = new Map<ProofGraphNodeKind, ProofGraphNode[]>();
    for (const kind of kindOrder) {
      byKind.set(
        kind,
        owned.filter((node) => node.kind === kind).sort(compareNodes),
      );
    }
    const largestLane = Math.max(
      1,
      ...kindOrder.map((kind) => byKind.get(kind)!.length),
    );
    const groupHeight = Math.max(280, largestLane * ROW_GAP + 90);

    for (const kind of kindOrder) {
      const lane = byKind.get(kind)!;
      const laneHeight = Math.max(1, lane.length) * ROW_GAP;
      const laneTop = groupTop + Math.max(58, (groupHeight - laneHeight) / 2);
      lane.forEach((node, index) => {
        positions.set(node.id, {
          x: kindPresentation[kind].x,
          y: laneTop + index * ROW_GAP,
        });
      });
    }
    groupTop += groupHeight + 120;
  }

  return nodes.map((node) => ({
    ...node,
    position: positions.get(node.id) ?? {
      x: kindPresentation[node.kind].x,
      y: groupTop,
    },
  }));
}

function useMobileSheet(): boolean {
  const [mobile, setMobile] = useState(false);
  useEffect(() => {
    const media = window.matchMedia("(max-width: 767px)");
    const update = () => setMobile(media.matches);
    update();
    media.addEventListener("change", update);
    return () => media.removeEventListener("change", update);
  }, []);
  return mobile;
}

function InspectorRows({ node }: { node: ProofGraphNode }) {
  return (
    <dl className="rounded-lg border border-neutral-200 px-4">
      {node.inspectorRows.map((row) => (
        <div
          key={row.label}
          className="grid gap-1 border-b border-neutral-100 py-3 last:border-b-0 sm:grid-cols-[9rem_minmax(0,1fr)] sm:gap-4"
        >
          <dt className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
            {row.label}
          </dt>
          <dd
            className={cn(
              "min-w-0 break-all text-xs text-neutral-900",
              row.monospace && "font-mono",
            )}
          >
            {Array.isArray(row.value) ? (
              row.value.length > 0 ? (
                <span className="flex flex-col gap-1">
                  {row.value.map((value) => (
                    <span key={value}>{value}</span>
                  ))}
                </span>
              ) : (
                <span className="font-sans text-neutral-500">None declared</span>
              )
            ) : (
              row.value
            )}
          </dd>
        </div>
      ))}
    </dl>
  );
}

function RelationshipList({
  title,
  relationships,
  nodes,
}: {
  title: string;
  relationships: ProofRelationship[];
  nodes: ProofGraphNode[];
}) {
  if (relationships.length === 0) return null;
  return (
    <section>
      <h3 className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
        {title}
      </h3>
      <ul className="mt-2 space-y-2">
        {relationships.map((relationship) => (
          <li
            key={relationship.relationshipId}
            className="rounded-md border border-neutral-200 bg-neutral-50 p-3"
          >
            <p className="mb-2 break-words text-sm">{nodes.find(node => node.id === relationship.fromId)?.title ?? relationship.fromKind} → {nodes.find(node => node.id === relationship.toId)?.title ?? relationship.toKind}</p>
            <details><summary className="cursor-pointer text-xs font-medium focus-visible:ring-2 focus-visible:ring-neutral-950">Exact relationship</summary>
              <code className="mt-2 block break-all font-mono text-xs font-semibold text-neutral-900">
                {relationship.contractField}
              </code>
              <p className="mt-1 break-all font-mono text-[10px] text-neutral-600">
                {relationship.fromId} → {relationship.toId}
              </p>
            </details>
          </li>
        ))}
      </ul>
    </section>
  );
}

export function NodeInspector({
  node,
  relationships,
  nodes,
}: {
  node: ProofGraphNode;
  relationships: ProofRelationship[];
  nodes: ProofGraphNode[];
}) {
  const incoming = relationships.filter(
    (relationship) => relationship.toId === node.id,
  );
  const outgoing = relationships.filter(
    (relationship) => relationship.fromId === node.id,
  );
  const safeExcerpt = node.directEvidence.find(
    (evidence) => evidence.safeExcerpt.length > 0,
  )?.safeExcerpt;

  return (
    <div className="space-y-5 px-4 pb-6">
      <section className="space-y-3">
        <h3 className="break-words text-lg font-semibold text-neutral-950">{node.title}</h3>
        <p className="break-words whitespace-pre-wrap text-base text-neutral-900"><span className="font-semibold">Value: </span>{node.value}</p>
        {node.context.map((row) => <div key={row.label}><p className="text-xs font-semibold text-neutral-600">{row.label}</p><p className="break-words whitespace-pre-wrap text-sm leading-6">{Array.isArray(row.value) ? row.value.join(" · ") : row.value}</p></div>)}
        <p className="text-sm"><span className="font-semibold">Provenance / state: </span>{readableToken(node.stateLabel)}</p>
      </section>
      {node.limitations.length > 0 && <section aria-label="Applicable limitations" className="space-y-3 rounded-lg border border-amber-200 bg-amber-50 p-4">
        <h3 className="text-sm font-semibold">Applicable limitations</h3>
        {node.limitations.map((limitation, index) => <div key={index}><p className="break-words text-xs text-amber-900">{limitation.scope}</p><p className="break-words text-sm leading-6 text-amber-950">{limitation.summary}</p></div>)}
      </section>}

      {safeExcerpt ? (
        <section>
          <h3 className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
            Contract-approved safe excerpt
          </h3>
          <code className="mt-2 block break-words rounded-md border border-emerald-200 bg-emerald-50 p-3 font-mono text-xs leading-5 text-emerald-950">
            {safeExcerpt}
          </code>
        </section>
      ) : null}

      {node.directEvidence.length > 0 ? (
        <section className="border-l-2 border-emerald-600 pl-3">
          <h3 className="text-[10px] font-bold uppercase tracking-[0.06em] text-emerald-800">
            Direct evidence relationship
          </h3>
          <div className="mt-2 flex flex-wrap gap-2">
            {node.directEvidence.map((evidence) => (
              <EvidenceInspector
                key={evidence.evidenceId}
                evidence={evidence}
                label={evidence.evidenceId}
              />
            ))}
          </div>
        </section>
      ) : null}

      {node.throughSourceEvidence.length > 0 ? (
        <section className="border-l-2 border-dashed border-slate-500 pl-3">
          <h3 className="text-[10px] font-bold uppercase tracking-[0.06em] text-slate-700">
            Evidence through declared sources
          </h3>
          <div className="mt-2 flex flex-wrap gap-2">
            {node.throughSourceEvidence.map((evidence) => (
              <EvidenceInspector
                key={evidence.evidenceId}
                evidence={evidence}
                label={evidence.evidenceId}
              />
            ))}
          </div>
        </section>
      ) : null}

      <RelationshipList title="Declared incoming relationships" relationships={incoming} nodes={nodes} />
      <RelationshipList title="Declared dependents" relationships={outgoing} nodes={nodes} />

      <details className="rounded-lg border border-neutral-200 p-4">
        <summary className="cursor-pointer text-sm font-semibold outline-none focus-visible:ring-2 focus-visible:ring-neutral-950">Technical details</summary>
        <div className="mt-4 space-y-4">
          <InspectorRows node={node} />
          <h3 className="text-sm font-semibold">Complete limitations by owner</h3>
          <pre className="whitespace-pre-wrap break-words text-xs">{JSON.stringify(node.limitations, null, 2)}</pre>
        </div>
      </details>

      {node.href && node.hrefLabel ? (
        <Link
          href={node.href}
          className="inline-flex min-h-9 w-full items-center justify-center gap-2 rounded-md bg-neutral-950 px-4 text-sm font-semibold text-white outline-none hover:bg-neutral-800 focus-visible:ring-2 focus-visible:ring-neutral-950 focus-visible:ring-offset-2"
        >
          {node.hrefLabel}
          <ArrowRight className="size-4" aria-hidden />
        </Link>
      ) : null}
    </div>
  );
}

function EdgeInspector({
  relationship,
  nodes,
}: {
  relationship: ProofRelationship;
  nodes: ProofGraphNode[];
}) {
  const sourceNode = nodes.find((node) => node.id === relationship.fromId);
  const targetNode = nodes.find((node) => node.id === relationship.toId);
  const evidenceReferences = [
    ...(sourceNode?.directEvidence ?? []),
    ...(relationship.relationshipType === "declared_source"
      ? (sourceNode?.throughSourceEvidence ?? [])
      : []),
  ].filter(
    (evidence, index, records) =>
      records.findIndex(
        (candidate) => candidate.evidenceId === evidence.evidenceId,
      ) === index,
  );
  const navigationNodes = [targetNode, sourceNode].filter(
    (node, index, records): node is ProofGraphNode =>
      Boolean(node?.href && node.hrefLabel) &&
      records.findIndex((candidate) => candidate?.href === node?.href) === index,
  );

  return (
    <div className="space-y-5 px-4 pb-6">
      <section className="space-y-3 text-sm">
        <h3 className="text-lg font-semibold">{sourceNode?.title} → {targetNode?.title}</h3>
        <p>{readableToken(relationship.relationshipType)} relationship</p>
        <p className="break-words">Source value: {sourceNode?.value}</p>
        <p className="break-words">Target value: {targetNode?.value}</p>
      </section>
      <details className="rounded-lg border border-neutral-200 p-4">
      <summary className="cursor-pointer text-sm font-semibold focus-visible:ring-2 focus-visible:ring-neutral-950">Technical details</summary>
      <dl className="rounded-lg border border-neutral-200 px-4">
        {[
          ["Relationship ID", relationship.relationshipId],
          ["Contract field", relationship.contractField],
          ["Relationship type", relationship.relationshipType],
          ["Session ID", relationship.sessionId],
          ["From entity", `${relationship.fromKind}: ${relationship.fromId}`],
          ["To entity", `${relationship.toKind}: ${relationship.toId}`],
        ].map(([label, value]) => (
          <div
            key={label}
            className="grid gap-1 border-b border-neutral-100 py-3 last:border-b-0 sm:grid-cols-[9rem_minmax(0,1fr)] sm:gap-4"
          >
            <dt className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
              {label}
            </dt>
            <dd className="min-w-0 break-all font-mono text-xs text-neutral-900">
              {value}
            </dd>
          </div>
        ))}
      </dl>
      </details>
      {relationship.relationshipType === "declared_source" ? (
        <p className="rounded-md border-l-2 border-dashed border-slate-500 bg-slate-50 p-3 text-xs leading-5 text-slate-700">
          <strong>Evidence through declared sources.</strong> This transitive path
          follows the exact source field above; it is not a direct evidence ID
          on the derived fact.
        </p>
      ) : null}
      {relationship.relationshipType === "direct_evidence" ? (
        <p className="rounded-md border-l-2 border-emerald-600 bg-emerald-50 p-3 text-xs leading-5 text-emerald-900">
          This solid green edge exists because the validated contract explicitly
          names the evidence ID.
        </p>
      ) : null}
      {evidenceReferences.length > 0 ? (
        <section
          className={cn(
            "pl-3",
            relationship.relationshipType === "declared_source"
              ? "border-l-2 border-dashed border-slate-500"
              : "border-l-2 border-emerald-600",
          )}
        >
          <h3 className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-600">
            {relationship.relationshipType === "declared_source"
              ? "Evidence through declared sources"
              : "Safe evidence references"}
          </h3>
          <div className="mt-2 flex flex-wrap gap-2">
            {evidenceReferences.map((evidence) => (
              <EvidenceInspector
                key={evidence.evidenceId}
                evidence={evidence}
                label={evidence.evidenceId}
              />
            ))}
          </div>
        </section>
      ) : null}
      {navigationNodes.length > 0 ? (
        <div className="grid gap-2">
          {navigationNodes.map((node) => (
            <Link
              key={node.href}
              href={node.href!}
              className="inline-flex min-h-9 w-full items-center justify-center gap-2 rounded-md border border-neutral-300 bg-white px-4 text-sm font-semibold text-neutral-900 outline-none hover:bg-neutral-50 focus-visible:ring-2 focus-visible:ring-neutral-950 focus-visible:ring-offset-2"
            >
              {node.hrefLabel}
              <ArrowRight className="size-4" aria-hidden />
            </Link>
          ))}
        </div>
      ) : null}
    </div>
  );
}

function GraphInspector({
  selection,
  nodes,
  edges,
  onClose,
  open,
  returnFocus,
}: {
  open: boolean;
  returnFocus: React.RefObject<HTMLElement | null>;
  selection: InspectorSelection;
  nodes: ProofGraphNode[];
  edges: ProofRelationship[];
  onClose: () => void;
}) {
  const mobile = useMobileSheet();
  const node =
    selection?.kind === "node"
      ? nodes.find((candidate) => candidate.id === selection.id)
      : undefined;
  const relationship =
    selection?.kind === "edge"
      ? edges.find((candidate) => candidate.relationshipId === selection.id)
      : undefined;
  const title = node
    ? `${kindPresentation[node.kind].label} inspector`
    : relationship
      ? "Relationship inspector"
      : "Proof inspector";

  return (
    <Sheet open={open && selection !== null} onOpenChange={(open) => !open && onClose()}>
      <SheetContent
        showCloseButton={false}
        finalFocus={returnFocus}
        side={mobile ? "bottom" : "right"}
        className={cn(
          "gap-0 overflow-hidden",
          mobile
            ? "max-h-[82svh] rounded-t-xl"
            : "w-full sm:max-w-[30rem]",
        )}
      >
        <SheetHeader className="shrink-0 border-b border-neutral-200 bg-white">
          <SheetClose render={<Button variant="outline" size="sm" className="self-end" />}>Close</SheetClose>
          <SheetTitle>{title}</SheetTitle>
          <SheetDescription>
            Supplied values, provenance and limitations. Exact source metadata is available in technical details.
          </SheetDescription>
        </SheetHeader>
        <div className="min-h-0 overflow-y-auto pt-4">
          {node ? <NodeInspector node={node} relationships={edges} nodes={nodes} /> : null}
          {relationship ? (
            <EdgeInspector relationship={relationship} nodes={nodes} />
          ) : null}
        </div>
      </SheetContent>
    </Sheet>
  );
}

function ActiveFindingContext({
  investigation,
  visibility,
  onClear,
}: {
  investigation: FindingInvestigation;
  visibility: FindingInvestigationVisibility;
  onClear: () => void;
}) {
  return (
    <section
      aria-label="Active finding investigation"
      className="mt-4 flex flex-col gap-3 rounded-lg border border-violet-200 bg-violet-50/60 p-3 text-violet-950 sm:flex-row sm:items-center sm:justify-between"
    >
      <div className="min-w-0">
        <p className="text-[10px] font-bold uppercase tracking-[0.06em] text-violet-700">
          Active finding investigation
        </p>
        <p className="mt-1 break-words text-sm font-semibold">
          {investigation.findingTitle}
        </p>
        <p className="mt-1 text-xs leading-5 text-violet-900/80">
          Finding-declared support, not a complete causal proof. {visibility.visibleNodeIds.size} of {investigation.nodeIds.size} supporting nodes and {visibility.visibleEdgeIds.size} of {investigation.edgeIds.size} supporting canvas relationships are visible.
        </p>
        {visibility.hiddenNodeCount > 0 || visibility.hiddenEdgeCount > 0 ? (
          <p className="mt-1 text-xs font-medium">
            Active filters hide {visibility.hiddenNodeCount} supporting node{visibility.hiddenNodeCount === 1 ? "" : "s"} and {visibility.hiddenEdgeCount} supporting relationship{visibility.hiddenEdgeCount === 1 ? "" : "s"}.
          </p>
        ) : null}
        {investigation.nonCanvasPolicyRelationships.length > 0 ? (
          <p className="mt-1 text-xs text-violet-900/80">
            {investigation.nonCanvasPolicyRelationships.length} policy-evaluation relationship{investigation.nonCanvasPolicyRelationships.length === 1 ? "" : "s"} remain available in technical context and have no canvas representation.
          </p>
        ) : null}
      </div>
      <Button
        type="button"
        size="sm"
        variant="outline"
        className="shrink-0 bg-white"
        onClick={onClear}
      >
        Clear selection
      </Button>
    </section>
  );
}

function Canvas({
  nodes,
  edges,
  layoutKey,
  selection,
  investigation,
  investigationVisibility: supportVisibility,
  onSelection,
  onClearSelection,
}: {
  nodes: CanvasNode[];
  edges: CanvasEdge[];
  layoutKey: string;
  selection: InspectorSelection;
  investigation: FindingInvestigation | null;
  investigationVisibility: FindingInvestigationVisibility | null;
  onSelection: (selection: InspectorSelection) => void;
  onClearSelection: () => void;
}) {
  const { fitView, setViewport } = useReactFlow<CanvasNode, CanvasEdge>();
  const containerRef = useInitialProofMapFit(nodes, layoutKey);

  return (
    <ReactFlow<CanvasNode, CanvasEdge>
      ref={containerRef}
      nodes={nodes}
      edges={edges}
      nodeTypes={nodeTypes}
      minZoom={0.15}
      maxZoom={1.8}
      nodesDraggable={false}
      nodesConnectable={false}
      edgesReconnectable={false}
      elementsSelectable
      nodesFocusable
      edgesFocusable
      panOnScroll={false}
      zoomOnScroll
      zoomOnPinch
      zoomOnDoubleClick={false}
      preventScrolling
      onNodeClick={(_, node) => onSelection({ kind: "node", id: node.id })}
      onEdgeClick={(_, edge) => onSelection({ kind: "edge", id: edge.id })}
      onPaneClick={onClearSelection}
      aria-label="Interactive Chain-of-Proof graph"
      colorMode="light"
    >
      <Background
        variant={BackgroundVariant.Dots}
        gap={20}
        size={1}
        color="#d4d4d4"
      />
      <Controls
        showInteractive={false}
        fitViewOptions={{ padding: 0.15, maxZoom: 1 }}
        aria-label="Proof graph zoom and fit controls"
      />
      <MiniMap<CanvasNode>
        className="!hidden !border !border-neutral-200 !bg-white md:!block"
        nodeColor={(node) => kindPresentation[node.data.kind].dot}
        maskColor="rgb(245 245 245 / 0.72)"
        pannable
        zoomable
        ariaLabel="Proof graph minimap"
      />
      <div className="absolute right-3 top-3 z-10 flex gap-2">
        {investigation ? (
          <Button
            type="button"
            size="sm"
            variant="outline"
            className="bg-white shadow-sm"
            disabled={!supportVisibility || supportVisibility.visibleNodeIds.size === 0}
            onClick={() => {
              const selectedNodes = nodes.filter((node) =>
                supportVisibility?.visibleNodeIds.has(node.id),
              );
              if (selectedNodes.length > 0) {
                void fitView({
                  nodes: selectedNodes,
                  padding: 0.2,
                  duration: 250,
                  maxZoom: 1.15,
                });
              }
            }}
            aria-label="Fit visible finding support"
          >
            <Focus className="size-3.5" aria-hidden />
            Fit selection
          </Button>
        ) : null}
        <Button
          type="button"
          size="sm"
          variant="outline"
          className="bg-white shadow-sm"
          onClick={() => void fitView({ padding: 0.15, duration: 250, maxZoom: 1 })}
          aria-label="Fit all visible proof nodes"
        >
          <Focus className="size-3.5" aria-hidden />
          Fit
        </Button>
        <Button
          type="button"
          size="sm"
          variant="outline"
          className="bg-white shadow-sm"
          onClick={() => {
            onClearSelection();
            void setViewport({ x: 28, y: 28, zoom: 0.72 }, { duration: 250 });
          }}
          aria-label="Reset proof graph viewport"
        >
          <RotateCcw className="size-3.5" aria-hidden />
          Reset
        </Button>
      </div>
      {nodes.length === 0 ? (
        <div className="pointer-events-none absolute inset-0 z-10 flex items-center justify-center p-6">
          <p className="max-w-sm rounded-lg border border-dashed border-neutral-300 bg-white/95 p-4 text-center text-sm leading-6 text-neutral-600 shadow-sm">
            No nodes match the current filters. Relationships were hidden with
            their endpoints; no replacement edges were created.
          </p>
        </div>
      ) : null}
      <span className="sr-only" aria-live="polite">
        {selection ? "Proof selection active." : "Proof selection cleared."}
      </span>
    </ReactFlow>
  );
}

export function ProofMapGraph({ data, lockedSessionId }: { data: ProofMapData; lockedSessionId?: string }) {
  const [selectedScope, setScope] = useState(data.defaultSessionId ?? "all");
  const scope = lockedSessionId ?? selectedScope;
  const [enabledKinds, setEnabledKinds] = useState<Set<ProofGraphNodeKind>>(
    () => new Set(kindOrder),
  );
  const [stateFilter, setStateFilter] = useState("all");
  const [selection, setSelection] = useState<InspectorSelection>(null);
  const [activeFindingId, setActiveFindingId] = useState<string | null>(null);
  const [inspectorOpen, setInspectorOpen] = useState(false);
  const returnFocus = useRef<HTMLElement | null>(null);
  const select = useCallback((next: InspectorSelection) => {
    if (next) returnFocus.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    if (next?.kind === "node") {
      const node = data.graphNodes.find((candidate) => candidate.id === next.id);
      if (node?.kind === "finding") setActiveFindingId(node.id);
    }
    setSelection(next);
    setInspectorOpen(next !== null);
  }, [data.graphNodes]);
  const clearSelection = useCallback(() => {
    setActiveFindingId(null);
    setSelection(null);
    setInspectorOpen(false);
  }, []);
  const previousScope = useRef(`${data.analysisId}:${scope}`);
  useEffect(() => {
    const nextScope = `${data.analysisId}:${scope}`;
    if (previousScope.current !== nextScope) {
      previousScope.current = nextScope;
      clearSelection();
    }
  }, [clearSelection, data.analysisId, scope]);
  const scopeStats = useMemo(() => {
    const bySession = new Map(
      data.sessions.map((session) => [
        session.sessionId,
        {
          nodes: data.graphNodes.filter((node) =>
            node.sessionIds.includes(session.sessionId),
          ).length,
          edges: data.graphEdges.filter(
            (edge) => edge.sessionId === session.sessionId,
          ).length,
        },
      ]),
    );
    return {
      all: { nodes: data.graphNodes.length, edges: data.graphEdges.length },
      bySession,
    };
  }, [data.graphEdges, data.graphNodes, data.sessions]);

  const selectedSessionIds = useMemo(
    () =>
      scope === "all"
        ? data.sessions.map((session) => session.sessionId).sort()
        : [scope],
    [data.sessions, scope],
  );
  const scopedNodes = useMemo(
    () =>
      data.graphNodes.filter((node) =>
        node.sessionIds.some((sessionId) => selectedSessionIds.includes(sessionId)),
      ),
    [data.graphNodes, selectedSessionIds],
  );
  const positionedNodes = useMemo(
    () => layoutNodes(scopedNodes, selectedSessionIds),
    [scopedNodes, selectedSessionIds],
  );
  const visibleRecords = useMemo(
    () =>
      positionedNodes.filter(
        (node) =>
          enabledKinds.has(node.kind) &&
          (stateFilter === "all" || node.stateLabel === stateFilter),
      ),
    [enabledKinds, positionedNodes, stateFilter],
  );
  const visibleIds = useMemo(
    () => new Set(visibleRecords.map((node) => node.id)),
    [visibleRecords],
  );
  const visibleRelationships = useMemo(
    () =>
      data.graphEdges.filter(
        (relationship) =>
          selectedSessionIds.includes(relationship.sessionId) &&
          visibleIds.has(relationship.fromId) &&
          visibleIds.has(relationship.toId),
      ),
    [data.graphEdges, selectedSessionIds, visibleIds],
  );
  const allScopedRelationships = useMemo(
    () =>
      data.sessions
        .filter((session) => selectedSessionIds.includes(session.sessionId))
        .flatMap((session) => session.relationships),
    [data.sessions, selectedSessionIds],
  );
  const activeInvestigation = useMemo(
    () =>
      activeFindingId &&
      scopedNodes.some((node) => node.id === activeFindingId)
        ? buildFindingInvestigation(
            data.graphNodes,
            data.sessions.flatMap((session) => session.relationships),
            activeFindingId,
          )
        : null,
    [activeFindingId, data.graphNodes, data.sessions, scopedNodes],
  );
  const visibleEdgeIds = useMemo(
    () =>
      new Set(
        visibleRelationships.map((relationship) => relationship.relationshipId),
      ),
    [visibleRelationships],
  );
  const supportVisibility = useMemo(
    () =>
      activeInvestigation
        ? investigationVisibility(
            activeInvestigation,
            visibleIds,
            visibleEdgeIds,
          )
        : null,
    [activeInvestigation, visibleEdgeIds, visibleIds],
  );

  const highlight = useMemo(() => {
    const nodeIds = new Set<string>();
    const edgeIds = new Set<string>();
    if (activeInvestigation && supportVisibility) {
      return {
        nodeIds: supportVisibility.visibleNodeIds,
        edgeIds: supportVisibility.visibleEdgeIds,
      };
    }
    if (selection?.kind === "node") {
      nodeIds.add(selection.id);
      for (const relationship of visibleRelationships) {
        if (
          relationship.fromId === selection.id ||
          relationship.toId === selection.id
        ) {
          edgeIds.add(relationship.relationshipId);
          nodeIds.add(relationship.fromId);
          nodeIds.add(relationship.toId);
        }
      }
    }
    if (selection?.kind === "edge") {
      const relationship = visibleRelationships.find(
        (candidate) => candidate.relationshipId === selection.id,
      );
      if (relationship) {
        edgeIds.add(relationship.relationshipId);
        nodeIds.add(relationship.fromId);
        nodeIds.add(relationship.toId);
      }
    }
    return { nodeIds, edgeIds };
  }, [activeInvestigation, selection, supportVisibility, visibleRelationships]);

  const canvasNodes: CanvasNode[] = useMemo(
    () =>
      visibleRecords.map((node) => ({
        id: node.id,
        type: "proofNode",
        position: node.position,
        data: {
          ...node,
          highlighted: highlight.nodeIds.has(node.id),
          dimmed:
            (selection !== null || activeInvestigation !== null) &&
            !highlight.nodeIds.has(node.id),
          onInspect: () => select({ kind: "node", id: node.id }),
        },
        width: NODE_WIDTH,
        height: NODE_HEIGHT,
        draggable: false,
        connectable: false,
        selectable: true,
        focusable: true,
        ariaLabel: `${kindPresentation[node.kind].label}: ${node.title}, value ${node.value}, ${node.id}, state ${node.stateLabel}. Select to inspect.`,
      })),
    [activeInvestigation, highlight.nodeIds, selection, visibleRecords, select],
  );

  const canvasEdges: CanvasEdge[] = useMemo(
    () =>
      visibleRelationships.map((relationship) => {
        const color = relationshipColor(relationship.relationshipType);
        const highlighted = highlight.edgeIds.has(relationship.relationshipId);
        const dimmed =
          (selection !== null || activeInvestigation !== null) && !highlighted;
        return {
          id: relationship.relationshipId,
          source: relationship.fromId,
          target: relationship.toId,
          type: "smoothstep",
          label: relationshipLabel(relationship),
          labelStyle: {
            fill: color,
            fontSize: 9,
            fontWeight: 600,
          },
          labelBgStyle: { fill: "#ffffff", fillOpacity: 0.9 },
          labelBgPadding: [4, 2] as [number, number],
          labelBgBorderRadius: 4,
          style: {
            stroke: color,
            strokeWidth: highlighted ? 3 : 1.75,
            strokeDasharray:
              relationship.relationshipType === "declared_source"
                ? "7 5"
                : undefined,
            opacity: dimmed ? 0.12 : 1,
          },
          markerEnd: {
            type: MarkerType.ArrowClosed,
            color,
            width: 14,
            height: 14,
          },
          data: { relationship },
          selectable: true,
          focusable: true,
          ariaLabel: `${relationship.contractField}: ${relationship.fromId} to ${relationship.toId}. Select to inspect.`,
        };
      }),
    [activeInvestigation, highlight.edgeIds, selection, visibleRelationships],
  );

  const layoutKey = `${scope}:${[...enabledKinds].sort().join(",")}:${stateFilter}`;

  return (
    <section
      aria-labelledby="proof-graph-heading"
      className="min-w-0 overflow-hidden rounded-lg border border-neutral-200 bg-white shadow-sm"
      data-proof-scope={scope}
      data-proof-node-count={visibleRecords.length}
      data-proof-edge-count={visibleRelationships.length}
    >
      <div className="border-b border-neutral-200 px-4 py-4 sm:px-5">
        <div className="flex min-w-0 flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
          <div className="min-w-0">
            <div className="flex items-start gap-3">
              <span className="flex size-9 shrink-0 items-center justify-center rounded-md border border-neutral-200 bg-neutral-50 text-neutral-700">
                <Filter className="size-4" aria-hidden />
              </span>
              <div>
                <h2 id="proof-graph-heading" className="font-semibold text-neutral-950">
                  Interactive declared-relationship graph
                </h2>
                <p className="mt-1 max-w-3xl text-xs leading-5 text-neutral-600">
                  Select a node or edge to inspect exact IDs and safe evidence.
                  Finding selection follows only its declared support fields;
                  other selections show immediate declared context.
                  Filtering hides endpoints and never reconnects an edge.
                </p>
              </div>
            </div>
          </div>

          <label className="grid min-w-0 gap-1 xl:w-80">
            <span className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
              Session scope
            </span>
            <select
              value={scope}
              disabled={Boolean(lockedSessionId)}
              onChange={(event) => {
                clearSelection();
                setScope(event.target.value);
              }}
              className="h-9 min-w-0 rounded-md border border-neutral-300 bg-white px-3 text-xs text-neutral-900 outline-none focus-visible:ring-2 focus-visible:ring-neutral-950"
              aria-label="Proof graph session scope"
            >
              <option
                value="all"
                data-node-count={scopeStats.all.nodes}
                data-edge-count={scopeStats.all.edges}
              >
                All sessions · {scopeStats.all.nodes} nodes / {scopeStats.all.edges} edges
              </option>
              {data.sessions.map((session) => (
                <option
                  key={session.sessionId}
                  value={session.sessionId}
                  data-node-count={scopeStats.bySession.get(session.sessionId)?.nodes}
                  data-edge-count={scopeStats.bySession.get(session.sessionId)?.edges}
                >
                  {session.protocol.toUpperCase()} · stream {session.tcpStreamId} · {session.sessionId} · {scopeStats.bySession.get(session.sessionId)?.nodes} nodes / {scopeStats.bySession.get(session.sessionId)?.edges} edges
                </option>
              ))}
            </select>
          </label>
        </div>

        <div className="mt-4 grid gap-3 lg:grid-cols-[minmax(0,1fr)_15rem]">
          <fieldset className="min-w-0">
            <legend className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
              Entity types
            </legend>
            <div className="mt-2 flex min-w-0 flex-wrap gap-2">
              {kindOrder.map((kind) => (
                <label
                  key={kind}
                  className={cn(
                    "inline-flex min-h-8 cursor-pointer items-center gap-2 rounded-md border px-2.5 text-[11px] font-medium",
                    enabledKinds.has(kind)
                      ? "border-neutral-400 bg-neutral-100 text-neutral-950"
                      : "border-neutral-200 bg-white text-neutral-500",
                  )}
                >
                  <input
                    type="checkbox"
                    checked={enabledKinds.has(kind)}
                    onChange={() => {
                      setSelection(null);
                      setInspectorOpen(false);
                      setEnabledKinds((current) => {
                        const next = new Set(current);
                        if (next.has(kind)) next.delete(kind);
                        else next.add(kind);
                        return next;
                      });
                    }}
                    className="size-3.5 accent-neutral-900"
                  />
                  {kindPresentation[kind].label}
                </label>
              ))}
            </div>
          </fieldset>
          <label className="grid content-start gap-1">
            <span className="text-[10px] font-bold uppercase tracking-[0.06em] text-neutral-500">
              Provenance / event state
            </span>
            <select
              value={stateFilter}
              onChange={(event) => {
                setSelection(null);
                setInspectorOpen(false);
                setStateFilter(event.target.value);
              }}
              className="h-9 rounded-md border border-neutral-300 bg-white px-3 text-xs text-neutral-900 outline-none focus-visible:ring-2 focus-visible:ring-neutral-950"
              aria-label="Proof graph provenance and event state filter"
            >
              <option value="all">All provenance states</option>
              {stateOptions.map((state) => (
                <option key={state} value={state}>
                  {readableToken(state)}
                </option>
              ))}
            </select>
          </label>
        </div>

        <div className="mt-3 flex flex-wrap items-center gap-2 text-[10px] text-neutral-600">
          <Badge variant="outline" className="rounded-md font-mono text-[10px]">
            {visibleRecords.length} nodes
          </Badge>
          <Badge variant="outline" className="rounded-md font-mono text-[10px]">
            {visibleRelationships.length} declared edges
          </Badge>
          <span>Filters match provenance and qualified event state, not result values.</span>
        </div>
        {activeInvestigation && supportVisibility ? (
          <ActiveFindingContext
            investigation={activeInvestigation}
            visibility={supportVisibility}
            onClear={clearSelection}
          />
        ) : selection ? (
          <div className="mt-3">
            <Button type="button" size="sm" variant="outline" onClick={clearSelection}>
              Clear selection
            </Button>
          </div>
        ) : null}
      </div>

      <div className="relative h-[68dvh] min-h-[30rem] max-h-[44rem] w-full overflow-hidden bg-neutral-50 md:h-[44rem]">
        <ReactFlowProvider>
          <Canvas
            nodes={canvasNodes}
            edges={canvasEdges}
            layoutKey={layoutKey}
            selection={selection}
            investigation={activeInvestigation}
            investigationVisibility={supportVisibility}
            onSelection={select}
            onClearSelection={clearSelection}
          />
        </ReactFlowProvider>
      </div>

      <div className="border-t border-neutral-200 bg-neutral-50 px-4 py-3 text-[10px] leading-5 text-neutral-600 sm:px-5">
        Touch: drag the canvas to pan and pinch to zoom. Keyboard: tab to a node
        or edge and press Enter to inspect; Escape closes the inspector; Clear selection removes highlighting without moving the view. The
        minimap is intentionally hidden on small screens.
      </div>

      <GraphInspector
        selection={selection}
        nodes={data.graphNodes}
        edges={allScopedRelationships}
        open={inspectorOpen}
        returnFocus={returnFocus}
        onClose={() => setInspectorOpen(false)}
      />
    </section>
  );
}
