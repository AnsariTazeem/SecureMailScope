"use client";

import { useEffect, useRef } from "react";
import { useReactFlow, useStoreApi, type Node } from "@xyflow/react";

export function useInitialProofMapFit(nodes: Node[], layoutKey: string) {
  const containerRef = useRef<HTMLDivElement>(null);
  const fittedLayout = useRef<string | null>(null);
  const store = useStoreApi();
  const { fitView } = useReactFlow();

  useEffect(() => {
    const container = containerRef.current;
    if (!container || fittedLayout.current === layoutKey) return;

    const fitWhenReady = () => {
      if (fittedLayout.current === layoutKey || nodes.length === 0) return;

      const { width, height, panZoom, nodeLookup } = store.getState();
      // Kept-mounted tabs have no layout box while hidden. React Flow may
      // still retain an old size (or a fallback), so check the actual DOM too.
      if (
        container.clientWidth <= 0 ||
        container.clientHeight <= 0 ||
        !(container.checkVisibility?.() ?? true) ||
        width !== container.clientWidth ||
        height !== container.clientHeight ||
        !panZoom
      ) {
        return;
      }

      // A scope/filter update must reach the store before we fit. Declared
      // node width/height alone do not prove that DOM measurement has run.
      if (
        nodeLookup.size !== nodes.length ||
        !nodes.every((node) => {
          const measured = nodeLookup.get(node.id);
          return (
            measured?.internals.userNode === node &&
            measured.internals.handleBounds !== undefined &&
            (measured.measured.width ?? 0) > 0 &&
            (measured.measured.height ?? 0) > 0
          );
        })
      ) {
        return;
      }

      // Mark before calling fitView, which itself updates the store. An
      // immediate fit cannot leave an animation competing with user input.
      fittedLayout.current = layoutKey;
      void fitView({ padding: 0.15, maxZoom: 1, duration: 0 });
    };

    // Either measurement order is valid: viewport first or nodes first.
    const unsubscribe = store.subscribe(fitWhenReady);
    const observer = new ResizeObserver(fitWhenReady);
    observer.observe(container);
    fitWhenReady();

    return () => {
      unsubscribe();
      observer.disconnect();
    };
  }, [fitView, layoutKey, nodes, store]);

  return containerRef;
}
