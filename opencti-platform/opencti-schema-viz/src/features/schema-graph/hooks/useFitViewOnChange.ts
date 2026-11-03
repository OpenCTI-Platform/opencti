import { useEffect, useRef } from 'react';
import { useReactFlow, useStoreApi } from 'reactflow';
import { useSchemaGraphStore } from '../../../state/schemaGraphStore';
import type { VisibleGraph } from '../buildVisibleGraph';
import { typeNodeId } from '../graphIds';
import type { GraphLayout } from '../layout/useDagreLayout';

const FIT_PADDING = 0.15;
/** Framing a handful of nodes should not blow them up to the maximum zoom. */
const FIT_MAX_ZOOM = 1.2;
const FIT_MIN_ZOOM = 0.05;

const prefersReducedMotion = () => window.matchMedia?.('(prefers-reduced-motion: reduce)').matches ?? false;

const boundsOf = (ids: Iterable<string>, layout: GraphLayout) => {
  let minX = Infinity;
  let minY = Infinity;
  let maxX = -Infinity;
  let maxY = -Infinity;
  for (const id of ids) {
    const position = layout.positions.get(id);
    const size = layout.sizes.get(id);
    if (!position || !size) continue;
    minX = Math.min(minX, position.x);
    minY = Math.min(minY, position.y);
    maxX = Math.max(maxX, position.x + size.width);
    maxY = Math.max(maxY, position.y + size.height);
  }
  return Number.isFinite(minX) ? { x: minX, y: minY, width: maxX - minX, height: maxY - minY } : null;
};

/**
 * Moves the camera when the store asks for it (focus, expand, view change), using the computed
 * layout rather than measured DOM nodes, so it works on the very first frame after a re-layout.
 */
export const useFitViewOnChange = (graph: VisibleGraph, layout: GraphLayout) => {
  const camera = useSchemaGraphStore((state) => state.camera);
  const { setCenter } = useReactFlow();
  const store = useStoreApi();
  const handled = useRef<number | null>(null);

  useEffect(() => {
    if (handled.current === camera.nonce || graph.nodes.length === 0) return undefined;
    let ids: Set<string>;
    if (camera.typeIds === null) {
      ids = new Set(layout.positions.keys());
    } else {
      ids = new Set(camera.typeIds.map(typeNodeId));
      if (camera.withNeighbors) {
        for (const edge of graph.edges) {
          if (ids.has(edge.source) || ids.has(edge.target)) {
            ids.add(edge.source);
            ids.add(edge.target);
          }
        }
      }
    }
    const bounds = boundsOf(ids, layout);
    if (!bounds) return undefined;
    const duration = prefersReducedMotion() ? 0 : 450;
    // Two frames: the inspector may open in the same update, and React Flow learns the new canvas size from a ResizeObserver.
    let frame = requestAnimationFrame(() => {
      frame = requestAnimationFrame(() => {
        handled.current = camera.nonce;
        const { width, height } = store.getState();
        const zoom = Math.max(FIT_MIN_ZOOM, Math.min(
          FIT_MAX_ZOOM,
          width / (bounds.width * (1 + FIT_PADDING)),
          height / (bounds.height * (1 + FIT_PADDING)),
        ));
        setCenter(bounds.x + bounds.width / 2, bounds.y + bounds.height / 2, { zoom, duration });
      });
    });
    return () => cancelAnimationFrame(frame);
  }, [camera, graph, layout, setCenter, store]);
};
