import { MutableRefObject, useEffect, useRef, useState } from 'react';
import type { GraphNode, OctiGraphPositions } from '../graph.types';
import type { GraphRef2D } from '../GraphContext';
import type { LayoutPositions } from './graphLayouts';

const TRANSITION_MS = 480;
const FIT_PADDING = 60;

const easeInOutCubic = (t: number) => (t < 0.5 ? 4 * t * t * t : 1 - (-2 * t + 2) ** 3 / 2);

const prefersReducedMotion = () => typeof window !== 'undefined'
  && typeof window.matchMedia === 'function'
  && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

export interface GraphLayoutRequest {
  /** Identity of the layout and its parameters; a new key is a new arrangement. */
  key: string;
  compute: () => LayoutPositions;
}

interface UseGraphLayoutEngineArgs {
  graphRef: MutableRefObject<GraphRef2D | undefined>;
  nodes: readonly GraphNode[];
  /** Changes whenever the drawn nodes or links change, which calls for a new arrangement. */
  shapeSignature: string;
  layout: GraphLayoutRequest | null;
  enabled: boolean;
  /**
   * The 2D graph is left (3D mode), not just paused while data loads: the nodes are given back
   * their saved positions so the 3D forces arrange them, and the layout applies afresh on return.
   */
  released?: boolean;
  /** Positions saved by the reader, given back to the nodes when the layout is switched off. */
  savedPositions: OctiGraphPositions;
  /** Frames the arranged graph clear of the floating panels; false when it could not. */
  frameView?: (padding: number, duration: number) => boolean;
}

/**
 * Applies a deterministic layout: every node glides from where it is to its place, then stays
 * pinned there (forces no longer move it, a drag still does). Switching the layout off gives the
 * nodes back their saved positions and lets the forces arrange the rest. While nodes glide the
 * canvas must repaint every frame, which `animating` tells the caller.
 */
const useGraphLayoutEngine = ({ graphRef, nodes, shapeSignature, layout, enabled, released = false, savedPositions, frameView }: UseGraphLayoutEngineArgs) => {
  const [animating, setAnimating] = useState(false);
  const [targets, setTargets] = useState<LayoutPositions | null>(null);
  const frame = useRef(0);
  const appliedKey = useRef<string | null>(null);
  const latestNodes = useRef(nodes);
  latestNodes.current = nodes;

  /** Leaves the applied layout: the nodes take their saved pins back. Whether one was applied. */
  const leaveLayout = () => {
    setTargets(null);
    if (appliedKey.current === null) return false;
    appliedKey.current = null;
    latestNodes.current.forEach((node) => {
      const saved = savedPositions[node.id];
      node.fx = saved?.x;
      node.fy = saved?.y;
    });
    return true;
  };

  // Applied again when the node objects change too: the graph data can replace them under the
  // same ids (an edited entity), and the replacements must take the positions and pins.
  useEffect(() => {
    // Turned off or without a layout during a transition: the frame is cancelled, so is the repaint.
    if (!enabled) {
      setAnimating(false);
      if (released) leaveLayout();
      return undefined;
    }
    if (!layout) {
      setAnimating(false);
      if (leaveLayout()) graphRef.current?.d3ReheatSimulation();
      return undefined;
    }
    const computed = layout.compute();
    setTargets(computed);
    const isNewArrangement = appliedKey.current !== layout.key;
    appliedKey.current = layout.key;
    const starts = new Map(latestNodes.current.map((node) => [node.id, {
      x: Number.isFinite(node.x) ? node.x : computed.get(node.id)?.x ?? 0,
      y: Number.isFinite(node.y) ? node.y : computed.get(node.id)?.y ?? 0,
    }]));
    const duration = prefersReducedMotion() ? 0 : TRANSITION_MS;
    const startTime = performance.now();
    cancelAnimationFrame(frame.current);
    setAnimating(true);
    const step = () => {
      const progress = duration === 0 ? 1 : Math.min(1, (performance.now() - startTime) / duration);
      const eased = easeInOutCubic(progress);
      latestNodes.current.forEach((node: GraphNode & { vx?: number; vy?: number }) => {
        const target = computed.get(node.id);
        const start = starts.get(node.id);
        if (!target || !start) return;
        node.x = start.x + (target.x - start.x) * eased;
        node.y = start.y + (target.y - start.y) * eased;
        node.fx = node.x;
        node.fy = node.y;
        node.vx = 0;
        node.vy = 0;
      });
      if (progress < 1) {
        frame.current = requestAnimationFrame(step);
      } else {
        setAnimating(false);
        if (isNewArrangement && !frameView?.(FIT_PADDING, 400)) graphRef.current?.zoomToFit(400, FIT_PADDING);
      }
    };
    frame.current = requestAnimationFrame(step);
    return () => cancelAnimationFrame(frame.current);
  }, [enabled, released, layout?.key, shapeSignature, nodes]);

  /** `targets`: where the applied layout puts the nodes, `null` without one. */
  return { animating, targets };
};

export default useGraphLayoutEngine;
