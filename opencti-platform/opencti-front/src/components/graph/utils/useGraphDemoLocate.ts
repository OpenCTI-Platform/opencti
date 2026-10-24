import { MutableRefObject, useEffect, useRef } from 'react';
import type { GraphNode } from '../graph.types';
import type { GraphRef2D } from '../GraphContext';
import { DEMO_LOCATE_HOOK, demoLabels, demoLocation, type DemoLocation, findDemoNode, isDemoMode } from './graphDemoLocate';

type DemoWindow = Window & { [DEMO_LOCATE_HOOK]?: (label?: string) => DemoLocation | string[] | null };

/**
 * Exposes `window.__xtmDemoLocate` on a 2D graph opened with `?demo=1` (`graphDemoLocate`): called
 * with a label it answers where that node stands on the page, or null; called without one, the
 * labels of the nodes shown. Read on each call, so a node moved, a zoom or a pan is where the
 * recording acts; removed when the graph leaves, switches to 3D or the flag is absent.
 */
const useGraphDemoLocate = (
  graphRef: MutableRefObject<GraphRef2D | undefined>,
  containerRef: MutableRefObject<HTMLDivElement | null>,
  nodes: GraphNode[],
  mode3D: boolean,
) => {
  const shown = useRef(nodes);
  shown.current = nodes;

  useEffect(() => {
    if (mode3D || !isDemoMode(window.location.search)) return undefined;
    const target = window as DemoWindow;
    const locate = (label?: string): DemoLocation | string[] | null => {
      if (label === undefined) return demoLabels(shown.current);
      const graph = graphRef.current;
      const container = containerRef.current;
      const node = findDemoNode(shown.current, String(label));
      if (!graph || !container || !node) return null;
      // The graph's canvas fills its container: its screen coordinates start at the container's corner.
      return demoLocation(node, graph.graph2ScreenCoords(node.x, node.y), container.getBoundingClientRect(), graph.zoom());
    };
    target[DEMO_LOCATE_HOOK] = locate;
    return () => {
      if (target[DEMO_LOCATE_HOOK] === locate) delete target[DEMO_LOCATE_HOOK];
    };
  }, [graphRef, containerRef, mode3D]);
};

export default useGraphDemoLocate;
