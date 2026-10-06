import { createContext, useContext } from 'react';
import type { GraphCounter } from './components/GraphCounters';

/**
 * What the graph view hands to the toolbar rendered inside it: the counters of what is drawn and
 * the actions that need the canvas (full screen, image export, the shortcuts dialog).
 */
export interface GraphViewActions {
  counters: readonly GraphCounter[];
  /** The entity and relationship types drawn, as the legend lists them: what the type filter offers. */
  drawnTypes: { entityTypes: readonly string[]; relationshipTypes: readonly string[] };
  /** Entity and relationship types filtered out, as counted by the legend and the type filter. */
  typeFilterCount: number;
  /** Absent for a user without the capability of the other knowledge exports. */
  exportImage?: () => void;
  toggleFullscreen: () => void;
  showShortcuts: () => void;
}

export const GraphViewContext = createContext<GraphViewActions | null>(null);

/** `null` outside a graph view, for a toolbar rendered on its own. */
export const useGraphView = () => useContext(GraphViewContext);
