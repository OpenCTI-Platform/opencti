import { createContext, useContext } from 'react';
import type { GraphCounter } from './components/GraphCounters';
import type { GraphToolbarAction } from './components/useGraphToolbarActions';

/**
 * What the graph view hands to the toolbar rendered inside it: the counters of what is drawn and
 * the actions that need the canvas (full screen, image export, the shortcuts dialog).
 */
export interface GraphViewActions {
  /**
   * The actions of the empty canvas that are not toolbar actions (invert or clear the selection,
   * show the hidden entities, ungroup): its context menu lists them, and "More actions" in 3D, which has none.
   */
  canvasActions?: readonly GraphToolbarAction[];
  counters: readonly GraphCounter[];
  /** The entity and relationship types drawn, as the legend lists them: what the type filter offers. */
  drawnTypes: { entityTypes: readonly string[]; relationshipTypes: readonly string[] };
  /** Entity and relationship types filtered out, as counted by the legend and the type filter. */
  typeFilterCount: number;
  /** Whether the relationships drawn close a cycle: the 3D view has no tree layout for one. */
  drawnHasCycle: boolean;
  /** Absent for a user without the capability of the other knowledge exports. */
  exportImage?: () => void;
  toggleFullscreen: () => void;
  showShortcuts: () => void;
}

export const GraphViewContext = createContext<GraphViewActions | null>(null);

/** `null` outside a graph view, for a toolbar rendered on its own. */
export const useGraphView = () => useContext(GraphViewContext);
