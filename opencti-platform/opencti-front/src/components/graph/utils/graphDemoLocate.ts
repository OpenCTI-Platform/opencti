import type { GraphNode } from '../graph.types';
import { nodeRadius } from './graphPainting';
import { graphNodeTitle } from './useGraphParser';

/**
 * The page hook a scripted recording of the graph locates its nodes through: the XTM One Video
 * Studio recorder clicks, right-clicks and drags a node by its label, where a canvas has no
 * element to name. Exposed only when the page is opened with the demo flag.
 */
export const DEMO_LOCATE_HOOK = '__xtmDemoLocate';
/** The query flag that exposes the hook (`?demo=1`): a reader who did not ask never has it. */
export const DEMO_FLAG = 'demo';

/** Where a node stands on the page: its centre and its drawn radius, in CSS pixels of the window. */
export interface DemoLocation {
  x: number;
  y: number;
  r: number;
  id: string;
  label: string;
}

export const isDemoMode = (search: string): boolean => new URLSearchParams(search).get(DEMO_FLAG) === '1';

type LocatableNode = Pick<GraphNode, 'id' | 'name' | 'label' | 'raw' | 'relationship_type' | 'groupOf' | 'isRestricted' | 'x' | 'y'>;

/** The labels a recording may name a node by: the title the graph shows, else its name. */
export const demoLabels = (nodes: LocatableNode[]): string[] => nodes.map((node) => graphNodeTitle(node) || node.name || node.id);

/**
 * The node a recording names by *label*: its title as the graph shows it, its name or its id, the
 * exact text first, then in any case; a node not laid out yet (no position) is never found.
 */
export const findDemoNode = <T extends LocatableNode>(nodes: T[], label: string): T | undefined => {
  const placed = nodes.filter((node) => Number.isFinite(node.x) && Number.isFinite(node.y));
  const names = (node: T) => [graphNodeTitle(node), node.name, node.id].filter(Boolean);
  const wanted = label.trim();
  return placed.find((node) => names(node).includes(wanted))
    ?? placed.find((node) => names(node).some((name) => name.toLocaleLowerCase() === wanted.toLocaleLowerCase()));
};

/**
 * Where *node* stands in CSS pixels of the window: its position on the graph (*screen*, what the
 * graph's `graph2ScreenCoords` answers) offset by the corner of the container its canvas fills
 * (*origin*), its radius drawn at *zoom*.
 */
export const demoLocation = (
  node: LocatableNode,
  screen: { x: number; y: number },
  origin: { left: number; top: number },
  zoom: number,
): DemoLocation => ({
  x: origin.left + screen.x,
  y: origin.top + screen.y,
  r: nodeRadius(node) * zoom,
  id: node.id,
  label: graphNodeTitle(node) || node.name || node.id,
});
