import type { Node, Viewport, XYPosition } from 'reactflow';
import type { PlaybookLayoutDirection } from '../hooks/usePlaybookLayoutMode';
import { PLAYBOOK_CARD } from '../types/nodes/playbookNodeGeometry';

// Opening a playbook fits it, never above 100% (a one-step playbook is not blown up) and never under
// the zoom where a card title stays readable: a playbook too large for that lands on its entry point.
export const PLAYBOOK_LANDING = { padding: 0.2, maxZoom: 1, minZoom: 0.75, margin: 24 };

type Pane = { width: number; height: number };

const steps = (nodes: Node[]) => nodes.filter((node) => node.type !== 'placeholder');

// The zoom a fit of the steps would reach, with the padding React Flow applies to a fit.
export const playbookFitZoom = (nodes: Node[], pane: Pane): number | null => {
  const cards = steps(nodes);
  if (cards.length === 0 || pane.width <= 0 || pane.height <= 0) return null;
  const xs = cards.map((n) => n.position.x);
  const ys = cards.map((n) => n.position.y);
  const width = Math.max(...xs) + PLAYBOOK_CARD.width - Math.min(...xs);
  const height = Math.max(...ys) + PLAYBOOK_CARD.height - Math.min(...ys);
  const zoom = Math.min(
    pane.width / (width * (1 + PLAYBOOK_LANDING.padding)),
    pane.height / (height * (1 + PLAYBOOK_LANDING.padding)),
  );
  return Math.min(PLAYBOOK_LANDING.maxZoom, zoom);
};

// The entry point of the playbook, else the first step in the reading order of the direction.
const entryOf = (nodes: Node[], direction: PlaybookLayoutDirection): XYPosition | null => {
  const cards = steps(nodes);
  const byReadingOrder = (a: Node, b: Node) => (direction === 'horizontal'
    ? (a.position.x - b.position.x) || (a.position.y - b.position.y)
    : (a.position.y - b.position.y) || (a.position.x - b.position.x));
  const entries = cards.filter((n) => n.data?.component?.is_entry_point).sort(byReadingOrder);
  const first = entries[0] ?? cards.slice().sort(byReadingOrder)[0];
  return first ? first.position : null;
};

// The viewport a playbook opens on when a fit would make its cards unreadable: the readable floor
// zoom, the entry point at the start of the reading direction, centred across it, on whole pixels.
// null when the fit itself is readable.
export const playbookLandingViewport = (nodes: Node[], pane: Pane, direction: PlaybookLayoutDirection): Viewport | null => {
  const fit = playbookFitZoom(nodes, pane);
  if (fit === null || fit >= PLAYBOOK_LANDING.minZoom) return null;
  const entry = entryOf(nodes, direction);
  if (!entry) return null;
  const zoom = PLAYBOOK_LANDING.minZoom;
  if (direction === 'horizontal') {
    return {
      x: Math.round(PLAYBOOK_LANDING.margin - entry.x * zoom),
      y: Math.round(pane.height / 2 - (entry.y + PLAYBOOK_CARD.height / 2) * zoom),
      zoom,
    };
  }
  return {
    x: Math.round(pane.width / 2 - (entry.x + PLAYBOOK_CARD.width / 2) * zoom),
    y: Math.round(PLAYBOOK_LANDING.margin - entry.y * zoom),
    zoom,
  };
};
