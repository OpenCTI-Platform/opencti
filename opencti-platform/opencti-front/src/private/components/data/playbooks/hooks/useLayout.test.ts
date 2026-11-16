import { describe, expect, it } from 'vitest';
import type { Edge, Node } from 'reactflow';
import { layoutNodes, PLAYBOOK_LAYOUT_SPACING, playbookLanding } from './useLayout';
import { PLAYBOOK_CARD, PLAYBOOK_PORT_ADD } from '../types/nodes/playbookNodeGeometry';
import { PLAYBOOK_LANDING, PLAYBOOK_MINIMAP } from '../utils/playbookLanding';

const component = (id: string, outs: string[], is_entry_point = false) => ({
  id,
  is_entry_point,
  ports: outs.map((p) => ({ id: p, type: 'out' })),
});
const LISTEN = component('LISTEN', ['out'], true);
const MATCH = component('MATCH', ['out', 'no-match']);
const LOG = component('LOG', ['out']);

const node = (id: string, c: ReturnType<typeof component>): Node => ({ id, type: 'workflow', position: { x: 0, y: 0 }, data: { component: c } });
const placeholder = (id: string): Node => ({ id, type: 'placeholder', position: { x: 0, y: 0 }, data: { component: { is_entry_point: false } } });
const edge = (source: string, sourceHandle: string, target: string): Edge => ({ id: `${source}-${sourceHandle}-${target}`, source, sourceHandle, target });

const NODES = [node('a', LISTEN), node('b', MATCH), node('c', LOG), node('d', LOG), node('e', LOG), placeholder('p1'), placeholder('p2')];
const EDGES = [edge('a', 'out', 'b'), edge('b', 'out', 'c'), edge('b', 'no-match', 'd'), edge('c', 'out', 'e'), edge('d', 'out', 'e'), edge('e', 'out', 'p1'), edge('a', 'out', 'p2')];

const picture = (nodes: Node[]) => nodes.map((n) => `${n.id}@${n.position.x},${n.position.y}`).sort().join('|');

describe('useLayout layoutNodes', () => {
  it('gives the same picture whatever the order of the store (the d3 tree picked the first link as parent)', () => {
    const reference = picture(layoutNodes(NODES, EDGES));
    expect(picture(layoutNodes(NODES.slice().reverse(), EDGES.slice().reverse()))).toBe(reference);
    const shuffledNodes = [NODES[3], NODES[0], NODES[6], NODES[2], NODES[5], NODES[1], NODES[4]];
    const shuffledEdges = [EDGES[4], EDGES[2], EDGES[6], EDGES[0], EDGES[3], EDGES[5], EDGES[1]];
    expect(picture(layoutNodes(shuffledNodes, shuffledEdges))).toBe(reference);
  });

  it('places a node joined from two branches below both of them', () => {
    const laid = new Map(layoutNodes(NODES, EDGES).map((n) => [n.id, n.position]));
    expect(laid.get('e')!.y).toBeGreaterThan(laid.get('c')!.y);
    expect(laid.get('e')!.y).toBeGreaterThan(laid.get('d')!.y);
    // out on the left of no-match
    expect(laid.get('c')!.x).toBeLessThan(laid.get('d')!.x);
  });

  it('puts every card one rank pitch below its parent on a chain', () => {
    const laid = new Map(layoutNodes(NODES, EDGES).map((n) => [n.id, n.position]));
    expect(laid.get('b')!.y - laid.get('a')!.y).toBe(PLAYBOOK_CARD.height + PLAYBOOK_LAYOUT_SPACING[1]);
  });

  it('draws the add button of a free port next to that port, never as a step that moves the others', () => {
    const laid = new Map(layoutNodes(NODES, EDGES).map((n) => [n.id, n.position]));
    const withoutButtons = new Map(layoutNodes(NODES.filter((n) => n.type !== 'placeholder'), EDGES.slice(0, 5)).map((n) => [n.id, n.position]));
    ['a', 'b', 'c', 'd', 'e'].forEach((id) => expect(laid.get(id)).toEqual(withoutButtons.get(id)));
    const e = laid.get('e')!;
    expect(laid.get('p1')).toEqual({ x: e.x + PLAYBOOK_CARD.width / 2 - 14, y: e.y + PLAYBOOK_CARD.height + PLAYBOOK_PORT_ADD.gap });
  });

  it('keeps the add button of a free port clear of the line where a neighbour\'s links turn', () => {
    // Links between two ranks turn on the middle line of the gap: a link from a neighbouring step
    // to a card of the next rank must never run through the add button of a free port.
    const laid = new Map(layoutNodes(NODES, EDGES).map((n) => [n.id, n.position]));
    [['p1', 'e'], ['p2', 'a']].forEach(([button, card]) => {
      const middleLine = laid.get(card)!.y + PLAYBOOK_CARD.height + PLAYBOOK_LAYOUT_SPACING[1] / 2;
      expect(laid.get(button)!.y + PLAYBOOK_PORT_ADD.size).toBeLessThanOrEqual(middleLine - 8);
    });
  });

  it('lays the same structure left to right in the horizontal direction', () => {
    const laid = new Map(layoutNodes(NODES, EDGES, 'horizontal').map((n) => [n.id, n.position]));
    expect(laid.get('b')!.x).toBeGreaterThan(laid.get('a')!.x);
    expect(laid.get('e')!.x).toBeGreaterThan(laid.get('c')!.x);
    expect(laid.get('c')!.y).toBeLessThan(laid.get('d')!.y);
  });

  it('lays out nothing for an empty playbook', () => {
    expect(layoutNodes([], [])).toEqual([]);
  });
});

// The 11-step report qualification pipeline of the UX rounds: listen, scrape, qualify (out /
// unmodified), a status match (out / no-match), a failure log, extraction, the status changes and
// the two ingestions. Its fit is unreadable at 1080x800, so it lands on its entry point.
const AI = component('AI', ['out', 'unmodified']);
const PIPELINE = [
  node('listen', LISTEN), node('scrape', LOG), node('qualify', AI), node('status', MATCH), node('failed', LOG),
  node('extract', AI), node('rejected', LOG), node('processed', AI), node('categorize', AI), node('ready', AI),
  node('ingest', LOG),
];
const PIPELINE_LINKS = [
  edge('listen', 'out', 'scrape'), edge('scrape', 'out', 'qualify'), edge('qualify', 'out', 'status'),
  edge('qualify', 'unmodified', 'failed'), edge('status', 'out', 'extract'), edge('status', 'no-match', 'rejected'),
  edge('extract', 'out', 'processed'), edge('extract', 'unmodified', 'processed'), edge('processed', 'out', 'categorize'),
  edge('processed', 'unmodified', 'categorize'), edge('categorize', 'out', 'ready'), edge('categorize', 'unmodified', 'ready'),
  edge('ready', 'out', 'ingest'), edge('ready', 'unmodified', 'ingest'),
];

describe('useLayout playbookLanding', () => {
  const cardsUnderMiniMap = (nodes: Node[], viewport: { x: number; y: number; zoom: number }, pane: { width: number; height: number }) => {
    const box = { left: pane.width - PLAYBOOK_MINIMAP.margin - PLAYBOOK_MINIMAP.width, top: pane.height - PLAYBOOK_MINIMAP.margin - PLAYBOOK_MINIMAP.height };
    return nodes.filter((n) => n.type !== 'placeholder').filter((n) => {
      const left = n.position.x * viewport.zoom + viewport.x;
      const top = n.position.y * viewport.zoom + viewport.y;
      return left + PLAYBOOK_CARD.width * viewport.zoom > box.left && left < pane.width - PLAYBOOK_MINIMAP.margin
        && top + PLAYBOOK_CARD.height * viewport.zoom > box.top && top < pane.height - PLAYBOOK_MINIMAP.margin;
    }).map((n) => n.id);
  };

  [{ width: 1080, height: 800 }, { width: 1440, height: 900 }].forEach((pane) => {
    it(`opens with the horizontal layout remembered at ${pane.width}x${pane.height}: entry centred, minimap only when no card is under it`, () => {
      // On a first open the store still holds the saved (vertical) positions: the landing reads the laid-out ones.
      const saved = PIPELINE.map((n, i) => ({ ...n, position: { x: (i % 2) * 320, y: i * 200 } }));
      const fromSaved = playbookLanding(saved, PIPELINE_LINKS, pane, 'horizontal');
      const fromLaid = playbookLanding(fromSaved.laid, PIPELINE_LINKS, pane, 'horizontal');
      expect(fromSaved.viewport).toEqual(fromLaid.viewport);
      const viewport = fromSaved.viewport!;
      expect(viewport.zoom).toBe(PLAYBOOK_LANDING.minZoom);
      const entry = fromSaved.laid.find((n) => n.id === 'listen')!.position;
      expect(entry.x * viewport.zoom + viewport.x).toBe(PLAYBOOK_LANDING.margin);
      const middle = (entry.y + PLAYBOOK_CARD.height / 2) * viewport.zoom + viewport.y;
      expect(Math.abs(middle - pane.height / 2)).toBeLessThanOrEqual(1);
      // the minimap is drawn only when it hides no card of the landed picture
      expect(fromSaved.miniMapClear(viewport)).toBe(cardsUnderMiniMap(fromSaved.laid, viewport, pane).length === 0);
    });
  });

  it('lands again on the pane as drawn: a taller pane moves the horizontal landing down to its new middle', () => {
    const first = playbookLanding(PIPELINE, PIPELINE_LINKS, { width: 1080, height: 600 }, 'horizontal').viewport!;
    const drawn = playbookLanding(PIPELINE, PIPELINE_LINKS, { width: 1080, height: 800 }, 'horizontal').viewport!;
    expect(drawn.y - first.y).toBe(100);
    expect(drawn.x).toBe(first.x);
  });
});
