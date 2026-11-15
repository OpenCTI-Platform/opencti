import { describe, expect, it } from 'vitest';
import { Position } from 'reactflow';
import { playbookEdgePath, PLAYBOOK_STRAIGHT_TOLERANCE } from './playbookEdgePath';
import { layoutPlaybook } from '../../layout/layoutPlaybook';
import type { PlaybookLayoutComponent, PlaybookLayoutLink, PlaybookLayoutNode } from '../../layout/layoutPlaybook';
import { PLAYBOOK_CARD, portAnchor } from '../nodes/playbookNodeGeometry';

// Every number written in a path, to check it is a whole pixel.
const coordinates = (path: string) => (path.match(/-?\d+(\.\d+)?/g) ?? []).map(Number);

describe('playbookEdgePath', () => {
  it('draws aligned ends as one straight segment, whatever the sub-pixel offset', () => {
    [0, 0.4, 1, 2.6, PLAYBOOK_STRAIGHT_TOLERANCE].forEach((offset) => {
      const edge = playbookEdgePath({ sourceX: 132 + offset, sourceY: 104.3, targetX: 132, targetY: 248, sourcePosition: Position.Bottom });
      expect(edge.bends).toBe(0);
      expect(edge.path).toBe('M132,104 L132,248');
    });
  });

  it('draws straight horizontal links in the horizontal layout', () => {
    const edge = playbookEdgePath({ sourceX: 264, sourceY: 52.5, targetX: 400, targetY: 51, sourcePosition: Position.Right });
    expect(edge.bends).toBe(0);
    expect(edge.path).toBe('M264,51 L400,51');
  });

  it('turns twice with rounded corners on a real offset, on whole pixels', () => {
    const edge = playbookEdgePath({ sourceX: 100.4, sourceY: 104.6, targetX: 300.2, targetY: 248.1, sourcePosition: Position.Bottom });
    expect(edge.bends).toBe(2);
    expect(edge.path.startsWith('M100,105')).toBe(true);
    expect(edge.path.endsWith('L300,248')).toBe(true);
    coordinates(edge.path).forEach((value) => expect(Number.isInteger(value)).toBe(true));
    expect(edge.labelY).toBe(Math.round((105 + 248) / 2));
  });

  it('joins two ports of one step into the same target as one merge, never as crossing links', () => {
    // out and unmodified of an AI step (anchors at a third and two thirds of the card) both go to the
    // next step: the two links meet on the middle line and share the last straight segment.
    const ends = { sourceY: PLAYBOOK_CARD.height, targetX: 132, targetY: 248, sourcePosition: Position.Bottom };
    const out = playbookEdgePath({ ...ends, sourceX: portAnchor(0, 2, 'vertical').x });
    const unmodified = playbookEdgePath({ ...ends, sourceX: portAnchor(1, 2, 'vertical').x });
    const trunk = 'Q132,176 132,188 L132,248';
    expect(out.path.endsWith(trunk)).toBe(true);
    expect(unmodified.path.endsWith(trunk)).toBe(true);
    // Each link keeps its own side until the merge point: the two never cross.
    expect(out.path).toContain('L120,176');
    expect(unmodified.path).toContain('L144,176');
    // Their insert buttons stay apart, one on each side of the merge.
    expect(out.labelX).toBeLessThan(132);
    expect(unmodified.labelX).toBeGreaterThan(132);
  });

  it('caps the corner radius when the bend has little room', () => {
    const edge = playbookEdgePath({ sourceX: 0, sourceY: 0, targetX: 10, targetY: 200, sourcePosition: Position.Bottom });
    // 10 px across: 5 px radius at most, the path never goes back on itself.
    expect(edge.path).toContain('Q0,100 5,100');
    expect(edge.path).toContain('Q10,100 10,105');
  });
});

// The report pipeline of the issue screenshots: no link of a single-parent chain may jog.
const COMPONENTS: PlaybookLayoutComponent[] = [
  { id: 'LISTEN', is_entry_point: true, ports: [{ id: 'out', type: 'out' }] },
  { id: 'ENRICH', ports: [{ id: 'in', type: 'in' }, { id: 'out', type: 'out' }] },
  { id: 'AI', ports: [{ id: 'in', type: 'in' }, { id: 'out', type: 'out' }, { id: 'unmodified', type: 'out' }] },
  { id: 'MATCH', ports: [{ id: 'in', type: 'in' }, { id: 'out', type: 'out' }, { id: 'no-match', type: 'out' }] },
  { id: 'LOG', ports: [{ id: 'in', type: 'in' }, { id: 'out', type: 'out' }] },
  { id: 'INGEST', ports: [{ id: 'in', type: 'in' }] },
];
const node = (id: string, component_id: string): PlaybookLayoutNode => ({ id, component_id, position: { x: 0, y: 0 } });
const link = (from: string, port: string, to: string): PlaybookLayoutLink => ({ id: `${from}:${port}->${to}`, from: { id: from, port }, to: { id: to } });

describe('layoutPlaybook and the link paths together', () => {
  const nodes = [node('a', 'LISTEN'), node('b', 'ENRICH'), node('c', 'ENRICH'), node('d', 'MATCH'), node('e', 'LOG'), node('f', 'INGEST')];
  const links = [link('a', 'out', 'b'), link('b', 'out', 'c'), link('c', 'out', 'd'), link('d', 'out', 'e'), link('e', 'out', 'f')];
  const result = layoutPlaybook(nodes, links, COMPONENTS, { mode: 'vertical', nodeSize: PLAYBOOK_CARD });
  const ports = new Map(COMPONENTS.map((c) => [c.id, (c.ports ?? []).flatMap((p) => (p && p.type === 'out' ? [p.id] : []))]));
  const componentOf = new Map(nodes.map((n) => [n.id, n.component_id]));

  it('places every card on whole pixels', () => {
    result.positions.forEach((p) => {
      expect(Number.isInteger(p.x)).toBe(true);
      expect(Number.isInteger(p.y)).toBe(true);
    });
  });

  it('draws every single-port link of a single-parent chain without a jog', () => {
    links.filter((l) => ports.get(componentOf.get(l.from.id)!)!.length === 1).forEach((l) => {
      const from = result.positions.get(l.from.id)!;
      const to = result.positions.get(l.to.id)!;
      const outs = ports.get(componentOf.get(l.from.id)!)!;
      const anchor = portAnchor(outs.indexOf(l.from.port), outs.length, 'vertical');
      const edge = playbookEdgePath({
        sourceX: from.x + anchor.x,
        sourceY: from.y + anchor.y,
        targetX: to.x + PLAYBOOK_CARD.width / 2,
        targetY: to.y,
        sourcePosition: Position.Bottom,
      });
      expect(edge.bends).toBe(0);
    });
  });
});
