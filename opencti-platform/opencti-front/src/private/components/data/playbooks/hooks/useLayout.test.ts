import { describe, expect, it } from 'vitest';
import type { Edge, Node } from 'reactflow';
import { layoutNodes } from './useLayout';

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

  it('keeps the 250 x 175 pitch of the previous layout on a chain', () => {
    const laid = new Map(layoutNodes(NODES, EDGES).map((n) => [n.id, n.position]));
    expect(laid.get('b')!.y - laid.get('a')!.y).toBe(175);
  });

  it('lays out nothing for an empty playbook', () => {
    expect(layoutNodes([], [])).toEqual([]);
  });
});
