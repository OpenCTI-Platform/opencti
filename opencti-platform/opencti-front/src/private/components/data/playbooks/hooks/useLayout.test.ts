import { describe, expect, it } from 'vitest';
import type { Edge, Node } from 'reactflow';
import { layoutNodes } from './useLayout';
import { PLAYBOOK_CARD } from '../types/nodes/playbookNodeGeometry';

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
    expect(laid.get('b')!.y - laid.get('a')!.y).toBe(PLAYBOOK_CARD.height + 88);
  });

  it('draws the add button of a free port next to that port, never as a step that moves the others', () => {
    const laid = new Map(layoutNodes(NODES, EDGES).map((n) => [n.id, n.position]));
    const withoutButtons = new Map(layoutNodes(NODES.filter((n) => n.type !== 'placeholder'), EDGES.slice(0, 5)).map((n) => [n.id, n.position]));
    ['a', 'b', 'c', 'd', 'e'].forEach((id) => expect(laid.get(id)).toEqual(withoutButtons.get(id)));
    const e = laid.get('e')!;
    expect(laid.get('p1')).toEqual({ x: e.x + PLAYBOOK_CARD.width / 2 - 14, y: e.y + PLAYBOOK_CARD.height + 36 });
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
