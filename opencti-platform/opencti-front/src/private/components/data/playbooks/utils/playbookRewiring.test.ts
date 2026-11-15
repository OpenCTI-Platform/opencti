import { describe, expect, it } from 'vitest';
import type { Edge, Node } from 'reactflow';
import { applyRewire, planConnect, planEdgeUpdate, reaches, toDefinitionLinks } from './playbookRewiring';

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
const edge = (id: string, source: string, sourceHandle: string, target: string, type = 'workflow'): Edge => ({ id, type, source, sourceHandle, target });

// a(LISTEN) -> b(MATCH); b.out -> c; b.no-match -> d; c -> e; d -> e (e has two parents)
const NODES = [node('a', LISTEN), node('b', MATCH), node('c', LOG), node('d', LOG), node('e', LOG), placeholder('p1')];
const EDGES = [
  edge('l1', 'a', 'out', 'b'),
  edge('l2', 'b', 'out', 'c'),
  edge('l3', 'b', 'no-match', 'd'),
  edge('l4', 'c', 'out', 'e'),
  edge('l5', 'd', 'out', 'e'),
  edge('lp', 'e', 'out', 'p1', 'placeholder'),
];

describe('playbook rewiring plan', () => {
  it('keeps the links between steps only, never the add buttons', () => {
    expect(toDefinitionLinks(NODES, EDGES).map((l) => l.id)).toEqual(['l1', 'l2', 'l3', 'l4', 'l5']);
  });

  it('follows the links to tell reachability', () => {
    const links = toDefinitionLinks(NODES, EDGES);
    expect(reaches(links, 'a', 'e')).toBe(true);
    expect(reaches(links, 'e', 'a')).toBe(false);
  });

  it('moves a step under another out port with one playbookMoveNode', () => {
    expect(planConnect(NODES, EDGES, { source: 'b', sourceHandle: 'no-match', target: 'c', targetHandle: null }))
      .toEqual({ kind: 'move', nodeId: 'c', parentNodeId: 'b', parentPortId: 'no-match' });
  });

  it('refuses a connection that makes a step its own ancestor, targets the entry point or leaves a non out port', () => {
    expect(planConnect(NODES, EDGES, { source: 'e', sourceHandle: 'out', target: 'b', targetHandle: null })).toBeNull();
    expect(planConnect(NODES, EDGES, { source: 'b', sourceHandle: 'out', target: 'a', targetHandle: null })).toBeNull();
    expect(planConnect(NODES, EDGES, { source: 'b', sourceHandle: 'in', target: 'c', targetHandle: null })).toBeNull();
    expect(planConnect(NODES, EDGES, { source: 'b', sourceHandle: 'out', target: 'p1', targetHandle: null })).toBeNull();
  });

  it('does nothing when the step already has that single parent', () => {
    expect(planConnect(NODES, EDGES, { source: 'b', sourceHandle: 'out', target: 'c', targetHandle: null })).toBeNull();
  });

  it('re-points a link end with one playbookRelink when the former target keeps a parent', () => {
    expect(planEdgeUpdate(NODES, EDGES, EDGES[4], { source: 'd', sourceHandle: 'out', target: 'c', targetHandle: null }))
      .toEqual({ kind: 'relink', linkId: 'l5', toNodeId: 'c' });
  });

  it('re-points the source port of a link', () => {
    expect(planEdgeUpdate(NODES, EDGES, EDGES[1], { source: 'b', sourceHandle: 'no-match', target: 'c', targetHandle: null }))
      .toEqual({ kind: 'relink', linkId: 'l2', toNodeId: 'c', fromNodeId: 'b', fromPortId: 'no-match' });
  });

  it('refuses a relink that leaves its former target without a parent', () => {
    expect(planEdgeUpdate(NODES, EDGES, EDGES[1], { source: 'b', sourceHandle: 'out', target: 'd', targetHandle: null })).toBeNull();
  });

  it('applies the server answer to the links', () => {
    const links = toDefinitionLinks(NODES, EDGES);
    const moved = applyRewire(links, { kind: 'move', nodeId: 'e', parentNodeId: 'b', parentPortId: 'out' }, 'new');
    expect(moved.filter((l) => l.to.id === 'e')).toEqual([{ id: 'new', from: { id: 'b', port: 'out' }, to: { id: 'e' } }]);
    const relinked = applyRewire(links, { kind: 'relink', linkId: 'l2', toNodeId: 'c', fromNodeId: 'b', fromPortId: 'no-match' }, 'l2');
    expect(relinked.find((l) => l.id === 'l2')).toEqual({ id: 'l2', from: { id: 'b', port: 'no-match' }, to: { id: 'c' } });
  });
});
