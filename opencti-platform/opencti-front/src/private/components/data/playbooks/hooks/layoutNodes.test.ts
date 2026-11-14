import { describe, expect, it } from 'vitest';
import type { Edge, Node } from 'reactflow';
import { layoutNodes } from './layoutNodes';

const node = (id: string): Node => ({ id, position: { x: 0, y: 0 }, data: {} });
const edge = (source: string, target: string): Edge => ({ id: `${source}-${target}`, source, target });

describe('layoutNodes', () => {
  it('returns nothing for an empty playbook', () => {
    expect(layoutNodes([], [])).toEqual([]);
  });

  it('lays out a single tree from its entry node', () => {
    const result = layoutNodes([node('entry'), node('a'), node('b')], [edge('entry', 'a'), edge('entry', 'b')]);
    const byId = Object.fromEntries(result.map((n) => [n.id, n.position]));
    expect(Object.keys(byId).sort()).toEqual(['a', 'b', 'entry']);
    expect(byId.entry.y).toBe(0);
    expect(byId.a.y).toBe(175);
    expect(byId.b.y).toBe(175);
    expect(byId.a.x).not.toBe(byId.b.x);
  });

  it('positions every node when two nodes have no parent, without throwing', () => {
    const nodes = [node('entry'), node('log'), node('orphan')];
    const edges = [edge('entry', 'log')];
    let result: Node[] = [];
    expect(() => {
      result = layoutNodes(nodes, edges);
    }).not.toThrow();
    const byId = Object.fromEntries(result.map((n) => [n.id, n.position]));
    expect(Object.keys(byId).sort()).toEqual(['entry', 'log', 'orphan']);
    expect(byId.entry.y).toBe(0);
    expect(byId.orphan.y).toBe(0);
    expect(byId.log.y).toBe(175);
    expect(byId.entry.x).not.toBe(byId.orphan.x);
  });

  it('treats a link from a node absent from the graph as no parent', () => {
    const result = layoutNodes([node('entry'), node('a')], [edge('ghost', 'a')]);
    expect(result.map((n) => n.id).sort()).toEqual(['a', 'entry']);
  });
});
