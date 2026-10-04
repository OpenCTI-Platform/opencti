import { describe, expect, it } from 'vitest';
import { isPathDrawable, neighbourhood, relationshipCounts, shortestPath } from './graphFocus';
import { linkEndsKey } from './graphGeometry';

const links = [
  { id: 'ab', sourceId: 'a', targetId: 'b', relationship_type: 'uses' },
  { id: 'bc', sourceId: 'b', targetId: 'c', relationship_type: 'uses' },
  { id: 'cd', sourceId: 'c', targetId: 'd', relationship_type: 'targets' },
  { id: 'ad', sourceId: 'd', targetId: 'a', relationship_type: 'targets' },
  { id: 'ef', sourceId: 'e', targetId: 'f', relationship_type: 'related-to' },
];
const key = (id: string, sourceId: string, targetId: string) => linkEndsKey({ id, sourceId, targetId });
// A nested relationship `rel` drawn as the node `r` between two connector links sharing its id.
const nested = [
  { id: 'rel', sourceId: 'x', targetId: 'r' },
  { id: 'rel', sourceId: 'r', targetId: 'y' },
  { id: 'zx', sourceId: 'z', targetId: 'x' },
];

describe('neighbourhood', () => {
  it('keeps the centre, its direct neighbours and the links joining them', () => {
    const focus = neighbourhood(links, ['a']);
    expect([...focus.nodeIds].sort()).toEqual(['a', 'b', 'd']);
    expect([...focus.linkKeys].sort()).toEqual([key('ab', 'a', 'b'), key('ad', 'd', 'a')]);
  });

  it('keeps only the connector of a nested relationship that touches the centre', () => {
    expect([...neighbourhood(nested, ['y']).linkKeys]).toEqual([key('rel', 'r', 'y')]);
  });

  it('is empty around nothing', () => {
    const focus = neighbourhood(links, []);
    expect(focus.nodeIds.size).toBe(0);
    expect(focus.linkKeys.size).toBe(0);
  });
});

describe('shortestPath', () => {
  it('finds the path with the fewest links, whatever their direction', () => {
    expect(shortestPath(links, 'a', 'd')).toEqual({ nodeIds: ['a', 'd'], linkKeys: [key('ad', 'd', 'a')] });
    expect(shortestPath(links, 'b', 'd')?.nodeIds).toHaveLength(3);
  });

  it('names each connector of a nested relationship on its way', () => {
    expect(shortestPath(nested, 'z', 'y')?.linkKeys).toEqual([key('zx', 'z', 'x'), key('rel', 'x', 'r'), key('rel', 'r', 'y')]);
  });

  it('breaks ties the same way every time', () => {
    const first = shortestPath(links, 'b', 'd');
    const second = shortestPath([...links].reverse(), 'b', 'd');
    expect(second).toEqual(first);
  });

  it('gives null between disconnected nodes and a trivial path to itself', () => {
    expect(shortestPath(links, 'a', 'e')).toBeNull();
    expect(shortestPath(links, 'a', 'a')).toEqual({ nodeIds: ['a'], linkKeys: [] });
  });
});

describe('isPathDrawable', () => {
  const path = { nodeIds: ['a', 'b', 'c'], linkKeys: [key('ab', 'a', 'b'), key('bc', 'b', 'c')] };
  const nodes = ['a', 'b', 'c'].map((id) => ({ id, disabled: false }));
  const drawnLinks = links.slice(0, 2).map((link) => ({ ...link, disabled: false }));

  it('accepts a path whose nodes and links are all drawn', () => {
    expect(isPathDrawable(path, nodes, drawnLinks)).toBe(true);
  });

  it('rejects a path with a faded node or link', () => {
    expect(isPathDrawable(path, nodes.map((n) => ({ ...n, disabled: n.id === 'b' })), drawnLinks)).toBe(false);
    expect(isPathDrawable(path, nodes, drawnLinks.map((l) => ({ ...l, disabled: l.id === 'bc' })))).toBe(false);
  });

  it('rejects a path with a node or link no longer drawn', () => {
    expect(isPathDrawable(path, nodes.filter((n) => n.id !== 'c'), drawnLinks)).toBe(false);
    expect(isPathDrawable(path, nodes, drawnLinks.slice(0, 1))).toBe(false);
  });
});

describe('relationshipCounts', () => {
  it('counts the relationship types touching a node, most frequent first', () => {
    expect(relationshipCounts(links, 'a')).toEqual([{ type: 'targets', count: 1 }, { type: 'uses', count: 1 }]);
    expect(relationshipCounts(links, 'z')).toEqual([]);
  });
});
