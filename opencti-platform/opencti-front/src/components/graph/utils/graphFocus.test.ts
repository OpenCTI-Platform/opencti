import { describe, expect, it } from 'vitest';
import { isPathDrawable, neighbourhood, relationshipCounts, shortestPath } from './graphFocus';

const links = [
  { id: 'ab', sourceId: 'a', targetId: 'b', relationship_type: 'uses' },
  { id: 'bc', sourceId: 'b', targetId: 'c', relationship_type: 'uses' },
  { id: 'cd', sourceId: 'c', targetId: 'd', relationship_type: 'targets' },
  { id: 'ad', sourceId: 'd', targetId: 'a', relationship_type: 'targets' },
  { id: 'ef', sourceId: 'e', targetId: 'f', relationship_type: 'related-to' },
];

describe('neighbourhood', () => {
  it('keeps the centre, its direct neighbours and the links joining them', () => {
    const focus = neighbourhood(links, ['a']);
    expect([...focus.nodeIds].sort()).toEqual(['a', 'b', 'd']);
    expect([...focus.linkIds].sort()).toEqual(['ab', 'ad']);
  });

  it('is empty around nothing', () => {
    const focus = neighbourhood(links, []);
    expect(focus.nodeIds.size).toBe(0);
    expect(focus.linkIds.size).toBe(0);
  });
});

describe('shortestPath', () => {
  it('finds the path with the fewest links, whatever their direction', () => {
    expect(shortestPath(links, 'a', 'd')).toEqual({ nodeIds: ['a', 'd'], linkIds: ['ad'] });
    expect(shortestPath(links, 'b', 'd')?.nodeIds).toHaveLength(3);
  });

  it('breaks ties the same way every time', () => {
    const first = shortestPath(links, 'b', 'd');
    const second = shortestPath([...links].reverse(), 'b', 'd');
    expect(second).toEqual(first);
  });

  it('gives null between disconnected nodes and a trivial path to itself', () => {
    expect(shortestPath(links, 'a', 'e')).toBeNull();
    expect(shortestPath(links, 'a', 'a')).toEqual({ nodeIds: ['a'], linkIds: [] });
  });
});

describe('isPathDrawable', () => {
  const path = { nodeIds: ['a', 'b', 'c'], linkIds: ['ab', 'bc'] };
  const nodes = ['a', 'b', 'c'].map((id) => ({ id, disabled: false }));
  const drawnLinks = ['ab', 'bc'].map((id) => ({ id, disabled: false }));

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
