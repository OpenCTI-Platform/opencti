import { describe, expect, it } from 'vitest';
import { type PathEdge, type PathExpansion, type PathSearchOptions, searchPaths } from '../../../../src/modules/graphAnalytics/graphAnalytics-pathfinder';

// Undirected in-memory graph: [relationship id, type, from, to]
type Edge = [string, string, string, string];

const buildGraph = (edges: Edge[]) => {
  const adjacency = new Map<string, PathEdge[]>();
  const add = (node: string, edge: PathEdge) => adjacency.set(node, [...(adjacency.get(node) ?? []), edge]);
  edges.forEach(([id, type, from, to]) => {
    add(from, { relationship_id: id, relationship_type: type, neighbor_id: to, neighbor_type: 'Intrusion-Set' });
    add(to, { relationship_id: id, relationship_type: type, neighbor_id: from, neighbor_type: 'Intrusion-Set' });
  });
  let expansions = 0;
  const expand = async (nodeIds: string[], limit: number): Promise<PathExpansion> => {
    expansions += 1;
    const result = new Map<string, PathEdge[]>();
    let count = 0;
    nodeIds.forEach((node) => {
      const nodeEdges = (adjacency.get(node) ?? []).slice(0, Math.max(0, limit - count));
      count += nodeEdges.length;
      result.set(node, nodeEdges);
    });
    return { edges: result, relationshipsCount: count, truncated: false };
  };
  return { expand, expansions: () => expansions };
};

const options = (expand: PathSearchOptions['expand'], overrides: Partial<PathSearchOptions> = {}): PathSearchOptions => ({
  fromId: 'a',
  toId: 'z',
  maxDepth: 4,
  maxPaths: 5,
  maxExpandedNodes: 1000,
  maxRelationshipsPerLevel: 1000,
  maxParentsPerNode: 8,
  deadline: Date.now() + 60000,
  expand,
  acceptNodes: async (nodes) => new Set(nodes.map((n) => n.id)),
  ...overrides,
});

describe('graph analytics path finder', () => {
  it('should find a direct relationship', async () => {
    const { expand } = buildGraph([['r1', 'uses', 'a', 'z']]);
    const result = await searchPaths(options(expand));
    expect(result.paths).toEqual([{ node_ids: ['a', 'z'], relationship_ids: ['r1'], relationship_types: ['uses'] }]);
    expect(result.depth_reached).toBe(1);
    expect(result.truncated).toBe(false);
    expect(result.timed_out).toBe(false);
  });

  it('should find every shortest path first, ordered deterministically', async () => {
    const { expand } = buildGraph([
      ['r1', 'uses', 'a', 'b'],
      ['r2', 'targets', 'b', 'z'],
      ['r3', 'uses', 'a', 'c'],
      ['r4', 'targets', 'c', 'z'],
      ['r5', 'related-to', 'a', 'd'],
      ['r6', 'related-to', 'd', 'e'],
      ['r7', 'related-to', 'e', 'z'],
    ]);
    const result = await searchPaths(options(expand, { maxPaths: 2 }));
    expect(result.paths.map((p) => p.relationship_ids)).toEqual([['r1', 'r2'], ['r3', 'r4']]);
    const longer = await searchPaths(options(expand, { maxPaths: 3 }));
    expect(longer.paths.map((p) => p.relationship_ids)).toEqual([['r1', 'r2'], ['r3', 'r4'], ['r5', 'r6', 'r7']]);
    expect(longer.paths[2].node_ids).toEqual(['a', 'd', 'e', 'z']);
  });

  it('should not return a detour rejoining a node reached by a shorter route', async () => {
    const { expand } = buildGraph([
      ['r1', 'uses', 'a', 'd'],
      ['r2', 'uses', 'd', 'z'],
      ['r3', 'uses', 'a', 'f'],
      ['r4', 'uses', 'f', 'c'],
      ['r5', 'uses', 'c', 'z'],
      ['r6', 'uses', 'c', 'd'],
    ]);
    const result = await searchPaths(options(expand, { maxPaths: 10 }));
    // a-f-c-d-z is a simple path of length 4, but c and d are both at their minimal depth on another route
    expect(result.paths.map((p) => p.node_ids)).toEqual([['a', 'd', 'z'], ['a', 'd', 'c', 'z'], ['a', 'f', 'c', 'z']]);
  });

  it('should not return a longer path while the parent cap leaves shortest paths out', async () => {
    const edges: Edge[] = [['r-ab', 'uses', 'a', 'b'], ['r-bc', 'uses', 'b', 'c'], ['r-ce', 'uses', 'c', 'e'], ['r-ez', 'uses', 'e', 'z'], ['r-xz', 'uses', 'x', 'z']];
    for (let i = 1; i <= 9; i += 1) {
      edges.push([`r-ap${i}`, 'uses', 'a', `p${i}`], [`r-px${i}`, 'uses', `p${i}`, 'x']);
    }
    // the dead ends around z make the side of a reach x from its nine parents
    for (let i = 1; i <= 20; i += 1) {
      edges.push([`r-zd${i}`, 'related-to', 'z', `d${i}`]);
    }
    const { expand } = buildGraph(edges);
    const result = await searchPaths(options(expand, { maxPaths: 5, maxParentsPerNode: 2 }));
    // nine shortest paths go through x: five of them are returned, never a-b-c-e-z
    expect(result.paths.map((p) => p.node_ids)).toEqual([1, 2, 3, 4, 5].map((i) => ['a', `p${i}`, 'x', 'z']));
  });

  it('should respect the maximum depth', async () => {
    const { expand } = buildGraph([
      ['r1', 'uses', 'a', 'b'],
      ['r2', 'uses', 'b', 'c'],
      ['r3', 'uses', 'c', 'z'],
    ]);
    expect((await searchPaths(options(expand, { maxDepth: 2 }))).paths).toEqual([]);
    expect((await searchPaths(options(expand, { maxDepth: 3 }))).paths).toHaveLength(1);
  });

  it('should never traverse a node rejected by the access check', async () => {
    const { expand } = buildGraph([
      ['r1', 'uses', 'a', 'secret'],
      ['r2', 'uses', 'secret', 'z'],
      ['r3', 'uses', 'a', 'b'],
      ['r4', 'uses', 'b', 'c'],
      ['r5', 'uses', 'c', 'z'],
    ]);
    const acceptNodes = async (nodes: Array<{ id: string }>) => new Set(nodes.map((n) => n.id).filter((id) => id !== 'secret'));
    const result = await searchPaths(options(expand, { acceptNodes }));
    expect(result.paths.map((p) => p.node_ids)).toEqual([['a', 'b', 'c', 'z']]);
    expect(result.paths.flatMap((p) => p.node_ids)).not.toContain('secret');
  });

  it('should keep only simple paths', async () => {
    const { expand } = buildGraph([
      ['r1', 'uses', 'a', 'b'],
      ['r2', 'uses', 'b', 'a'],
      ['r3', 'uses', 'b', 'z'],
    ]);
    const result = await searchPaths(options(expand));
    result.paths.forEach((path) => expect(new Set(path.node_ids).size).toBe(path.node_ids.length));
    expect(result.paths.map((p) => p.relationship_ids)).toEqual([['r1', 'r3'], ['r2', 'r3']]);
  });

  it('should report a truncated search when the node cap is reached', async () => {
    const edges: Edge[] = [];
    for (let i = 0; i < 50; i += 1) edges.push([`r${i}`, 'uses', 'a', `n${i}`]);
    const { expand } = buildGraph(edges);
    const result = await searchPaths(options(expand, { maxExpandedNodes: 10 }));
    expect(result.paths).toEqual([]);
    expect(result.truncated).toBe(true);
    // a hard cap: the level that reaches it only admits the nodes that fit
    expect(result.explored_nodes).toBeLessThanOrEqual(10);
  });

  it('should still find the paths through the nodes admitted before the cap', async () => {
    const edges: Edge[] = [['r0', 'uses', 'a', 'b'], ['r1', 'uses', 'b', 'z']];
    for (let i = 0; i < 20; i += 1) edges.push([`x${i}`, 'uses', 'a', `n${i}`]);
    const { expand } = buildGraph(edges);
    const result = await searchPaths(options(expand, { maxExpandedNodes: 4 }));
    expect(result.explored_nodes).toBeLessThanOrEqual(4);
    expect(result.truncated).toBe(true);
    expect(result.paths.map((p) => p.node_ids)).toEqual([['a', 'b', 'z']]);
  });

  it('should stop on the deadline', async () => {
    const { expand } = buildGraph([['r1', 'uses', 'a', 'b'], ['r2', 'uses', 'b', 'z']]);
    let clock = 0;
    const result = await searchPaths(options(expand, {
      deadline: 5,
      now: () => {
        clock += 10;
        return clock;
      },
    }));
    expect(result.timed_out).toBe(true);
    expect(result.paths).toEqual([]);
  });

  it('should report a timeout when the deadline passes during the expansion of a level', async () => {
    const graph = buildGraph([['r1', 'uses', 'a', 'b'], ['r2', 'uses', 'b', 'c'], ['r3', 'uses', 'c', 'z']]);
    let clock = 0;
    let accessChecks = 0;
    const result = await searchPaths(options(async (nodeIds, limit) => {
      const expansion = await graph.expand(nodeIds, limit);
      if (graph.expansions() === 2) clock = 100;
      return expansion;
    }, {
      deadline: 50,
      now: () => clock,
      acceptNodes: async (nodes) => {
        accessChecks += 1;
        return new Set(nodes.map((n) => n.id));
      },
    }));
    expect(result.timed_out).toBe(true);
    expect(result.paths).toEqual([]);
    // the nodes discovered after the deadline are not checked nor traversed
    expect(accessChecks).toBe(1);
    expect(result.explored_nodes).toBe(3);
  });

  it('should keep the paths a late level closes without new nodes to check', async () => {
    const graph = buildGraph([['r1', 'uses', 'a', 'b'], ['r2', 'uses', 'b', 'z']]);
    let clock = 0;
    const result = await searchPaths(options(async (nodeIds, limit) => {
      const expansion = await graph.expand(nodeIds, limit);
      if (graph.expansions() === 2) clock = 100;
      return expansion;
    }, { deadline: 50, now: () => clock }));
    expect(result.paths.map((p) => p.node_ids)).toEqual([['a', 'b', 'z']]);
    expect(result.timed_out).toBe(false);
  });

  it('should not report a timeout when the last level ends after the deadline', async () => {
    const graph = buildGraph([['r1', 'uses', 'a', 'b'], ['r2', 'uses', 'b', 'c'], ['r3', 'uses', 'c', 'd']]);
    let clock = 0;
    const result = await searchPaths(options(async (nodeIds, limit) => {
      const expansion = await graph.expand(nodeIds, limit);
      if (graph.expansions() === 2) clock = 100;
      return expansion;
    }, { maxDepth: 2, deadline: 50, now: () => clock }));
    expect(result.paths).toEqual([]);
    expect(result.depth_reached).toBe(2);
    expect(result.timed_out).toBe(false);
  });

  it('should expand the smallest frontier first', async () => {
    const edges: Edge[] = [['r0', 'uses', 'a', 'b']];
    for (let i = 0; i < 20; i += 1) edges.push([`h${i}`, 'uses', 'z', `x${i}`]);
    edges.push(['r1', 'uses', 'b', 'z']);
    const graph = buildGraph(edges);
    const result = await searchPaths(options(graph.expand));
    expect(result.paths.map((p) => p.relationship_ids)).toEqual([['r0', 'r1']]);
    expect(graph.expansions()).toBe(2);
  });
});
