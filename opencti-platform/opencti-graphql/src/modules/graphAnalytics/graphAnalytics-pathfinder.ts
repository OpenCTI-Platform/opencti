import type { StixPathRaw, StixPathsSearchResult } from './graphAnalytics-types';

export interface PathEdge {
  relationship_id: string;
  relationship_type: string;
  neighbor_id: string;
  neighbor_type: string;
}

export interface PathExpansion {
  // node id -> edges leaving or entering this node (direction is irrelevant for connectivity)
  edges: Map<string, PathEdge[]>;
  relationshipsCount: number;
  truncated: boolean;
}

export interface PathSearchOptions {
  fromId: string;
  toId: string;
  maxDepth: number;
  maxPaths: number;
  maxExpandedNodes: number;
  maxRelationshipsPerLevel: number;
  maxParentsPerNode: number;
  deadline: number;
  expand: (nodeIds: string[], limit: number) => Promise<PathExpansion>;
  // Returns the subset of candidate intermediate nodes the traversal may go through
  // (access rights of the caller, entity type constraints).
  acceptNodes: (nodes: Array<{ id: string; type: string }>) => Promise<Set<string>>;
  now?: () => number;
}

interface ParentLink {
  parent: string;
  relationship_id: string;
  relationship_type: string;
}

interface SearchSide {
  depth: number;
  frontier: string[];
  levels: Map<string, number>;
  parents: Map<string, ParentLink[]>;
}

const createSide = (root: string): SearchSide => ({
  depth: 0,
  frontier: [root],
  levels: new Map([[root, 0]]),
  parents: new Map(),
});

interface HalfPath {
  nodes: string[]; // from root to the meeting node
  relationships: ParentLink[];
}

// Enumerate the paths from the side root to `node`, following parent links (bounded).
const enumerateHalfPaths = (side: SearchSide, node: string, limit: number): HalfPath[] => {
  const results: HalfPath[] = [];
  const walk = (current: string, nodesAcc: string[], relsAcc: ParentLink[]) => {
    if (results.length >= limit) return;
    const links = side.parents.get(current);
    if (!links || links.length === 0) {
      // reached the root of the side
      results.push({ nodes: [...nodesAcc].reverse(), relationships: [...relsAcc].reverse() });
      return;
    }
    for (let i = 0; i < links.length && results.length < limit; i += 1) {
      const link = links[i];
      if (nodesAcc.includes(link.parent)) continue; // keep simple paths only
      nodesAcc.push(link.parent);
      relsAcc.push(link);
      walk(link.parent, nodesAcc, relsAcc);
      nodesAcc.pop();
      relsAcc.pop();
    }
  };
  walk(node, [node], []);
  return results;
};

const buildPaths = (forward: SearchSide, backward: SearchSide, meetingNodes: string[], maxPaths: number): StixPathRaw[] => {
  const unique = new Map<string, StixPathRaw>();
  const halfLimit = Math.max(maxPaths, 4) * 4;
  for (let m = 0; m < meetingNodes.length; m += 1) {
    const meeting = meetingNodes[m];
    const forwardHalves = enumerateHalfPaths(forward, meeting, halfLimit);
    const backwardHalves = enumerateHalfPaths(backward, meeting, halfLimit);
    for (let f = 0; f < forwardHalves.length; f += 1) {
      for (let b = 0; b < backwardHalves.length; b += 1) {
        const fh = forwardHalves[f];
        const bh = backwardHalves[b];
        // backward half goes toId -> meeting, reverse it to get meeting -> toId
        const tailNodes = [...bh.nodes].reverse().slice(1);
        const nodes = [...fh.nodes, ...tailNodes];
        if (new Set(nodes).size !== nodes.length) continue;
        const relationships = [...fh.relationships, ...[...bh.relationships].reverse()];
        const relationshipIds = relationships.map((r) => r.relationship_id);
        if (new Set(relationshipIds).size !== relationshipIds.length) continue;
        const key = relationshipIds.join('|');
        if (!unique.has(key)) {
          unique.set(key, {
            node_ids: nodes,
            relationship_ids: relationshipIds,
            relationship_types: relationships.map((r) => r.relationship_type),
          });
        }
      }
    }
  }
  return Array.from(unique.values())
    .sort((a, b) => (a.relationship_ids.length - b.relationship_ids.length) || a.relationship_ids.join('|').localeCompare(b.relationship_ids.join('|')))
    .slice(0, maxPaths);
};

/**
 * Bidirectional breadth-first search between two nodes.
 * Levels are expanded completely, always on the smallest frontier, so every shortest path is found first;
 * the search then continues with longer paths until `maxPaths` paths are found or a cap is reached.
 * Each node keeps up to `maxParentsPerNode` parents at its minimal depth, and never fewer than `maxPaths`, which bounds
 * the enumeration without trading a shorter path for a longer one: a node whose parents are left out already leads
 * to `maxPaths` paths of its length. A longer path is only found when each of its nodes is at its minimal depth from
 * one side, so a detour rejoining a node already reached by a shorter route is never returned (not a k shortest
 * simple paths enumeration).
 * The deadline is checked before each level and again before the access check of the nodes a level discovers;
 * `timed_out` is reported whenever it leaves a level of the search unexplored.
 */
export const searchPaths = async (opts: PathSearchOptions): Promise<StixPathsSearchResult> => {
  const now = opts.now ?? (() => Date.now());
  const start = now();
  const maxParentsPerNode = Math.max(opts.maxParentsPerNode, opts.maxPaths);
  const forward = createSide(opts.fromId);
  const backward = createSide(opts.toId);
  let exploredRelationships = 0;
  let truncated = false;
  let timedOut = false;
  const meetingNodes = new Set<string>();
  const endpoints = new Set([opts.fromId, opts.toId]);
  let paths: StixPathRaw[] = [];

  const exploredNodes = () => new Set([...forward.levels.keys(), ...backward.levels.keys()]).size;

  while (forward.depth + backward.depth < opts.maxDepth) {
    if (forward.frontier.length === 0 || backward.frontier.length === 0) break;
    if (now() > opts.deadline) {
      timedOut = true;
      break;
    }
    // once the node cap is reached, levels keep linking the nodes already admitted to the other side, without new ones
    const side = forward.frontier.length <= backward.frontier.length ? forward : backward;
    const other = side === forward ? backward : forward;
    const expansion = await opts.expand(side.frontier, opts.maxRelationshipsPerLevel);
    exploredRelationships += expansion.relationshipsCount;
    if (expansion.truncated) truncated = true;
    const nextDepth = side.depth + 1;
    // collect candidates
    const candidates = new Map<string, string>();
    side.frontier.forEach((nodeId) => {
      (expansion.edges.get(nodeId) ?? []).forEach((edge) => {
        const knownLevel = side.levels.get(edge.neighbor_id);
        if (knownLevel === undefined && !candidates.has(edge.neighbor_id)) {
          candidates.set(edge.neighbor_id, edge.neighbor_type);
        }
      });
    });
    const toCheck = Array.from(candidates.entries())
      .filter(([id]) => !endpoints.has(id) && !other.levels.has(id))
      .map(([id, type]) => ({ id, type }));
    // past the deadline the level still links the nodes already admitted, the new ones would need another access check
    const deadlineReached = toCheck.length > 0 && now() > opts.deadline;
    const accepted = toCheck.length > 0 && !deadlineReached ? await opts.acceptNodes(toCheck) : new Set<string>();
    // the node cap is a hard limit: a level only admits the new nodes that fit, in discovery order
    const budget = Math.max(0, opts.maxExpandedNodes - exploredNodes());
    let admitted = accepted;
    if (accepted.size > budget) {
      admitted = new Set(toCheck.map(({ id }) => id).filter((id) => accepted.has(id)).slice(0, budget));
      truncated = true;
    }
    const isAllowed = (id: string) => endpoints.has(id) || other.levels.has(id) || admitted.has(id);
    // register parents
    const newFrontier = new Set<string>();
    side.frontier.forEach((nodeId) => {
      (expansion.edges.get(nodeId) ?? []).forEach((edge) => {
        const neighbor = edge.neighbor_id;
        if (neighbor === nodeId || !isAllowed(neighbor)) return;
        const knownLevel = side.levels.get(neighbor);
        if (knownLevel !== undefined && knownLevel !== nextDepth) return;
        if (knownLevel === undefined) {
          side.levels.set(neighbor, nextDepth);
          newFrontier.add(neighbor);
        }
        const links = side.parents.get(neighbor) ?? [];
        if (links.length < maxParentsPerNode && !links.some((l) => l.relationship_id === edge.relationship_id)) {
          links.push({ parent: nodeId, relationship_id: edge.relationship_id, relationship_type: edge.relationship_type });
          side.parents.set(neighbor, links);
        }
        if (other.levels.has(neighbor)) meetingNodes.add(neighbor);
      });
    });
    side.depth = nextDepth;
    // never walk further from the opposite endpoint, a path stops when it reaches it
    side.frontier = Array.from(newFrontier).filter((id) => !endpoints.has(id));
    if (meetingNodes.size > 0) {
      paths = buildPaths(forward, backward, Array.from(meetingNodes), opts.maxPaths);
      if (paths.length >= opts.maxPaths) break;
    }
    if (deadlineReached) {
      // the nodes left out can only start longer paths, so the result is complete once the maximum depth is reached
      timedOut = forward.depth + backward.depth < opts.maxDepth;
      break;
    }
  }
  return {
    paths,
    max_depth: opts.maxDepth,
    depth_reached: forward.depth + backward.depth,
    explored_nodes: exploredNodes(),
    explored_relationships: exploredRelationships,
    truncated,
    timed_out: timedOut,
    duration_ms: Math.max(0, Math.round(now() - start)),
  };
};
