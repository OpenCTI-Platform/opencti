import { type LinkEnds, linkEndsKey } from './graphGeometry';

/** Links are named by `linkEndsKey`: the two connector links of a nested relationship share its id. */
export interface GraphFocus {
  nodeIds: ReadonlySet<string>;
  linkKeys: ReadonlySet<string>;
}

export interface GraphPath {
  nodeIds: string[];
  linkKeys: string[];
  /** For the shortest paths between two nodes: how many there are, and their number of hops. */
  count?: number;
  hops?: number;
}

const adjacency = (links: readonly LinkEnds[]) => {
  const byNode = new Map<string, LinkEnds[]>();
  const push = (nodeId: string, link: LinkEnds) => {
    const list = byNode.get(nodeId);
    if (list) list.push(link);
    else byNode.set(nodeId, [link]);
  };
  links.forEach((link) => {
    push(link.sourceId, link);
    if (link.targetId !== link.sourceId) push(link.targetId, link);
  });
  return byNode;
};

/**
 * The given nodes, every node one link away from them and the links joining them: what stays at
 * full strength when the reader focuses on a part of the graph.
 */
export const neighbourhood = (links: readonly LinkEnds[], centreIds: Iterable<string>): GraphFocus => {
  const nodeIds = new Set<string>(centreIds);
  const linkKeys = new Set<string>();
  const centres = new Set(nodeIds);
  links.forEach((link) => {
    if (centres.has(link.sourceId) || centres.has(link.targetId)) {
      linkKeys.add(linkEndsKey(link));
      nodeIds.add(link.sourceId);
      nodeIds.add(link.targetId);
    }
  });
  return { nodeIds, linkKeys };
};

/**
 * The shortest path between two nodes over the links drawn, whatever their direction, found
 * breadth-first so that it has the fewest hops. Ties are broken by link key, which makes the
 * answer the same at every call. `null` when the two nodes are not connected.
 */
export const shortestPath = (links: readonly LinkEnds[], fromId: string, toId: string): GraphPath | null => {
  if (fromId === toId) return { nodeIds: [fromId], linkKeys: [] };
  const byNode = adjacency(links);
  byNode.forEach((list) => list.sort((a, b) => linkEndsKey(a).localeCompare(linkEndsKey(b))));
  const previous = new Map<string, { nodeId: string; linkKey: string }>();
  const visited = new Set([fromId]);
  let frontier = [fromId];
  while (frontier.length > 0 && !visited.has(toId)) {
    const next: string[] = [];
    frontier.forEach((nodeId) => {
      (byNode.get(nodeId) ?? []).forEach((link) => {
        const other = link.sourceId === nodeId ? link.targetId : link.sourceId;
        if (!visited.has(other)) {
          visited.add(other);
          previous.set(other, { nodeId, linkKey: linkEndsKey(link) });
          next.push(other);
        }
      });
    });
    frontier = next;
  }
  if (!visited.has(toId)) return null;
  const nodeIds = [toId];
  const linkKeys: string[] = [];
  let cursor = toId;
  while (cursor !== fromId) {
    const step = previous.get(cursor);
    if (!step) return null;
    linkKeys.unshift(step.linkKey);
    nodeIds.unshift(step.nodeId);
    cursor = step.nodeId;
  }
  return { nodeIds, linkKeys };
};

const distancesFrom = (byNode: Map<string, LinkEnds[]>, startId: string) => {
  const distance = new Map<string, number>([[startId, 0]]);
  let frontier = [startId];
  while (frontier.length > 0) {
    const next: string[] = [];
    frontier.forEach((nodeId) => {
      (byNode.get(nodeId) ?? []).forEach((link) => {
        const other = link.sourceId === nodeId ? link.targetId : link.sourceId;
        if (!distance.has(other)) {
          distance.set(other, (distance.get(nodeId) ?? 0) + 1);
          next.push(other);
        }
      });
    });
    frontier = next;
  }
  return distance;
};

/**
 * Every shortest path between two nodes over the links drawn, whatever their direction: the nodes
 * and links on at least one of them, nodes ordered by their distance from `fromId`, with how many
 * such paths there are (two links between the same nodes make two paths) and their number of hops.
 * `null` when the two nodes are not connected.
 */
export const shortestPaths = (links: readonly LinkEnds[], fromId: string, toId: string): (GraphPath & { count: number; hops: number }) | null => {
  if (fromId === toId) return { nodeIds: [fromId], linkKeys: [], count: 1, hops: 0 };
  const byNode = adjacency(links);
  const fromDistance = distancesFrom(byNode, fromId);
  const hops = fromDistance.get(toId);
  if (hops === undefined) return null;
  const toDistance = distancesFrom(byNode, toId);
  const near = (id: string) => fromDistance.get(id) ?? Infinity;
  const onPath = (id: string) => near(id) + (toDistance.get(id) ?? Infinity) === hops;
  const nodeIds = [...fromDistance.keys()].filter(onPath).sort((a, b) => near(a) - near(b) || a.localeCompare(b));
  // The links from one layer of the paths to the next, layer by layer from the start: each adds the
  // ways of reaching its near end to its far end.
  const steps = links
    .map((link) => (near(link.sourceId) <= near(link.targetId)
      ? { link, from: link.sourceId, to: link.targetId }
      : { link, from: link.targetId, to: link.sourceId }))
    .filter(({ from, to }) => onPath(from) && onPath(to) && near(to) === near(from) + 1)
    .sort((a, b) => near(a.from) - near(b.from) || linkEndsKey(a.link).localeCompare(linkEndsKey(b.link)));
  const ways = new Map<string, number>([[fromId, 1]]);
  steps.forEach(({ from, to }) => ways.set(to, (ways.get(to) ?? 0) + (ways.get(from) ?? 0)));
  return { nodeIds, linkKeys: steps.map(({ link }) => linkEndsKey(link)), count: ways.get(toId) ?? 0, hops };
};

/**
 * Whether the reader can still follow a path: each of its nodes and links is among those drawn
 * and none is faded by a filter.
 */
export const isPathDrawable = (
  path: GraphPath,
  nodes: readonly { id: string; disabled?: boolean }[],
  links: readonly (LinkEnds & { disabled?: boolean })[],
): boolean => {
  const nodeIds = new Set(nodes.filter((node) => !node.disabled).map((node) => node.id));
  const linkKeys = new Set(links.filter((link) => !link.disabled).map(linkEndsKey));
  return path.nodeIds.every((id) => nodeIds.has(id)) && path.linkKeys.every((key) => linkKeys.has(key));
};

/**
 * Number of relationships of each type touching a node, sorted by count then name: the
 * neighbourhood summary of the hover card. A link drawn towards a group counts every relationship
 * it stands for.
 */
export const relationshipCounts = <L extends LinkEnds & { relationship_type?: string; entity_type?: string; represents?: number }>(
  links: readonly L[],
  nodeId: string,
): { type: string; count: number }[] => {
  const counts = new Map<string, number>();
  links.forEach((link) => {
    if (link.sourceId !== nodeId && link.targetId !== nodeId) return;
    const type = link.relationship_type || link.entity_type || '';
    counts.set(type, (counts.get(type) ?? 0) + (link.represents ?? 1));
  });
  return [...counts.entries()]
    .map(([type, count]) => ({ type, count }))
    .sort((a, b) => b.count - a.count || a.type.localeCompare(b.type));
};
