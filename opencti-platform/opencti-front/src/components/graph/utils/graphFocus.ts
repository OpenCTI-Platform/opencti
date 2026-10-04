import { type LinkEnds, linkEndsKey } from './graphGeometry';

/** Links are named by `linkEndsKey`: the two connector links of a nested relationship share its id. */
export interface GraphFocus {
  nodeIds: ReadonlySet<string>;
  linkKeys: ReadonlySet<string>;
}

export interface GraphPath {
  nodeIds: string[];
  linkKeys: string[];
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
