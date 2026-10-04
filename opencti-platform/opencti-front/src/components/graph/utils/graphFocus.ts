import type { LinkEnds } from './graphGeometry';

export interface GraphFocus {
  nodeIds: ReadonlySet<string>;
  linkIds: ReadonlySet<string>;
}

export interface GraphPath {
  nodeIds: string[];
  linkIds: string[];
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
  const linkIds = new Set<string>();
  const centres = new Set(nodeIds);
  links.forEach((link) => {
    if (centres.has(link.sourceId) || centres.has(link.targetId)) {
      linkIds.add(link.id);
      nodeIds.add(link.sourceId);
      nodeIds.add(link.targetId);
    }
  });
  return { nodeIds, linkIds };
};

/**
 * The shortest path between two nodes over the links drawn, whatever their direction, found
 * breadth-first so that it has the fewest hops. Ties are broken by link id, which makes the
 * answer the same at every call. `null` when the two nodes are not connected.
 */
export const shortestPath = (links: readonly LinkEnds[], fromId: string, toId: string): GraphPath | null => {
  if (fromId === toId) return { nodeIds: [fromId], linkIds: [] };
  const byNode = adjacency(links);
  byNode.forEach((list) => list.sort((a, b) => a.id.localeCompare(b.id)));
  const previous = new Map<string, { nodeId: string; linkId: string }>();
  const visited = new Set([fromId]);
  let frontier = [fromId];
  while (frontier.length > 0 && !visited.has(toId)) {
    const next: string[] = [];
    frontier.forEach((nodeId) => {
      (byNode.get(nodeId) ?? []).forEach((link) => {
        const other = link.sourceId === nodeId ? link.targetId : link.sourceId;
        if (!visited.has(other)) {
          visited.add(other);
          previous.set(other, { nodeId, linkId: link.id });
          next.push(other);
        }
      });
    });
    frontier = next;
  }
  if (!visited.has(toId)) return null;
  const nodeIds = [toId];
  const linkIds: string[] = [];
  let cursor = toId;
  while (cursor !== fromId) {
    const step = previous.get(cursor);
    if (!step) return null;
    linkIds.unshift(step.linkId);
    nodeIds.unshift(step.nodeId);
    cursor = step.nodeId;
  }
  return { nodeIds, linkIds };
};

/**
 * Whether the reader can still follow a path: each of its nodes and links is among those drawn
 * and none is faded by a filter.
 */
export const isPathDrawable = (
  path: GraphPath,
  nodes: readonly { id: string; disabled?: boolean }[],
  links: readonly { id: string; disabled?: boolean }[],
): boolean => {
  const nodeIds = new Set(nodes.filter((node) => !node.disabled).map((node) => node.id));
  const linkIds = new Set(links.filter((link) => !link.disabled).map((link) => link.id));
  return path.nodeIds.every((id) => nodeIds.has(id)) && path.linkIds.every((id) => linkIds.has(id));
};

/**
 * Number of links of each relationship type touching a node, sorted by count then name: the
 * neighbourhood summary of the hover card.
 */
export const relationshipCounts = <L extends LinkEnds & { relationship_type?: string; entity_type?: string }>(
  links: readonly L[],
  nodeId: string,
): { type: string; count: number }[] => {
  const counts = new Map<string, number>();
  links.forEach((link) => {
    if (link.sourceId !== nodeId && link.targetId !== nodeId) return;
    const type = link.relationship_type || link.entity_type || '';
    counts.set(type, (counts.get(type) ?? 0) + 1);
  });
  return [...counts.entries()]
    .map(([type, count]) => ({ type, count }))
    .sort((a, b) => b.count - a.count || a.type.localeCompare(b.type));
};
