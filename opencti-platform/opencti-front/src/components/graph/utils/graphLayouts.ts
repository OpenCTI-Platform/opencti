import type { LinkEnds, Point } from './graphGeometry';

export interface LayoutNode {
  id: string;
  entity_type?: string;
}

export type LayoutPositions = Map<string, Point>;

export type LayeredDirection = 'lr' | 'td';

/** Graph units between two layers and between two neighbours of one layer, per reading direction. */
const SPACING: Record<LayeredDirection, { layer: number; sibling: number }> = {
  // Left to right: labels sit under the nodes, so a column needs room for one label width.
  lr: { layer: 110, sibling: 34 },
  // Top to bottom: a row needs room for one label width between two nodes.
  td: { layer: 70, sibling: 62 },
};
const RING_GAP = 80;
/** Graph units of arc a node of a ring needs, its label included. */
const RING_ARC_PER_NODE = 48;
const ORDERING_SWEEPS = 6;

const byId = (a: { id: string }, b: { id: string }) => a.id.localeCompare(b.id);

/** Both ends of every link, each node listing the nodes it is linked to, sorted and unique. */
const neighbourLists = (links: readonly LinkEnds[]): Map<string, string[]> => {
  const neighbours = new Map<string, Set<string>>();
  const add = (from: string, to: string) => {
    const set = neighbours.get(from);
    if (set) set.add(to);
    else neighbours.set(from, new Set([to]));
  };
  links.forEach(({ sourceId, targetId }) => {
    add(sourceId, targetId);
    add(targetId, sourceId);
  });
  return new Map([...neighbours.entries()].map(([id, set]) => [id, [...set].sort()]));
};

/**
 * Links whose both ends are drawn, deduplicated per ordered pair, self-loops left out: what the
 * layouts reason on.
 */
const usableLinks = (nodeIds: ReadonlySet<string>, links: readonly LinkEnds[]) => {
  const seen = new Set<string>();
  return [...links].sort(byId).filter((link) => {
    if (link.sourceId === link.targetId) return false;
    if (!nodeIds.has(link.sourceId) || !nodeIds.has(link.targetId)) return false;
    const key = `${link.sourceId}|${link.targetId}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
};

/**
 * Links reversed where they close a cycle, found with an iterative depth-first walk started from
 * the nodes in id order: the rest is acyclic and can be layered. Deterministic.
 */
export const breakCycles = (nodeIds: readonly string[], links: readonly LinkEnds[]): LinkEnds[] => {
  const outgoing = new Map<string, LinkEnds[]>();
  links.forEach((link) => {
    const list = outgoing.get(link.sourceId);
    if (list) list.push(link);
    else outgoing.set(link.sourceId, [link]);
  });
  const state = new Map<string, 'open' | 'done'>();
  // The links themselves, not their ids: the two connectors of a nested relationship share its id.
  const reversed = new Set<LinkEnds>();
  [...nodeIds].sort().forEach((root) => {
    if (state.has(root)) return;
    const stack: { nodeId: string; index: number }[] = [{ nodeId: root, index: 0 }];
    state.set(root, 'open');
    while (stack.length > 0) {
      const frame = stack[stack.length - 1];
      const edges = outgoing.get(frame.nodeId) ?? [];
      if (frame.index >= edges.length) {
        state.set(frame.nodeId, 'done');
        stack.pop();
      } else {
        const edge = edges[frame.index];
        frame.index += 1;
        const status = state.get(edge.targetId);
        if (status === 'open') {
          reversed.add(edge);
        } else if (!status) {
          state.set(edge.targetId, 'open');
          stack.push({ nodeId: edge.targetId, index: 0 });
        }
      }
    }
  });
  return links.map((link) => (reversed.has(link)
    ? { id: link.id, sourceId: link.targetId, targetId: link.sourceId }
    : link));
};

/** Whether the links close a cycle (a link from a node to itself included). */
export const hasCycle = (nodeIds: readonly string[], links: readonly LinkEnds[]): boolean => {
  const acyclic = breakCycles(nodeIds, links);
  return acyclic.some((link, index) => link !== links[index]);
};

/** Longest-path layering of an acyclic set of links: every link points to a later layer. */
const longestPathLayers = (nodeIds: readonly string[], links: readonly LinkEnds[]): Map<string, number> => {
  const incoming = new Map<string, string[]>();
  const outgoing = new Map<string, string[]>();
  nodeIds.forEach((id) => {
    incoming.set(id, []);
    outgoing.set(id, []);
  });
  links.forEach((link) => {
    incoming.get(link.targetId)?.push(link.sourceId);
    outgoing.get(link.sourceId)?.push(link.targetId);
  });
  const layer = new Map<string, number>();
  const remaining = new Map(nodeIds.map((id) => [id, incoming.get(id)?.length ?? 0]));
  let frontier = nodeIds.filter((id) => remaining.get(id) === 0).sort();
  frontier.forEach((id) => layer.set(id, 0));
  while (frontier.length > 0) {
    const next: string[] = [];
    frontier.forEach((id) => {
      (outgoing.get(id) ?? []).forEach((targetId) => {
        layer.set(targetId, Math.max(layer.get(targetId) ?? 0, (layer.get(id) ?? 0) + 1));
        const left = (remaining.get(targetId) ?? 1) - 1;
        remaining.set(targetId, left);
        if (left === 0) next.push(targetId);
      });
    });
    frontier = next.sort();
  }
  return layer;
};

/**
 * Orders the nodes of each layer to reduce crossings: alternate sweeps place every node at the
 * mean position of its neighbours in the layer before (barycentre heuristic), ties kept stable.
 */
const orderLayers = (
  layers: string[][],
  links: readonly LinkEnds[],
): string[][] => {
  const neighbours = neighbourLists(links);
  const ordered = layers.map((layer) => [...layer]);
  const positionOf = new Map<string, number>();
  const index = () => ordered.forEach((layer) => layer.forEach((id, i) => positionOf.set(id, i / Math.max(1, layer.length - 1))));
  index();
  for (let sweep = 0; sweep < ORDERING_SWEEPS; sweep += 1) {
    const downward = sweep % 2 === 0;
    const range = downward
      ? ordered.map((_, i) => i).slice(1)
      : ordered.map((_, i) => i).slice(0, -1).reverse();
    range.forEach((layerIndex) => {
      const reference = new Set(ordered[downward ? layerIndex - 1 : layerIndex + 1]);
      const current = ordered[layerIndex];
      const weights = new Map(current.map((id, i) => {
        const related = (neighbours.get(id) ?? []).filter((other) => reference.has(other));
        const value = related.length === 0
          ? (positionOf.get(id) ?? i / Math.max(1, current.length - 1))
          : related.reduce((sum, other) => sum + (positionOf.get(other) ?? 0), 0) / related.length;
        return [id, value];
      }));
      current.sort((a, b) => (weights.get(a) ?? 0) - (weights.get(b) ?? 0) || a.localeCompare(b));
      current.forEach((id, i) => positionOf.set(id, i / Math.max(1, current.length - 1)));
    });
  }
  return ordered;
};

const placeLayers = (layers: string[][], direction: LayeredDirection): LayoutPositions => {
  const { layer: layerGap, sibling } = SPACING[direction];
  const positions: LayoutPositions = new Map();
  const offset = ((layers.length - 1) * layerGap) / 2;
  layers.forEach((layer, layerIndex) => {
    layer.forEach((id, i) => {
      const along = layerIndex * layerGap - offset;
      const across = (i - (layer.length - 1) / 2) * sibling;
      positions.set(id, direction === 'lr' ? { x: along, y: across } : { x: across, y: along });
    });
  });
  return positions;
};

/**
 * Layers following the direction of the relationships (a source before its targets), cycles
 * included, read left to right or top to bottom. The same graph always gets the same picture.
 */
export const layeredLayout = (
  nodes: readonly LayoutNode[],
  links: readonly LinkEnds[],
  direction: LayeredDirection,
): LayoutPositions => {
  const nodeIds = [...nodes].sort(byId).map(({ id }) => id);
  const kept = usableLinks(new Set(nodeIds), links);
  const acyclic = breakCycles(nodeIds, kept);
  const layerOf = longestPathLayers(nodeIds, acyclic);
  const count = Math.max(0, ...layerOf.values()) + 1;
  const layers: string[][] = Array.from({ length: count }, () => []);
  nodeIds.forEach((id) => layers[layerOf.get(id) ?? 0].push(id));
  return placeLayers(orderLayers(layers, kept), direction);
};

/**
 * Columns by entity tier, read left to right like an attack: who (threats), with what (arsenal),
 * how (techniques), through what (infrastructure and observables), against whom (victims), where
 * (locations), then the reports and cases describing it.
 */
const FAMILY_TIER: Record<string, number> = {
  allThreats: 0,
  arsenal: 1,
  techniques: 2,
  observations: 3,
  observables: 3,
  victimology: 4,
  locations: 5,
  events: 6,
  cases: 6,
  analyse: 7,
  relationships: 3,
  restricted: 8,
};
const UNKNOWN_TIER = 8;

export const entityTier = (family: string | null | undefined): number => (family ? FAMILY_TIER[family] ?? UNKNOWN_TIER : UNKNOWN_TIER);

export const tierLayout = (
  nodes: readonly LayoutNode[],
  links: readonly LinkEnds[],
  tierOf: (node: LayoutNode) => number,
): LayoutPositions => {
  const sorted = [...nodes].sort(byId);
  const tiers = [...new Set(sorted.map(tierOf))].sort((a, b) => a - b);
  const layers = tiers.map((tier) => sorted.filter((node) => tierOf(node) === tier)
    // Within a tier, one type after the other before the crossing reduction mixes them.
    .sort((a, b) => (a.entity_type ?? '').localeCompare(b.entity_type ?? '') || a.id.localeCompare(b.id))
    .map(({ id }) => id));
  const kept = usableLinks(new Set(sorted.map(({ id }) => id)), links);
  return placeLayers(orderLayers(layers, kept), 'lr');
};

/** The node with the most links, ties broken by id: the default centre of the radial layout. */
export const mostConnected = (nodes: readonly LayoutNode[], links: readonly LinkEnds[]): string | null => {
  if (nodes.length === 0) return null;
  const degree = new Map<string, number>();
  links.forEach(({ sourceId, targetId }) => {
    degree.set(sourceId, (degree.get(sourceId) ?? 0) + 1);
    degree.set(targetId, (degree.get(targetId) ?? 0) + 1);
  });
  return [...nodes].sort((a, b) => (degree.get(b.id) ?? 0) - (degree.get(a.id) ?? 0) || a.id.localeCompare(b.id))[0].id;
};

/**
 * Rings around one node by distance (in links, whatever their direction). Every node gets a
 * sector of the circle proportional to the part of the graph reached through it, so branches
 * never cross; nodes out of reach are laid on one outer ring.
 */
export const radialLayout = (
  nodes: readonly LayoutNode[],
  links: readonly LinkEnds[],
  centreId: string | null,
): LayoutPositions => {
  const positions: LayoutPositions = new Map();
  const sorted = [...nodes].sort(byId);
  const nodeIds = new Set(sorted.map(({ id }) => id));
  const centre = centreId && nodeIds.has(centreId) ? centreId : mostConnected(sorted, links);
  if (!centre) return positions;
  const neighbours = neighbourLists(usableLinks(nodeIds, links));

  // Breadth-first tree from the centre.
  const depth = new Map([[centre, 0]]);
  const children = new Map<string, string[]>();
  let frontier = [centre];
  while (frontier.length > 0) {
    const next: string[] = [];
    frontier.forEach((id) => {
      (neighbours.get(id) ?? []).forEach((other) => {
        if (!depth.has(other)) {
          depth.set(other, (depth.get(id) ?? 0) + 1);
          const list = children.get(id);
          if (list) list.push(other);
          else children.set(id, [other]);
          next.push(other);
        }
      });
    });
    frontier = next;
  }

  const weight = new Map<string, number>();
  const weigh = (id: string): number => {
    const value = Math.max(1, (children.get(id) ?? []).reduce((sum, child) => sum + weigh(child), 0));
    weight.set(id, value);
    return value;
  };
  weigh(centre);

  const ringCount = new Map<number, number>();
  depth.forEach((d) => ringCount.set(d, (ringCount.get(d) ?? 0) + 1));
  const radiusOf = (d: number) => Math.max(d * RING_GAP, ((ringCount.get(d) ?? 0) * RING_ARC_PER_NODE) / (2 * Math.PI));

  const place = (id: string, from: number, to: number) => {
    const d = depth.get(id) ?? 0;
    const angle = (from + to) / 2;
    const radius = d === 0 ? 0 : radiusOf(d);
    positions.set(id, { x: radius * Math.cos(angle), y: radius * Math.sin(angle) });
    const kids = children.get(id) ?? [];
    const total = kids.reduce((sum, child) => sum + (weight.get(child) ?? 1), 0);
    let cursor = from;
    kids.forEach((child) => {
      const span = ((to - from) * (weight.get(child) ?? 1)) / Math.max(1, total);
      place(child, cursor, cursor + span);
      cursor += span;
    });
  };
  place(centre, -Math.PI / 2, (3 * Math.PI) / 2);

  const unreached = sorted.filter(({ id }) => !depth.has(id));
  if (unreached.length > 0) {
    const outer = Math.max(...[...depth.values()].map(radiusOf), 0) + RING_GAP;
    const radius = Math.max(outer, (unreached.length * RING_ARC_PER_NODE) / (2 * Math.PI));
    unreached.forEach(({ id }, i) => {
      const angle = -Math.PI / 2 + (2 * Math.PI * i) / unreached.length;
      positions.set(id, { x: radius * Math.cos(angle), y: radius * Math.sin(angle) });
    });
  }
  return positions;
};
