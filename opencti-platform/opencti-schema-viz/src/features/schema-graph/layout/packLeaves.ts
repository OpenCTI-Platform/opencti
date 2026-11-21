import type { LayoutDirection, LayoutEdge, LayoutEngine, LayoutNode, Position } from './LayoutEngine';

/** Below this many siblings, a plain row (or column) reads fine. */
const PACK_MIN = 7;
const GAP_X = 24;
const GAP_Y = 24;

interface Pack {
  id: string;
  leafIds: string[];
  columns: number;
  cell: { width: number; height: number };
}

/**
 * Layered layouts put every child of a node on one rank, so a parent with 60 leaf children becomes a
 * 60-node row (or column). This folds such leaves into one grid-shaped placeholder before layout and
 * spreads them back afterwards. Works with any LayoutEngine.
 */
export const withPackedLeaves = (engine: LayoutEngine, isPackable: (id: string) => boolean): LayoutEngine => ({
  layout: (nodes: LayoutNode[], edges: LayoutEdge[], direction: LayoutDirection) => {
    const degree = new Map<string, number>();
    for (const edge of edges) {
      if (edge.source === edge.target) continue;
      degree.set(edge.source, (degree.get(edge.source) ?? 0) + 1);
      degree.set(edge.target, (degree.get(edge.target) ?? 0) + 1);
    }

    // Leaves hanging from the same node on the same side.
    const groups = new Map<string, { anchor: string; leafIsTarget: boolean; leafIds: string[] }>();
    for (const edge of edges) {
      for (const [leaf, anchor, leafIsTarget] of [[edge.target, edge.source, true], [edge.source, edge.target, false]] as const) {
        if (leaf === anchor || degree.get(leaf) !== 1 || !isPackable(leaf)) continue;
        const key = `${anchor}|${leafIsTarget}`;
        const group = groups.get(key) ?? { anchor, leafIsTarget, leafIds: [] };
        group.leafIds.push(leaf);
        groups.set(key, group);
      }
    }

    const sizes = new Map(nodes.map((node) => [node.id, node]));
    const packs: Pack[] = [];
    const packedLeaf = new Map<string, string>();
    for (const [key, group] of groups) {
      if (group.leafIds.length < PACK_MIN) continue;
      const cell = {
        width: Math.max(...group.leafIds.map((id) => sizes.get(id)?.width ?? 0)),
        height: Math.max(...group.leafIds.map((id) => sizes.get(id)?.height ?? 0)),
      };
      // Grow the grid across the layout direction, so it stays compact along it.
      const columns = direction === 'TB'
        ? Math.ceil(Math.sqrt(group.leafIds.length * 2))
        : Math.ceil(Math.sqrt(group.leafIds.length / 2));
      const pack = { id: `pack:${key}`, leafIds: group.leafIds, columns, cell };
      packs.push(pack);
      for (const leaf of group.leafIds) packedLeaf.set(leaf, pack.id);
    }
    if (packs.length === 0) return engine.layout(nodes, edges, direction);

    const packSize = (pack: Pack) => {
      const rows = Math.ceil(pack.leafIds.length / pack.columns);
      return {
        width: pack.columns * pack.cell.width + (pack.columns - 1) * GAP_X,
        height: rows * pack.cell.height + (rows - 1) * GAP_Y,
      };
    };
    const reducedNodes = [
      ...nodes.filter((node) => !packedLeaf.has(node.id)),
      ...packs.map((pack) => ({ id: pack.id, ...packSize(pack) })),
    ];
    const seenPackEdges = new Set<string>();
    const reducedEdges = edges.flatMap((edge) => {
      const source = packedLeaf.get(edge.source) ?? edge.source;
      const target = packedLeaf.get(edge.target) ?? edge.target;
      if (source === edge.source && target === edge.target) return [edge];
      const key = `${source}->${target}`;
      if (seenPackEdges.has(key)) return [];
      seenPackEdges.add(key);
      return [{ ...edge, source, target }];
    });

    const positions = engine.layout(reducedNodes, reducedEdges, direction);
    for (const pack of packs) {
      const origin = positions.get(pack.id);
      positions.delete(pack.id);
      if (!origin) continue;
      pack.leafIds.forEach((leaf, index) => {
        const size = sizes.get(leaf);
        const column = index % pack.columns;
        const row = Math.floor(index / pack.columns);
        const position: Position = {
          x: origin.x + column * (pack.cell.width + GAP_X) + (pack.cell.width - (size?.width ?? 0)) / 2,
          y: origin.y + row * (pack.cell.height + GAP_Y) + (pack.cell.height - (size?.height ?? 0)) / 2,
        };
        positions.set(leaf, position);
      });
    }
    return positions;
  },
});
