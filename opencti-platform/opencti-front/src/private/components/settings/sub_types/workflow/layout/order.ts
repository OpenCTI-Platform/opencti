import type { Graph, Ordering, RankedGraph } from './types';

const SWEEPS = 24;
const TRANSPOSE_ROUNDS = 8;

// Phase 3: crossing reduction. Rows start in DFS preorder (a subtree stays together), then
// alternate barycenter sweeps down and up, each followed by a transpose pass. The ordering
// with the fewest crossings wins.
export const orderLayers = (graph: Graph, ranked: RankedGraph): Ordering => {
  const { layered, up, down, segments, maxRank } = ranked;
  const seen = new Set<string>();
  const seed = new Map<string, number>();
  const treeKids = new Map<string, string[]>();
  let counter = 0;
  const dfs = (id: string) => {
    seen.add(id);
    seed.set(id, counter);
    counter += 1;
    down.get(id)!.forEach((child) => {
      if (seen.has(child)) return;
      if (!treeKids.has(id)) treeKids.set(id, []);
      treeKids.get(id)!.push(child);
      dfs(child);
    });
  };
  const modelOrder = (id: string) => graph.nodes.get(id)?.order ?? Infinity;
  [...layered.values()]
    .filter((n) => up.get(n.id)!.length === 0)
    .sort((a, b) => a.rank - b.rank || modelOrder(a.id) - modelOrder(b.id))
    .forEach((n) => {
      if (!seen.has(n.id)) dfs(n.id);
    });

  let layers: string[][] = Array.from({ length: maxRank + 1 }, () => []);
  layered.forEach((n) => layers[n.rank].push(n.id));
  layers.forEach((layer) => layer.sort((a, b) => seed.get(a)! - seed.get(b)!));

  const pos = new Map<string, number>();
  const setPos = (r: number) => layers[r].forEach((id, i) => pos.set(id, i));
  layers.forEach((_, r) => setPos(r));

  const segmentsByRank = layers.map(() => [] as typeof segments);
  segments.forEach((s) => segmentsByRank[layered.get(s.u)!.rank].push(s));
  const crossingsAt = (r: number) => {
    const rowSegments = segmentsByRank[r] ?? [];
    let c = 0;
    for (let i = 0; i < rowSegments.length; i += 1) {
      for (let j = i + 1; j < rowSegments.length; j += 1) {
        const a = rowSegments[i];
        const b = rowSegments[j];
        if ((pos.get(a.u)! - pos.get(b.u)!) * (pos.get(a.v)! - pos.get(b.v)!) < 0) c += 1;
      }
    }
    return c;
  };
  const totalCrossings = () => layers.reduce((sum, _, r) => sum + crossingsAt(r), 0);

  const reorder = (r: number, useUp: boolean) => {
    const barycenter = new Map<string, number>();
    layers[r].forEach((id) => {
      const neighbours = (useUp ? up : down).get(id)!;
      barycenter.set(id, neighbours.length
        ? neighbours.reduce((s, n) => s + pos.get(n)!, 0) / neighbours.length
        : pos.get(id)!);
    });
    layers[r].sort((a, b) => barycenter.get(a)! - barycenter.get(b)! || pos.get(a)! - pos.get(b)!);
    setPos(r);
  };
  // Crossings caused by keeping u left of v, against both neighbouring rows.
  const pairCrossings = (u: string, v: string) => {
    let c = 0;
    [up, down].forEach((neighbours) => {
      neighbours.get(u)!.forEach((a) => neighbours.get(v)!.forEach((b) => {
        if (pos.get(a)! > pos.get(b)!) c += 1;
      }));
    });
    return c;
  };
  const transpose = () => {
    let improved = true;
    for (let round = 0; improved && round < TRANSPOSE_ROUNDS; round += 1) {
      improved = false;
      layers.forEach((layer, r) => {
        for (let i = 0; i + 1 < layer.length; i += 1) {
          if (pairCrossings(layer[i + 1], layer[i]) < pairCrossings(layer[i], layer[i + 1])) {
            [layer[i], layer[i + 1]] = [layer[i + 1], layer[i]];
            setPos(r);
            improved = true;
          }
        }
      });
    }
  };

  let best = layers.map((l) => l.slice());
  let bestCrossings = totalCrossings();
  for (let it = 0; it < SWEEPS && bestCrossings > 0; it += 1) {
    if (it % 2 === 0) {
      for (let r = 1; r <= maxRank; r += 1) reorder(r, true);
    } else {
      for (let r = maxRank - 1; r >= 0; r -= 1) reorder(r, false);
    }
    transpose();
    const c = totalCrossings();
    if (c < bestCrossings) {
      bestCrossings = c;
      best = layers.map((l) => l.slice());
    }
  }
  layers = best;
  layers.forEach((_, r) => setPos(r));
  return { layers, pos, seed, treeKids, crossings: bestCrossings };
};
