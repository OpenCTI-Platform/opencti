import type { Ordering, RankedGraph } from './types';

const BALANCE_ITERATIONS = 30;
const STRAIGHTEN_PASSES = 4;
const SNAP_DISTANCE = 6;
const DUMMY_WEIGHT = 4;
const PIN_WEIGHT = 1e6;
const EPSILON = 0.01;

export const median = (values: number[]): number => {
  const s = values.slice().sort((a, b) => a - b);
  const m = Math.floor(s.length / 2);
  return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2;
};

// Pool-adjacent-violators: the non-decreasing sequence closest to `y` (weighted least squares).
export const pava = (y: number[], w: number[]): number[] => {
  const blocks: { v: number; w: number; n: number }[] = [];
  y.forEach((v, i) => {
    blocks.push({ v, w: w[i], n: 1 });
    while (blocks.length > 1 && blocks[blocks.length - 2].v > blocks[blocks.length - 1].v) {
      const b = blocks.pop()!;
      const a = blocks.pop()!;
      const ww = a.w + b.w;
      blocks.push({ v: (a.v * a.w + b.v * b.w) / ww, w: ww, n: a.n + b.n });
    }
  });
  return blocks.flatMap((b) => Array<number>(b.n).fill(b.v));
};

// Phase 4: horizontal placement. Returns the centre x of every layered node (real and dummy).
export const placeX = (ranked: RankedGraph, ordering: Ordering, gapX: number): Map<string, number> => {
  const { layered, up, down, chains, segments, maxRank } = ranked;
  const { layers, pos, seed, treeKids } = ordering;
  const x = new Map<string, number>();

  const sep = (a: string, b: string) => {
    const A = layered.get(a)!;
    const B = layered.get(b)!;
    return A.w / 2 + B.w / 2 + (A.dummy || B.dummy ? gapX * 0.4 : gapX);
  };
  const weight = (id: string) => (layered.get(id)!.dummy ? DUMMY_WEIGHT : 1 + up.get(id)!.length + down.get(id)!.length);
  // Closest positions to `desired` that keep each neighbour at least `sep` away, in row order.
  const project = (layer: string[], desired: number[], w: number[] = layer.map(weight)) => {
    const offsets = [0];
    for (let i = 1; i < layer.length; i += 1) offsets.push(offsets[i - 1] + sep(layer[i - 1], layer[i]));
    return pava(desired.map((d, i) => d - offsets[i]), w).map((v, i) => v + offsets[i]);
  };
  const apply = (layer: string[], xs: number[]) => layer.forEach((id, i) => x.set(id, xs[i]));
  const neighbourMedian = (id: string, neighbours: string[]) => (neighbours.length ? median(neighbours.map((n) => x.get(n)!)) : x.get(id)!);

  // a) Balance: each node aims for the median x of its neighbours.
  layers.forEach((layer) => apply(layer, project(layer, layer.map(() => 0))));
  const ranks = [...Array(maxRank + 1).keys()];
  for (let it = 0; it < BALANCE_ITERATIONS; it += 1) {
    const mode = it % 3; // 0: parents, 1: children, 2: both
    (mode === 1 ? ranks.slice().reverse() : ranks).forEach((r) => {
      const layer = layers[r];
      const desired = layer.map((id) => {
        if (mode === 0) return neighbourMedian(id, up.get(id)!);
        if (mode === 1) return neighbourMedian(id, down.get(id)!);
        return neighbourMedian(id, up.get(id)!.concat(down.get(id)!));
      });
      apply(layer, project(layer, desired));
    });
  }

  // b) Main-path alignment: top to bottom, each node's first DFS-tree child (when it has no
  //    other parent) is pinned straight under it if the row can make room. Pins never move.
  const alignTo = new Map<string, string>();
  treeKids.forEach((kids, parent) => {
    const first = kids.find((child) => up.get(child)!.length === 1);
    if (first) alignTo.set(first, parent);
  });
  const pinned = new Map<string, number>();
  for (let r = 1; r <= maxRank; r += 1) {
    const layer = layers[r];
    const solve = (extra: Map<string, number>) => {
      const desired = layer.map((id) => extra.get(id) ?? pinned.get(id) ?? neighbourMedian(id, up.get(id)!));
      return project(layer, desired, layer.map((id) => (extra.has(id) || pinned.has(id) ? PIN_WEIGHT : weight(id))));
    };
    apply(layer, solve(new Map()));
    layer.filter((id) => alignTo.has(id))
      .sort((a, b) => seed.get(alignTo.get(a)!)! - seed.get(alignTo.get(b)!)!)
      .forEach((child) => {
        const target = x.get(alignTo.get(child)!)!;
        const xs = solve(new Map([[child, target]]));
        const keepsPins = layer.every((id, i) => !pinned.has(id) || Math.abs(xs[i] - pinned.get(id)!) < 0.5);
        if (Math.abs(xs[layer.indexOf(child)] - target) < 0.5 && keepsPins) {
          pinned.set(child, target);
          apply(layer, xs);
        }
      });
  }

  // c) Snap near-straight single-neighbour edges, when separation allows.
  const snap = (r: number, neighbours: Map<string, string[]>) => {
    const layer = layers[r];
    layer.forEach((id, i) => {
      const nb = neighbours.get(id)!;
      if (nb.length !== 1) return;
      const target = x.get(nb[0])!;
      if (Math.abs(target - x.get(id)!) > SNAP_DISTANCE) return;
      const leftOk = i === 0 || target - x.get(layer[i - 1])! >= sep(layer[i - 1], id) - EPSILON;
      const rightOk = i === layer.length - 1 || x.get(layer[i + 1])! - target >= sep(id, layer[i + 1]) - EPSILON;
      if (leftOk && rightOk) x.set(id, target);
    });
  };
  for (let r = 1; r <= maxRank; r += 1) snap(r, up);
  for (let r = maxRank - 1; r >= 0; r -= 1) snap(r, down);
  for (let r = 1; r <= maxRank; r += 1) snap(r, up);

  // d) Straightening. A node may move anywhere between its row neighbours (minus the gap).
  const bounds = (id: string): [number, number] => {
    const layer = layers[layered.get(id)!.rank];
    const i = pos.get(id)!;
    const lo = i > 0 ? x.get(layer[i - 1])! + sep(layer[i - 1], id) : -Infinity;
    const hi = i < layer.length - 1 ? x.get(layer[i + 1])! - sep(id, layer[i + 1]) : Infinity;
    return [lo, hi];
  };
  const fits = (id: string, v: number) => {
    const [lo, hi] = bounds(id);
    return v >= lo - EPSILON && v <= hi + EPSILON;
  };
  for (let pass = 0; pass < STRAIGHTEN_PASSES; pass += 1) {
    // Long edges: split the dummies into as few vertical runs as the rows allow (greedy
    // interval stabbing, starting straight down from the source).
    chains.forEach((chain) => {
      if (chain.length < 3) return;
      const xs = x.get(chain[0])!;
      const xt = x.get(chain[chain.length - 1])!;
      const runs: { lo: number; hi: number; ids: string[] }[] = [];
      let current = { lo: xs, hi: xs, ids: [] as string[] };
      chain.slice(1, -1).forEach((d) => {
        const [lo, hi] = bounds(d);
        const nlo = Math.max(current.lo, lo);
        const nhi = Math.min(current.hi, hi);
        if (nlo <= nhi + EPSILON) {
          current.lo = nlo;
          current.hi = Math.max(nlo, nhi);
          current.ids.push(d);
          return;
        }
        if (current.ids.length) runs.push(current);
        current = { lo, hi, ids: [d] };
      });
      runs.push(current);
      let previous = xs;
      runs.forEach((run, i) => {
        const clamp = (v: number) => Math.min(run.hi, Math.max(run.lo, v));
        const last = i === runs.length - 1;
        const targetFits = xt >= run.lo - EPSILON && xt <= run.hi + EPSILON;
        const v = last && targetFits ? xt : clamp(last ? xt : previous);
        run.ids.forEach((d) => x.set(d, v));
        previous = v;
      });
    });
    // One-to-one links: align child under parent, or parent over child.
    segments.forEach(({ u, v }) => {
      if (layered.get(u)!.dummy || layered.get(v)!.dummy) return;
      if (down.get(u)!.length !== 1 || up.get(v)!.length !== 1) return;
      if (Math.abs(x.get(u)! - x.get(v)!) < 0.5) return;
      if (fits(v, x.get(u)!)) {
        x.set(v, x.get(u)!);
      } else if (fits(u, x.get(v)!)) {
        x.set(u, x.get(v)!);
      }
    });
  }
  x.forEach((v, id) => x.set(id, Math.round(v)));
  return x;
};
