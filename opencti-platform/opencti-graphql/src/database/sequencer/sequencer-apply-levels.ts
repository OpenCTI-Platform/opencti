// Concurrent apply within a batch (rung 5, 2026-09-21). The batch plan orders producers before
// consumers and records, per group, the positions of its in-batch producers (dependsOn). That
// gives every group a level: 0 when it has no in-batch producer, else one more than its deepest
// producer. Groups of one level share no edge and may apply concurrently; a level starts only
// when the previous one has fully settled, so the failure-aware skip reads settled state exactly
// as the sequential path does. Pure helpers, unit-tested on their own.

export const computeApplyLevels = (order: Array<{ dependsOn?: number[] }>): number[] => {
  const levels: number[] = new Array(order.length).fill(0);
  for (let i = 0; i < order.length; i += 1) {
    let level = 0;
    (order[i].dependsOn ?? []).forEach((d) => {
      // producers always sit earlier in the plan; anything else is ignored, never trusted
      if (d >= 0 && d < i) level = Math.max(level, levels[d] + 1);
    });
    levels[i] = level;
  }
  return levels;
};

export const groupIndicesByLevel = (levels: number[]): number[][] => {
  const byLevel: number[][] = [];
  levels.forEach((lvl, i) => {
    if (!byLevel[lvl]) byLevel[lvl] = [];
    byLevel[lvl].push(i);
  });
  return byLevel;
};

// At most `limit` tasks in flight, items taken in order, results in input order. Each task is
// expected to handle its own failure (applyGroup does); a rejection would still propagate once
// the other workers have drained.
export const runBounded = async <T, R>(items: T[], limit: number, fn: (item: T, position: number) => Promise<R>): Promise<R[]> => {
  const results: R[] = new Array(items.length);
  let next = 0;
  const width = Math.max(1, Math.min(Math.floor(limit), items.length));
  const worker = async () => {
    for (;;) {
      const i = next;
      next += 1;
      if (i >= items.length) return;
      results[i] = await fn(items[i], i);
    }
  };
  await Promise.all(Array.from({ length: width }, () => worker()));
  return results;
};
