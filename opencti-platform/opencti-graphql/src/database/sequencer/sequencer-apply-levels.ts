// Concurrent apply within a batch (rung 5, 2026-09-21). The batch plan orders producers before
// consumers and records, per group, the positions of its in-batch producers (dependsOn). That
// gives every group a level: 0 when it has no in-batch producer, else one more than its deepest
// producer. Groups of one level share no edge and may apply concurrently; a level starts only
// when the previous one has fully settled, so the failure-aware skip reads settled state exactly
// as the sequential path does. Pure helpers, unit-tested on their own.

// Three ordering rules complete the plan's recorded edges, because the sequential path carried
// dependencies the plan does NOT record and that concurrency exposed (2026-09-21, MITRE):
//   - phase barrier: `phaseOf` gives the planner phase (0 entities, 1 relations, 2 containers and
//     relations on relations); a group waits for every earlier group of a lower phase. A relation
//     whose endpoint was resolvable at plan time (an upsert re-asserted in the same batch) has no
//     dependsOn edge yet read the endpoint's fresh in-batch result: 20 relations failed on a
//     missing reference at concurrency 4;
//   - same identity: two groups owning a common id (an entity present in two collections under
//     two STIX ids: same standard id, different canonical keys) apply one after the other; the
//     second's existence check then sees the first through the identity map, as the sequential
//     path did. Applied concurrently they both created: two documents per malware at 16;
//   - reference: a group waits for any earlier group owning an id it references (a relation's
//     endpoints, an entity's author or markings created in the same batch). Groups that merely
//     share a referenced id (many relations to one technique) stay parallel.
export interface ApplyLevelInputs {
  phaseOf?: (index: number) => number;
  ownIdsOf?: (index: number) => Iterable<string>; // the identities a group creates or upserts
  refIdsOf?: (index: number) => Iterable<string>; // the identities a group reads
}

export const computeApplyLevels = (order: Array<{ dependsOn?: number[] }>, inputs: ApplyLevelInputs = {}): number[] => {
  const levels: number[] = new Array(order.length).fill(0);
  const deepestByPhase = new Map<number, number>(); // phase -> deepest level seen so far
  const ownerLevel = new Map<string, number>(); // id -> deepest level of a group owning it so far
  for (let i = 0; i < order.length; i += 1) {
    let level = 0;
    (order[i].dependsOn ?? []).forEach((d) => {
      // producers always sit earlier in the plan; anything else is ignored, never trusted
      if (d >= 0 && d < i) level = Math.max(level, levels[d] + 1);
    });
    if (inputs.phaseOf) {
      const phase = inputs.phaseOf(i);
      deepestByPhase.forEach((deepest, p) => {
        if (p < phase) level = Math.max(level, deepest + 1);
      });
      deepestByPhase.set(phase, Math.max(deepestByPhase.get(phase) ?? -1, level));
    }
    if (inputs.refIdsOf) {
      for (const id of inputs.refIdsOf(i)) {
        const owner = ownerLevel.get(id);
        if (owner !== undefined) level = Math.max(level, owner + 1);
      }
    }
    const own = inputs.ownIdsOf ? Array.from(inputs.ownIdsOf(i)) : [];
    own.forEach((id) => {
      const owner = ownerLevel.get(id);
      if (owner !== undefined) level = Math.max(level, owner + 1);
    });
    if (inputs.phaseOf) deepestByPhase.set(inputs.phaseOf(i), Math.max(deepestByPhase.get(inputs.phaseOf(i)) ?? -1, level));
    own.forEach((id) => ownerLevel.set(id, Math.max(ownerLevel.get(id) ?? -1, level)));
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
