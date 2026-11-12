// POC ingestion sequencer (plan 0009, Stage D4). Holder for the CURRENT batch lock, read by
// the middleware lock call sites at acquisition time. The loop applies intents one at a time
// (concurrency 1), so a module-level current lock is unambiguous. This module has zero
// imports on purpose: master-lock and middleware can use it without any cycle risk.
export interface SequencerBatchLock {
  // live: the loop adds the instance ids of every element it writes during the batch, so a
  // later apply of the same batch finds the internal id of an endpoint created before it
  heldKeys: Set<string>;
  signal: AbortSignal;
  // fix 2026-09-22 instrumentation: keys an apply-time lock site asked for and the batch lock
  // did not hold (a real Redis lock is then taken; under concurrent apply those contend)
  onMiss?: (keys: string[]) => void;
  // task 0040 multi_writer step 2: a key outside the batch lock is tried once, never waited for
  // (another platform may hold it while waiting for one of ours); the apply fails with LOCK_ERROR
  // and its group starts a new cycle with the key locked up front
  noWait?: boolean;
}

// Keys the batch lock must hold so the apply-time lock sites are no-ops (master-lock's
// lockResources skips held keys). Fix 2026-09-22 (A/B chunk-queue-mix285k-w1-ab: 1,309 s of lock
// wait at apply concurrency 8 on the full mix): the REFERENCED ids join the candidates, since the
// applies upsert the meta objects they reference under their own lock (markings, identities,
// labels, external references, kill chain phases), each with the instance ids of its
// pre-resolved element; a relation's endpoints are resolved to their internal id when the map
// knows them. Zero imports kept on purpose: lookups are injected.
export interface BatchLockGroup {
  leader: { kind: string; candidateIds: string[]; referencedIds: string[]; input: Record<string, any>; extraLockKeys?: string[] };
  absorbed: { referencedIds: string[]; extraLockKeys?: string[] }[];
}

// Increment 2026-09-24: a relation's OWN ids (standard id and aliases) only exist once its
// endpoints are resolved, so the apply-time lock site asked for them outside the batch lock
// (62,521 real locks on one full-mix run, unique keys, no contention but one round trip each).
// When both endpoints are already in the identity map, the injected relationOwnIds computes
// them at plan time with the same function the apply uses (getInputIds on the input carrying
// from and to), exactly as the dedup prefetch does; unresolved endpoints keep today's real lock.
export const computeBatchLockKeys = (
  groups: BatchLockGroup[],
  peekInstanceIds: (id: string) => string[] | null,
  resolveInternalId: (id: string) => string | null,
  relationOwnIds?: (leader: BatchLockGroup['leader']) => string[] | null,
): string[] => {
  const keys = new Set<string>();
  const addWithInstance = (id: string) => {
    if (typeof id !== 'string' || id.length === 0) return;
    keys.add(id);
    const instance = peekInstanceIds(id);
    if (instance) instance.forEach((k) => keys.add(k));
  };
  groups.forEach(({ leader, absorbed }) => {
    leader.candidateIds.forEach(addWithInstance);
    leader.referencedIds.forEach(addWithInstance);
    absorbed.forEach((a) => a.referencedIds.forEach(addWithInstance));
    if (leader.kind === 'relation') {
      [leader.input.fromId, leader.input.toId].forEach((id) => {
        if (typeof id === 'string' && id.length > 0) keys.add(resolveInternalId(id) ?? id);
      });
      const own = relationOwnIds?.(leader);
      if (own) {
        own.forEach((id) => {
          if (typeof id === 'string' && id.length > 0) keys.add(id);
        });
      }
    }
  });
  return Array.from(keys);
};

// task 0040 multi_writer step 2: the keys a batch locks in Redis when several platforms write. Only
// what the batch writes as its own: the intents' own ids with the instance ids of their resolved
// target, the relations' own ids and the key of the document their dedup may land on, the meta
// objects an apply may create from its input, and the keys an apply could not take in an earlier
// cycle. Referenced ids and relation endpoints are not locked across platforms: an apply only reads
// them and appends to their denormalized refs, a scripted update that commutes (KB
// opencti-sequencer-multi-platform-scaling). The batch still HOLDS the full set of
// computeBatchLockKeys, so the apply-time lock sites asking for them stay no-ops.
export const computeOwnLockKeys = (
  groups: BatchLockGroup[],
  peekInstanceIds: (id: string) => string[] | null,
  relationOwnIds: (leader: BatchLockGroup['leader']) => string[] | null,
  creatableIds: (input: Record<string, any>) => string[],
  relationDedupKey: (leader: BatchLockGroup['leader']) => string | null = () => null,
): string[] => {
  const keys = new Set<string>();
  const add = (id: unknown) => {
    if (typeof id === 'string' && id.length > 0) keys.add(id);
  };
  groups.forEach(({ leader, absorbed }) => {
    if (leader.kind === 'relation') {
      const endpoints = new Set([leader.input.fromId, leader.input.toId]);
      leader.candidateIds.filter((id) => !endpoints.has(id)).forEach(add);
      (relationOwnIds(leader) ?? []).forEach(add);
      add(relationDedupKey(leader));
    } else {
      leader.candidateIds.forEach((id) => {
        add(id);
        (peekInstanceIds(id) ?? []).forEach(add);
      });
    }
    creatableIds(leader.input).forEach(add);
    [leader, ...absorbed].forEach((intent) => (intent.extraLockKeys ?? []).forEach(add));
  });
  return Array.from(keys);
};

let current: SequencerBatchLock | null = null;

export const setCurrentBatchLock = (lock: SequencerBatchLock | null) => {
  current = lock;
};

export const getCurrentBatchLock = (): SequencerBatchLock | null => current;
