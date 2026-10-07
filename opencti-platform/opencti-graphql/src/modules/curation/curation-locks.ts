import { lockResources } from '../../lock/master-lock';

const withLock = async <T>(key: string, fn: () => Promise<T>, opts: { retryCount?: number } = {}): Promise<T> => {
  let lock;
  try {
    lock = await lockResources([key], opts);
    return await fn();
  } finally {
    if (lock) {
      await lock.unlock();
    }
  }
};

/**
 * Runs one status transition of a proposal at a time (accept, reject, decide, revert, recording an adjudication):
 * callers read the proposal again under the lock, so two decisions never both see it open and both change the graph.
 * The key is not an element id, so it never collides with the locks the merge and the unmerge take on participants.
 */
export const withProposalTransitionLock = <T>(id: string, fn: () => Promise<T>, opts: { retryCount?: number } = {}) => {
  return withLock(`curation-proposal-transition-${id}`, fn, opts);
};

/** Persists one finding at a time: its lookup by fingerprint and the creation of its proposal never interleave. */
export const withProposalFingerprintLock = <T>(fingerprint: string, fn: () => Promise<T>) => withLock(`curation-proposal-fingerprint-${fingerprint}`, fn);

/**
 * Schedules one policy application at a time, whatever the policy: the proposals it queues are read and handed to a
 * background task under the lock, so two runs never queue the same proposal.
 */
export const withPolicySchedulingLock = <T>(fn: () => Promise<T>) => withLock('curation-policy-scheduling', fn);

/**
 * Creates one Knowledge health snapshot at a time, from the manager or a manual refresh: each reads the snapshot it
 * follows under the lock, so two snapshots never cover the same activity window.
 */
export const withHealthSnapshotLock = <T>(fn: () => Promise<T>) => withLock('curation-health-snapshot', fn);

/** Runs one adjudication request of a proposal at a time, so concurrent requests never call the agent twice. */
export const withProposalAdjudicationLock = <T>(id: string, fn: () => Promise<T>) => withLock(`curation-proposal-adjudication-${id}`, fn);
