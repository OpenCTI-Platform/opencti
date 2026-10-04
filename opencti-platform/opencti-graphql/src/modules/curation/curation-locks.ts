import { lockResources } from '../../lock/master-lock';

const withLock = async <T>(key: string, fn: () => Promise<T>): Promise<T> => {
  let lock;
  try {
    lock = await lockResources([key]);
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
export const withProposalTransitionLock = <T>(id: string, fn: () => Promise<T>) => withLock(`curation-proposal-transition-${id}`, fn);

/** Runs one adjudication request of a proposal at a time, so concurrent requests never call the agent twice. */
export const withProposalAdjudicationLock = <T>(id: string, fn: () => Promise<T>) => withLock(`curation-proposal-adjudication-${id}`, fn);
