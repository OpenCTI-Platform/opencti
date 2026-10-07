import { LockTimeoutError, TYPE_LOCK_ERROR } from '../../config/errors';
import { lockResources } from '../../lock/master-lock';

/** The lock of the transitions of a run: its dispatch, connector reports, expiry, cancellation and replacement. */
export const huntRunTransitionLockKey = (runId: string) => `hunt_run_transition_${runId}`;

/**
 * Runs the action while holding the platform-wide lock of the key, so that check-then-write sequences of the hunt module
 * (run transitions, connector reservations, playbook debounce) never interleave across platform nodes.
 */
export const withHuntLock = async <T>(lockKey: string, action: () => Promise<T>): Promise<T> => {
  let lock;
  try {
    lock = await lockResources([lockKey]);
    return await action();
  } catch (e: any) {
    if (e.name === TYPE_LOCK_ERROR) {
      throw LockTimeoutError({ participantIds: [lockKey] });
    }
    throw e;
  } finally {
    if (lock) {
      await lock.unlock();
    }
  }
};
