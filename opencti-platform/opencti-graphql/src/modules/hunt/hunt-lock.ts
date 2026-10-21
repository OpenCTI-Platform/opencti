import { LockTimeoutError, TYPE_LOCK_ERROR } from '../../config/errors';
import { lockResources } from '../../lock/master-lock';

/** The lock of the transitions of a run: its dispatch, connector reports, expiry, cancellation and replacement. */
export const huntRunTransitionLockKey = (runId: string) => `hunt_run_transition_${runId}`;

/** The lock of the changes validated against the stored state of a hunt: its edits, and its targets, techniques and sources. */
export const huntStateLockKey = (huntId: string) => `hunt_state_${huntId}`;

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
