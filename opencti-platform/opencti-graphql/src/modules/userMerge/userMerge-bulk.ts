import { DatabaseError } from '../../config/errors';
import { elRawUpdateByQuery } from '../../database/engine';
import { logApp } from '../../config/conf';

/** What an update actually did. All four counters are surfaced, none is swallowed. */
export interface UserMergeBulkResult {
  updated: number;
  total: number;
  failures: unknown[];
  version_conflicts: number;
}

/**
 * Bulk update primitive for the merge engine.
 *
 * None of the platform's existing paths is usable here, and this is what the coverage
 * manifest's real counts depend on:
 *
 * - `elOperationForMigration` polls the task until `completed` and logs the duration, but
 *   never inspects `failures` or `version_conflicts`, and returns nothing. A task that
 *   updates 3 000 documents out of 10 000 and conflicts on the rest is reported as a success.
 * - The other bulk paths run with `conflicts: 'proceed'`, silently skipping conflicting
 *   documents; one of them is fire-and-forget, with no task follow-up at all.
 *
 * This wrapper surfaces the counters and fails on any non-empty failure or conflict. The
 * platform is supposed to be at rest during a merge, so a conflict means the execution
 * precondition was violated — precisely when to stop rather than carry on.
 */
export const userMergeBulkUpdate = async (
  label: string,
  indices: string[],
  body: Record<string, unknown>,
): Promise<UserMergeBulkResult> => {
  const response = await elRawUpdateByQuery({
    index: indices,
    refresh: true,
    // Deliberately not 'proceed': a conflict is a violated precondition, not something to skip.
    conflicts: 'abort',
    wait_for_completion: true,
    body,
  }).catch((err) => {
    throw DatabaseError('User merge bulk update failed', { label, cause: err });
  });
  const result: UserMergeBulkResult = {
    updated: response.updated ?? 0,
    total: response.total ?? 0,
    failures: response.failures ?? [],
    version_conflicts: response.version_conflicts ?? 0,
  };
  if (result.failures.length > 0 || result.version_conflicts > 0) {
    throw DatabaseError('User merge bulk update reported failures or version conflicts', {
      label,
      updated: result.updated,
      total: result.total,
      failure_count: result.failures.length,
      version_conflicts: result.version_conflicts,
    });
  }
  logApp.info('[MERGE_USERS] bulk update done', { label, updated: result.updated, total: result.total });
  return result;
};
