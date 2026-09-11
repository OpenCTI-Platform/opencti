import type { AuthContext } from '../../types/user';
import { buildUserMergeCoverage } from './userMerge-coverage';
import { executeUserMerge } from './userMerge-engine';
import { UserMergeRightsStrategy, UserMergeStatus } from './userMerge-types';

/**
 * Whether the source account of a past merge may now be deleted.
 *
 * Deleting the source is a separate operation from the merge, and it is out of the MVP: at this
 * point PR9/PR10/PR11 have not landed, so register rows a handler must claim are still
 * uncovered and deleting would leave references pointing at a user that no longer exists —
 * silently, since a filter naming a deleted user matches nothing rather than raising.
 *
 * What ships here is the gate, not the deletion. The deletion itself is written in PR11, once
 * coverage is complete, and it calls this. Shipping the destructive half now would mean code
 * that cannot run until then and cannot be exercised against a real platform.
 *
 * The gate answers two questions, and combining them is the point: both operands are already
 * exposed separately, but which of them has to hold before a source is deleted is a procedure,
 * not something to leave to whoever runs the operation.
 */
export interface UserMergeSourceDeletionReadiness {
  allowed: boolean;
  coverage_complete: boolean;
  /** References to the source a dry-run still plans to move. Only meaningful when it ran. */
  pending_change_count: number;
  /** Human-readable reasons the deletion is refused. Empty when it is allowed. */
  blockers: string[];
}

/**
 * A dry-run at deletion time rather than a record of a past merge.
 *
 * A record attests to the past and can be wrong about the present: references to the source
 * created after the merge — a manual operation, an import, a draft validated late — would leave
 * it reading "complete". The dry-run cannot be wrong about the current state, and it has both
 * of its operands because the source is still there: the merge disables it, it does not delete it.
 *
 * Run under the strict rights strategy, the one that widens nothing: the question is whether
 * anything is left to move, not what a new merge could be allowed to do.
 */
export const computeUserMergeSourceDeletionReadiness = async (
  context: AuthContext,
  sourceId: string,
  targetId: string,
): Promise<UserMergeSourceDeletionReadiness> => {
  const blockers: string[] = [];
  const coverage = buildUserMergeCoverage();
  if (!coverage.is_complete) {
    blockers.push(`${coverage.gating_uncovered_count} register rows a handler must claim are still uncovered`);
  }
  const result = await executeUserMerge(context, sourceId, targetId, {
    dryRun: true,
    rightsStrategy: UserMergeRightsStrategy.Strict,
    acknowledgeExposureChange: false,
  });
  if (result.status !== UserMergeStatus.Success || !result.report) {
    blockers.push(`the dry-run on the pair did not complete: ${result.message ?? 'unknown cause'}`);
    return { allowed: false, coverage_complete: coverage.is_complete, pending_change_count: 0, blockers };
  }
  const pending = result.report.handlers.reduce(
    (total, outcome) => total + outcome.changes.reduce((sum, change) => sum + change.count, 0),
    0,
  );
  if (pending > 0) {
    blockers.push(`${pending} references to the source are still pending; run the merge again before deleting`);
  }
  return { allowed: blockers.length === 0, coverage_complete: coverage.is_complete, pending_change_count: pending, blockers };
};
