import { ENABLED_DEMO_MODE } from '../../config/conf';
import { FunctionalError } from '../../config/errors';
import { deleteElementById } from '../../database/middleware';
import { storeLoadById } from '../../database/middleware-loader';
import { killUserSessions } from '../../database/session';
import { publishUserAction } from '../../listener/UserActionListener';
import { ENTITY_TYPE_USER } from '../../schema/internalObject';
import type { BasicStoreCommon } from '../../types/store';
import type { AuthContext, AuthUser } from '../../types/user';
import { REDACTED_USER, SYSTEM_USER } from '../../utils/access';
import { buildUserMergeCoverage } from './userMerge-coverage';
import { executeUserMerge } from './userMerge-engine';
import { UserMergeRightsStrategy, UserMergeStatus } from './userMerge-types';

/**
 * Whether the source account of a past merge may now be deleted.
 *
 * Deleting the source is a separate operation from the merge, and it is gated rather than
 * chained to it: a merge that leaves references behind is recoverable by running it again,
 * whereas deleting the account they point at is not. A filter naming a deleted user matches
 * nothing rather than raising, so the damage would also be silent.
 *
 * The gate answers three questions, and combining them is the point: each operand is available
 * on its own, but which of them has to hold before a source is deleted is a procedure, not
 * something to leave to whoever runs the operation.
 */
export interface UserMergeSourceDeletionReadiness {
  allowed: boolean;
  coverage_complete: boolean;
  /** References to the source a dry-run still plans to move. Only meaningful when it ran. */
  pending_change_count: number;
  /** Human-readable reasons the deletion is refused. Empty when it is allowed. */
  blockers: string[];
}

type DeletableUser = BasicStoreCommon & { user_email?: string; account_status?: string; merged_into?: string };

/**
 * A dry-run at deletion time rather than a record of a past merge.
 *
 * A record attests to the past and can be wrong about the present: references to the source
 * created after the merge — a manual operation, an import, a draft validated late — would leave
 * it reading "complete". The dry-run cannot be wrong about the current state, and it has both
 * of its operands because the source is still there: the merge disables it, it does not delete it.
 *
 * The mark the merge leaves on the source is read, and it is not a verdict either: it says which
 * target this account was merged into, which is an identity fact and stays true. What is left to
 * move is still the dry-run's answer alone.
 *
 * The journal is read for one thing only, and it is not a verdict: when the merge on this pair
 * started. Handlers need that instant to leave the merge's own traces alone, and it has to be the
 * first run rather than this one — the traces of a past merge name the source too, and counting
 * them as pending would refuse the deletion forever.
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
  // The mark the merge writes on its source, not the account status: a merge does expire the
  // account, but so does an administrator and so does an expiration date coming due, and the gate
  // needs the converse. Reading the status alone lets a wrong pair through whenever the source
  // happens to be disabled and the dry-run plans nothing because the two accounts are unrelated —
  // and it never checks the pair at all. Without this the gate would delete an account no merge
  // ever touched, permanently, on a typo.
  const source = await storeLoadById<DeletableUser>(context, SYSTEM_USER, sourceId, ENTITY_TYPE_USER);
  if (source && source.merged_into !== targetId) {
    blockers.push('no merge into this target has been recorded on the source account');
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

/**
 * Deletes the source account, and nothing else.
 *
 * `userDelete` is deliberately not reused. Its four cascades — triggers and digests, notifications,
 * workspaces, public sharing — all select by a reference to the account being deleted, so once a
 * merge has moved those references they find nothing and the cascades are no-ops. That is exactly
 * why running them is the wrong trade: they are worthless when coverage held, and destructive when
 * it did not. A reference the merge missed does not make the cascade skip a Trigger or a Workspace,
 * it makes the cascade delete it — and after the merge that object belongs to the target.
 *
 * Not running them turns a coverage gap into an orphan reference, which a re-run repairs, instead
 * of a deletion, which nothing repairs. The generic detector reports what is left without blocking,
 * so the gate cannot promise the gap is closed; the deletion is written to survive being wrong.
 *
 * The non-destructive halves of `userDelete` are kept: the activity trace and the session kill.
 * A User is an internal object, so it is not trashable and the deletion is permanent — the source
 * document does not survive in the trash index carrying everything the merge just moved.
 */
export const deleteUserMergeSource = async (
  context: AuthContext,
  user: AuthUser,
  sourceId: string,
  targetId: string,
): Promise<string> => {
  const readiness = await computeUserMergeSourceDeletionReadiness(context, sourceId, targetId);
  if (!readiness.allowed) {
    throw FunctionalError('Source account cannot be deleted yet', { sourceId, targetId, blockers: readiness.blockers });
  }
  const deleted = await deleteElementById(context, user, sourceId, ENTITY_TYPE_USER) as unknown as DeletableUser;
  const deletedEmail = ENABLED_DEMO_MODE ? REDACTED_USER.user_email : deleted.user_email;
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'delete',
    event_access: 'administration',
    message: `deletes merged user \`${deletedEmail}\``,
    context_data: { id: sourceId, entity_type: ENTITY_TYPE_USER, input: { source_id: sourceId, target_id: targetId } },
  });
  await killUserSessions(sourceId);
  return sourceId;
};
