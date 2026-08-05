import { v4 as uuidv4 } from 'uuid';
import { logApp } from '../../config/conf';
import { UnsupportedError } from '../../config/errors';
import type { AuthContext, AuthUser } from '../../types/user';
import { handlerDryRun, planFingerprint, type UserMergeHandler, type UserMergeHandlerContext, type UserMergeHandlerOutcome } from './userMerge-handler';
import { withJournalEntry, readJournalEntries } from './userMerge-journal';
import { buildApiUserMergeCoverage, type UserMergeCoverage } from './userMerge-coverage';
import { USER_MERGE_REGISTRY_VERSION } from './userMerge-register';
import { assertHandlersAreDisjoint, userMergeHandlers } from './userMerge-registry';
import { type UserMergeJournalEntry, type UserMergeOptions, type UserMergeResult, UserMergeStatus } from './userMerge-types';

const LOG_PREFIX = '[MERGE_USERS]';

export interface UserMergeExecutionReport {
  merge_id: string;
  registry_version: string;
  handlers: UserMergeHandlerOutcome[];
  total_updated: number;
  /**
   * Attached to every report, not only on demand. A report showing three handlers that
   * succeeded reads as a complete merge unless it also says what the register still holds.
   */
  coverage: UserMergeCoverage;
}

const buildReport = (mergeId: string, outcomes: UserMergeHandlerOutcome[]): UserMergeExecutionReport => ({
  merge_id: mergeId,
  registry_version: USER_MERGE_REGISTRY_VERSION,
  handlers: outcomes,
  total_updated: outcomes.reduce((total, outcome) => total + outcome.updated, 0),
  coverage: buildApiUserMergeCoverage(),
});

/**
 * Real pass for one handler: recompute, prove the computation still matches what the dry
 * pass reported, then write.
 *
 * The platform is required to be at rest during a merge, so a divergence here is not a race
 * to be retried — it is the premise of the operation being false. Writing anyway would apply
 * changes the operator never reviewed, which is precisely what the dry-run exists to prevent.
 */
const applyHandler = async (
  handler: UserMergeHandler,
  handlerContext: UserMergeHandlerContext,
  dryOutcome: UserMergeHandlerOutcome,
): Promise<UserMergeHandlerOutcome> => {
  const plan = await handler.compute(handlerContext);
  if (planFingerprint(plan) !== planFingerprint(dryOutcome)) {
    throw UnsupportedError('Platform state changed between the dry pass and the real pass, nothing was written for this handler', {
      handler: handler.identifier,
    });
  }
  const updated = await handler.apply(handlerContext, plan);
  return { ...plan, updated };
};

/**
 * Two full passes, never interleaved.
 *
 * Every handler computes first, the complete report is produced, and only then does any
 * handler write. Interleaving — compute A, write A, compute B — would let B observe what A
 * wrote, so B's dry figure and B's real figure would describe different platform states and
 * "dry-run == real impact" would stop holding at the second handler.
 *
 * The dry pass is journalled too. An operator who lost the connection mid-dry-run still has
 * a queryable trace of what was computed, and the two passes are distinguishable by dry_run.
 */
export const executeUserMerge = async (
  context: AuthContext,
  user: AuthUser,
  sourceId: string,
  targetId: string,
  options: UserMergeOptions,
): Promise<UserMergeResult & { report?: UserMergeExecutionReport }> => {
  const mergeId = uuidv4();
  const startedAt = new Date();
  const baseResult = {
    id: mergeId,
    source_id: sourceId,
    target_id: targetId,
    dry_run: options.dryRun,
    rights_strategy: options.rightsStrategy,
    started_at: startedAt,
  };
  try {
    const handlers = userMergeHandlers();
    assertHandlersAreDisjoint(handlers);
    const handlerContext: UserMergeHandlerContext = { context, sourceId, targetId, options };
    const journalInput = { mergeId, sourceId, targetId };

    const dryOutcomes: UserMergeHandlerOutcome[] = [];
    for (let i = 0; i < handlers.length; i += 1) {
      const handler = handlers[i];
      const outcome = await withJournalEntry(
        context,
        user,
        { ...journalInput, handler: handler.identifier, dryRun: true },
        () => handlerDryRun(handler, handlerContext),
      );
      dryOutcomes.push(outcome);
    }
    if (options.dryRun) {
      return { ...baseResult, status: UserMergeStatus.Success, completed_at: new Date(), report: buildReport(mergeId, dryOutcomes) };
    }

    const outcomes: UserMergeHandlerOutcome[] = [];
    for (let i = 0; i < handlers.length; i += 1) {
      const handler = handlers[i];
      const outcome = await withJournalEntry(
        context,
        user,
        { ...journalInput, handler: handler.identifier, dryRun: false },
        () => applyHandler(handler, handlerContext, dryOutcomes[i]),
      );
      outcomes.push(outcome);
    }
    return { ...baseResult, status: UserMergeStatus.Success, completed_at: new Date(), report: buildReport(mergeId, outcomes) };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    logApp.error(`${LOG_PREFIX} merge failed`, { merge_id: mergeId, source_id: sourceId, target_id: targetId, cause: message });
    // The failure is returned rather than thrown so the caller keeps the merge id: what was
    // and was not applied before the failure is only readable from the journal.
    return { ...baseResult, status: UserMergeStatus.Failed, completed_at: new Date(), message };
  }
};

export const readUserMergeJournal = async (
  context: AuthContext,
  user: AuthUser,
  mergeId?: string,
  first?: number,
): Promise<UserMergeJournalEntry[]> => {
  const entries = await readJournalEntries(context, user, mergeId, first);
  return entries.map((entry) => ({
    id: entry.internal_id,
    merge_id: entry.merge_id,
    source_id: entry.source_user_id,
    target_id: entry.target_user_id,
    handler: entry.handler,
    dry_run: entry.dry_run,
    status: entry.status as UserMergeStatus,
    started_at: entry.started_at,
    completed_at: entry.completed_at,
    message: entry.message,
  }));
};
