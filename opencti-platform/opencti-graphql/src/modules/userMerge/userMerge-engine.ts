import { v4 as uuidv4 } from 'uuid';
import { logApp } from '../../config/conf';
import { UnsupportedError } from '../../config/errors';
import type { AuthContext } from '../../types/user';
import { handlerDryRun, planDivergence, planFingerprint, type UserMergeHandler, type UserMergeHandlerContext, type UserMergeHandlerOutcome } from './userMerge-handler';
import { readJournalEntries, withJournalEntry } from './userMerge-journal';
import { buildApiUserMergeCoverage, type UserMergeApiCoverage } from './userMerge-coverage';
import { USER_MERGE_REGISTER_VERSION } from './userMerge-register';
import { userMergeHandlers } from './userMerge-registry';
import { type UserMergeJournalEntry, type UserMergeOptions, type UserMergeResult, UserMergeStatus } from './userMerge-types';

const LOG_PREFIX = '[MERGE_USERS]';

export interface UserMergeExecutionReport {
  merge_id: string;
  register_version: string;
  handlers: UserMergeHandlerOutcome[];
  total_updated: number;
  /**
   * Attached to every report, not only on demand. A report showing three handlers that
   * succeeded reads as a complete merge unless it also says what the register still holds.
   */
  coverage: UserMergeApiCoverage;
}

/** Coverage is built from the handlers that actually ran, not from the registry read again. */
const buildReport = (mergeId: string, handlers: UserMergeHandler[], outcomes: UserMergeHandlerOutcome[]): UserMergeExecutionReport => ({
  merge_id: mergeId,
  register_version: USER_MERGE_REGISTER_VERSION,
  handlers: outcomes,
  total_updated: outcomes.reduce((total, outcome) => total + outcome.updated, 0),
  coverage: buildApiUserMergeCoverage(handlers),
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
      ...planDivergence(dryOutcome, plan),
    });
  }
  const updated = await handler.apply(handlerContext, plan);
  return { ...plan, updated };
};

/**
 * Gate placed between the two passes, which is where the human decision belongs.
 *
 * Blocking on the dry pass would hide the difference from the report the operator needs to
 * decide with; blocking inside a handler's write would stop the merge after earlier handlers
 * already wrote.
 */
const assertBlockingAlertsAcknowledged = (outcomes: UserMergeHandlerOutcome[], options: UserMergeOptions): void => {
  if (options.acknowledgeExposureChange) {
    return;
  }
  const blocking = outcomes.flatMap((outcome) => outcome.alerts.filter((alert) => alert.blocking));
  if (blocking.length > 0) {
    throw UnsupportedError('Merge blocked by unacknowledged alerts, nothing was written', {
      alerts: blocking.map((alert) => ({ register_row_id: alert.register_row_id, kind: alert.kind, message: alert.message })),
    });
  }
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
 *
 * No calling user is taken: whether a merge may be asked for at all is decided in the domain
 * layer, and a merge rewrites references the caller has no reason to be allowed to read.
 */
export const executeUserMerge = async (
  context: AuthContext,
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
    const handlerContext: UserMergeHandlerContext = { context, sourceId, targetId, options };
    const journalInput = { mergeId, sourceId, targetId };

    const dryOutcomes: UserMergeHandlerOutcome[] = [];
    for (let i = 0; i < handlers.length; i += 1) {
      const handler = handlers[i];
      const outcome = await withJournalEntry(
        { ...journalInput, handler: handler.identifier, dryRun: true },
        () => handlerDryRun(handler, handlerContext),
      );
      dryOutcomes.push(outcome);
    }
    if (options.dryRun) {
      return { ...baseResult, status: UserMergeStatus.Success, completed_at: new Date(), report: buildReport(mergeId, handlers, dryOutcomes) };
    }
    assertBlockingAlertsAcknowledged(dryOutcomes, options);

    const outcomes: UserMergeHandlerOutcome[] = [];
    for (let i = 0; i < handlers.length; i += 1) {
      const handler = handlers[i];
      const outcome = await withJournalEntry(
        { ...journalInput, handler: handler.identifier, dryRun: false },
        () => applyHandler(handler, handlerContext, dryOutcomes[i]),
      );
      outcomes.push(outcome);
    }
    return { ...baseResult, status: UserMergeStatus.Success, completed_at: new Date(), report: buildReport(mergeId, handlers, outcomes) };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    logApp.error(`${LOG_PREFIX} merge failed`, { merge_id: mergeId, source_id: sourceId, target_id: targetId, cause: message });
    // The failure is returned rather than thrown so the caller keeps the merge id: what was
    // and was not applied before the failure is only readable from the journal.
    return { ...baseResult, status: UserMergeStatus.Failed, completed_at: new Date(), message };
  }
};

/**
 * Reads back what a handler recorded. Corrupt or truncated payloads are dropped rather than
 * propagated: the journal is what an operator falls back on when a run went wrong, so it has
 * to stay readable even when one entry is not.
 */
const parseJournalOutcome = (output?: string): UserMergeHandlerOutcome | undefined => {
  if (!output) {
    return undefined;
  }
  try {
    return JSON.parse(output) as UserMergeHandlerOutcome;
  } catch (err) {
    logApp.warn(`${LOG_PREFIX} unreadable journal outcome`, { cause: err instanceof Error ? err.message : String(err) });
    return undefined;
  }
};

export const readUserMergeJournal = async (
  mergeId?: string,
  first?: number,
): Promise<UserMergeJournalEntry[]> => {
  const entries = await readJournalEntries(mergeId, first);
  return entries.map((entry) => ({
    id: entry.id,
    merge_id: entry.merge_id,
    source_id: entry.source_user_id,
    target_id: entry.target_user_id,
    handler: entry.handler,
    dry_run: entry.dry_run,
    status: entry.status,
    started_at: new Date(entry.started_at),
    completed_at: entry.completed_at ? new Date(entry.completed_at) : undefined,
    message: entry.message,
    updated_count: entry.updated_count,
    outcome: parseJournalOutcome(entry.output),
  }));
};
