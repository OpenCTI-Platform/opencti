import { v4 as uuidv4 } from 'uuid';
import { redisUserMergeJournalRead, redisUserMergeJournalUpsert } from '../../database/redis';
import { utcDate } from '../../utils/format';
import { logApp } from '../../config/conf';
import { UserMergeStatus } from './userMerge-types';
import type { UserMergeHandlerOutcome } from './userMerge-handler';

export interface JournalEntryInput {
  mergeId: string;
  sourceId: string;
  targetId: string;
  handler: string;
  dryRun: boolean;
}

export interface UserMergeJournalRecord {
  id: string;
  merge_id: string;
  source_user_id: string;
  target_user_id: string;
  handler: string;
  dry_run: boolean;
  status: UserMergeStatus;
  started_at: string;
  completed_at?: string;
  message?: string;
  /** JSON-serialized UserMergeHandlerOutcome. */
  output?: string;
  updated_count?: number;
}

/**
 * Opens an entry before the handler runs, so that an execution killed mid-handler still
 * leaves a trace naming where it stopped. Writing only on completion would lose exactly the
 * case the journal exists for.
 */
export const openJournalEntry = async (input: JournalEntryInput): Promise<string> => {
  const entryId = uuidv4();
  await redisUserMergeJournalUpsert(entryId, input.mergeId, {
    id: entryId,
    merge_id: input.mergeId,
    source_user_id: input.sourceId,
    target_user_id: input.targetId,
    handler: input.handler,
    dry_run: input.dryRun,
    status: UserMergeStatus.Running,
    started_at: utcDate().toISOString(),
  });
  return entryId;
};

export const closeJournalEntry = async (
  entryId: string,
  mergeId: string,
  result: { status: UserMergeStatus; message?: string; outcome?: UserMergeHandlerOutcome },
): Promise<void> => {
  await redisUserMergeJournalUpsert(entryId, mergeId, {
    status: result.status,
    completed_at: utcDate().toISOString(),
    message: result.message,
    output: result.outcome ? JSON.stringify(result.outcome) : undefined,
    updated_count: result.outcome?.updated ?? 0,
  });
};

/**
 * Closes an entry without letting the journal decide the fate of the merge.
 *
 * The journal is diagnostic: a Redis write that fails must not turn a handler that succeeded
 * — and already wrote to the platform — into a FAILED entry, nor abort the run over a trace
 * nobody has read yet. The failure is logged, and the entry stays RUNNING, which reads as
 * what it is: an execution whose end was not recorded.
 */
const closeJournalEntrySafely = async (
  entryId: string,
  mergeId: string,
  result: { status: UserMergeStatus; message?: string; outcome?: UserMergeHandlerOutcome },
): Promise<void> => {
  try {
    await closeJournalEntry(entryId, mergeId, result);
  } catch (err) {
    const cause = err instanceof Error ? err.message : String(err);
    logApp.error('[MERGE_USERS] journal entry not closed', { entry_id: entryId, merge_id: mergeId, cause });
  }
};

/**
 * Runs a handler pass under the journal: opens an entry, records the outcome, and records
 * the failure too. A handler that throws must leave a FAILED entry, not an entry stuck in
 * RUNNING that is indistinguishable from a node that died.
 */
export const withJournalEntry = async <T extends UserMergeHandlerOutcome>(
  input: JournalEntryInput,
  execute: () => Promise<T>,
): Promise<T> => {
  const entryId = await openJournalEntry(input);
  let outcome: T;
  try {
    outcome = await execute();
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    logApp.error('[MERGE_USERS] handler failed', { handler: input.handler, merge_id: input.mergeId, cause: message });
    await closeJournalEntrySafely(entryId, input.mergeId, { status: UserMergeStatus.Failed, message });
    throw err;
  }
  await closeJournalEntrySafely(entryId, input.mergeId, { status: UserMergeStatus.Success, outcome });
  return outcome;
};

export const readJournalEntries = async (mergeId?: string, first?: number): Promise<UserMergeJournalRecord[]> => {
  const entries = await redisUserMergeJournalRead(mergeId) as UserMergeJournalRecord[];
  const sorted = [...entries].sort((a, b) => b.started_at.localeCompare(a.started_at));
  return first ? sorted.slice(0, first) : sorted;
};

/**
 * The instant the first real merge on this pair started, or the given fallback when there is none.
 *
 * Handlers reading the history index cut on this to tell what named the source before the merge
 * from what the merge itself wrote about the source. That boundary has to be a property of the
 * pair, not of the run: the deletion gate answers by running a fresh dry-run, so a boundary set
 * at the current instant would let the previous merge's own traces back in, count them as
 * references still pending, and refuse the deletion forever.
 *
 * Dry-runs are skipped because they write nothing to bound. The journal expires after 30 days, so
 * a pair merged longer ago reads as never merged and the gate refuses — the safe way to be wrong.
 */
export const resolveMergeStartedAt = async (sourceId: string, targetId: string, fallback: Date): Promise<Date> => {
  const entries = await redisUserMergeJournalRead() as UserMergeJournalRecord[];
  const starts = entries
    .filter((entry) => !entry.dry_run && entry.source_user_id === sourceId && entry.target_user_id === targetId)
    .map((entry) => new Date(entry.started_at).getTime())
    .filter((time) => !Number.isNaN(time));
  return starts.length > 0 ? new Date(Math.min(...starts)) : fallback;
};
