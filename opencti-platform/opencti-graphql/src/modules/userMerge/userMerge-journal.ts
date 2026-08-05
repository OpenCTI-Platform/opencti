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
 * Runs a handler pass under the journal: opens an entry, records the outcome, and records
 * the failure too. A handler that throws must leave a FAILED entry, not an entry stuck in
 * RUNNING that is indistinguishable from a node that died.
 */
export const withJournalEntry = async <T extends UserMergeHandlerOutcome>(
  input: JournalEntryInput,
  execute: () => Promise<T>,
): Promise<T> => {
  const entryId = await openJournalEntry(input);
  try {
    const outcome = await execute();
    await closeJournalEntry(entryId, input.mergeId, { status: UserMergeStatus.Success, outcome });
    return outcome;
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    await closeJournalEntry(entryId, input.mergeId, { status: UserMergeStatus.Failed, message });
    logApp.error('[MERGE_USERS] handler failed', { handler: input.handler, merge_id: input.mergeId, cause: message });
    throw err;
  }
};

export const readJournalEntries = async (mergeId?: string, first?: number): Promise<UserMergeJournalRecord[]> => {
  const entries = await redisUserMergeJournalRead(mergeId) as UserMergeJournalRecord[];
  const sorted = [...entries].sort((a, b) => b.started_at.localeCompare(a.started_at));
  return first ? sorted.slice(0, first) : sorted;
};
