import { createEntity, updateAttribute } from '../../database/middleware';
import { fullEntitiesList } from '../../database/middleware-loader';
import { FilterMode, FilterOperator } from '../../generated/graphql';
import { utcDate } from '../../utils/format';
import { logApp } from '../../config/conf';
import type { AuthContext, AuthUser } from '../../types/user';
import { UserMergeStatus } from './userMerge-types';
import type { UserMergeHandlerOutcome } from './userMerge-handler';
import { type BasicStoreEntityUserMergeJournal, ENTITY_TYPE_USER_MERGE_JOURNAL } from './userMergeJournal-types';

export interface JournalEntryInput {
  mergeId: string;
  sourceId: string;
  targetId: string;
  handler: string;
  dryRun: boolean;
}

/**
 * Opens an entry before the handler runs, so that an execution killed mid-handler still
 * leaves a trace naming where it stopped. Writing only on completion would lose exactly the
 * case the journal exists for.
 */
export const openJournalEntry = async (context: AuthContext, user: AuthUser, input: JournalEntryInput): Promise<string> => {
  const created = await createEntity(context, user, {
    merge_id: input.mergeId,
    source_user_id: input.sourceId,
    target_user_id: input.targetId,
    handler: input.handler,
    dry_run: input.dryRun,
    status: UserMergeStatus.Running,
    started_at: utcDate().toISOString(),
  }, ENTITY_TYPE_USER_MERGE_JOURNAL);
  return created.internal_id;
};

export const closeJournalEntry = async (
  context: AuthContext,
  user: AuthUser,
  entryId: string,
  result: { status: UserMergeStatus; message?: string; outcome?: UserMergeHandlerOutcome },
): Promise<void> => {
  await updateAttribute(context, user, entryId, ENTITY_TYPE_USER_MERGE_JOURNAL, [
    { key: 'status', value: [result.status] },
    { key: 'completed_at', value: [utcDate().toISOString()] },
    { key: 'message', value: [result.message ?? ''] },
    { key: 'output', value: [result.outcome ? JSON.stringify(result.outcome) : ''] },
    { key: 'updated_count', value: [result.outcome?.updated ?? 0] },
  ]);
};

/**
 * Runs a handler pass under the journal: opens an entry, records the outcome, and records
 * the failure too. A handler that throws must leave a FAILED entry, not an entry stuck in
 * RUNNING that is indistinguishable from a node that died.
 */
export const withJournalEntry = async <T extends UserMergeHandlerOutcome>(
  context: AuthContext,
  user: AuthUser,
  input: JournalEntryInput,
  execute: () => Promise<T>,
): Promise<T> => {
  const entryId = await openJournalEntry(context, user, input);
  try {
    const outcome = await execute();
    await closeJournalEntry(context, user, entryId, { status: UserMergeStatus.Success, outcome });
    return outcome;
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    await closeJournalEntry(context, user, entryId, { status: UserMergeStatus.Failed, message });
    logApp.error('[MERGE_USERS] handler failed', { handler: input.handler, merge_id: input.mergeId, cause: message });
    throw err;
  }
};

export const readJournalEntries = async (
  context: AuthContext,
  user: AuthUser,
  mergeId?: string,
  first?: number,
): Promise<BasicStoreEntityUserMergeJournal[]> => {
  const filters = mergeId
    ? {
        mode: FilterMode.And,
        filters: [{ key: ['merge_id'], values: [mergeId], operator: FilterOperator.Eq, mode: FilterMode.Or }],
        filterGroups: [],
      }
    : undefined;
  const entries = await fullEntitiesList<BasicStoreEntityUserMergeJournal>(
    context,
    user,
    [ENTITY_TYPE_USER_MERGE_JOURNAL],
    { filters, orderBy: 'started_at', orderMode: 'desc' as never },
  );
  return first ? entries.slice(0, first) : entries;
};
