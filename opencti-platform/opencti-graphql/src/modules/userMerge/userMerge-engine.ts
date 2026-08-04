import { v4 as uuidv4 } from 'uuid';
import { logApp } from '../../config/conf';
import { type UserMergeJournalEntry, type UserMergeOptions, type UserMergeResult, UserMergeStatus } from './userMerge-types';

const LOG_PREFIX = '[MERGE_USERS]';

/**
 * Stubbed merge engine.
 *
 * PR1 ships the API surface only, so this executes nothing. PR2 replaces this file with the
 * handler registry and the dry-run/run framework; the signature below is the one it must
 * honour, so the resolver and the domain guard-rails do not move when it lands.
 *
 * The placeholder deliberately reports FAILED rather than SUCCESS. Reporting success for
 * work that was never done is exactly the `cleanInconsistency` behaviour this feature is
 * specified against — an unimplemented engine must be impossible to mistake for a merge
 * that happened.
 */
export const executeUserMerge = async (
  sourceId: string,
  targetId: string,
  options: UserMergeOptions,
): Promise<UserMergeResult> => {
  const startedAt = new Date();
  logApp.warn(`${LOG_PREFIX} merge requested but the engine is not implemented yet, nothing was executed`, {
    source_id: sourceId,
    target_id: targetId,
    dry_run: options.dryRun,
    rights_strategy: options.rightsStrategy,
  });
  return {
    id: uuidv4(),
    source_id: sourceId,
    target_id: targetId,
    dry_run: options.dryRun,
    rights_strategy: options.rightsStrategy,
    status: UserMergeStatus.Failed,
    started_at: startedAt,
    completed_at: new Date(),
    message: 'Merge engine not implemented: this build ships the API surface only (PR1). No data was modified.',
  };
};

/**
 * Reads the execution journal. The journal entity itself is created by PR2, so this returns
 * an empty list for now — typed, so the query contract is reviewable and the frontend or an
 * operator script can be written against it before the engine exists.
 */
export const readUserMergeJournal = async (
  mergeId?: string,
  first?: number,
): Promise<UserMergeJournalEntry[]> => {
  logApp.debug(`${LOG_PREFIX} journal read but the journal is not implemented yet`, { merge_id: mergeId, first });
  return [];
};
