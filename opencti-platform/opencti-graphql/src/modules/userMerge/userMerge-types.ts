/**
 * Contract of the user merge feature.
 *
 * PR1 ships this contract and a stubbed engine. PR2 replaces the stub with the real
 * handler registry; nothing in this file is expected to change when it does, because the
 * shape returned in dry mode and in real mode is deliberately identical.
 */

import type { UserMergeHandlerOutcome } from './userMerge-handler';

export const MERGE_USERS_MODULE_NAME = 'userMerge';

/**
 * Field naming the account a source was merged into, written on the source by the merge.
 *
 * It states a fact about identity, not a verdict about references: "this account was merged
 * into that one" stays true forever, whereas "its references are clean" is a claim about the
 * present that only a dry-run can make. The deletion gate keeps asking the dry-run; this field
 * exists so that the *ordinary* deletion path can recognise a merged source and refuse it.
 *
 * Declared here rather than in a handler file because `domain/user` reads it, and this module
 * imports `domain/user`: any other home would close an import cycle.
 */
export const USER_MERGED_INTO_FIELD = 'merged_into';

export enum UserMergeRightsStrategy {
  Strict = 'STRICT',
  Union = 'UNION',
}

export enum UserMergeStatus {
  Running = 'RUNNING',
  Success = 'SUCCESS',
  Failed = 'FAILED',
}

/**
 * Options left to the operator.
 *
 * Kept minimal on purpose: every option multiplies the combinations the dry-run has to be
 * proven against, and the promise of this feature is that the dry-run is trustworthy.
 * Everything settled during spec review stays non-configurable.
 */
export interface UserMergeOptions {
  /**
   * Write-suppression flag on a single execution path, not a separate estimation endpoint.
   * Defaults to true: calling the mutation without options must never rewrite data.
   */
  dryRun: boolean;
  rightsStrategy: UserMergeRightsStrategy;
  /**
   * Lets the real pass proceed despite a blocking alert. Defaults to false: a merge that
   * widens what the source's data is exposed under has to be decided, not discovered.
   */
  acknowledgeExposureChange: boolean;
}

/**
 * Result of one merge execution. Same shape in dry and real mode — that identity is what
 * makes "dry-run == real impact" verifiable from the API alone.
 */
export interface UserMergeResult {
  id: string;
  source_id: string;
  target_id: string;
  dry_run: boolean;
  rights_strategy: UserMergeRightsStrategy;
  status: UserMergeStatus;
  started_at: Date;
  completed_at?: Date;
  message?: string;
}

/**
 * One entry of the execution journal, written per handler as the merge progresses (PR2).
 * Reading it is how a run stays observable when the HTTP connection dies.
 */
export interface UserMergeJournalEntry {
  id: string;
  merge_id: string;
  source_id: string;
  target_id: string;
  handler: string;
  dry_run: boolean;
  status: UserMergeStatus;
  started_at: Date;
  completed_at?: Date;
  message?: string;
  updated_count?: number;
  outcome?: UserMergeHandlerOutcome;
}
