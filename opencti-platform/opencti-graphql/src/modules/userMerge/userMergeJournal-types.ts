import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import type { StixObject, StixOpenctiExtensionSDO } from '../../types/stix-2-1-common';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';

export const ENTITY_TYPE_USER_MERGE_JOURNAL = 'UserMergeJournal';

interface UserMergeJournalFields {
  /** Groups every entry of one execution. */
  merge_id: string;
  source_user_id: string;
  target_user_id: string;
  handler: string;
  /** Which of the two passes wrote this entry. */
  dry_run: boolean;
  status: string;
  started_at: Date;
  completed_at?: Date;
  message?: string;
  /** JSON-serialized UserMergeHandlerOutcome. */
  output?: string;
  updated_count?: number;
}

export interface BasicStoreEntityUserMergeJournal extends BasicStoreEntity, UserMergeJournalFields {}

export interface StoreEntityUserMergeJournal extends StoreEntity, UserMergeJournalFields {}

export interface StixUserMergeJournal extends StixObject, UserMergeJournalFields {
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtensionSDO;
  };
}
