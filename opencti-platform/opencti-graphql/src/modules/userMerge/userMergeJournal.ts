import { v4 as uuidv4 } from 'uuid';
import { type ModuleDefinition, registerDefinition } from '../../schema/module';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import convertUserMergeJournalToStix from './userMergeJournal-converter';
import { ENTITY_TYPE_USER_MERGE_JOURNAL, type StixUserMergeJournal, type StoreEntityUserMergeJournal } from './userMergeJournal-types';

/**
 * The execution journal, persisted as the merge goes rather than as a single record at the
 * end. An interrupted run must stay diagnosable: on a 200-user batch, a failure on the 57th
 * leaves 56 completed merges, one partial and 143 untouched, and without a journal nothing
 * in the database says so.
 *
 * It is also what makes a resume possible. After a partial run, a handler's computation no
 * longer sees the already-moved objects, so an empty result is indistinguishable from a
 * broken handler — the journal is consulted instead of re-deriving it.
 *
 * An internal object rather than Redis, which serves locks and streams here and offers no
 * audit durability, and rather than the application log, which is neither queryable through
 * the API nor structured. Platform writes run with refresh: true, so an entry is immediately
 * readable from another session — which is what makes the follow-up query usable while the
 * merge is still running.
 */
const USER_MERGE_JOURNAL_DEFINITION: ModuleDefinition<StoreEntityUserMergeJournal, StixUserMergeJournal> = {
  type: {
    id: 'userMergeJournal',
    name: ENTITY_TYPE_USER_MERGE_JOURNAL,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_USER_MERGE_JOURNAL]: () => uuidv4(),
    },
  },
  attributes: [
    { name: 'merge_id', label: 'Merge id', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'source_user_id', label: 'Source user id', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'target_user_id', label: 'Target user id', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'handler', label: 'Handler', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'dry_run', label: 'Dry run', type: 'boolean', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'status', label: 'Merge status', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'started_at', label: 'Started at', type: 'date', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'completed_at', label: 'Completed at', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: false },
    { name: 'message', label: 'Message', type: 'string', format: 'text', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: false },
    { name: 'output', label: 'Output', type: 'string', format: 'json', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: false },
    { name: 'updated_count', label: 'Updated count', type: 'numeric', precision: 'integer', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: false },
  ],
  relations: [],
  representative: (stix: StixUserMergeJournal) => {
    return `${stix.merge_id} / ${stix.handler}`;
  },
  converter_2_1: convertUserMergeJournalToStix,
};

registerDefinition(USER_MERGE_JOURNAL_DEFINITION);
