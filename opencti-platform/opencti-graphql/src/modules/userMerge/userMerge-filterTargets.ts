import { ENTITY_TYPE_BACKGROUND_TASK, ENTITY_TYPE_CONNECTOR, ENTITY_TYPE_RETENTION_RULE } from '../../schema/internalObject';
import { ENTITY_TYPE_FEED } from '../dataSharing/feed-types';
import { ENTITY_TYPE_STREAM_COLLECTION } from '../dataSharing/streamCollection-types';
import { ENTITY_TYPE_TAXII_COLLECTION } from '../dataSharing/taxiiCollection-types';
import { ENTITY_TYPE_DECAY_RULE } from '../decayRule/decayRule-types';
import { ENTITY_TYPE_DECAY_EXCLUSION_RULE } from '../decayRule/exclusions/decayExclusionRule-types';
import { ENTITY_TYPE_FINTEL_TEMPLATE } from '../fintelTemplate/fintelTemplate-types';
import { ENTITY_TYPE_TRIGGER } from '../notification/notification-types';
import { ENTITY_TYPE_PIR } from '../pir/pir-types';
import { ENTITY_TYPE_SAVED_FILTER } from '../savedFilter/savedFilter-types';

/**
 * How the filter string sits on the document.
 *
 * `field` is a plain serialized field. `criteria-array` is the PIR criteria list, an array of
 * weighted objects each holding its own serialized filter.
 */
export type UserMergeFilterShape = 'field' | 'criteria-array';

/**
 * A lifecycle state the platform is not supposed to be in during a merge.
 *
 * The precondition is an idle platform with no worker and no connector running. The register
 * asks for a connector to be paused and for a running task to be drained, which protects
 * nothing once that precondition holds — so the state is reported rather than orchestrated,
 * following what the scalar handler already does for a pending background task.
 */
export interface UserMergeFilterActivity {
  path: string;
  equals: string | boolean;
  negate?: boolean;
}

export interface UserMergeFilterTarget {
  /** Stable identifier, used in the report detail and in the journal. */
  id: string;
  registerRow: string;
  entityType: string;
  path: string;
  shape: UserMergeFilterShape;
  activity?: UserMergeFilterActivity;
}

/**
 * Every stored filter that can name a user.
 *
 * `History.context_data` also holds filters, and is deliberately absent: its volume is of a
 * different order, the payload is a frozen snapshot that is never re-executed, never rendered
 * as an editable chip and never scored, and the register groups it with the raw mutation input
 * and the subject ids that belong to later chunks. It is claimed whole, later.
 *
 * `InternalFile.list_filters` is absent for the same reason and is claimed at zero: the
 * register disposes of it as `retain`, being the provenance snapshot of an export.
 */
export const USER_MERGE_FILTER_TARGETS: UserMergeFilterTarget[] = [
  { id: 'trigger-filters', registerRow: 'trigger.filters', entityType: ENTITY_TYPE_TRIGGER, path: 'filters', shape: 'field' },
  { id: 'feed-filters', registerRow: 'feed.filters', entityType: ENTITY_TYPE_FEED, path: 'filters', shape: 'field' },
  { id: 'stream-collection-filters', registerRow: 'stream-collection.filters', entityType: ENTITY_TYPE_STREAM_COLLECTION, path: 'filters', shape: 'field' },
  {
    id: 'stream-collection-origin-filters',
    registerRow: 'stream-collection.origin-filters',
    entityType: ENTITY_TYPE_STREAM_COLLECTION,
    path: 'origin_filters',
    shape: 'field',
  },
  { id: 'taxii-collection-filters', registerRow: 'taxii-collection.filters', entityType: ENTITY_TYPE_TAXII_COLLECTION, path: 'filters', shape: 'field' },
  { id: 'fintel-template-instance-filters', registerRow: 'fintel-template.instance-filters', entityType: ENTITY_TYPE_FINTEL_TEMPLATE, path: 'instance_filters', shape: 'field' },
  { id: 'pir-filters', registerRow: 'pir.pir-filters', entityType: ENTITY_TYPE_PIR, path: 'pir_filters', shape: 'field' },
  { id: 'pir-criteria-filters', registerRow: 'pir.criteria-filters', entityType: ENTITY_TYPE_PIR, path: 'pir_criteria', shape: 'criteria-array' },
  { id: 'saved-filter-filters', registerRow: 'saved-filter.filters', entityType: ENTITY_TYPE_SAVED_FILTER, path: 'filters', shape: 'field' },
  { id: 'retention-rule-filters', registerRow: 'retention-rule.filters', entityType: ENTITY_TYPE_RETENTION_RULE, path: 'filters', shape: 'field' },
  { id: 'decay-rule-filters', registerRow: 'decay-rule.filters', entityType: ENTITY_TYPE_DECAY_RULE, path: 'decay_filters', shape: 'field' },
  {
    id: 'decay-exclusion-rule-filters',
    registerRow: 'decay-exclusion-rule.filters',
    entityType: ENTITY_TYPE_DECAY_EXCLUSION_RULE,
    path: 'decay_exclusion_filters',
    shape: 'field',
  },
  {
    id: 'background-task-filters',
    registerRow: 'background-task.task-filters',
    entityType: ENTITY_TYPE_BACKGROUND_TASK,
    path: 'task_filters',
    shape: 'field',
    activity: { path: 'completed', equals: true, negate: true },
  },
  {
    id: 'connector-trigger-filters',
    registerRow: 'connector.trigger-filters',
    entityType: ENTITY_TYPE_CONNECTOR,
    path: 'connector_trigger_filters',
    shape: 'field',
    activity: { path: 'active', equals: true },
  },
];

/** The `retain` row this handler answers for without writing anything. */
export const USER_MERGE_FILTER_ACKNOWLEDGED_ROWS: { registerRow: string; reason: string }[] = [
  {
    registerRow: 'internal-file.list-filters',
    reason: 'provenance snapshot of a past export, never re-executed: rewriting it would misreport what was exported',
  },
];

export const userMergeFilterCoveredRows = (): string[] => {
  const written = USER_MERGE_FILTER_TARGETS.map((target) => target.registerRow);
  const acknowledged = USER_MERGE_FILTER_ACKNOWLEDGED_ROWS.map((row) => row.registerRow);
  return Array.from(new Set([...written, ...acknowledged]));
};

/** Paths qualified by entity type, as the disjointness check compares them literally. */
export const userMergeFilterFieldPaths = (): string[] => {
  return Array.from(new Set(USER_MERGE_FILTER_TARGETS.map((target) => `${target.entityType}.${target.path}`)));
};
