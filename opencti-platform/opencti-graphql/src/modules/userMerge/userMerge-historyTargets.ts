import { ENTITY_TYPE_ACTIVITY, ENTITY_TYPE_HISTORY, ENTITY_TYPE_PIR_HISTORY } from '../../schema/internalObject';
import { ENTITY_TYPE_WORKFLOW_INSTANCE } from '../workflow/types/workflow-types';
import type { UserMergeScalarTarget } from './userMerge-scalarTargets';

/**
 * The three types share one attribute definition, so they carry the same attribution fields.
 * `Activity` holds the audit trail, `History` the object history, `PirHistory` the PIR one.
 */
const HISTORY_ENTITY_TYPES = [ENTITY_TYPE_ACTIVITY, ENTITY_TYPE_HISTORY, ENTITY_TYPE_PIR_HISTORY];

/**
 * Who a past event is attributed to: the history index, the per-attribute last modifier every
 * document carries, and the workflow transition log.
 *
 * The register splits `user_id` per entity type and groups `applicant_id` on the three, which
 * is kept here: the paths a handler declares are compared as literal strings against the other
 * handlers', so an unqualified `user_id` would collide with the ones the scalar handler owns
 * on `Sync`, `Ingestion` or `PublicDashboard`.
 *
 * `context_data.creator_ids` is claimed for the three types rather than for `History` alone.
 * The register names `History` because that is where the field is populated in practice, but
 * an activity event copying the creators of the entity it describes would otherwise keep a
 * reference to a user that no longer exists.
 */
export const USER_MERGE_HISTORY_TARGETS: UserMergeScalarTarget[] = [
  {
    id: 'activity-user-id',
    registerRow: 'activity.user-id',
    entityTypes: [ENTITY_TYPE_ACTIVITY],
    path: 'user_id',
    shape: 'single',
  },
  {
    id: 'history-user-id',
    registerRow: 'history.user-id',
    entityTypes: [ENTITY_TYPE_HISTORY],
    path: 'user_id',
    shape: 'single',
  },
  {
    id: 'pir-history-user-id',
    registerRow: 'pir-history.user-id',
    entityTypes: [ENTITY_TYPE_PIR_HISTORY],
    path: 'user_id',
    shape: 'single',
  },
  {
    id: 'history-applicant-id',
    registerRow: 'activity-history-pir-history.applicant-id',
    entityTypes: HISTORY_ENTITY_TYPES,
    path: 'applicant_id',
    shape: 'single',
  },
  {
    id: 'history-context-data-creator-ids',
    registerRow: 'history.context-data-attribution',
    entityTypes: HISTORY_ENTITY_TYPES,
    path: 'context_data.creator_ids',
    shape: 'multiple',
  },
  {
    // No entity type filter: `i_attributes` is declared on the abstract roots, so the field
    // exists on every object and every relationship, in every platform index.
    id: 'basic-object-i-attributes-user-id',
    registerRow: 'basic-object.i-attributes-user-id',
    path: 'i_attributes.user_id',
    shape: 'object-array',
  },
  {
    // The transition log is stored as a JSON string, not as a document array, so it is
    // rewritten as text rather than traversed.
    id: 'workflow-instance-history-user-id',
    registerRow: 'workflow-instance.history-user-id',
    entityTypes: [ENTITY_TYPE_WORKFLOW_INSTANCE],
    path: 'history',
    shape: 'serialized',
    serializedKey: 'user_id',
  },
];

export const userMergeHistoryCoveredRows = (): string[] => {
  return Array.from(new Set(USER_MERGE_HISTORY_TARGETS.map((target) => target.registerRow)));
};

/**
 * Paths qualified by entity type, as the disjointness check compares them literally.
 * The targets declared on an abstract root are qualified with `*`.
 */
export const userMergeHistoryFieldPaths = (): string[] => {
  const paths = USER_MERGE_HISTORY_TARGETS.flatMap((target) => {
    const types = target.entityTypes ?? ['*'];
    return types.map((entityType) => `${entityType}.${target.path}`);
  });
  return Array.from(new Set(paths));
};
