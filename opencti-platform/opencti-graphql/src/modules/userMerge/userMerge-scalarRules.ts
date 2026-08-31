import { ENTITY_TYPE_BACKGROUND_TASK, ENTITY_TYPE_CONNECTOR, ENTITY_TYPE_INTERNAL_FILE, ENTITY_TYPE_WORK } from '../../schema/internalObject';
import { ENTITY_TYPE_NOTIFICATION } from '../notification/notification-types';
import { ENTITY_TYPE_PUBLIC_DASHBOARD } from '../publicDashboard/publicDashboard-types';
import { ENTITY_TYPE_NEWS_FEED_ITEM } from '../xtm/hub/news-feed/news-feed-types';
import { ENTITY_TYPE_WORKFLOW_DEFINITION } from '../workflow/types/workflow-types';
import { ENTITY_USER_ACCOUNT } from '../../schema/stixCyberObservable';
import type { UserMergeScalarCondition, UserMergeScalarTarget } from './userMerge-scalarTargets';

/**
 * Why a discovered attribute is not rewritten by this handler.
 *
 * `not-a-platform-user` means the schema is wrong: the attribute is declared as referencing a
 * User but holds something else entirely.
 */
export type UserMergeScalarExclusionReason = 'not-a-platform-user' | 'another-chunk' | 'another-handler';

export interface UserMergeScalarExclusion {
  reason: UserMergeScalarExclusionReason;
  detail: string;
}

export interface UserMergeScalarSplit {
  id: string;
  registerRow: string;
  condition: UserMergeScalarCondition;
  unexpectedAtRest?: boolean;
}

export type UserMergeScalarDisposition
  = | ({ kind: 'excluded' } & UserMergeScalarExclusion)
    | { kind: 'covered'; registerRow: string }
    | { kind: 'split'; variants: UserMergeScalarSplit[] };

/**
 * Disposition of every attribute the schema discovers, keyed by `<entity type>.<attribute>`.
 *
 * A `*.<attribute>` key applies to every carrying type. Discovering an attribute absent from this
 * table is a hard error: the register has not been consulted for it.
 */
export const USER_MERGE_SCALAR_DISPOSITIONS: Record<string, UserMergeScalarDisposition> = {
  '*.creator_id': { kind: 'covered', registerRow: 'basic-object.creator-id' },
  '*.applicant_id': { kind: 'excluded', reason: 'another-chunk', detail: 'History, Activity and PirHistory are rewritten by the history chunk' },
  '*.xtm_hub_registration_user_id': { kind: 'covered', registerRow: 'settings.xtm-hub-registration-user-id' },
  '*.platform_ip_whitelist_exclusion_ids': { kind: 'excluded', reason: 'another-handler', detail: 'Settings handler, which writes through the domain layer so the platform cache follows' },
  // Removal then guarded append, which is what the register asks for: replace the source by the
  // target, then deduplicate. A trigger already naming both members ends up naming the target once.
  '*.recipients': { kind: 'covered', registerRow: 'trigger.recipients' },
  '*.feed_public_user_id': { kind: 'excluded', reason: 'another-handler', detail: 'Public sharing handler, which also reports the exposure change' },
  '*.taxii_public_user_id': { kind: 'excluded', reason: 'another-handler', detail: 'Public sharing handler, which also reports the exposure change' },
  '*.stream_public_user_id': { kind: 'excluded', reason: 'another-handler', detail: 'Public sharing handler, which also reports the exposure change' },
  'Sync.user_id': { kind: 'covered', registerRow: 'sync.user-id' },
  'IngestionCsv.user_id': { kind: 'covered', registerRow: 'ingestion.user-id' },
  'IngestionJson.user_id': { kind: 'covered', registerRow: 'ingestion.user-id' },
  'IngestionRss.user_id': { kind: 'covered', registerRow: 'ingestion.user-id' },
  'IngestionTaxii.user_id': { kind: 'covered', registerRow: 'ingestion.user-id' },
  'IngestionTaxiiCollection.user_id': { kind: 'covered', registerRow: 'ingestion.user-id' },
  'History.user_id': { kind: 'excluded', reason: 'another-chunk', detail: 'History is rewritten by the history chunk' },
  'PirHistory.user_id': { kind: 'excluded', reason: 'another-chunk', detail: 'PirHistory is rewritten by the history chunk' },
  'Activity.user_id': { kind: 'excluded', reason: 'another-chunk', detail: 'Activity is rewritten by the history chunk' },
  [`${ENTITY_USER_ACCOUNT}.user_id`]: {
    kind: 'excluded',
    reason: 'not-a-platform-user',
    detail: 'STIX user-account property holding the account identifier on the observed system, next to credential and account_login',
  },
  [`${ENTITY_TYPE_WORK}.user_id`]: {
    kind: 'split',
    variants: [
      { id: 'work-terminal-user-id', registerRow: 'work-terminal.user-id', condition: { path: 'status', equals: 'complete' } },
      { id: 'work-active-user-id', registerRow: 'work-active.user-id', condition: { path: 'status', equals: 'complete', negate: true }, unexpectedAtRest: true },
    ],
  },
  [`${ENTITY_TYPE_NOTIFICATION}.user_id`]: {
    kind: 'split',
    variants: [
      { id: 'notification-read-user-id', registerRow: 'notification-terminal.user-id', condition: { path: 'is_read', equals: true } },
      { id: 'notification-unread-user-id', registerRow: 'notification-unread.user-id', condition: { path: 'is_read', equals: true, negate: true } },
    ],
  },
};

/**
 * Targets the schema cannot yield, each with the reason it is missing.
 *
 * These are gaps in the attribute declarations, not deliberate register choices. Fixing a
 * declaration changes how filters and history diffs behave platform-wide, so the fix belongs
 * outside this feature; the guard test flags the entry once the schema starts yielding it.
 */
export interface UserMergeScalarComplement extends UserMergeScalarTarget {
  missingBecause: string;
}

export const USER_MERGE_SCALAR_COMPLEMENTS: UserMergeScalarComplement[] = [
  {
    id: 'connector-user-id',
    registerRow: 'connector.user-id',
    entityTypes: [ENTITY_TYPE_CONNECTOR],
    path: 'connector_user_id',
    shape: 'single',
    missingBecause: "declared with format 'short'",
  },
  {
    id: 'news-feed-item-user-id',
    registerRow: 'news-feed-item.user-id',
    entityTypes: [ENTITY_TYPE_NEWS_FEED_ITEM],
    path: 'user_id',
    shape: 'single',
    missingBecause: "declared with format 'short'",
  },
  {
    id: 'public-dashboard-user-id',
    registerRow: 'public-dashboard.user-id',
    entityTypes: [ENTITY_TYPE_PUBLIC_DASHBOARD],
    path: 'user_id',
    shape: 'single',
    missingBecause: 'not declared at all, though the entity stores it',
  },
  {
    id: 'background-task-terminal-initiator-id',
    registerRow: 'background-task-terminal.initiator-id',
    entityTypes: [ENTITY_TYPE_BACKGROUND_TASK],
    path: 'initiator_id',
    shape: 'single',
    condition: { path: 'completed', equals: true },
    missingBecause: "declared with format 'short'",
  },
  {
    id: 'background-task-pending-initiator-id',
    registerRow: 'background-task-pending.initiator-id',
    entityTypes: [ENTITY_TYPE_BACKGROUND_TASK],
    path: 'initiator_id',
    shape: 'single',
    condition: { path: 'completed', equals: true, negate: true },
    unexpectedAtRest: true,
    missingBecause: "declared with format 'short'",
  },
  {
    id: 'internal-file-metadata-creator-id',
    registerRow: 'internal-file.metadata-creator-id',
    entityTypes: [ENTITY_TYPE_INTERNAL_FILE],
    path: 'metaData.creator_id',
    shape: 'single',
    missingBecause: "held under metaData, declared with format 'standard' and no attribute definitions",
  },
  {
    id: 'workflow-definition-published-version-created-by',
    registerRow: 'workflow-definition.versions-created-by',
    entityTypes: [ENTITY_TYPE_WORKFLOW_DEFINITION],
    path: 'published_version.createdBy',
    shape: 'single',
    nestedRoot: 'published_version',
    missingBecause: 'nested mapping child declared without entityTypes',
  },
  {
    id: 'workflow-definition-draft-version-created-by',
    registerRow: 'workflow-definition.versions-created-by',
    entityTypes: [ENTITY_TYPE_WORKFLOW_DEFINITION],
    path: 'draft_version.createdBy',
    shape: 'single',
    nestedRoot: 'draft_version',
    missingBecause: 'nested mapping child declared without entityTypes',
  },
  {
    id: 'workflow-definition-all-versions-created-by',
    registerRow: 'workflow-definition.versions-created-by',
    entityTypes: [ENTITY_TYPE_WORKFLOW_DEFINITION],
    path: 'all_versions.createdBy',
    shape: 'object-array',
    nestedRoot: 'all_versions',
    missingBecause: 'nested mapping child declared without entityTypes',
  },
];
