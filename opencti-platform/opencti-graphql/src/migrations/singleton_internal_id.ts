import { loadEntity } from '../database/middleware';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { logMigration } from '../config/conf';
import { elRawDelete, elRawGet, elRawIndex, elRawSearch } from '../database/engine';
import { type EntityOptions, fullEntitiesList } from '../database/middleware-loader';
import { READ_INDEX_INTERNAL_RELATIONSHIPS } from '../database/utils';
import { RELATION_MIGRATES } from '../schema/internalRelationship';
import { ENTITY_TYPE_MIGRATION_STATUS, ENTITY_TYPE_SETTINGS, ENTITY_TYPE_THEME } from '../schema/internalObject';
import { THEME_DARK_ID, THEME_LIGHT_ID } from '../modules/theme/theme-domain';
import { ENTITY_TYPE_RETENTION_RULE } from '../modules/retentionRules/retentionRules-types';
import { RETENTION_RULE_ACTIVITY_ID, RETENTION_RULE_FILES_ID, RETENTION_RULE_HISTORY_ID, RETENTION_RULE_WORKBENCHES_ID } from '../modules/retentionRules/retentionRules-domain';
import { ENTITY_TYPE_NOTIFIER } from '../modules/notifier/notifier-types';
import { NOTIFIER_DEFAULT_TEAM_DIGEST_MESSAGE_ID, NOTIFIER_DEFAULT_TEAM_MESSAGE_ID } from '../modules/notifier/notifier-statics';
import { ENTITY_TYPE_DECAY_RULE } from '../modules/decayRule/decayRule-types';
import { DECAY_RULE_DOMAIN_NAME_ID, DECAY_RULE_FALLBACK_ID, DECAY_RULE_FILE_ARTEFACT_ID, DECAY_RULE_IP_URL_ID } from '../modules/decayRule/decayRule-domain';
import { ENTITY_TYPE_EMAIL_TEMPLATE } from '../modules/emailTemplate/emailTemplate-types';
import { EMAIL_TEMPLATE_DEFAULT_ID } from '../modules/emailTemplate/emailTemplate-domain';
import { OPENCTI_PLATFORM_UUID } from '../schema/general';
import { MIGRATION_STATUS_ID } from '../database/migration';
import type { AuthContext } from '../types/user';
import type { BasicStoreEntity } from '../types/store';
import { type FilterGroup, FilterMode } from '../generated/graphql';

type MigrationNext = () => void;

type StoreLikeEntity = BasicStoreEntity & { name?: string };

interface RelConnection {
  internal_id: string;
  role: string;
  types?: string[];
  [key: string]: unknown;
}

interface RelSource {
  fromId: string;
  connections?: RelConnection[];
  [key: string]: unknown;
}

interface ElRawGetResponse<T = Record<string, unknown>> {
  _index: string;
  _id: string;
  _source: T;
}

interface ElHit<T = Record<string, unknown>> {
  _index: string;
  _id: string;
  _source: T;
}
interface ElSearchResponse<T = Record<string, unknown>> {
  hits?: { hits: ElHit<T>[] };
  body?: { hits?: { hits: ElHit<T>[] } };
}

// ---------------------------------------------------------------------------
// Generic helper: reindex a single-instance-by-type internal object.
// (true singletons resolved by loadEntity on type only: Settings, MigrationStatus)
// Returns the OLD internal_id when a reindex happened, otherwise null.
// ---------------------------------------------------------------------------
const fixSingletonByType = async (
  context: AuthContext,
  entityType: string,
  expectedId: string,
  label: string,
): Promise<string | null> => {
  const entity = await loadEntity(context, SYSTEM_USER, [entityType]) as StoreLikeEntity | undefined;
  if (!entity) {
    logMigration.info(`[MIGRATION] ${label}: no entity found for type ${entityType}, skipping`);
    return null;
  }
  if (entity.internal_id === expectedId) {
    logMigration.info(`[MIGRATION] ${label}: internal_id already ${expectedId}, skipping`);
    return null;
  }
  const oldId = entity.internal_id;
  const index = entity._index;
  logMigration.info(`[MIGRATION] ${label}: reindexing ${oldId} -> ${expectedId}`);
  const rawDoc = await elRawGet({ index, id: oldId }) as ElRawGetResponse;
  await elRawIndex({
    index,
    id: expectedId,
    body: { ...rawDoc._source, internal_id: expectedId, id: expectedId },
    refresh: true,
  });
  await elRawDelete({ index, id: oldId, refresh: true });
  logMigration.info(`[MIGRATION] ${label}: done`);
  return oldId;
};

// ---------------------------------------------------------------------------
// Generic helper: reindex one instance among several of the same entity_type,
// identified by a unique field (typically "name").
// (Theme, RetentionRule, FintelTemplate, Notifier, DecayRule, EmailTemplate)
// Returns the OLD internal_id when a reindex happened, otherwise null.
// ---------------------------------------------------------------------------

const buildNameFilters = (name: string, settingsType?: string): FilterGroup => ({
  mode: FilterMode.And,
  filters: [
    { key: ['name'], values: [name], operator: undefined, mode: undefined },
    ...(settingsType ? [{ key: ['settings_types'], values: [settingsType], operator: undefined, mode: undefined }] : []),
  ],
  filterGroups: [],
});

const fixSingletonByName = async (
  context: AuthContext,
  entityType: string,
  name: string,
  expectedId: string,
  label: string,
  settingsType?: string,
): Promise<string | null> => {
  const args: EntityOptions<StoreLikeEntity> = { filters: buildNameFilters(name, settingsType) };
  const results = await fullEntitiesList<StoreLikeEntity>(context, SYSTEM_USER, [entityType], args);
  if (results.length === 0) {
    logMigration.info(`[MIGRATION] ${label} ("${name}"): not found, skipping (custom/removed instance?)`);
    return null;
  }
  if (results.length > 1) {
    logMigration.info(`[MIGRATION] ${label} ("${name}"): ${results.length} matches found, skipping to avoid ambiguity - manual review required`);
    return null;
  }
  const entity = results[0];
  if (entity.internal_id === expectedId) {
    logMigration.info(`[MIGRATION] ${label} ("${name}"): internal_id already ${expectedId}, skipping`);
    return null;
  }
  const oldId = entity.internal_id;
  const index = entity._index;
  logMigration.info(`[MIGRATION] ${label} ("${name}"): reindexing ${oldId} -> ${expectedId}`);
  const rawDoc = await elRawGet({ index, id: oldId }) as ElRawGetResponse;
  await elRawIndex({
    index,
    id: expectedId,
    body: { ...rawDoc._source, internal_id: expectedId, id: expectedId },
    refresh: true,
  });
  await elRawDelete({ index, id: oldId, refresh: true });
  logMigration.info(`[MIGRATION] ${label} ("${name}"): done`);
  return oldId;
};

// ---------------------------------------------------------------------------
// MigrationStatus special case: after reindexing the entity itself, every
// existing "migrates" relationship pointing FROM the old id must be rewritten
// to point FROM the new fixed id, otherwise migration history breaks.
// ---------------------------------------------------------------------------
const fixMigrationStatusRelations = async (
  context: AuthContext,
  oldId: string | null,
  newId: string,
): Promise<void> => {
  if (!oldId || oldId === newId) {
    logMigration.info('[MIGRATION] MigrationStatus relations: nothing to rewrite');
    return;
  }
  logMigration.info(`[MIGRATION] MigrationStatus relations: rewriting "migrates" relationships from ${oldId} to ${newId}`);

  const searchResult = await elRawSearch(
    context,
    SYSTEM_USER,
    READ_INDEX_INTERNAL_RELATIONSHIPS,
    {
      size: 10000,
      query: {
        bool: {
          must: [
            { term: { 'entity_type.keyword': RELATION_MIGRATES } },
            { term: { 'fromId.keyword': oldId } },
          ],
        },
      },
    },
  ) as ElSearchResponse<RelSource>;

  const hits: ElHit<RelSource>[] = (searchResult.hits && searchResult.hits.hits)
    || (searchResult.body && searchResult.body.hits && searchResult.body.hits.hits)
    || [];
  logMigration.info(`[MIGRATION] MigrationStatus relations: ${hits.length} relationship(s) to fix`);

  for (let i = 0; i < hits.length; i += 1) {
    const hit = hits[i];
    const relId = hit._id;
    const source = hit._source;
    const patchedConnections: RelConnection[] = (source.connections || []).map((connection) => (
      connection.internal_id === oldId ? { ...connection, internal_id: newId } : connection
    ));
    await elRawIndex({
      index: hit._index,
      id: relId,
      body: {
        ...source,
        fromId: newId,
        connections: patchedConnections,
      },
      refresh: true,
    });
  }
  logMigration.info('[MIGRATION] MigrationStatus relations: done');
};

// Declarative list of the "fix by name" singletons (7 groups / 20 instances).
interface ByNameRow {
  entityType: string;
  name: string;
  expectedId: string;
  label: string;
  settingsType?: string;
}

const BY_NAME_ROWS: ByNameRow[] = [
  // Theme
  { entityType: ENTITY_TYPE_THEME, name: 'Dark', expectedId: THEME_DARK_ID, label: 'Theme' },
  { entityType: ENTITY_TYPE_THEME, name: 'Light', expectedId: THEME_LIGHT_ID, label: 'Theme' },

  // RetentionRule
  { entityType: ENTITY_TYPE_RETENTION_RULE, name: 'Global files retention', expectedId: RETENTION_RULE_FILES_ID, label: 'RetentionRule' },
  { entityType: ENTITY_TYPE_RETENTION_RULE, name: 'All workbenches retention', expectedId: RETENTION_RULE_WORKBENCHES_ID, label: 'RetentionRule' },
  { entityType: ENTITY_TYPE_RETENTION_RULE, name: 'History retention', expectedId: RETENTION_RULE_HISTORY_ID, label: 'RetentionRule' },
  { entityType: ENTITY_TYPE_RETENTION_RULE, name: 'Activity retention', expectedId: RETENTION_RULE_ACTIVITY_ID, label: 'RetentionRule' },

  // Notifier
  { entityType: ENTITY_TYPE_NOTIFIER, name: 'Sample of Microsoft Teams message for live trigger', expectedId: NOTIFIER_DEFAULT_TEAM_MESSAGE_ID, label: 'Notifier' },
  { entityType: ENTITY_TYPE_NOTIFIER, name: 'Sample of Microsoft Teams message for digest trigger', expectedId: NOTIFIER_DEFAULT_TEAM_DIGEST_MESSAGE_ID, label: 'Notifier' },

  // DecayRule
  { entityType: ENTITY_TYPE_DECAY_RULE, name: 'Built-in default', expectedId: DECAY_RULE_FALLBACK_ID, label: 'DecayRule' },
  { entityType: ENTITY_TYPE_DECAY_RULE, name: 'Built-in files and artifact', expectedId: DECAY_RULE_FILE_ARTEFACT_ID, label: 'DecayRule' },
  { entityType: ENTITY_TYPE_DECAY_RULE, name: 'Built-in IP and URL', expectedId: DECAY_RULE_IP_URL_ID, label: 'DecayRule' },
  { entityType: ENTITY_TYPE_DECAY_RULE, name: 'Built-in domain name', expectedId: DECAY_RULE_DOMAIN_NAME_ID, label: 'DecayRule' },

  // EmailTemplate
  { entityType: ENTITY_TYPE_EMAIL_TEMPLATE, name: 'Built-In Template For Onboarding', expectedId: EMAIL_TEMPLATE_DEFAULT_ID, label: 'EmailTemplate' },

  // FintelTemplate (6) - TODO: fill in the 6 real rows once names/constants are confirmed, e.g.:
  // { entityType: ENTITY_TYPE_FINTEL_TEMPLATE, name: '<exact built-in name>', expectedId: FINTEL_TEMPLATE_XXX_ID, label: 'FintelTemplate' },
];

export const up = async (next: MigrationNext): Promise<void> => {
  const context = executionContext('migration');

  // 1) Settings (true singleton, by type)
  //    ⚠️ VERIFY BEFORE MERGE: Settings.internal_id is already handled by
  //    setPlatformId()/patchPlatformId() at boot (platform_id). Reindexing it here
  //    may conflict with that mechanism.
  await fixSingletonByType(context, ENTITY_TYPE_SETTINGS, OPENCTI_PLATFORM_UUID, 'Settings');

  // 2) All "by name" singletons (Theme, RetentionRule, Notifier, DecayRule, EmailTemplate, FintelTemplate)
  for (let i = 0; i < BY_NAME_ROWS.length; i += 1) {
    const row = BY_NAME_ROWS[i];
    await fixSingletonByName(context, row.entityType, row.name, row.expectedId, row.label);
  }

  // 3) MigrationStatus (true singleton, by type) + relationship rewrite.
  //    Done LAST on purpose: this entity is the migration mechanism's own anchor.
  const oldMigrationStatusId = await fixSingletonByType(context, ENTITY_TYPE_MIGRATION_STATUS, MIGRATION_STATUS_ID, 'MigrationStatus');
  await fixMigrationStatusRelations(context, oldMigrationStatusId, MIGRATION_STATUS_ID);

  logMigration.info('[MIGRATION] fix_singleton_internal_ids: completed');
  next();
};

export const down = async (next: MigrationNext): Promise<void> => {
  logMigration.info('[MIGRATION] fix_singleton_internal_ids: this migration is NOT reversible '
    + '(original random internal_ids were not preserved before the fix). No action taken.');
  next();
};
