import { loadEntity } from '../database/middleware';
import { executionContext, SYSTEM_USER } from '../utils/access';
import conf, { logMigration } from '../config/conf';
import { elRawDelete, elRawGet, elRawIndex } from '../database/engine';
import { type EntityOptions, fullEntitiesList } from '../database/middleware-loader';
import { isNotEmptyField } from '../database/utils';
import { ENTITY_TYPE_SETTINGS, ENTITY_TYPE_THEME } from '../schema/internalObject';
import { THEME_DARK_ID, THEME_LIGHT_ID } from '../modules/theme/theme-domain';
import { ENTITY_TYPE_RETENTION_RULE } from '../modules/retentionRules/retentionRules-types';
import { RETENTION_RULE_ACTIVITY_ID, RETENTION_RULE_FILES_ID, RETENTION_RULE_HISTORY_ID, RETENTION_RULE_WORKBENCHES_ID } from '../modules/retentionRules/retentionRules-domain';
import { ENTITY_TYPE_NOTIFIER } from '../modules/notifier/notifier-types';
import { NOTIFIER_DEFAULT_TEAM_DIGEST_MESSAGE_ID, NOTIFIER_DEFAULT_TEAM_MESSAGE_ID } from '../modules/notifier/notifier-statics';
import { ENTITY_TYPE_DECAY_RULE } from '../modules/decayRule/decayRule-types';
import { DECAY_RULE_DOMAIN_NAME_ID, DECAY_RULE_FALLBACK_ID, DECAY_RULE_FILE_ARTEFACT_ID, DECAY_RULE_IP_URL_ID } from '../modules/decayRule/decayRule-domain';
import { ENTITY_TYPE_EMAIL_TEMPLATE } from '../modules/emailTemplate/emailTemplate-types';
import { EMAIL_TEMPLATE_DEFAULT_ID } from '../modules/emailTemplate/emailTemplate-domain';
import { ENTITY_TYPE_FINTEL_TEMPLATE } from '../modules/fintelTemplate/fintelTemplate-types';
import {
  FINTEL_TEMPLATE_EXEC_SUMMARY_CASE_INCIDENT_ID,
  FINTEL_TEMPLATE_EXEC_SUMMARY_CASE_RFI_ID,
  FINTEL_TEMPLATE_EXEC_SUMMARY_CASE_RFT_ID,
  FINTEL_TEMPLATE_EXEC_SUMMARY_GROUPING_ID,
  FINTEL_TEMPLATE_EXEC_SUMMARY_REPORT_ID,
  FINTEL_TEMPLATE_INCIDENT_RESPONSE_ID,
} from '../modules/fintelTemplate/fintelTemplate-domain';
import { OPENCTI_PLATFORM_UUID } from '../schema/general';
import type { AuthContext } from '../types/user';
import type { BasicStoreEntity } from '../types/store';
import { type FilterGroup, FilterMode } from '../generated/graphql';

type MigrationNext = () => void;

type StoreLikeEntity = BasicStoreEntity & { name?: string };

interface ElRawGetResponse<T = Record<string, unknown>> {
  _index: string;
  _id: string;
  _source: T;
}

// Generic helper: reindex a single-instance-by-type internal object.
// Returns the old internal_id when a reindex happened, otherwise null.

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

const fixSettingsSingleton = async (context: AuthContext): Promise<string | null> => {
  const operatorPlatformId = conf.get('platform_id');
  if (isNotEmptyField(operatorPlatformId)) {
    logMigration.info(
      `[MIGRATION] Settings: a custom platform_id (${operatorPlatformId}) is configured by the operator, `
      + 'skipping - patchPlatformId() at boot is the source of truth for this platform',
    );
    return null;
  }
  return fixSingletonByType(context, ENTITY_TYPE_SETTINGS, OPENCTI_PLATFORM_UUID, 'Settings');
};

// Generic helper: reindex one instance among several of the same entity_type,
// identified by a unique field (typically "name").
// (Theme, RetentionRule, FintelTemplate, Notifier, DecayRule, EmailTemplate)
// Returns the old internal_id when a reindex happened, otherwise null.

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
  const matchLabel = settingsType ? `${name}" / settings_types="${settingsType}` : name;
  const args: EntityOptions<StoreLikeEntity> = { filters: buildNameFilters(name, settingsType) };
  const results = await fullEntitiesList<StoreLikeEntity>(context, SYSTEM_USER, [entityType], args);
  if (results.length === 0) {
    logMigration.info(`[MIGRATION] ${label} ("${matchLabel}"): not found, skipping (custom/removed instance?)`);
    return null;
  }
  if (results.length > 1) {
    logMigration.info(`[MIGRATION] ${label} ("${matchLabel}"): ${results.length} matches found, skipping to avoid ambiguity - manual review required`);
    return null;
  }
  const entity = results[0];
  if (entity.internal_id === expectedId) {
    logMigration.info(`[MIGRATION] ${label} ("${matchLabel}"): internal_id already ${expectedId}, skipping`);
    return null;
  }
  const oldId = entity.internal_id;
  const index = entity._index;
  logMigration.info(`[MIGRATION] ${label} ("${matchLabel}"): reindexing ${oldId} -> ${expectedId}`);
  const rawDoc = await elRawGet({ index, id: oldId }) as ElRawGetResponse;
  await elRawIndex({
    index,
    id: expectedId,
    body: { ...rawDoc._source, internal_id: expectedId, id: expectedId },
    refresh: true,
  });
  await elRawDelete({ index, id: oldId, refresh: true });
  logMigration.info(`[MIGRATION] ${label} ("${matchLabel}"): done`);
  return oldId;
};

// Declarative list of the "fix by name" singletons (8 groups / 26 instances:
// Theme x2, RetentionRule x4, Notifier x2, DecayRule x4, EmailTemplate x1,
// FintelTemplate x6 - Settings and MigrationStatus are handled separately below
// since they are resolved by type only, not by name).
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

  // FintelTemplate (6) - "Executive Summary" is NOT unique by name alone: 5 of the
  // 6 built-in templates share this exact name (see generateFintelTemplateExecutiveSummary()
  // in modules/fintelTemplate/fintelTemplate-domain.ts) and are only distinguished by
  // their `settings_types` value. `settingsType` below is mandatory for these 5 rows.
  {
    entityType: ENTITY_TYPE_FINTEL_TEMPLATE,
    name: 'Executive Summary',
    expectedId: FINTEL_TEMPLATE_EXEC_SUMMARY_REPORT_ID,
    label: 'FintelTemplate',
    settingsType: 'Report',
  },
  {
    entityType: ENTITY_TYPE_FINTEL_TEMPLATE,
    name: 'Executive Summary',
    expectedId: FINTEL_TEMPLATE_EXEC_SUMMARY_GROUPING_ID,
    label: 'FintelTemplate',
    settingsType: 'Grouping',
  },
  {
    entityType: ENTITY_TYPE_FINTEL_TEMPLATE,
    name: 'Executive Summary',
    expectedId: FINTEL_TEMPLATE_EXEC_SUMMARY_CASE_INCIDENT_ID,
    label: 'FintelTemplate',
    settingsType: 'Case-Incident',
  },
  {
    entityType: ENTITY_TYPE_FINTEL_TEMPLATE,
    name: 'Executive Summary',
    expectedId: FINTEL_TEMPLATE_EXEC_SUMMARY_CASE_RFI_ID,
    label: 'FintelTemplate',
    settingsType: 'Case-Rfi',
  },
  {
    entityType: ENTITY_TYPE_FINTEL_TEMPLATE,
    name: 'Executive Summary',
    expectedId: FINTEL_TEMPLATE_EXEC_SUMMARY_CASE_RFT_ID,
    label: 'FintelTemplate',
    settingsType: 'Case-Rft',
  },
  // This one has a unique name ("Incident Response Report") - settingsType is not
  // strictly required for disambiguation but is passed anyway for consistency
  // and defense-in-depth (in case a user creates a custom template with the same name).
  {
    entityType: ENTITY_TYPE_FINTEL_TEMPLATE,
    name: 'Incident Response Report',
    expectedId: FINTEL_TEMPLATE_INCIDENT_RESPONSE_ID,
    label: 'FintelTemplate',
    settingsType: 'Case-Incident',
  },
];

export const up = async (next: MigrationNext): Promise<void> => {
  const context = executionContext('migration');

  await fixSettingsSingleton(context);

  for (let i = 0; i < BY_NAME_ROWS.length; i += 1) {
    const row = BY_NAME_ROWS[i];
    await fixSingletonByName(context, row.entityType, row.name, row.expectedId, row.label, row.settingsType);
  }

  logMigration.info('[MIGRATION] fix_singleton_internal_ids: completed');
  next();
};

export const down = async (next: MigrationNext): Promise<void> => {
  logMigration.info('[MIGRATION] fix_singleton_internal_ids: this migration is NOT reversible '
    + '(original random internal_ids were not preserved before the fix). No action taken.');
  next();
};
