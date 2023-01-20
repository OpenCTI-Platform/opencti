import * as R from 'ramda';
import { ABSTRACT_INTERNAL_OBJECT, schemaTypes } from './general';

export const ENTITY_TYPE_SETTINGS = 'Settings';
export const ENTITY_TYPE_MIGRATION_STATUS = 'MigrationStatus';
export const ENTITY_TYPE_MIGRATION_REFERENCE = 'MigrationReference';
export const ENTITY_TYPE_RULE_MANAGER = 'RuleManager';
export const ENTITY_TYPE_GROUP = 'Group';
export const ENTITY_TYPE_USER = 'User';
export const ENTITY_TYPE_RULE = 'Rule';
export const ENTITY_TYPE_ROLE = 'Role';
export const ENTITY_TYPE_CAPABILITY = 'Capability';
export const ENTITY_TYPE_CONNECTOR = 'Connector';
export const ENTITY_TYPE_WORKSPACE = 'Workspace';
export const ENTITY_TYPE_HISTORY = 'History';
export const ENTITY_TYPE_WORK = 'work';
export const ENTITY_TYPE_TASK = 'Task';
export const ENTITY_TYPE_RETENTION_RULE = 'RetentionRule';
export const ENTITY_TYPE_SYNC = 'Sync';
export const ENTITY_TYPE_TAXII_COLLECTION = 'TaxiiCollection';
export const ENTITY_TYPE_FEED = 'Feed';
export const ENTITY_TYPE_STREAM_COLLECTION = 'StreamCollection';
export const ENTITY_TYPE_STATUS_TEMPLATE = 'StatusTemplate';
export const ENTITY_TYPE_STATUS = 'Status';
const DATED_INTERNAL_OBJECTS = [
  ENTITY_TYPE_SETTINGS,
  ENTITY_TYPE_GROUP,
  ENTITY_TYPE_USER,
  ENTITY_TYPE_ROLE,
  ENTITY_TYPE_CAPABILITY,
  ENTITY_TYPE_CONNECTOR,
  ENTITY_TYPE_WORKSPACE,
  ENTITY_TYPE_SYNC,
];
const INTERNAL_OBJECTS = [
  ENTITY_TYPE_SETTINGS,
  ENTITY_TYPE_TAXII_COLLECTION,
  ENTITY_TYPE_FEED,
  ENTITY_TYPE_STREAM_COLLECTION,
  ENTITY_TYPE_STATUS_TEMPLATE,
  ENTITY_TYPE_STATUS,
  ENTITY_TYPE_TASK,
  ENTITY_TYPE_RETENTION_RULE,
  ENTITY_TYPE_SYNC,
  ENTITY_TYPE_MIGRATION_STATUS,
  ENTITY_TYPE_MIGRATION_REFERENCE,
  ENTITY_TYPE_GROUP,
  ENTITY_TYPE_USER,
  ENTITY_TYPE_ROLE,
  ENTITY_TYPE_RULE,
  ENTITY_TYPE_RULE_MANAGER,
  ENTITY_TYPE_CAPABILITY,
  ENTITY_TYPE_CONNECTOR,
  ENTITY_TYPE_WORKSPACE,
  ENTITY_TYPE_HISTORY,
];
const HISTORY_OBJECTS = [ENTITY_TYPE_WORK];
schemaTypes.register(ABSTRACT_INTERNAL_OBJECT, INTERNAL_OBJECTS);
export const isInternalObject = (type: string) => R.includes(type, INTERNAL_OBJECTS) || type === ABSTRACT_INTERNAL_OBJECT;
export const isDatedInternalObject = (type: string) => R.includes(type, DATED_INTERNAL_OBJECTS);
export const isHistoryObject = (type: string) => R.includes(type, HISTORY_OBJECTS);

const internalObjectsAttributes = {
  [ENTITY_TYPE_SETTINGS]: [
    'internal_id',
    'standard_id',
    'entity_type',
    'platform_title',
    'platform_organization',
    'platform_favicon',
    'platform_email',
    'platform_theme',
    'platform_theme_dark_background',
    'platform_theme_dark_paper',
    'platform_theme_dark_nav',
    'platform_theme_dark_primary',
    'platform_theme_dark_secondary',
    'platform_theme_dark_accent',
    'platform_theme_dark_logo',
    'platform_theme_dark_logo_collapsed',
    'platform_theme_dark_logo_login',
    'platform_theme_light_background',
    'platform_theme_light_paper',
    'platform_theme_light_nav',
    'platform_theme_light_primary',
    'platform_theme_light_secondary',
    'platform_theme_light_accent',
    'platform_theme_light_logo',
    'platform_theme_light_logo_collapsed',
    'platform_theme_light_logo_login',
    'platform_language',
    'platform_login_message',
    'created_at',
    'i_created_at_day',
    'i_created_at_month',
    'i_created_at_year',
    'updated_at',
    'otp_mandatory',
  ],
  [ENTITY_TYPE_MIGRATION_STATUS]: ['internal_id', 'standard_id', 'entity_type', 'lastRun', 'platformVersion'],
  [ENTITY_TYPE_MIGRATION_REFERENCE]: ['internal_id', 'standard_id', 'entity_type', 'title', 'timestamp'],
  [ENTITY_TYPE_GROUP]: [
    'internal_id',
    'standard_id',
    'entity_type',
    'name',
    'description',
    'default_assignation',
    'auto_new_marking',
    'created_at',
    'i_created_at_day',
    'i_created_at_month',
    'i_created_at_year',
    'updated_at',
  ],
  [ENTITY_TYPE_USER]: [
    'internal_id',
    'standard_id',
    'entity_type',
    'user_email',
    'password',
    'name',
    'description',
    'firstname',
    'lastname',
    'theme',
    'language',
    'external',
    'dashboard',
    'bookmarks',
    'created_at',
    'i_created_at_day',
    'i_created_at_month',
    'i_created_at_year',
    'updated_at',
    'api_token',
    'otp_secret',
    'otp_qr',
    'otp_activated',
  ],
  [ENTITY_TYPE_ROLE]: [
    'internal_id',
    'standard_id',
    'entity_type',
    'name',
    'default_assignation',
    'description',
    'created_at',
    'i_created_at_day',
    'i_created_at_month',
    'i_created_at_year',
    'updated_at',
  ],
  [ENTITY_TYPE_RULE]: ['internal_id', 'standard_id', 'entity_type', 'active'],
  [ENTITY_TYPE_RULE_MANAGER]: ['internal_id', 'lastEventId', 'errors'],
  [ENTITY_TYPE_CAPABILITY]: [
    'internal_id',
    'standard_id',
    'entity_type',
    'name',
    'attribute_order',
    'description',
    'created_at',
    'i_created_at_day',
    'i_created_at_month',
    'i_created_at_year',
    'updated_at',
  ],
  [ENTITY_TYPE_CONNECTOR]: [
    'internal_id',
    'standard_id',
    'entity_type',
    'name',
    'active',
    'auto',
    'only_contextual',
    'connector_type',
    'connector_scope',
    'connector_state',
    'connector_state_reset',
    'connector_user_id',
    'created_at',
    'i_created_at_day',
    'i_created_at_month',
    'i_created_at_year',
    'updated_at',
  ],
  [ENTITY_TYPE_WORKSPACE]: [
    'internal_id',
    'standard_id',
    'entity_type',
    'identifier',
    'name',
    'description',
    'manifest',
    'owner',
    'type',
    'tags',
    'graph_data',
    'created_at',
    'i_created_at_day',
    'i_created_at_month',
    'i_created_at_year',
    'updated_at',
  ],
  [ENTITY_TYPE_TAXII_COLLECTION]: ['internal_id', 'standard_id', 'name', 'description', 'filters'],
  [ENTITY_TYPE_STREAM_COLLECTION]: ['internal_id', 'standard_id', 'name', 'description', 'filters'],
  [ENTITY_TYPE_STATUS_TEMPLATE]: ['internal_id', 'standard_id', 'name', 'color'],
  [ENTITY_TYPE_STATUS]: ['internal_id', 'standard_id', 'template_id', 'type', 'order'],
  [ENTITY_TYPE_TASK]: [
    'standard_id',
    'task_position',
    'task_processed_number',
    'task_expected_number',
    'last_execution_date',
    'completed',
  ],
  [ENTITY_TYPE_RETENTION_RULE]: [
    'standard_id',
    'name',
    'filters',
    'max_retention',
    'last_execution_date',
    'last_deleted_count',
    'remaining_count',
  ],
  [ENTITY_TYPE_SYNC]: [
    'internal_id',
    'standard_id',
    'name',
    'uri',
    'ssl_verify',
    'user_id',
    'token',
    'stream_id',
    'running',
    'current_state',
    'listen_deletion',
    'no_dependencies',
  ],
};

const internalObjectsFieldsToBeUpdated = {
  [ENTITY_TYPE_RULE]: ['active'],
};

schemaTypes.register(ABSTRACT_INTERNAL_OBJECT, INTERNAL_OBJECTS);

export const registerInternalObject = (type: string) => {
  INTERNAL_OBJECTS.push(type);
};

R.forEachObjIndexed((value, key) => schemaTypes.registerAttributes(key, value), internalObjectsAttributes);
R.forEachObjIndexed((value, key) => schemaTypes.registerUpsertAttributes(key, value), internalObjectsFieldsToBeUpdated);
