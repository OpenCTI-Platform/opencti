import * as R from 'ramda';
import { ABSTRACT_INTERNAL_OBJECT } from './general';
import { AttributeDefinition, createdAt, entityType, internalId, standardId, updatedAt } from './attribute-definition';
import { schemaAttributesDefinition } from './schema-attributes';

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

export const isInternalObject = (type: string) => schemaAttributesDefinition.isTypeIncludedIn(type, ABSTRACT_INTERNAL_OBJECT) || type === ABSTRACT_INTERNAL_OBJECT;
export const isDatedInternalObject = (type: string) => DATED_INTERNAL_OBJECTS.includes(type);
export const isHistoryObject = (type: string) => HISTORY_OBJECTS.includes(type);

const internalObjectsAttributes: { [k: string]: Array<AttributeDefinition> } = {
  [ENTITY_TYPE_SETTINGS]: [
    internalId,
    standardId,
    entityType,
    { name: 'platform_title', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'platform_organization', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'platform_favicon', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'platform_email', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'platform_theme', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'platform_theme_dark_background', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'platform_theme_dark_paper', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'platform_theme_dark_nav', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'platform_theme_dark_primary', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'platform_theme_dark_secondary', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'platform_theme_dark_accent', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'platform_theme_dark_logo', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'platform_theme_dark_logo_collapsed', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'platform_theme_dark_logo_login', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'platform_theme_light_background', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'platform_theme_light_paper', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'platform_theme_light_nav', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'platform_theme_light_primary', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'platform_theme_light_secondary', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'platform_theme_light_accent', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'platform_theme_light_logo', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'platform_theme_light_logo_collapsed', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'platform_theme_light_logo_login', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'platform_language', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'platform_login_message', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    createdAt,
    updatedAt,
    { name: 'i_created_at_day', type: 'date', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'i_created_at_month', type: 'date', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'i_created_at_year', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'otp_mandatory', type: 'boolean', mandatoryType: 'no', multiple: false, upsert: false },
  ],
  [ENTITY_TYPE_MIGRATION_STATUS]: [
    internalId,
    standardId,
    entityType,
    { name: 'lastRun', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'platformVersion', type: 'string', mandatoryType: 'no', multiple: false, upsert: false }
  ],
  [ENTITY_TYPE_MIGRATION_REFERENCE]: [
    internalId,
    standardId,
    entityType,
    { name: 'title', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'timestamp', type: 'date', mandatoryType: 'no', multiple: false, upsert: false }
  ],
  [ENTITY_TYPE_GROUP]: [
    internalId,
    standardId,
    entityType,
    createdAt,
    updatedAt,
    { name: 'name', type: 'string', mandatoryType: 'external', multiple: false, upsert: false },
    { name: 'description', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'default_assignation', type: 'boolean', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'auto_new_marking', type: 'boolean', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'i_created_at_day', type: 'date', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'i_created_at_month', type: 'date', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'i_created_at_year', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
  ],
  [ENTITY_TYPE_USER]: [
    internalId,
    standardId,
    entityType,
    { name: 'user_email', type: 'string', mandatoryType: 'external', multiple: false, upsert: false },
    { name: 'password', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'name', type: 'string', mandatoryType: 'external', multiple: false, upsert: false },
    { name: 'description', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'firstname', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'lastname', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'theme', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'language', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'external', type: 'boolean', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'dashboard', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'bookmarks', type: 'json', mandatoryType: 'no', multiple: true, upsert: false },
    createdAt,
    updatedAt,
    { name: 'i_created_at_day', type: 'date', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'i_created_at_month', type: 'date', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'i_created_at_year', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'api_token', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'otp_secret', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'otp_qr', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'otp_activated', type: 'boolean', mandatoryType: 'no', multiple: false, upsert: false }
  ],
  [ENTITY_TYPE_ROLE]: [
    internalId,
    standardId,
    entityType,
    { name: 'name', type: 'string', mandatoryType: 'external', multiple: false, upsert: false },
    { name: 'default_hidden_types', type: 'string', mandatoryType: 'no', multiple: true, upsert: false },
    { name: 'description', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    createdAt,
    updatedAt,
    { name: 'i_created_at_day', type: 'date', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'i_created_at_month', type: 'date', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'i_created_at_year', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
  ],
  [ENTITY_TYPE_RULE]: [
    internalId,
    standardId,
    entityType,
    { name: 'active', type: 'boolean', mandatoryType: 'no', multiple: false, upsert: true }
  ],
  [ENTITY_TYPE_RULE_MANAGER]: [
    internalId,
    { name: 'lastEventId', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'errors', type: 'string', mandatoryType: 'no', multiple: false, upsert: false }
  ],
  [ENTITY_TYPE_CAPABILITY]: [
    internalId,
    standardId,
    entityType,
    { name: 'name', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'attribute_order', type: 'numeric', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'description', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    createdAt,
    updatedAt,
    { name: 'i_created_at_day', type: 'date', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'i_created_at_month', type: 'date', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'i_created_at_year', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
  ],
  [ENTITY_TYPE_CONNECTOR]: [
    internalId,
    standardId,
    entityType,
    { name: 'name', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'active', type: 'boolean', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'auto', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'only_contextual', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'connector_type', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'connector_scope', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'connector_state', type: 'json', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'connector_state_reset', type: 'boolean', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'connector_user_id', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    createdAt,
    updatedAt,
    { name: 'i_created_at_day', type: 'date', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'i_created_at_month', type: 'date', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'i_created_at_year', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
  ],
  [ENTITY_TYPE_WORKSPACE]: [
    internalId,
    standardId,
    entityType,
    { name: 'identifier', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'name', type: 'string', mandatoryType: 'external', multiple: false, upsert: false },
    { name: 'description', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'manifest', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'owner', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'type', type: 'string', mandatoryType: 'internal', multiple: false, upsert: false },
    { name: 'tags', type: 'string', mandatoryType: 'no', multiple: true, upsert: false },
    { name: 'graph_data', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    createdAt,
    updatedAt,
    { name: 'i_created_at_day', type: 'date', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'i_created_at_month', type: 'date', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'i_created_at_year', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
  ],
  [ENTITY_TYPE_TAXII_COLLECTION]: [
    internalId,
    standardId,
    { name: 'name', type: 'string', mandatoryType: 'external', multiple: false, upsert: false },
    { name: 'description', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'filters', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
  ],
  [ENTITY_TYPE_STREAM_COLLECTION]: [
    internalId,
    standardId,
    { name: 'name', type: 'string', mandatoryType: 'external', multiple: false, upsert: false },
    { name: 'description', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'filters', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'stream_public', type: 'boolean', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'stream_live', type: 'boolean', mandatoryType: 'no', multiple: false, upsert: false },
  ],
  [ENTITY_TYPE_STATUS_TEMPLATE]: [
    internalId,
    standardId,
    { name: 'name', type: 'string', mandatoryType: 'external', multiple: false, upsert: false },
    { name: 'color', type: 'string', mandatoryType: 'external', multiple: false, upsert: false },
  ],
  [ENTITY_TYPE_STATUS]: [
    internalId,
    standardId,
    { name: 'template_id', type: 'string', mandatoryType: 'external', multiple: false, upsert: false },
    { name: 'type', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'order', type: 'numeric', mandatoryType: 'external', multiple: false, upsert: false },
  ],
  [ENTITY_TYPE_TASK]: [
    standardId,
    { name: 'task_position', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'task_processed_number', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'task_expected_number', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'last_execution_date', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'completed', type: 'boolean', mandatoryType: 'no', multiple: false, upsert: false },
  ],
  [ENTITY_TYPE_RETENTION_RULE]: [
    standardId,
    { name: 'name', type: 'string', mandatoryType: 'external', multiple: false, upsert: false },
    { name: 'filters', type: 'string', mandatoryType: 'external', multiple: false, upsert: false },
    { name: 'max_retention', type: 'string', mandatoryType: 'external', multiple: false, upsert: false },
    { name: 'last_execution_date', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'last_deleted_count', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'remaining_count', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
  ],
  [ENTITY_TYPE_SYNC]: [
    internalId,
    standardId,
    { name: 'name', type: 'string', mandatoryType: 'external', multiple: false, upsert: false },
    { name: 'uri', type: 'string', mandatoryType: 'external', multiple: false, upsert: false },
    { name: 'ssl_verify', type: 'boolean', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'user_id', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'token', type: 'string', mandatoryType: 'external', multiple: false, upsert: false },
    { name: 'stream_id', type: 'string', mandatoryType: 'external', multiple: false, upsert: false },
    { name: 'running', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'current_state', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'listen_deletion', type: 'boolean', mandatoryType: 'external', multiple: false, upsert: false },
    { name: 'no_dependencies', type: 'boolean', mandatoryType: 'external', multiple: false, upsert: false },
    { name: 'user_id', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
  ],
};

schemaAttributesDefinition.register(ABSTRACT_INTERNAL_OBJECT, INTERNAL_OBJECTS);

export const registerInternalObject = (type: string) => schemaAttributesDefinition.add(ABSTRACT_INTERNAL_OBJECT, type);

R.forEachObjIndexed((value, key) => schemaAttributesDefinition.registerAttributes(key as string, value), internalObjectsAttributes);
