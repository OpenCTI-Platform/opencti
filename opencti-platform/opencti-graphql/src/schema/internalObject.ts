import { ABSTRACT_INTERNAL_OBJECT } from './general';
import { schemaTypesDefinition } from './schema-types';
import { ENTITY_TYPE_WORKSPACE } from '../modules/workspace/workspace-types';
import { ENTITY_TYPE_PUBLIC_DASHBOARD } from '../modules/publicDashboard/publicDashboard-types';
import { ENTITY_TYPE_DELETE_OPERATION } from '../modules/deleteOperation/deleteOperation-types';
import { ENTITY_TYPE_DRAFT_WORKSPACE } from '../modules/draftWorkspace/draftWorkspace-types';
import { ENTITY_TYPE_EXCLUSION_LIST } from '../modules/exclusionList/exclusionList-types';
import { ENTITY_TYPE_FINTEL_TEMPLATE } from '../modules/fintelTemplate/fintelTemplate-types';
import { ENTITY_TYPE_SAVED_FILTER } from '../modules/savedFilter/savedFilter-types';

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
export const ENTITY_TYPE_HISTORY = 'History';
export const ENTITY_TYPE_ACTIVITY = 'Activity';
export const ENTITY_TYPE_WORK = 'work';
export const ENTITY_TYPE_BACKGROUND_TASK = 'BackgroundTask';
export const ENTITY_TYPE_RETENTION_RULE = 'RetentionRule';
// FIXME: recommend 'Sync' be changed to 'Synchronizer' or vice versa
//  this should be done for consistency across baseline.  GraphQL
//  object is named 'Synchronizer'
export const ENTITY_TYPE_SYNC = 'Sync';
export const ENTITY_TYPE_TAXII_COLLECTION = 'TaxiiCollection';
export const ENTITY_TYPE_INTERNAL_FILE = 'InternalFile';
export const ENTITY_TYPE_FEED = 'Feed';
export const ENTITY_TYPE_STREAM_COLLECTION = 'StreamCollection';
export const ENTITY_TYPE_STATUS_TEMPLATE = 'StatusTemplate';
export const ENTITY_TYPE_STATUS = 'Status';
export const ENTITY_TYPE_THEME = 'Theme';
const DATED_INTERNAL_OBJECTS = [
  ENTITY_TYPE_SETTINGS,
  ENTITY_TYPE_GROUP,
  ENTITY_TYPE_USER,
  ENTITY_TYPE_ROLE,
  ENTITY_TYPE_CAPABILITY,
  ENTITY_TYPE_CONNECTOR,
  ENTITY_TYPE_WORKSPACE,
  ENTITY_TYPE_SYNC,
  ENTITY_TYPE_PUBLIC_DASHBOARD,
  ENTITY_TYPE_DELETE_OPERATION,
  ENTITY_TYPE_DRAFT_WORKSPACE,
  ENTITY_TYPE_EXCLUSION_LIST,
  ENTITY_TYPE_SAVED_FILTER,
];
const INTERNAL_OBJECTS = [
  ENTITY_TYPE_SETTINGS,
  ENTITY_TYPE_TAXII_COLLECTION,
  ENTITY_TYPE_FEED,
  ENTITY_TYPE_STREAM_COLLECTION,
  ENTITY_TYPE_STATUS_TEMPLATE,
  ENTITY_TYPE_STATUS,
  ENTITY_TYPE_BACKGROUND_TASK,
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
  ENTITY_TYPE_PUBLIC_DASHBOARD,
  ENTITY_TYPE_HISTORY,
  ENTITY_TYPE_ACTIVITY,
  ENTITY_TYPE_INTERNAL_FILE,
  ENTITY_TYPE_WORK,
  ENTITY_TYPE_DRAFT_WORKSPACE,
  ENTITY_TYPE_EXCLUSION_LIST,
  ENTITY_TYPE_FINTEL_TEMPLATE,
  ENTITY_TYPE_SAVED_FILTER,
  ENTITY_TYPE_THEME,
];
const HISTORY_OBJECTS = [ENTITY_TYPE_WORK];

export const isInternalObject = (type: string) => schemaTypesDefinition.isTypeIncludedIn(type, ABSTRACT_INTERNAL_OBJECT) || type === ABSTRACT_INTERNAL_OBJECT;
export const isDatedInternalObject = (type: string) => DATED_INTERNAL_OBJECTS.includes(type);
export const isHistoryObject = (type: string) => HISTORY_OBJECTS.includes(type);

schemaTypesDefinition.register(ABSTRACT_INTERNAL_OBJECT, INTERNAL_OBJECTS);
