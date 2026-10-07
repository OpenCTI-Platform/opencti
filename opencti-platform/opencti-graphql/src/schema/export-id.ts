import { ENTITY_TYPE_CONNECTOR, ENTITY_TYPE_RULE, ENTITY_TYPE_STATUS, ENTITY_TYPE_STATUS_TEMPLATE, ENTITY_TYPE_THEME } from './internalObject';
import { ENTITY_TYPE_KILL_CHAIN_PHASE, ENTITY_TYPE_LABEL } from './stixMetaObject';
import { ENTITY_TYPE_WORKSPACE } from '../modules/workspace/workspace-types';
import { ENTITY_TYPE_PLAYBOOK } from '../modules/playbook/playbook-types';
import { ENTITY_TYPE_CUSTOM_VIEW } from '../modules/customView/customView-types';
import { ENTITY_TYPE_FINTEL_TEMPLATE } from '../modules/fintelTemplate/fintelTemplate-types';
import { ENTITY_TYPE_FORM } from '../modules/form/form-types';
import {
  ENTITY_TYPE_INGESTION_CSV,
  ENTITY_TYPE_INGESTION_JSON,
  ENTITY_TYPE_INGESTION_RSS,
  ENTITY_TYPE_INGESTION_TAXII,
  ENTITY_TYPE_INGESTION_TAXII_COLLECTION,
} from '../modules/ingestion/ingestion-types';
import { ENTITY_TYPE_WORKFLOW_DEFINITION } from '../modules/workflow/types/workflow-types';
import { ENTITY_TYPE_CUSTOM_FIELD_DEFINITION } from '../modules/customField/custom-field-types';
import { ENTITY_TYPE_VOCABULARY } from '../modules/vocabulary/vocabulary-types';
import { ENTITY_TYPE_CASE_TEMPLATE } from '../modules/case/case-template/case-template-types';
import { ENTITY_TYPE_SAVED_FILTER } from '../modules/savedFilter/savedFilter-types';
import { ENTITY_TYPE_FINTEL_DESIGN } from '../modules/fintelDesign/fintelDesign-types';
import { ENTITY_TYPE_DECAY_RULE } from '../modules/decayRule/decayRule-types';
import { ENTITY_TYPE_EXCLUSION_LIST } from '../modules/exclusionList/exclusionList-types';
import { ENTITY_TYPE_DISSEMINATION_LIST } from '../modules/disseminationList/disseminationList-types';
import { ENTITY_TYPE_AUTHENTICATION_PROVIDER } from '../modules/authenticationProvider/authenticationProvider-types';
import { ENTITY_TYPE_EMAIL_TEMPLATE } from '../modules/emailTemplate/emailTemplate-types';
import { ENTITY_TYPE_NOTIFIER } from '../modules/notifier/notifier-types';

// Configuration elements created by users that can be carried from one platform to another.
// They get their internal_id as export_id when created: it identifies the element in the exported bundles.
// Built-in elements of these types already get a deterministic export_id at platform init (see generateBuiltInExportId).
export const EXPORT_ID_ON_CREATION_TYPES = [
  ENTITY_TYPE_PLAYBOOK,
  ENTITY_TYPE_CUSTOM_VIEW,
  ENTITY_TYPE_FINTEL_TEMPLATE,
  ENTITY_TYPE_FORM,
  ENTITY_TYPE_INGESTION_CSV,
  ENTITY_TYPE_INGESTION_JSON,
  ENTITY_TYPE_INGESTION_RSS,
  ENTITY_TYPE_INGESTION_TAXII,
  ENTITY_TYPE_INGESTION_TAXII_COLLECTION,
  ENTITY_TYPE_WORKFLOW_DEFINITION,
  ENTITY_TYPE_CUSTOM_FIELD_DEFINITION,
  ENTITY_TYPE_STATUS,
  ENTITY_TYPE_LABEL,
  ENTITY_TYPE_VOCABULARY,
  ENTITY_TYPE_KILL_CHAIN_PHASE,
  ENTITY_TYPE_STATUS_TEMPLATE,
  ENTITY_TYPE_CASE_TEMPLATE,
  ENTITY_TYPE_SAVED_FILTER,
  ENTITY_TYPE_FINTEL_DESIGN,
  ENTITY_TYPE_EXCLUSION_LIST,
  // A rule is stored with its rule identifier as internal_id, so its export_id is the same on every platform
  ENTITY_TYPE_RULE,
  ENTITY_TYPE_DISSEMINATION_LIST,
  ENTITY_TYPE_AUTHENTICATION_PROVIDER,
  ENTITY_TYPE_EMAIL_TEMPLATE,
  ENTITY_TYPE_NOTIFIER,
  ENTITY_TYPE_THEME,
];

// Types where only some elements are exportable configuration: investigations, connectors registered by
// themselves and built-in decay rules (not editable) get no export_id.
const isDashboard = (element: Record<string, any>) => element.type === 'dashboard';
const isManagedConnector = (element: Record<string, any>) => Boolean(element.catalog_id);
const isCustomDecayRule = (element: Record<string, any>) => element.built_in !== true;
const PARTIAL_EXPORT_ID_TYPES: Record<string, (element: Record<string, any>) => boolean> = {
  [ENTITY_TYPE_WORKSPACE]: isDashboard,
  [ENTITY_TYPE_CONNECTOR]: isManagedConnector,
  [ENTITY_TYPE_DECAY_RULE]: isCustomDecayRule,
};

export const isExportIdOnCreation = (type: string, element: Record<string, any>) => {
  return EXPORT_ID_ON_CREATION_TYPES.includes(type) || (PARTIAL_EXPORT_ID_TYPES[type]?.(element) ?? false);
};

// Same scope as isExportIdOnCreation, as an elasticsearch query
export const exportIdOnCreationQuery = () => {
  const ofType = (type: string) => ({ term: { 'entity_type.keyword': { value: type } } });
  return {
    bool: {
      should: [
        { terms: { 'entity_type.keyword': EXPORT_ID_ON_CREATION_TYPES } },
        { bool: { must: [ofType(ENTITY_TYPE_WORKSPACE), { term: { 'type.keyword': { value: 'dashboard' } } }] } },
        { bool: { must: [ofType(ENTITY_TYPE_CONNECTOR), { exists: { field: 'catalog_id' } }] } },
        { bool: { must: [ofType(ENTITY_TYPE_DECAY_RULE)], must_not: [{ term: { built_in: true } }] } },
      ],
      minimum_should_match: 1,
    },
  };
};
