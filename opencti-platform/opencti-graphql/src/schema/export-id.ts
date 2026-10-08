import {
  ENTITY_TYPE_CONNECTOR,
  ENTITY_TYPE_GROUP,
  ENTITY_TYPE_RETENTION_RULE,
  ENTITY_TYPE_ROLE,
  ENTITY_TYPE_RULE,
  ENTITY_TYPE_STATUS,
  ENTITY_TYPE_STATUS_TEMPLATE,
  ENTITY_TYPE_THEME,
} from './internalObject';
import { ENTITY_TYPE_KILL_CHAIN_PHASE, ENTITY_TYPE_LABEL, ENTITY_TYPE_MARKING_DEFINITION } from './stixMetaObject';
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
// They get their internal_id as export_id when created: it identifies the element in the exported bundles,
// so that importing it again on a platform finds the element it comes from instead of creating a duplicate.
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
  ENTITY_TYPE_ROLE,
  ENTITY_TYPE_GROUP,
  ENTITY_TYPE_MARKING_DEFINITION,
  ENTITY_TYPE_RETENTION_RULE,
];

// Types where only some elements are exportable configuration: investigations, connectors registered by
// themselves and built-in decay rules (not editable) get no export_id.
// Each type declares its condition twice, for an element and as an elasticsearch clause for the migration: keep them aligned.
type PartialExportIdType = {
  isExportable: (element: Record<string, any>) => boolean;
  clause: { must?: object[]; must_not?: object[] };
};
const PARTIAL_EXPORT_ID_TYPES: Record<string, PartialExportIdType> = {
  [ENTITY_TYPE_WORKSPACE]: {
    isExportable: (element) => element.type === 'dashboard',
    clause: { must: [{ term: { 'type.keyword': { value: 'dashboard' } } }] },
  },
  [ENTITY_TYPE_CONNECTOR]: {
    isExportable: (element) => Boolean(element.catalog_id),
    clause: { must: [{ exists: { field: 'catalog_id' } }] },
  },
  [ENTITY_TYPE_DECAY_RULE]: {
    isExportable: (element) => element.built_in !== true,
    clause: { must_not: [{ term: { built_in: true } }] },
  },
};

export const isExportIdOnCreation = (type: string, element: Record<string, any>) => {
  return EXPORT_ID_ON_CREATION_TYPES.includes(type) || (PARTIAL_EXPORT_ID_TYPES[type]?.isExportable(element) ?? false);
};

// Same scope as isExportIdOnCreation, as an elasticsearch query
export const exportIdOnCreationQuery = () => {
  const partialClauses = Object.entries(PARTIAL_EXPORT_ID_TYPES).map(([type, { clause }]) => ({
    bool: { ...clause, must: [{ term: { 'entity_type.keyword': { value: type } } }, ...(clause.must ?? [])] },
  }));
  return {
    bool: {
      should: [{ terms: { 'entity_type.keyword': EXPORT_ID_ON_CREATION_TYPES } }, ...partialClauses],
      minimum_should_match: 1,
    },
  };
};
