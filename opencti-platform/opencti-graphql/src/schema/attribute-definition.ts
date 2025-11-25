import { ENTITY_TYPE_GROUP, ENTITY_TYPE_USER } from './internalObject';
import { ABSTRACT_BASIC_OBJECT, ABSTRACT_BASIC_RELATIONSHIP } from './general';
import { getDraftOperations } from '../modules/draftWorkspace/draftOperations';

export const shortMapping = {
  type: 'text',
  fields: {
    keyword: {
      type: 'keyword',
      ignore_above: 512,
      normalizer: 'string_normalizer'
    },
  },
};
export const textMapping = { type: 'text' };
export const dateMapping = { type: 'date' };
export const booleanMapping = { type: 'boolean' };
export const numericMapping = (precision: string) => ({ type: precision, coerce: false });

export type Checker = (fromType: string, toType: string) => boolean;

export type AttrType = 'string' | 'date' | 'numeric' | 'boolean' | 'object' | 'ref';

export type MandatoryType = 'internal' | 'external' | 'customizable' | 'no';
// internal =
// external =
// customizable =
// no = impossible to change to mandatory in the dynamic configuration

type BasicDefinition = {
  name: string // name in the database
  label: string // label for front display
  description?: string // Description of the attribute
  multiple: boolean, // If attribute can have multiple values
  mandatoryType: MandatoryType // If attribute is mandatory
  upsert: boolean // If attribute can be upsert by the integration
  upsert_force_replace?: boolean, // For multiple, if upsert will for a replacement instead of cumulate information
  isFilterable: boolean // If attribute can be used as a filter key in the UI
  editDefault: boolean // TO CHECK ?????
  update?: boolean // If attribute can be updated (null = true)
  featureFlag?: string // if attribute is on feature flag, null by default
};

export type MappingDefinition = AttributeDefinition & {
  associatedFilterKeys?: { key: string, label: string }[] // filter key and their label, to add if key is different from: 'parentAttributeName.nestedAttributeName'
};

type BasicObjectDefinition = BasicDefinition & {
  mappings: MappingDefinition[],
  // if the object attribute can be used for sorting, we need to know how
  sortBy?: {
    path: string // path leading to the value that serves for sorting
    type: string // type of this value, copied for convenience from corresponding mapping (checked at registration)
  }
};
export type DateAttribute = { type: 'date' } & BasicDefinition;
export type BooleanAttribute = { type: 'boolean' } & BasicDefinition;
export type NumericAttribute = { type: 'numeric', precision: 'integer' | 'long' | 'float', scalable?: boolean } & BasicDefinition;
export type IdAttribute = { type: 'string', format: 'id', entityTypes: string[] } & BasicDefinition;
export type TextAttribute = { type: 'string', format: 'short' | 'text' } & BasicDefinition;
export type EnumAttribute = { type: 'string', format: 'enum', values: string[] } & BasicDefinition;
export type VocabAttribute = { type: 'string', format: 'vocabulary', vocabularyCategory: string } & BasicDefinition;
export type JsonAttribute = { type: 'string', format: 'json', multiple: false, schemaDef?: Record<string, any> } & BasicDefinition;
export type FlatObjectAttribute = { type: 'object', format: 'flat' } & BasicDefinition;
export type ObjectAttribute = { type: 'object', format: 'standard' } & BasicObjectDefinition;
export type NestedObjectAttribute = { type: 'object', format: 'nested' } & BasicObjectDefinition;
export type RefAttribute = { type: 'ref', databaseName: string, stixName: string, isRefExistingForTypes: Checker, datable?: boolean, toTypes: string[] } & BasicDefinition;
export type StringAttribute = IdAttribute | TextAttribute | EnumAttribute | VocabAttribute | JsonAttribute;
export type ComplexAttribute = FlatObjectAttribute | ObjectAttribute | NestedObjectAttribute;
export type ComplexAttributeWithMappings = ObjectAttribute | NestedObjectAttribute;

export type AttributeDefinition = NumericAttribute | DateAttribute | BooleanAttribute | StringAttribute | ComplexAttribute | RefAttribute;

export const shortStringFormats = ['id', 'short', 'enum', 'vocabulary'];
export const longStringFormats = ['text', 'json'];

// -- Type guards TS --
export const isNumericAttribute = (attribute: AttributeDefinition): attribute is NumericAttribute => attribute.type === 'numeric';
export const isDateAttribute = (attribute: AttributeDefinition): attribute is DateAttribute => attribute.type === 'date';
export const isBooleanAttribute = (attribute: AttributeDefinition): attribute is BooleanAttribute => attribute.type === 'boolean';
export const isStringAttribute = (attribute: AttributeDefinition): attribute is StringAttribute => attribute.type === 'string';
export const isComplexAttribute = (attribute: AttributeDefinition): attribute is ComplexAttribute => attribute.type === 'object';
export const isRefAttribute = (attribute: AttributeDefinition): attribute is RefAttribute => attribute.type === 'ref';

// -- GLOBAL --
export const id: AttributeDefinition = {
  name: 'id',
  label: 'Id',
  type: 'string',
  format: 'id',
  update: false,
  mandatoryType: 'no',
  multiple: false,
  editDefault: false,
  upsert: false,
  isFilterable: false,
  entityTypes: [ABSTRACT_BASIC_OBJECT, ABSTRACT_BASIC_RELATIONSHIP]
};

export const draftIds: AttributeDefinition = {
  name: 'draft_ids',
  label: 'Draft ids',
  type: 'string',
  format: 'id',
  update: false,
  mandatoryType: 'no',
  multiple: true,
  editDefault: false,
  upsert: false,
  isFilterable: false,
  entityTypes: [ABSTRACT_BASIC_OBJECT, ABSTRACT_BASIC_RELATIONSHIP],
};

export const draftContext: AttributeDefinition = {
  name: 'draft_context',
  label: 'Current draft context',
  type: 'string',
  format: 'short',
  mandatoryType: 'no',
  multiple: false,
  editDefault: false,
  upsert: false,
  isFilterable: true,
};

export const draftChange: AttributeDefinition = {
  name: 'draft_change',
  label: 'Draft change',
  type: 'object',
  format: 'standard',
  update: false,
  mandatoryType: 'no',
  editDefault: false,
  multiple: false,
  upsert: false,
  isFilterable: true,
  mappings: [
    { name: 'draft_operation', label: 'Draft operation', type: 'string', format: 'enum', values: getDraftOperations(), mandatoryType: 'external', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'draft_updates_patch', label: 'Draft update patch', type: 'string', format: 'json', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: false },
  ]
};

export const iAttributes: AttributeDefinition = {
  name: 'i_attributes',
  label: 'Attributes',
  type: 'object',
  format: 'standard',
  update: false,
  mandatoryType: 'no',
  editDefault: false,
  multiple: true,
  upsert: false,
  isFilterable: false,
  mappings: [
    { name: 'name', label: 'Attribute name', type: 'string', format: 'short', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'updated_at', label: 'Updated at', type: 'date', editDefault: false, mandatoryType: 'no', multiple: false, upsert: false, isFilterable: true },
    { name: 'confidence', label: 'Confidence', type: 'numeric', precision: 'integer', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'user_id', label: 'Last modifier', type: 'string', format: 'id', entityTypes: [ENTITY_TYPE_USER], editDefault: false, mandatoryType: 'no', multiple: false, upsert: false, isFilterable: false },
  ]
};

export const internalId: AttributeDefinition = {
  name: 'internal_id',
  label: 'Internal id',
  type: 'string',
  format: 'id',
  update: false,
  mandatoryType: 'no',
  editDefault: false,
  multiple: false,
  upsert: false,
  isFilterable: false,
  entityTypes: [ABSTRACT_BASIC_OBJECT, ABSTRACT_BASIC_RELATIONSHIP]
};

export const creators: AttributeDefinition = {
  name: 'creator_id',
  label: 'Creators',
  type: 'string',
  format: 'id',
  update: true,
  entityTypes: [ENTITY_TYPE_USER],
  mandatoryType: 'no',
  editDefault: false,
  multiple: true,
  upsert: true,
  isFilterable: true,
};

export const standardId: AttributeDefinition = {
  name: 'standard_id',
  label: 'Standard id',
  type: 'string',
  format: 'short',
  update: false,
  mandatoryType: 'internal',
  editDefault: false,
  multiple: false,
  upsert: false,
  isFilterable: false,
};

export const iAliasedIds: AttributeDefinition = {
  name: 'i_aliases_ids',
  label: 'Internal aliases',
  type: 'string',
  format: 'short', // Not ID as alias is not really an entity
  update: false,
  mandatoryType: 'no',
  editDefault: false,
  multiple: true,
  upsert: false,
  isFilterable: false,
};

export const lastEventId: AttributeDefinition = {
  name: 'lastEventId',
  label: 'Last event id',
  type: 'string',
  format: 'short',
  mandatoryType: 'no',
  editDefault: false,
  multiple: false,
  upsert: false,
  isFilterable: false,
};

export const files: AttributeDefinition = {
  name: 'x_opencti_files',
  label: 'Files',
  type: 'object',
  format: 'standard',
  mandatoryType: 'no',
  editDefault: false,
  multiple: true,
  upsert: false,
  update: false,
  isFilterable: false,
  mappings: [
    id,
    { name: 'name', label: 'Name', type: 'string', format: 'short', editDefault: false, mandatoryType: 'no', multiple: true, upsert: true, isFilterable: true },
    { name: 'description', label: 'Description', type: 'string', format: 'text', editDefault: false, mandatoryType: 'no', multiple: true, upsert: true, isFilterable: true },
    { name: 'version', label: 'Version', type: 'date', editDefault: false, mandatoryType: 'no', multiple: true, upsert: true, isFilterable: true },
    { name: 'mime_type', label: 'Mime type', type: 'string', format: 'short', editDefault: false, mandatoryType: 'no', multiple: true, upsert: true, isFilterable: true },
    { name: 'inCarousel', label: 'Include in carousel', type: 'boolean', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'order', label: 'Order in carousel', type: 'numeric', precision: 'integer', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'file_markings', label: 'Markings', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: true, upsert: true, isFilterable: true },
  ]
};

export const authorizedMembers: AttributeDefinition = {
  name: 'restricted_members',
  label: 'Authorized members',
  type: 'object',
  format: 'nested',
  mandatoryType: 'no',
  editDefault: false,
  multiple: true,
  upsert: false,
  isFilterable: false,
  mappings: [
    id,
    { name: 'access_right', label: 'Access right', type: 'string', format: 'short', editDefault: false, mandatoryType: 'no', multiple: true, upsert: true, isFilterable: false },
    { name: 'groups_restriction_ids', label: 'Groups restriction IDs', type: 'string', format: 'id', entityTypes: [ENTITY_TYPE_GROUP], editDefault: false, mandatoryType: 'no', multiple: true, upsert: true, isFilterable: false },
  ]
};

export const authorizedMembersActivationDate : AttributeDefinition = {
  name: 'authorized_members_activation_date',
  label: 'Authorized members activation date',
  type: 'date',
  mandatoryType: 'no',
  editDefault: false,
  multiple: false,
  upsert: false,
  isFilterable: false,
};

export const authorizedAuthorities: AttributeDefinition = {
  name: 'authorized_authorities',
  label: 'Authorized authorities',
  type: 'string',
  format: 'short', // Not ID as could be anything
  mandatoryType: 'no',
  editDefault: false,
  multiple: true,
  upsert: false,
  isFilterable: false,
};

export const metrics: AttributeDefinition = {
  name: 'metrics',
  label: 'Entity metrics',
  type: 'object',
  format: 'nested',
  mandatoryType: 'no',
  editDefault: false,
  multiple: true,
  upsert: true,
  isFilterable: false,
  mappings: [
    { name: 'name', label: 'Metric name', type: 'string', format: 'short', editDefault: false, mandatoryType: 'no', multiple: false, upsert: true, isFilterable: false },
    { name: 'value', label: 'Metric value', type: 'numeric', precision: 'float', editDefault: false, mandatoryType: 'no', multiple: false, upsert: true, isFilterable: false },
  ]
};

// -- ENTITY TYPE --

export const parentTypes: AttributeDefinition = {
  name: 'parent_types',
  label: 'Parent types',
  type: 'string',
  format: 'short',
  mandatoryType: 'internal',
  update: false,
  editDefault: false,
  multiple: true,
  upsert: false,
  isFilterable: false,
};

export const baseType: AttributeDefinition = {
  name: 'base_type',
  label: 'Base type',
  type: 'string',
  format: 'short',
  mandatoryType: 'internal',
  update: false,
  editDefault: false,
  multiple: false,
  upsert: false,
  isFilterable: false,
};

export const entityType: AttributeDefinition = {
  name: 'entity_type',
  label: 'Entity type',
  type: 'string',
  format: 'short',
  mandatoryType: 'internal',
  update: false,
  editDefault: false,
  multiple: false,
  upsert: false,
  isFilterable: true, // filterable only for abstract types in filterKeysSchema
};

export const entityLocationType: AttributeDefinition = {
  name: 'x_opencti_location_type',
  label: 'Location type',
  type: 'string',
  format: 'short',
  mandatoryType: 'internal',
  update: false,
  editDefault: false,
  multiple: false,
  upsert: false,
  isFilterable: false,
};

export const relationshipType: AttributeDefinition = {
  name: 'relationship_type',
  label: 'Relationship type',
  type: 'string',
  format: 'short',
  mandatoryType: 'internal',
  update: false,
  editDefault: false,
  multiple: false,
  upsert: false,
  isFilterable: true,
};

export const xOpenctiType: AttributeDefinition = {
  name: 'x_opencti_type',
  label: 'Type',
  type: 'string',
  format: 'short',
  mandatoryType: 'no',
  update: false,
  editDefault: false,
  multiple: false,
  upsert: false,
  isFilterable: true,
};

export const errors: AttributeDefinition = {
  name: 'errors',
  label: 'Errors',
  type: 'object',
  format: 'standard',
  mandatoryType: 'no',
  editDefault: false,
  multiple: true,
  upsert: false,
  isFilterable: true,
  mappings: [
    id,
    { name: 'message', label: 'Message', type: 'string', format: 'text', editDefault: false, mandatoryType: 'no', multiple: true, upsert: true, isFilterable: true },
    { name: 'error', label: 'Error', type: 'string', format: 'text', editDefault: false, mandatoryType: 'no', multiple: true, upsert: true, isFilterable: true },
    { name: 'source', label: 'Source', type: 'string', format: 'text', editDefault: false, mandatoryType: 'no', multiple: true, upsert: true, isFilterable: true },
    { name: 'timestamp', label: 'Timestamp', type: 'date', editDefault: false, mandatoryType: 'no', multiple: true, upsert: true, isFilterable: true },
  ]
};

export const coverageInformation: AttributeDefinition = {
  name: 'coverage_information',
  label: 'Coverage',
  type: 'object',
  format: 'nested',
  mandatoryType: 'no',
  editDefault: false,
  multiple: true,
  upsert: true,
  upsert_force_replace: true,
  isFilterable: false, // Filter will be done by a special key
  mappings: [
    { name: 'coverage_name', label: 'Coverage name', type: 'string', format: 'vocabulary', vocabularyCategory: 'coverage_ov', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'coverage_score', label: 'Coverage score', type: 'numeric', mandatoryType: 'external', precision: 'float', upsert: true, editDefault: false, multiple: false, isFilterable: false },
  ]
};

export const opinionsMetrics: AttributeDefinition = {
  name: 'opinions_metrics',
  label: 'Opinion metrics',
  type: 'object',
  format: 'standard',
  mandatoryType: 'no',
  editDefault: false,
  multiple: false,
  upsert: true,
  isFilterable: true,
  mappings: [
    { name: 'mean', label: 'Opinions mean', type: 'numeric', precision: 'float', editDefault: false, mandatoryType: 'no', multiple: false, upsert: true, isFilterable: true },
    { name: 'max', label: 'Opinions max', type: 'numeric', precision: 'integer', editDefault: false, mandatoryType: 'no', multiple: false, upsert: true, isFilterable: true },
    { name: 'min', label: 'Opinions min', type: 'numeric', precision: 'integer', editDefault: false, mandatoryType: 'no', multiple: false, upsert: true, isFilterable: true },
    { name: 'total', label: 'Opinions total number', type: 'numeric', precision: 'integer', editDefault: false, mandatoryType: 'no', multiple: false, upsert: true, isFilterable: true },
  ]
};

// -- STIX DOMAIN OBJECT --

// IDS

export const xOpenctiStixIds: AttributeDefinition = {
  name: 'x_opencti_stix_ids',
  label: 'STIX IDs',
  type: 'string',
  format: 'short', // No ID as self contains internal id of the elements
  mandatoryType: 'no',
  editDefault: false,
  multiple: true,
  upsert: true,
  isFilterable: false,
};

// ALIASES

export const xOpenctiAliases: AttributeDefinition = {
  name: 'x_opencti_aliases',
  label: 'X_Aliases',
  type: 'string',
  format: 'short',
  mandatoryType: 'no',
  editDefault: false,
  multiple: true,
  upsert: true,
  isFilterable: false, // special filter key 'alias' (to filer on both 'aliases' and 'x_opencti_aliases') is added in filterKeysSchema
};

export const aliases: AttributeDefinition = {
  name: 'aliases',
  label: 'Aliases',
  type: 'string',
  format: 'short',
  mandatoryType: 'no',
  editDefault: false,
  multiple: true,
  upsert: true,
  isFilterable: false, // special filter key 'alias' (to filer on both 'aliases' and 'x_opencti_aliases') is added in filterKeysSchema
};

// OTHERS

export const created: AttributeDefinition = {
  name: 'created',
  label: 'Original creation date',
  type: 'date',
  mandatoryType: 'no',
  editDefault: false,
  multiple: false,
  upsert: false,
  isFilterable: true,
};
export const modified: AttributeDefinition = {
  name: 'modified',
  label: 'Modified',
  type: 'date',
  mandatoryType: 'no',
  editDefault: false,
  multiple: false,
  upsert: true,
  isFilterable: false, // use updated_at filter
};

export const createdAt: AttributeDefinition = {
  name: 'created_at',
  label: 'Platform creation date',
  type: 'date',
  mandatoryType: 'internal',
  update: false,
  editDefault: false,
  multiple: false,
  upsert: false,
  isFilterable: true,
};
export const updatedAt: AttributeDefinition = {
  name: 'updated_at',
  label: 'Modification date',
  type: 'date',
  mandatoryType: 'internal',
  update: false,
  editDefault: false,
  multiple: false,
  upsert: false,
  isFilterable: true,
};
export const refreshedAt: AttributeDefinition = {
  name: 'refreshed_at',
  label: 'Freshness date',
  type: 'date',
  mandatoryType: 'internal',
  update: false,
  editDefault: false,
  multiple: false,
  upsert: false,
  isFilterable: true,
};

export const revoked: AttributeDefinition = {
  name: 'revoked',
  label: 'Revoked',
  type: 'boolean',
  mandatoryType: 'no',
  editDefault: false,
  multiple: false,
  upsert: true,
  isFilterable: false,
};

export const confidence: AttributeDefinition = {
  name: 'confidence',
  label: 'Confidence',
  type: 'numeric',
  precision: 'integer',
  mandatoryType: 'no',
  editDefault: true,
  multiple: false,
  scalable: true,
  upsert: true,
  isFilterable: true,
};

export const xOpenctiReliability: AttributeDefinition = {
  name: 'x_opencti_reliability',
  label: 'Reliability',
  type: 'string',
  format: 'vocabulary',
  vocabularyCategory: 'reliability_ov',
  mandatoryType: 'no',
  editDefault: false,
  multiple: false,
  upsert: false,
  isFilterable: false, // use special filter key 'computed_reliability'
};

export const lang: AttributeDefinition = {
  name: 'lang',
  label: 'Lang',
  type: 'string',
  format: 'short',
  mandatoryType: 'no',
  editDefault: false,
  multiple: false,
  upsert: false,
  isFilterable: false,
};

export const identityClass: AttributeDefinition = {
  name: 'identity_class',
  label: 'Identity class',
  type: 'string',
  format: 'short',
  mandatoryType: 'no',
  update: false,
  editDefault: false,
  multiple: false,
  upsert: false,
  isFilterable: false,
};
