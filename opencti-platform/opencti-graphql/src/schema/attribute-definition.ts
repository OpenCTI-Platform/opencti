import { ENTITY_TYPE_USER } from './internalObject';

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
  ignoreInCreationForm?: boolean // If this attribute will be part of auto generated creation form in the UI
  multiple: boolean, // If attribute can have multiple values
  mandatoryType: MandatoryType // If attribute is mandatory
  upsert: boolean // If attribute can be upsert by the integration
  isFilterable: boolean // If attribute can be used as a filter key in the UI
  editDefault: boolean // TO CHECK ?????
  update?: boolean // TO CHECK ?????
};

type BasicObjectDefinition = BasicDefinition & {
  mappings: (
    { associatedFilterKeys?: { key: string, label: string }[] } // filter key and their label, to add if key is different from: 'parentAttributeName.nestedAttributeName'
    & AttributeDefinition
  )[],
};
export type DateAttribute = { type: 'date' } & BasicDefinition;
export type BooleanAttribute = { type: 'boolean' } & BasicDefinition;
export type NumericAttribute = { type: 'numeric', precision: 'integer' | 'long' | 'float', scalable?: boolean } & BasicDefinition;
export type IdAttribute = { type: 'string', format: 'id', entityTypes: string[] } & BasicDefinition;
export type TextAttribute = { type: 'string', format: 'short' | 'text' } & BasicDefinition;
export type JsonAttribute = { type: 'string', format: 'json', multiple: false, schemaDef?: Record<string, any> } & BasicDefinition;
export type FlatObjectAttribute = { type: 'object', format: 'flat' } & BasicDefinition;
export type ObjectAttribute = { type: 'object', format: 'standard' } & BasicObjectDefinition;
export type NestedObjectAttribute = { type: 'object', format: 'nested' } & BasicObjectDefinition;
export type RefAttribute = { type: 'ref', databaseName: string, stixName: string, checker: Checker, datable?: boolean } & BasicDefinition;
export type StringAttribute = IdAttribute | TextAttribute | JsonAttribute;
export type ComplexAttribute = FlatObjectAttribute | ObjectAttribute | NestedObjectAttribute;

export type AttributeDefinition = NumericAttribute | DateAttribute | BooleanAttribute | StringAttribute | ComplexAttribute | RefAttribute;

// -- GLOBAL --
export const id: AttributeDefinition = {
  name: 'id',
  label: 'Id',
  type: 'string',
  format: 'short',
  mandatoryType: 'no',
  multiple: false,
  editDefault: false,
  upsert: false,
  isFilterable: false,
  ignoreInCreationForm: true,
};

export const internalId: AttributeDefinition = {
  name: 'internal_id',
  label: 'Internal id',
  type: 'string',
  format: 'short',
  mandatoryType: 'no',
  editDefault: false,
  multiple: false,
  upsert: false,
  isFilterable: false,
};

export const creators: AttributeDefinition = {
  name: 'creator_id',
  label: 'Creators',
  type: 'string',
  format: 'id',
  entityTypes: [ENTITY_TYPE_USER],
  mandatoryType: 'no',
  editDefault: false,
  multiple: true,
  upsert: false,
  isFilterable: true,
};

export const standardId: AttributeDefinition = {
  name: 'standard_id',
  label: 'Id',
  type: 'string',
  format: 'short',
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
  mandatoryType: 'no',
  editDefault: false,
  multiple: true,
  upsert: false,
  isFilterable: true,
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
  isFilterable: true,
  mappings: [
    id,
    { name: 'name', label: 'Name', type: 'string', format: 'short', editDefault: false, mandatoryType: 'no', multiple: true, upsert: true, isFilterable: true },
    { name: 'version', label: 'Version', type: 'string', format: 'short', editDefault: false, mandatoryType: 'no', multiple: true, upsert: true, isFilterable: true },
    { name: 'mime_type', label: 'Mime type', type: 'string', format: 'short', editDefault: false, mandatoryType: 'no', multiple: true, upsert: true, isFilterable: true },
  ]
};

export const authorizedMembers: AttributeDefinition = {
  name: 'authorized_members',
  label: 'Authorized members',
  type: 'object',
  format: 'standard',
  mandatoryType: 'no',
  editDefault: false,
  multiple: true,
  upsert: false,
  isFilterable: false,
  mappings: [
    id,
    { name: 'name', label: 'Name', type: 'string', format: 'short', editDefault: false, mandatoryType: 'no', multiple: true, upsert: true, isFilterable: false },
    { name: 'entity_type', label: 'Entity type', type: 'string', format: 'short', editDefault: false, mandatoryType: 'no', multiple: true, upsert: true, isFilterable: false },
    { name: 'access_right', label: 'Access right', type: 'string', format: 'short', editDefault: false, mandatoryType: 'no', multiple: true, upsert: true, isFilterable: false },
  ]
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

// -- ENTITY TYPE --

export const parentTypes: AttributeDefinition = {
  name: 'parent_types',
  label: 'Parent types',
  type: 'string',
  format: 'short',
  mandatoryType: 'internal',
  editDefault: false,
  multiple: true,
  upsert: false,
  isFilterable: true,
};

export const baseType: AttributeDefinition = {
  name: 'base_type',
  label: 'Base type',
  type: 'string',
  format: 'short',
  mandatoryType: 'internal',
  editDefault: false,
  multiple: false,
  upsert: false,
  isFilterable: true,
};

export const entityType: AttributeDefinition = {
  name: 'entity_type',
  label: 'Entity type',
  type: 'string',
  format: 'short',
  mandatoryType: 'internal',
  editDefault: false,
  multiple: false,
  upsert: false,
  isFilterable: true,
};

export const entityLocationType: AttributeDefinition = {
  name: 'x_opencti_location_type',
  label: 'Location type',
  type: 'string',
  format: 'short',
  mandatoryType: 'internal',
  editDefault: false,
  multiple: false,
  upsert: false,
  isFilterable: true,
};

export const relationshipType: AttributeDefinition = {
  name: 'relationship_type',
  label: 'Relationship type',
  type: 'string',
  format: 'short',
  mandatoryType: 'internal',
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
  upsert: false,
  isFilterable: false,
};

// ALIASES

export const xOpenctiAliases: AttributeDefinition = {
  name: 'x_opencti_aliases',
  label: 'Aliases',
  type: 'string',
  format: 'short',
  mandatoryType: 'no',
  editDefault: false,
  multiple: true,
  upsert: true,
  isFilterable: true,
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
  isFilterable: true,
};

// OTHERS

export const created: AttributeDefinition = {
  name: 'created',
  label: 'Created',
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
  upsert: false,
  isFilterable: true,
};

export const createdAt: AttributeDefinition = {
  name: 'created_at',
  label: 'Created at',
  type: 'date',
  mandatoryType: 'internal',
  editDefault: false,
  multiple: false,
  upsert: false,
  isFilterable: true,
};
export const updatedAt: AttributeDefinition = {
  name: 'updated_at',
  label: 'Updated at',
  type: 'date',
  mandatoryType: 'internal',
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
  isFilterable: true,
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
  format: 'short',
  mandatoryType: 'no',
  editDefault: false,
  multiple: false,
  upsert: false,
  isFilterable: true,
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
  isFilterable: true,
};

export const identityClass: AttributeDefinition = {
  name: 'identity_class',
  label: 'Identity class',
  type: 'string',
  format: 'short',
  mandatoryType: 'no',
  editDefault: false,
  multiple: false,
  upsert: false,
  isFilterable: true,
};
