export const textMapping = {
  type: 'text',
  fields: {
    keyword: {
      type: 'keyword',
      normalizer: 'string_normalizer'
    },
  },
};
export const dateMapping = { type: 'date' };

export type AttrType = 'string' | 'date' | 'numeric' | 'boolean' | 'dictionary' | 'json' | 'object';
export type MandatoryType = 'internal' | 'external' | 'customizable' | 'no';

type BasicDefinition = {
  name: string
  label?: string
  multiple: boolean,
  mandatoryType: MandatoryType
  editDefault: boolean
  multiple: boolean
  upsert: boolean
  update?: boolean
};

export type StringAttribute = { type: 'string' } & BasicDefinition;
export type DateAttribute = { type: 'date' } & BasicDefinition;
export type DictionaryAttribute = { type: 'dictionary' } & BasicDefinition;
export type BooleanAttribute = { type: 'boolean' } & BasicDefinition;
export type NumericAttribute = { type: 'numeric', scalable?: boolean } & BasicDefinition;
export type JsonAttribute = { type: 'json', multiple: false, schemaDef?: Record<string, any> } & BasicDefinition;
export type ObjectAttribute = { type: 'object', nested?: boolean, mapping: Record<string, any> } & BasicDefinition;

export type AttributeDefinition = StringAttribute | JsonAttribute | ObjectAttribute | DictionaryAttribute |
NumericAttribute | DateAttribute | BooleanAttribute;

// -- GLOBAL --

export const id: AttributeDefinition = {
  name: 'id',
  type: 'string',
  mandatoryType: 'no',
  multiple: false,
  upsert: false
};

// TODO Duplication of ID
export const internalId: AttributeDefinition = {
  name: 'internal_id',
  type: 'string',
  mandatoryType: 'no',
  editDefault: false,
  multiple: false,
  upsert: false
};

export const creators: AttributeDefinition = {
  name: 'creator_id',
  label: 'Creators',
  type: 'string',
  mandatoryType: 'no',
  editDefault: false,
  multiple: true,
  upsert: false
};

export const standardId: AttributeDefinition = {
  name: 'standard_id',
  label: 'Id',
  type: 'string',
  mandatoryType: 'internal',
  editDefault: false,
  multiple: false,
  upsert: false,
};

export const iAliasedIds: AttributeDefinition = {
  name: 'i_aliases_ids',
  label: 'Internal aliases',
  type: 'string',
  mandatoryType: 'no',
  editDefault: false,
  multiple: true,
  upsert: false,
};

export const files: AttributeDefinition = {
  name: 'x_opencti_files',
  type: 'object',
  mandatoryType: 'no',
  editDefault: false,
  multiple: true,
  upsert: false,
  update: false,
  mapping: {
    id: textMapping,
    name: textMapping,
    version: textMapping,
    mime_type: textMapping,
  }
};

export const authorizedMembers: AttributeDefinition = {
  name: 'authorized_members',
  type: 'object',
  mandatoryType: 'no',
  multiple: true,
  upsert: false,
  mapping: {
    id: textMapping,
    name: textMapping,
    entity_type: textMapping,
    access_right: textMapping,
  }
};

export const authorizedAuthorities: AttributeDefinition = {
  name: 'authorized_authorities',
  type: 'string',
  mandatoryType: 'no',
  multiple: true,
  upsert: false
};

// -- ENTITY TYPE --

export const parentTypes: AttributeDefinition = {
  name: 'parent_types',
  type: 'string',
  mandatoryType: 'internal',
  multiple: true,
  upsert: false
};

export const baseType: AttributeDefinition = {
  name: 'base_type',
  type: 'string',
  mandatoryType: 'internal',
  multiple: false,
  upsert: false
};

export const entityType: AttributeDefinition = {
  name: 'entity_type',
  type: 'string',
  mandatoryType: 'internal',
  editDefault: false,
  multiple: false,
  upsert: false
};

export const entityLocationType: AttributeDefinition = {
  name: 'x_opencti_location_type',
  label: 'Location type',
  type: 'string',
  mandatoryType: 'internal',
  editDefault: false,
  multiple: false,
  upsert: false
};

export const relationshipType: AttributeDefinition = {
  name: 'relationship_type',
  type: 'string',
  mandatoryType: 'internal',
  editDefault: false,
  multiple: false,
  upsert: false
};

export const xOpenctiType: AttributeDefinition = {
  name: 'x_opencti_type',
  type: 'string',
  mandatoryType: 'no',
  editDefault: false,
  multiple: false,
  upsert: false
};

export const errors: AttributeDefinition = {
  name: 'errors',
  type: 'object',
  mandatoryType: 'no',
  multiple: true,
  upsert: false,
  mapping: {
    id: textMapping,
    message: textMapping,
    error: textMapping,
    source: textMapping,
    timestamp: dateMapping,
  }
};

// -- STIX DOMAIN OBJECT --

// IDS

export const xOpenctiStixIds: AttributeDefinition = {
  name: 'x_opencti_stix_ids',
  label: 'STIX IDs',
  type: 'string',
  mandatoryType: 'no',
  editDefault: false,
  multiple: true,
  upsert: false,
};

// ALIASES

export const xOpenctiAliases: AttributeDefinition = {
  name: 'x_opencti_aliases',
  label: 'Aliases',
  type: 'string',
  mandatoryType: 'no',
  editDefault: false,
  multiple: true,
  upsert: true,
};

export const aliases: AttributeDefinition = {
  name: 'aliases',
  label: 'Aliases',
  type: 'string',
  mandatoryType: 'no',
  editDefault: false,
  multiple: true,
  upsert: true,
};

// OTHERS

export const created: AttributeDefinition = {
  name: 'created',
  type: 'date',
  mandatoryType: 'no',
  editDefault: false,
  multiple: false,
  upsert: false
};
export const modified: AttributeDefinition = {
  name: 'modified',
  type: 'date',
  mandatoryType: 'no',
  editDefault: false,
  multiple: false,
  upsert: false
};

export const createdAt: AttributeDefinition = {
  name: 'created_at',
  label: 'Created at',
  type: 'date',
  mandatoryType: 'internal',
  editDefault: false,
  multiple: false,
  upsert: false
};
export const updatedAt: AttributeDefinition = {
  name: 'updated_at',
  label: 'Updated at',
  type: 'date',
  mandatoryType: 'internal',
  editDefault: false,
  multiple: false,
  upsert: false
};

export const revoked: AttributeDefinition = {
  name: 'revoked',
  type: 'boolean',
  mandatoryType: 'no',
  editDefault: false,
  multiple: false,
  upsert: true,
};

export const confidence: AttributeDefinition = {
  name: 'confidence',
  type: 'numeric',
  mandatoryType: 'no',
  editDefault: true,
  multiple: false,
  scalable: true,
  upsert: true,
};

export const xOpenctiReliability: AttributeDefinition = {
  name: 'x_opencti_reliability',
  type: 'string',
  mandatoryType: 'no',
  editDefault: false,
  multiple: false,
  upsert: false,
  label: 'Reliability'
};

export const lang: AttributeDefinition = {
  name: 'lang',
  type: 'string',
  mandatoryType: 'no',
  editDefault: false,
  multiple: false,
  upsert: false,
};

export const identityClass: AttributeDefinition = {
  name: 'identity_class',
  type: 'string',
  mandatoryType: 'no',
  editDefault: false,
  multiple: false,
  upsert: false
};
