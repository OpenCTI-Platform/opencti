export type AttrType = 'string' | 'date' | 'numeric' | 'boolean' | 'dictionary' | 'json';
export type MandatoryType = 'internal' | 'external' | 'customizable' | 'no';

export interface AttributeDefinition {
  name: string
  type: AttrType
  mandatoryType: MandatoryType
  multiple: boolean
  upsert: boolean
  update?: boolean
  label?: string
  description?: string
  scalable?: boolean
  schemaDef?: Record<string, any>
}

// -- GLOBAL --

export const internalId: AttributeDefinition = {
  name: 'internal_id',
  type: 'string',
  mandatoryType: 'no',
  multiple: false,
  upsert: false
};

export const creators: AttributeDefinition = {
  name: 'creator_id',
  label: 'Creators',
  type: 'string',
  mandatoryType: 'no',
  multiple: true,
  upsert: false
};

export const standardId: AttributeDefinition = {
  name: 'standard_id',
  label: 'Id',
  type: 'string',
  mandatoryType: 'internal',
  multiple: false,
  upsert: false,
};

export const iAliasedIds: AttributeDefinition = {
  name: 'i_aliases_ids',
  label: 'Internal aliases',
  type: 'string',
  mandatoryType: 'no',
  multiple: true,
  upsert: false,
};

export const files: AttributeDefinition = {
  name: 'x_opencti_files',
  type: 'string',
  mandatoryType: 'no',
  multiple: true,
  upsert: false,
  update: false,
};

// -- ENTITY TYPE --

export const entityType: AttributeDefinition = {
  name: 'entity_type',
  type: 'string',
  mandatoryType: 'internal',
  multiple: false,
  upsert: false
};

export const entityLocationType: AttributeDefinition = {
  name: 'x_opencti_location_type',
  label: 'Location type',
  type: 'string',
  mandatoryType: 'internal',
  multiple: false,
  upsert: false
};

export const relationshipType: AttributeDefinition = {
  name: 'relationship_type',
  type: 'string',
  mandatoryType: 'internal',
  multiple: false,
  upsert: false
};

// -- STIX DOMAIN OBJECT --

// IDS

export const xOpenctiStixIds: AttributeDefinition = {
  name: 'x_opencti_stix_ids',
  label: 'Stix ids',
  type: 'string',
  mandatoryType: 'no',
  multiple: true,
  upsert: false,
};

// ALIASES

export const xOpenctiAliases: AttributeDefinition = {
  name: 'x_opencti_aliases',
  label: 'Aliases',
  type: 'string',
  mandatoryType: 'no',
  multiple: true,
  upsert: true,
};

export const aliases: AttributeDefinition = {
  name: 'aliases',
  label: 'Aliases',
  type: 'string',
  mandatoryType: 'no',
  multiple: true,
  upsert: true,
};

// OTHERS

export const specVersion: AttributeDefinition = {
  name: 'spec_version',
  type: 'string',
  mandatoryType: 'no',
  multiple: false,
  upsert: false
};

export const created: AttributeDefinition = {
  name: 'created',
  type: 'date',
  mandatoryType: 'no',
  multiple: false,
  upsert: false
};
export const modified: AttributeDefinition = {
  name: 'modified',
  type: 'date',
  mandatoryType: 'no',
  multiple: false,
  upsert: false
};

export const createdAt: AttributeDefinition = {
  name: 'created_at',
  label: 'Created at',
  type: 'date',
  mandatoryType: 'internal',
  multiple: false,
  upsert: false
};
export const updatedAt: AttributeDefinition = {
  name: 'updated_at',
  label: 'Updated at',
  type: 'date',
  mandatoryType: 'internal',
  multiple: false,
  upsert: false
};

// OTHERS

export const revoked: AttributeDefinition = {
  name: 'revoked',
  type: 'boolean',
  mandatoryType: 'no',
  multiple: false,
  upsert: true,
};

export const confidence: AttributeDefinition = {
  name: 'confidence',
  type: 'numeric',
  mandatoryType: 'customizable',
  multiple: false,
  scalable: true,
  upsert: true,
};

export const lang: AttributeDefinition = {
  name: 'lang',
  type: 'string',
  mandatoryType: 'no',
  multiple: false,
  upsert: false,
};
