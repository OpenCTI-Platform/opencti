import type { AttributeDefinition } from './module-register';

// -- GLOBAL --

export const standardId: AttributeDefinition = {
  name: 'standard_id',
  type: 'string',
  mandatoryType: 'internal',
  multiple: false,
  upsert: false,
};

export const iAliasedIds: AttributeDefinition = {
  name: 'i_aliases_ids',
  type: 'string',
  mandatoryType: 'no',
  multiple: false,
  upsert: false,
};

// -- STIX DOMAIN OBJECT --

export const xOpenctiStixIds: AttributeDefinition = {
  name: 'x_opencti_stix_ids',
  type: 'string',
  mandatoryType: 'no',
  multiple: true,
  upsert: true,
};

export const xOpenctiAliases: AttributeDefinition = {
  name: 'x_opencti_aliases',
  type: 'string',
  mandatoryType: 'no',
  multiple: true,
  upsert: false,
};

export const aliases: AttributeDefinition = {
  name: 'aliases',
  type: 'string',
  mandatoryType: 'no',
  multiple: true,
  upsert: false,
};

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
  upsert: true,
};

export const lang: AttributeDefinition = {
  name: 'lang',
  type: 'string',
  mandatoryType: 'no',
  multiple: false,
  upsert: false,
};
