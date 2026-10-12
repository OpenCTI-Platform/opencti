import type {
  AttributeDefinition,
  BooleanAttribute,
  DateAttribute,
  EnumAttribute,
  NestedObjectAttribute,
  NumericAttribute,
  ObjectAttribute,
  TextAttribute,
} from '../../schema/attribute-definition';
import {
  ASSERTION_SOURCE_KINDS,
  ATTRIBUTE_ASSERTION_SOURCE_IDS,
  ATTRIBUTE_ASSERTION_SOURCE_KINDS,
  ATTRIBUTE_ASSERTIONS,
  ATTRIBUTE_CONFLICT_FIELDS,
  ATTRIBUTE_CONFLICTS,
  ATTRIBUTE_CORROBORATION_COUNT,
  ATTRIBUTE_FRESHNESS_RULE_ID,
  ATTRIBUTE_FRESHNESS_STALE,
  ATTRIBUTE_FRESHNESS_STALE_AT,
  ATTRIBUTE_HAS_CONFLICTS,
  ATTRIBUTE_LAST_ASSERTED_AT,
  ATTRIBUTE_PROCEDURES,
  ATTRIBUTE_SINGLE_SOURCED,
} from './provenance-types';

export const xOpenctiAssertions: NestedObjectAttribute = {
  name: ATTRIBUTE_ASSERTIONS,
  label: 'Assertions',
  type: 'object',
  format: 'nested',
  mandatoryType: 'no',
  editDefault: false,
  multiple: true,
  upsert: false,
  update: false,
  isFilterable: false, // filtered through the flat assertion_source_ids and assertion_source_kinds
  mappings: [
    { name: 'source_id', label: 'Source id', type: 'string', format: 'short', mandatoryType: 'external', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'source_kind', label: 'Source kind', type: 'string', format: 'enum', values: [...ASSERTION_SOURCE_KINDS], mandatoryType: 'external', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'source_name', label: 'Source name', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'first_asserted_at', label: 'First asserted', type: 'date', mandatoryType: 'external', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'last_asserted_at', label: 'Last asserted', type: 'date', mandatoryType: 'external', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'assert_count', label: 'Assertion count', type: 'numeric', precision: 'integer', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'confidence', label: 'Asserted confidence', type: 'numeric', precision: 'integer', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'work_id', label: 'Work id', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
  ],
};

export const assertionSourceIds: TextAttribute = {
  name: ATTRIBUTE_ASSERTION_SOURCE_IDS,
  label: 'Asserted by',
  type: 'string',
  format: 'short',
  mandatoryType: 'no',
  editDefault: false,
  multiple: true,
  upsert: false,
  update: false,
  isFilterable: true,
};

export const assertionSourceKinds: EnumAttribute = {
  name: ATTRIBUTE_ASSERTION_SOURCE_KINDS,
  label: 'Assertion source kinds',
  type: 'string',
  format: 'enum',
  values: [...ASSERTION_SOURCE_KINDS],
  mandatoryType: 'no',
  editDefault: false,
  multiple: true,
  upsert: false,
  update: false,
  isFilterable: true,
};

export const conflictFields: TextAttribute = {
  name: ATTRIBUTE_CONFLICT_FIELDS,
  label: 'Conflicting fields',
  type: 'string',
  format: 'short',
  mandatoryType: 'no',
  editDefault: false,
  multiple: true,
  upsert: false,
  update: false,
  isFilterable: true,
};

export const corroborationCount: NumericAttribute = {
  name: ATTRIBUTE_CORROBORATION_COUNT,
  label: 'Corroboration',
  type: 'numeric',
  precision: 'integer',
  mandatoryType: 'no',
  editDefault: false,
  multiple: false,
  upsert: false,
  update: false,
  isFilterable: true,
};

export const lastAssertedAt: DateAttribute = {
  name: ATTRIBUTE_LAST_ASSERTED_AT,
  label: 'Last assertion date',
  type: 'date',
  mandatoryType: 'no',
  editDefault: false,
  multiple: false,
  upsert: false,
  update: false,
  isFilterable: true,
};

export const singleSourced: BooleanAttribute = {
  name: ATTRIBUTE_SINGLE_SOURCED,
  label: 'Single sourced',
  type: 'boolean',
  mandatoryType: 'no',
  editDefault: false,
  multiple: false,
  upsert: false,
  update: false,
  isFilterable: true,
};

export const hasConflicts: BooleanAttribute = {
  name: ATTRIBUTE_HAS_CONFLICTS,
  label: 'Has source conflicts',
  type: 'boolean',
  mandatoryType: 'no',
  editDefault: false,
  multiple: false,
  upsert: false,
  update: false,
  isFilterable: true,
};

export const xOpenctiConflicts: NestedObjectAttribute = {
  name: ATTRIBUTE_CONFLICTS,
  label: 'Source conflicts',
  type: 'object',
  format: 'nested',
  mandatoryType: 'no',
  editDefault: false,
  multiple: true,
  upsert: false,
  update: false,
  isFilterable: false, // filtered through the flat conflict_fields
  mappings: [
    { name: 'field', label: 'Conflicting field', type: 'string', format: 'short', mandatoryType: 'external', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    {
      name: 'values',
      label: 'Alternative values',
      type: 'object',
      format: 'standard',
      mandatoryType: 'no',
      editDefault: false,
      multiple: true,
      upsert: false,
      isFilterable: false,
      mappings: [
        { name: 'value_hash', label: 'Value hash', type: 'string', format: 'short', mandatoryType: 'external', editDefault: false, multiple: false, upsert: false, isFilterable: false },
        { name: 'display', label: 'Display value', type: 'string', format: 'text', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
        { name: 'value', label: 'Raw value', type: 'string', format: 'text', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
        { name: 'source_id', label: 'Source id', type: 'string', format: 'short', mandatoryType: 'external', editDefault: false, multiple: false, upsert: false, isFilterable: false },
        { name: 'source_kind', label: 'Source kind', type: 'string', format: 'enum', values: [...ASSERTION_SOURCE_KINDS], mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
        { name: 'source_name', label: 'Source name', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
        { name: 'confidence', label: 'Asserted confidence', type: 'numeric', precision: 'integer', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
        { name: 'last_asserted_at', label: 'Last asserted', type: 'date', mandatoryType: 'external', editDefault: false, multiple: false, upsert: false, isFilterable: false },
      ],
    },
  ],
};

export const freshnessStale: BooleanAttribute = {
  name: ATTRIBUTE_FRESHNESS_STALE,
  label: 'Stale knowledge',
  type: 'boolean',
  mandatoryType: 'no',
  editDefault: false,
  multiple: false,
  upsert: false,
  update: false,
  isFilterable: true,
};

export const freshnessStaleAt: DateAttribute = {
  name: ATTRIBUTE_FRESHNESS_STALE_AT,
  label: 'Stale since',
  type: 'date',
  mandatoryType: 'no',
  editDefault: false,
  multiple: false,
  upsert: false,
  update: false,
  isFilterable: true,
};

export const freshnessRuleId: TextAttribute = {
  name: ATTRIBUTE_FRESHNESS_RULE_ID,
  label: 'Knowledge freshness rule',
  type: 'string',
  format: 'short',
  mandatoryType: 'no',
  editDefault: false,
  multiple: false,
  upsert: false,
  update: false,
  isFilterable: false,
};

export const procedures: ObjectAttribute = {
  name: ATTRIBUTE_PROCEDURES,
  label: 'Procedures',
  type: 'object',
  format: 'standard',
  mandatoryType: 'no',
  editDefault: false,
  multiple: true,
  upsert: false,
  update: false,
  isFilterable: false,
  mappings: [
    { name: 'text', label: 'Procedure', type: 'string', format: 'text', mandatoryType: 'external', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'source_id', label: 'Source id', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'last_asserted_at', label: 'Last asserted', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
  ],
};

// Registered on Stix Core Objects, Stix Core Relationships and sightings.
export const provenanceAttributes: Array<AttributeDefinition> = [
  xOpenctiAssertions,
  assertionSourceIds,
  assertionSourceKinds,
  conflictFields,
  corroborationCount,
  lastAssertedAt,
  singleSourced,
  hasConflicts,
  xOpenctiConflicts,
  freshnessStale,
  freshnessStaleAt,
  freshnessRuleId,
];
