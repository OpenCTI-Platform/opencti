import * as R from 'ramda';
import {
  ABSTRACT_STIX_META_RELATIONSHIP,
  INPUT_CREATED_BY,
  INPUT_EXTERNAL_REFS,
  INPUT_KILLCHAIN,
  INPUT_LABELS,
  INPUT_MARKINGS,
  INPUT_OBJECTS,
  schemaTypes,
} from './general';

export const RELATION_CREATED_BY = 'created-by';
export const RELATION_OBJECT_MARKING = 'object-marking';
export const RELATION_OBJECT_LABEL = 'object-label';

export const RELATION_OBJECT = 'object'; // object_refs
export const RELATION_EXTERNAL_REFERENCE = 'external-reference'; // external_references
export const RELATION_KILL_CHAIN_PHASE = 'kill-chain-phase'; // kill_chain_phases

// Converter
export const FIELD_META_STIX_RELATIONS_TO_STIX_ATTRIBUTE: { [k: string]: string } = {
  [RELATION_CREATED_BY]: 'created_by_ref',
  [RELATION_OBJECT_MARKING]: 'object_marking_refs',
  [RELATION_OBJECT]: 'object_refs',
  [RELATION_EXTERNAL_REFERENCE]: 'external_references',
  [RELATION_KILL_CHAIN_PHASE]: 'kill_chain_phases',
  [RELATION_OBJECT_LABEL]: 'labels',
};

export const STIX_ATTRIBUTE_TO_META_RELATIONS = R.mergeAll(
  Object.keys(FIELD_META_STIX_RELATIONS_TO_STIX_ATTRIBUTE).map((k) => ({
    [FIELD_META_STIX_RELATIONS_TO_STIX_ATTRIBUTE[k]]: k,
  }))
);

export const STIX_ATTRIBUTE_TO_META_RELATIONS_FIELD: { [k: string]: string } = {
  created_by_ref: INPUT_CREATED_BY,
  object_marking_refs: INPUT_MARKINGS,
  object_refs: INPUT_OBJECTS,
  external_references: INPUT_EXTERNAL_REFS,
  kill_chain_phases: INPUT_KILLCHAIN,
  labels: INPUT_LABELS,
};

export const META_FIELD_TO_STIX_ATTRIBUTE = R.mergeAll(
  Object.keys(STIX_ATTRIBUTE_TO_META_RELATIONS_FIELD).map((k) => ({
    [STIX_ATTRIBUTE_TO_META_RELATIONS_FIELD[k]]: k,
  }))
);

export const STIX_META_RELATION_TO_FIELD: { [k: string]: string } = {
  [RELATION_EXTERNAL_REFERENCE]: INPUT_EXTERNAL_REFS,
  [RELATION_KILL_CHAIN_PHASE]: INPUT_KILLCHAIN,
  [RELATION_CREATED_BY]: INPUT_CREATED_BY,
  [RELATION_OBJECT_LABEL]: INPUT_LABELS,
  [RELATION_OBJECT_MARKING]: INPUT_MARKINGS,
  [RELATION_OBJECT]: INPUT_OBJECTS,
};

export const FIELD_TO_META_RELATION = R.mergeAll(
  Object.keys(STIX_META_RELATION_TO_FIELD).map((k) => ({
    [STIX_META_RELATION_TO_FIELD[k]]: k,
  }))
);

const STIX_EXTERNAL_META_RELATIONSHIPS = [RELATION_CREATED_BY, RELATION_OBJECT_MARKING, RELATION_OBJECT];
const STIX_INTERNAL_META_RELATIONSHIPS = [
  RELATION_OBJECT_LABEL,
  RELATION_EXTERNAL_REFERENCE,
  RELATION_KILL_CHAIN_PHASE,
];
export const STIX_META_RELATIONSHIPS = [...STIX_EXTERNAL_META_RELATIONSHIPS, ...STIX_INTERNAL_META_RELATIONSHIPS];
schemaTypes.register(ABSTRACT_STIX_META_RELATIONSHIP, STIX_META_RELATIONSHIPS);
export const isSingleStixMetaRelationship = (type: string): boolean => R.includes(type, [RELATION_CREATED_BY]);
export const isSingleStixMetaRelationshipInput = (input: string): boolean => R.includes(input, [INPUT_CREATED_BY]);

export const isStixMetaRelationship = (type: string) => R.includes(type, STIX_META_RELATIONSHIPS) || type === ABSTRACT_STIX_META_RELATIONSHIP;
export const isStixInternalMetaRelationship = (type: string) => R.includes(type, STIX_INTERNAL_META_RELATIONSHIPS) || type === ABSTRACT_STIX_META_RELATIONSHIP;

export const stixMetaRelationshipsAttributes = [
  'internal_id',
  'standard_id',
  'entity_type',
  'created_at',
  'i_created_at_day',
  'i_created_at_month',
  'i_created_at_year',
  'updated_at',
  'x_opencti_stix_ids',
  'spec_version',
  'revoked',
  'confidence',
  'lang',
  'created',
  'modified',
  'relationship_type',
];
R.map(
  (stixMetaRelationshipType) => schemaTypes.registerAttributes(stixMetaRelationshipType, stixMetaRelationshipsAttributes),
  STIX_META_RELATIONSHIPS
);
R.map(
  (stixInternalMetaRelationshipType) => schemaTypes.registerAttributes(stixInternalMetaRelationshipType, stixMetaRelationshipsAttributes),
  STIX_INTERNAL_META_RELATIONSHIPS
);
