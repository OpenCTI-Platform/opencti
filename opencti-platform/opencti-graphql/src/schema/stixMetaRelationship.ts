import {
  ABSTRACT_STIX_META_RELATIONSHIP,
  INPUT_ASSIGNEE,
  INPUT_CREATED_BY,
  INPUT_EXTERNAL_REFS,
  INPUT_GRANTED_REFS,
  INPUT_KILLCHAIN,
  INPUT_LABELS,
  INPUT_MARKINGS,
  INPUT_OBJECTS,
} from './general';
import {
  AttributeDefinition,
  confidence,
  created,
  createdAt,
  entityType,
  internalId,
  lang,
  modified,
  relationshipType,
  revoked,
  specVersion,
  standardId,
  updatedAt,
  xOpenctiStixIds
} from './attribute-definition';
import { schemaAttributesDefinition } from './schema-attributes';
import {
  ENTITY_TYPE_IDENTITY_ORGANIZATION,
  isStixDomainObjectContainer,
  isStixDomainObjectIdentity,
  isStixDomainObjectLocation
} from './stixDomainObject';
import { ENTITY_TYPE_USER } from './internalObject';
import {
  ENTITY_TYPE_EXTERNAL_REFERENCE,
  ENTITY_TYPE_KILL_CHAIN_PHASE,
  ENTITY_TYPE_LABEL,
  ENTITY_TYPE_MARKING_DEFINITION
} from './stixMetaObject';
import { ENTITY_TYPE_EVENT } from '../modules/event/event-types';
import type { RelationRefDefinition } from './relationRef-definition';

export const RELATION_CREATED_BY = 'created-by';
export const RELATION_OBJECT_MARKING = 'object-marking';
export const RELATION_OBJECT_LABEL = 'object-label';

export const RELATION_OBJECT = 'object'; // object_refs
export const RELATION_EXTERNAL_REFERENCE = 'external-reference'; // external_references
export const RELATION_KILL_CHAIN_PHASE = 'kill-chain-phase'; // kill_chain_phases
export const RELATION_GRANTED_TO = 'granted'; // granted_refs (OpenCTI)
export const RELATION_OBJECT_ASSIGNEE = 'object-assignee';

// -- RELATIONS REF ---

// EXTERNAL

export const createdBy: RelationRefDefinition = {
  inputName: INPUT_CREATED_BY,
  databaseName: RELATION_CREATED_BY,
  stixName: 'created_by_ref',
  mandatoryType: 'customizable',
  multiple: false,
  checker: (fromType, toType) => isStixDomainObjectIdentity(toType),
  label: 'Author'
};

export const objectMarking: RelationRefDefinition = {
  inputName: INPUT_MARKINGS,
  databaseName: RELATION_OBJECT_MARKING,
  stixName: 'object_marking_refs',
  mandatoryType: 'customizable',
  multiple: true,
  checker: (fromType, toType) => ENTITY_TYPE_MARKING_DEFINITION === toType,
  label: 'Markings'
};

export const objects: RelationRefDefinition = {
  inputName: INPUT_OBJECTS,
  databaseName: RELATION_OBJECT,
  stixName: 'object_refs',
  mandatoryType: 'internal',
  multiple: true,
  checker: (fromType,) => isStixDomainObjectContainer(fromType)
};

export const objectOrganization: RelationRefDefinition = { // Not in STANDARD
  inputName: INPUT_GRANTED_REFS,
  databaseName: RELATION_GRANTED_TO,
  stixName: 'granted_refs',
  mandatoryType: 'no',
  multiple: true,
  checker: (fromType, toType) => !(fromType === ENTITY_TYPE_EVENT || isStixDomainObjectIdentity(fromType)
    || isStixDomainObjectLocation(fromType)) && ENTITY_TYPE_IDENTITY_ORGANIZATION === toType
};

export const objectAssignee: RelationRefDefinition = { // Not in STANDARD
  inputName: INPUT_ASSIGNEE,
  databaseName: RELATION_OBJECT_ASSIGNEE,
  stixName: 'object_assignee_refs',
  mandatoryType: 'customizable',
  multiple: true,
  checker: (fromType, toType) => ENTITY_TYPE_USER === toType,
  label: 'Assignees'
};

const RELATIONS_REF_EXTERNAL: RelationRefDefinition[] = [
  createdBy,
  objectMarking,
  objects,
  // OCTI
  objectOrganization,
  objectAssignee,
];

// INTERNAL

export const objectLabel: RelationRefDefinition = {
  inputName: INPUT_LABELS,
  databaseName: RELATION_OBJECT_LABEL,
  stixName: 'labels',
  mandatoryType: 'no',
  multiple: true,
  checker: (fromType, toType) => toType === ENTITY_TYPE_LABEL,
  label: 'Labels'
};

export const externalReferences: RelationRefDefinition = {
  inputName: INPUT_EXTERNAL_REFS,
  databaseName: RELATION_EXTERNAL_REFERENCE,
  stixName: 'external_references',
  mandatoryType: 'no',
  multiple: true,
  checker: (fromType, toType) => toType === ENTITY_TYPE_EXTERNAL_REFERENCE,
  label: 'External references'
};
export const killChainPhases: RelationRefDefinition = {
  inputName: INPUT_KILLCHAIN,
  databaseName: RELATION_KILL_CHAIN_PHASE,
  stixName: 'kill_chain_phases',
  mandatoryType: 'customizable',
  multiple: true,
  checker: (fromType, toType) => toType === ENTITY_TYPE_KILL_CHAIN_PHASE,
  label: 'Kill chain phases'
};

const RELATIONS_REF_INTERNAL: RelationRefDefinition[] = [
  objectLabel,
  externalReferences,
  killChainPhases,
];

// -- TYPES --

schemaAttributesDefinition.register(
  ABSTRACT_STIX_META_RELATIONSHIP,
  RELATIONS_REF_INTERNAL.concat(RELATIONS_REF_EXTERNAL).map((arr) => arr.databaseName)
);
export const isStixMetaRelationship = (type: string) => schemaAttributesDefinition.get(ABSTRACT_STIX_META_RELATIONSHIP).includes(type)
  || type === ABSTRACT_STIX_META_RELATIONSHIP;

// -- ATTRIBUTES --

const stixMetaRelationshipsAttributes: AttributeDefinition[] = [
  internalId,
  standardId,
  entityType,
  createdAt,
  updatedAt,
  { name: 'i_created_at_day', type: 'date', mandatoryType: 'no', multiple: false, upsert: false },
  { name: 'i_created_at_month', type: 'date', mandatoryType: 'no', multiple: false, upsert: false },
  { name: 'i_created_at_year', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
  xOpenctiStixIds,
  specVersion,
  revoked,
  confidence,
  lang,
  created,
  modified,
  relationshipType,
  { name: 'i_inference_weight', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
];
schemaAttributesDefinition.get(ABSTRACT_STIX_META_RELATIONSHIP)
  .forEach((stixMetaRelationshipType) => schemaAttributesDefinition.registerAttributes(stixMetaRelationshipType, stixMetaRelationshipsAttributes));
