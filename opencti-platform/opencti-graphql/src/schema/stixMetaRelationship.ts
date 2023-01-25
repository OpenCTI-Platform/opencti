import {
  ABSTRACT_STIX_CORE_RELATIONSHIP,
  ABSTRACT_STIX_CYBER_OBSERVABLE,
  ABSTRACT_STIX_DOMAIN_OBJECT,
  ABSTRACT_STIX_META_RELATIONSHIP,
  ABSTRACT_STIX_RELATIONSHIP,
  ENTITY_TYPE_CONTAINER,
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
import { schemaRelationsRefDefinition } from './schema-relationsRef';
import {
  ENTITY_TYPE_ATTACK_PATTERN,
  ENTITY_TYPE_CAMPAIGN,
  ENTITY_TYPE_CONTAINER_NOTE,
  ENTITY_TYPE_CONTAINER_OBSERVED_DATA,
  ENTITY_TYPE_CONTAINER_OPINION,
  ENTITY_TYPE_CONTAINER_REPORT,
  ENTITY_TYPE_COURSE_OF_ACTION, ENTITY_TYPE_DATA_COMPONENT, ENTITY_TYPE_DATA_SOURCE,
  ENTITY_TYPE_IDENTITY_ORGANIZATION,
  ENTITY_TYPE_INCIDENT,
  ENTITY_TYPE_INDICATOR,
  ENTITY_TYPE_INFRASTRUCTURE,
  ENTITY_TYPE_INTRUSION_SET,
  ENTITY_TYPE_MALWARE,
  ENTITY_TYPE_THREAT_ACTOR,
  ENTITY_TYPE_TOOL,
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
import { STIX_SIGHTING_RELATIONSHIP } from './stixSightingRelationship';
import { ENTITY_TYPE_CONTAINER_CASE } from '../modules/case/case-types';
import { ENTITY_TYPE_LOCATION_ADMINISTRATIVE_AREA } from '../modules/administrativeArea/administrativeArea-types';
import { ENTITY_TYPE_CHANNEL } from '../modules/channel/channel-types';
import { ENTITY_TYPE_CONTAINER_GROUPING } from '../modules/grouping/grouping-types';
import { ENTITY_TYPE_NARRATIVE } from '../modules/narrative/narrative-types';
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

const createdBy: RelationRefDefinition = {
  inputName: INPUT_CREATED_BY,
  databaseName: RELATION_CREATED_BY,
  stixName: 'created_by_ref',
  mandatoryType: 'customizable',
  multiple: false,
  checker: (fromType, toType) => isStixDomainObjectIdentity(toType),
  label: 'Author'
};

const objectMarking: RelationRefDefinition = {
  inputName: INPUT_MARKINGS,
  databaseName: RELATION_OBJECT_MARKING,
  stixName: 'object_marking_refs',
  mandatoryType: 'customizable',
  multiple: true,
  checker: (fromType, toType) => ENTITY_TYPE_MARKING_DEFINITION === toType,
  label: 'Marking'
};

const objects: RelationRefDefinition = {
  inputName: INPUT_OBJECTS,
  databaseName: RELATION_OBJECT,
  stixName: 'object_refs',
  mandatoryType: 'internal',
  multiple: true,
  checker: (fromType,) => isStixDomainObjectContainer(fromType)
};

const objectOrganization: RelationRefDefinition = { // Not in STANDARD
  inputName: INPUT_GRANTED_REFS,
  databaseName: RELATION_GRANTED_TO,
  stixName: 'granted_refs',
  mandatoryType: 'no',
  multiple: true,
  checker: (fromType, toType) => !(fromType === ENTITY_TYPE_EVENT || isStixDomainObjectIdentity(fromType)
    || isStixDomainObjectLocation(fromType)) && ENTITY_TYPE_IDENTITY_ORGANIZATION === toType
};

const objectAssignee: RelationRefDefinition = { // Not in STANDARD
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

const objectLabel: RelationRefDefinition = {
  inputName: INPUT_LABELS,
  databaseName: RELATION_OBJECT_LABEL,
  stixName: 'labels',
  mandatoryType: 'no',
  multiple: true,
  checker: (fromType, toType) => toType === ENTITY_TYPE_LABEL,
  label: 'Labels'
};

const externalReferences: RelationRefDefinition = {
  inputName: INPUT_EXTERNAL_REFS,
  databaseName: RELATION_EXTERNAL_REFERENCE,
  stixName: 'external_references',
  mandatoryType: 'customizable',
  multiple: true,
  checker: (fromType, toType) => toType === ENTITY_TYPE_EXTERNAL_REFERENCE,
  label: 'External references'
};
const killChainPhases: RelationRefDefinition = {
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

schemaRelationsRefDefinition.registerRelationsRef(ABSTRACT_STIX_DOMAIN_OBJECT, [createdBy, objectMarking, objectLabel, externalReferences]);
schemaRelationsRefDefinition.registerRelationsRef(ABSTRACT_STIX_CYBER_OBSERVABLE, [objectMarking]);
schemaRelationsRefDefinition.registerRelationsRef(ABSTRACT_STIX_RELATIONSHIP, [
  {
    ...createdBy,
    mandatoryType: 'no',
  },
  {
    ...objectMarking,
    mandatoryType: 'no',
  }, {
    ...objectLabel,
    mandatoryType: 'no',
  }, {
    ...externalReferences,
    mandatoryType: 'no',
  },
  {
    ...killChainPhases,
    mandatoryType: 'no',
  }]);

schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_CONTAINER, [objects]);

schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_ATTACK_PATTERN, [killChainPhases, objectOrganization]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_INDICATOR, [killChainPhases]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_INFRASTRUCTURE, [killChainPhases, objectOrganization]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_MALWARE, [killChainPhases, objectOrganization]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_TOOL, [killChainPhases]);

schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_CAMPAIGN, [objectOrganization]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_CONTAINER_REPORT, [objectAssignee, objectOrganization]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_INTRUSION_SET, [objectOrganization]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_THREAT_ACTOR, [objectOrganization]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_INCIDENT, [objectAssignee, objectOrganization]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_CONTAINER_CASE, [objectAssignee, objectOrganization]);

schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_CONTAINER_NOTE, [objectOrganization]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_CONTAINER_OBSERVED_DATA, [objectOrganization]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_CONTAINER_OPINION, [objectOrganization]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_COURSE_OF_ACTION, [objectOrganization]);
schemaRelationsRefDefinition.registerRelationsRef(ABSTRACT_STIX_CORE_RELATIONSHIP, [objectOrganization]);
schemaRelationsRefDefinition.registerRelationsRef(STIX_SIGHTING_RELATIONSHIP, [objectOrganization]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_LOCATION_ADMINISTRATIVE_AREA, [objectOrganization]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_CHANNEL, [objectOrganization]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_DATA_SOURCE, [objectOrganization]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_DATA_COMPONENT, [objectOrganization]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_EVENT, [objectOrganization]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_CONTAINER_GROUPING, [objectOrganization]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TYPE_NARRATIVE, [objectOrganization]);

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
