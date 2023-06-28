import type { Checker, RelationRefDefinition } from './relationRef-definition';
import { ABSTRACT_STIX_CYBER_OBSERVABLE_RELATIONSHIP, ABSTRACT_STIX_META_RELATIONSHIP, ABSTRACT_STIX_REF_RELATIONSHIP, INPUT_ASSIGNEE, INPUT_CREATED_BY, INPUT_EXTERNAL_REFS, INPUT_GRANTED_REFS, INPUT_KILLCHAIN, INPUT_LABELS, INPUT_MARKINGS, INPUT_OBJECTS, INPUT_PARTICIPANT } from './general';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION, isStixDomainObjectContainer, isStixDomainObjectIdentity, isStixDomainObjectLocation } from './stixDomainObject';
import { ENTITY_TYPE_EXTERNAL_REFERENCE, ENTITY_TYPE_KILL_CHAIN_PHASE, ENTITY_TYPE_LABEL, ENTITY_TYPE_MARKING_DEFINITION } from './stixMetaObject';
import { ENTITY_TYPE_EVENT } from '../modules/event/event-types';
import { ENTITY_TYPE_USER } from './internalObject';
import { schemaTypesDefinition } from './schema-types';

export const ABSTRACT_STIX_NESTED_REF_RELATIONSHIP = 'stix-nested-ref-relationship'; // Only for front usage

export const INPUT_OPERATING_SYSTEM = 'operatingSystems';
export const INPUT_SAMPLE = 'samples';
export const INPUT_CONTAINS = 'contains';
export const INPUT_RESOLVES_TO = 'resolvesTo';
export const INPUT_BELONGS_TO = 'belongsTo';
export const INPUT_FROM = 'from';
export const INPUT_SENDER = 'sender';
export const INPUT_TO = 'to';
export const INPUT_CC = 'cc';
export const INPUT_BCC = 'bcc';
export const INPUT_RAW_EMAIL = 'rawEmail';
export const INPUT_BODY_RAW = 'bodyRaw';
export const INPUT_PARENT_DIRECTORY = 'parentDirectory';
export const INPUT_CONTENT = 'obsContent';
export const INPUT_SRC = 'src';
export const INPUT_DST = 'dst';
export const INPUT_SRC_PAYLOAD = 'srcPayload';
export const INPUT_DST_PAYLOAD = 'dstPayload';
export const INPUT_ENCAPSULATES = 'encapsulates';
export const INPUT_ENCAPSULATED_BY = 'encapsulatedBy';
export const INPUT_OPENED_CONNECTION = 'openedConnections';
export const INPUT_CREATOR_USER = 'creatorUser';
export const INPUT_IMAGE = 'image';
export const INPUT_PARENT = 'parent';
export const INPUT_CHILD = 'child';
export const INPUT_BODY_MULTIPART = 'bodyMultipart';
export const INPUT_VALUES = 'values';
export const INPUT_LINKED = 'xOpenctiLinkedTo';
export const INPUT_SERVICE_DLL = 'serviceDlls';

export const RELATION_OPERATING_SYSTEM = 'operating-system';
export const RELATION_SAMPLE = 'sample';
export const RELATION_CONTAINS = 'contains';
export const RELATION_RESOLVES_TO = 'obs_resolves-to';
export const RELATION_BELONGS_TO = 'obs_belongs-to';
export const RELATION_FROM = 'from';
export const RELATION_SENDER = 'sender';
export const RELATION_TO = 'to';
export const RELATION_CC = 'cc';
export const RELATION_BCC = 'bcc';
export const RELATION_RAW_EMAIL = 'raw-email';
export const RELATION_BODY_RAW = 'body-raw';
export const RELATION_PARENT_DIRECTORY = 'parent-directory';
export const RELATION_CONTENT = 'obs_content';
export const RELATION_SRC = 'src';
export const RELATION_DST = 'dst';
export const RELATION_SRC_PAYLOAD = 'src-payload';
export const RELATION_DST_PAYLOAD = 'dst-payload';
export const RELATION_ENCAPSULATES = 'encapsulates';
export const RELATION_ENCAPSULATED_BY = 'encapsulated-by';
export const RELATION_OPENED_CONNECTION = 'opened-connection';
export const RELATION_CREATOR_USER = 'creator-user';
export const RELATION_IMAGE = 'image';
export const RELATION_PARENT = 'parent';
export const RELATION_CHILD = 'child';
export const RELATION_BODY_MULTIPART = 'body-multipart';
export const RELATION_VALUES = 'values';
export const RELATION_LINKED = 'x_opencti_linked-to';
export const RELATION_SERVICE_DLL = 'service-dll';

// -- RELATIONS REF ---

export const operatingSystems: Omit<RelationRefDefinition, 'checker'> = {
  inputName: INPUT_OPERATING_SYSTEM,
  databaseName: RELATION_OPERATING_SYSTEM,
  stixName: 'operating_system_refs',
  mandatoryType: 'no',
  multiple: true,
  datable: true,
};

export const samples: Omit<RelationRefDefinition, 'checker'> = {
  inputName: INPUT_SAMPLE,
  databaseName: RELATION_SAMPLE,
  stixName: 'sample_refs',
  mandatoryType: 'no',
  multiple: true,
  datable: true,
};

export const contains: Omit<RelationRefDefinition, 'checker'> = {
  inputName: INPUT_CONTAINS,
  databaseName: RELATION_CONTAINS,
  stixName: 'contains_refs',
  mandatoryType: 'no',
  multiple: true,
  datable: true,
};
export const resolvesTo: Omit<RelationRefDefinition, 'checker'> = {
  inputName: INPUT_RESOLVES_TO,
  databaseName: RELATION_RESOLVES_TO,
  stixName: 'resolves_to_refs',
  mandatoryType: 'no',
  multiple: true,
  datable: true,
};
export const belongsTo: Omit<RelationRefDefinition, 'checker'> = {
  inputName: INPUT_BELONGS_TO,
  databaseName: RELATION_BELONGS_TO,
  stixName: 'belongs_to_refs',
  mandatoryType: 'no',
  multiple: true,
  datable: true,
};
export const from: Omit<RelationRefDefinition, 'checker'> = {
  inputName: INPUT_FROM,
  databaseName: RELATION_FROM,
  stixName: 'from_ref',
  mandatoryType: 'no',
  multiple: false,
  datable: true,
};
export const sender: Omit<RelationRefDefinition, 'checker'> = {
  inputName: INPUT_SENDER,
  databaseName: RELATION_SENDER,
  stixName: 'sender_ref',
  mandatoryType: 'no',
  multiple: false,
  datable: true,
};
export const to: Omit<RelationRefDefinition, 'checker'> = {
  inputName: INPUT_TO,
  databaseName: RELATION_TO,
  stixName: 'to_refs',
  mandatoryType: 'no',
  multiple: true,
  datable: true,
};
export const cc: Omit<RelationRefDefinition, 'checker'> = {
  inputName: INPUT_CC,
  databaseName: RELATION_CC,
  stixName: 'cc_refs',
  mandatoryType: 'no',
  multiple: true,
  datable: true,
};
export const bcc: Omit<RelationRefDefinition, 'checker'> = {
  inputName: INPUT_BCC,
  databaseName: RELATION_BCC,
  stixName: 'bcc_refs',
  mandatoryType: 'no',
  multiple: true,
  datable: true,
};
export const rawEmail: Omit<RelationRefDefinition, 'checker'> = {
  inputName: INPUT_RAW_EMAIL,
  databaseName: RELATION_RAW_EMAIL,
  stixName: 'raw_email_ref',
  mandatoryType: 'no',
  multiple: false,
  datable: true,
};
export const bodyRaw: Omit<RelationRefDefinition, 'checker'> = {
  inputName: INPUT_BODY_RAW,
  databaseName: RELATION_BODY_RAW,
  stixName: 'body_raw_ref',
  mandatoryType: 'no',
  multiple: false,
  datable: true,
};
export const parentDirectory: Omit<RelationRefDefinition, 'checker'> = {
  inputName: INPUT_PARENT_DIRECTORY,
  databaseName: RELATION_PARENT_DIRECTORY,
  stixName: 'parent_directory_ref',
  mandatoryType: 'no',
  multiple: false,
  datable: true,
};
export const obsContent: Omit<RelationRefDefinition, 'checker'> = {
  inputName: INPUT_CONTENT,
  databaseName: RELATION_CONTENT,
  stixName: 'content_ref',
  mandatoryType: 'no',
  multiple: false,
  datable: true,
};
export const src: Omit<RelationRefDefinition, 'checker'> = {
  inputName: INPUT_SRC,
  databaseName: RELATION_SRC,
  stixName: 'src_ref',
  mandatoryType: 'no',
  multiple: false,
  datable: true,
};
export const dst: Omit<RelationRefDefinition, 'checker'> = {
  inputName: INPUT_DST,
  databaseName: RELATION_DST,
  stixName: 'dst_ref',
  mandatoryType: 'no',
  multiple: false,
  datable: true,
};
export const srcPayload: Omit<RelationRefDefinition, 'checker'> = {
  inputName: INPUT_SRC_PAYLOAD,
  databaseName: RELATION_SRC_PAYLOAD,
  stixName: 'src_payload_ref',
  mandatoryType: 'no',
  multiple: false,
  datable: true,
};
export const dstPayload: Omit<RelationRefDefinition, 'checker'> = {
  inputName: INPUT_DST_PAYLOAD,
  databaseName: RELATION_DST_PAYLOAD,
  stixName: 'dst_payload_ref',
  mandatoryType: 'no',
  multiple: false,
  datable: true,
};
export const encapsulates: Omit<RelationRefDefinition, 'checker'> = {
  inputName: INPUT_ENCAPSULATES,
  databaseName: RELATION_ENCAPSULATES,
  stixName: 'encapsulates_refs',
  mandatoryType: 'no',
  multiple: true,
  datable: true,
};
export const encapsulatedBy: Omit<RelationRefDefinition, 'checker'> = {
  inputName: INPUT_ENCAPSULATED_BY,
  databaseName: RELATION_ENCAPSULATED_BY,
  stixName: 'encapsulated_by_ref',
  mandatoryType: 'no',
  multiple: false,
  datable: true,
};
export const openedConnections: Omit<RelationRefDefinition, 'checker'> = {
  inputName: INPUT_OPENED_CONNECTION,
  databaseName: RELATION_OPENED_CONNECTION,
  stixName: 'opened_connection_refs',
  mandatoryType: 'no',
  multiple: true,
  datable: true,
};
export const creatorUser: Omit<RelationRefDefinition, 'checker'> = {
  inputName: INPUT_CREATOR_USER,
  databaseName: RELATION_CREATOR_USER,
  stixName: 'creator_user_ref',
  mandatoryType: 'no',
  multiple: false,
  datable: true,
};
export const image: Omit<RelationRefDefinition, 'checker'> = {
  inputName: INPUT_IMAGE,
  databaseName: RELATION_IMAGE,
  stixName: 'image_ref',
  mandatoryType: 'no',
  multiple: false,
  datable: true,
};
export const parent: Omit<RelationRefDefinition, 'checker'> = {
  inputName: INPUT_PARENT,
  databaseName: RELATION_PARENT,
  stixName: 'parent_ref',
  mandatoryType: 'no',
  multiple: false,
  datable: true,
};
export const child: Omit<RelationRefDefinition, 'checker'> = {
  inputName: INPUT_CHILD,
  databaseName: RELATION_CHILD,
  stixName: 'child_refs',
  mandatoryType: 'no',
  multiple: true,
  datable: true,
};
export const bodyMultipart: Omit<RelationRefDefinition, 'checker'> = {
  inputName: INPUT_BODY_MULTIPART,
  databaseName: RELATION_BODY_MULTIPART,
  stixName: 'body_multipart',
  mandatoryType: 'no',
  multiple: true,
  datable: true,
};
export const values: Omit<RelationRefDefinition, 'checker'> = {
  inputName: INPUT_VALUES,
  databaseName: RELATION_VALUES,
  stixName: 'values_refs',
  mandatoryType: 'no',
  multiple: true,
  datable: true,
};
export const xOpenctiLinkedTo: RelationRefDefinition = {
  inputName: INPUT_LINKED,
  databaseName: RELATION_LINKED,
  stixName: 'x_opencti_linked_to_refs',
  mandatoryType: 'no',
  multiple: true,
  checker: () => true,
  datable: true,
};
export const serviceDlls: Omit<RelationRefDefinition, 'checker'> = {
  inputName: INPUT_SERVICE_DLL,
  databaseName: RELATION_SERVICE_DLL,
  stixName: 'service_dll_refs',
  mandatoryType: 'no',
  multiple: true,
  datable: true,
};

export const STIX_REF_RELATIONSHIPS: Omit<RelationRefDefinition, 'checker'>[] = [
  operatingSystems,
  samples,
  contains,
  resolvesTo,
  belongsTo,
  from,
  sender,
  to,
  cc,
  bcc,
  rawEmail,
  bodyRaw,
  parentDirectory,
  obsContent,
  src,
  dst,
  srcPayload,
  dstPayload,
  encapsulates,
  encapsulatedBy,
  openedConnections,
  creatorUser,
  image,
  parent,
  child,
  bodyMultipart,
  values,
  xOpenctiLinkedTo,
  serviceDlls
];

// -- Meta relationships

export const RELATION_CREATED_BY = 'created-by';
export const RELATION_OBJECT_MARKING = 'object-marking';
export const RELATION_OBJECT_LABEL = 'object-label';

export const RELATION_OBJECT = 'object'; // object_refs
export const RELATION_EXTERNAL_REFERENCE = 'external-reference'; // external_references
export const RELATION_KILL_CHAIN_PHASE = 'kill-chain-phase'; // kill_chain_phases
export const RELATION_GRANTED_TO = 'granted'; // granted_refs (OpenCTI)
export const RELATION_OBJECT_ASSIGNEE = 'object-assignee';
export const RELATION_OBJECT_PARTICIPANT = 'object-participant';

// EXTERNAL

export const createdBy: RelationRefDefinition = {
  inputName: INPUT_CREATED_BY,
  databaseName: RELATION_CREATED_BY,
  stixName: 'created_by_ref',
  mandatoryType: 'customizable',
  multiple: false,
  checker: (fromType, toType) => isStixDomainObjectIdentity(toType),
  label: 'Author',
  datable: false,
};

export const objectMarking: RelationRefDefinition = {
  inputName: INPUT_MARKINGS,
  databaseName: RELATION_OBJECT_MARKING,
  stixName: 'object_marking_refs',
  mandatoryType: 'customizable',
  multiple: true,
  checker: (fromType, toType) => ENTITY_TYPE_MARKING_DEFINITION === toType,
  label: 'Markings',
  datable: false,
};

export const objects: RelationRefDefinition = {
  inputName: INPUT_OBJECTS,
  databaseName: RELATION_OBJECT,
  stixName: 'object_refs',
  mandatoryType: 'internal',
  multiple: true,
  checker: (fromType,) => isStixDomainObjectContainer(fromType),
  datable: false,
};

export const objectOrganization: RelationRefDefinition = {
  inputName: INPUT_GRANTED_REFS,
  databaseName: RELATION_GRANTED_TO,
  stixName: 'granted_refs',
  mandatoryType: 'no',
  multiple: true,
  checker: (fromType, toType) => !(fromType === ENTITY_TYPE_EVENT || isStixDomainObjectIdentity(fromType)
      || isStixDomainObjectLocation(fromType)) && ENTITY_TYPE_IDENTITY_ORGANIZATION === toType,
  datable: false,
};

export const objectAssignee: RelationRefDefinition = {
  inputName: INPUT_ASSIGNEE,
  databaseName: RELATION_OBJECT_ASSIGNEE,
  stixName: 'object_assignee_refs',
  mandatoryType: 'customizable',
  multiple: true,
  checker: (fromType, toType) => ENTITY_TYPE_USER === toType,
  label: 'Assignees',
  datable: false,
};

export const objectParticipant: RelationRefDefinition = {
  inputName: INPUT_PARTICIPANT,
  databaseName: RELATION_OBJECT_PARTICIPANT,
  stixName: 'object_participant_refs',
  mandatoryType: 'customizable',
  multiple: true,
  checker: (fromType, toType) => ENTITY_TYPE_USER === toType,
  label: 'Participants',
  datable: false,
};

// INTERNAL

export const objectLabel: RelationRefDefinition = {
  inputName: INPUT_LABELS,
  databaseName: RELATION_OBJECT_LABEL,
  stixName: 'labels',
  mandatoryType: 'no',
  multiple: true,
  checker: (fromType, toType) => toType === ENTITY_TYPE_LABEL,
  label: 'Labels',
  datable: false,
};

export const externalReferences: RelationRefDefinition = {
  inputName: INPUT_EXTERNAL_REFS,
  databaseName: RELATION_EXTERNAL_REFERENCE,
  stixName: 'external_references',
  mandatoryType: 'no',
  multiple: true,
  checker: (fromType, toType) => toType === ENTITY_TYPE_EXTERNAL_REFERENCE,
  label: 'External references',
  datable: false,
};
export const killChainPhases: RelationRefDefinition = {
  inputName: INPUT_KILLCHAIN,
  databaseName: RELATION_KILL_CHAIN_PHASE,
  stixName: 'kill_chain_phases',
  mandatoryType: 'customizable',
  multiple: true,
  checker: (fromType, toType) => toType === ENTITY_TYPE_KILL_CHAIN_PHASE,
  label: 'Kill chain phases',
  datable: false,
};

export const META_RELATIONS: RelationRefDefinition[] = [
  objectLabel,
  externalReferences,
  killChainPhases,
  createdBy,
  objectMarking,
  objects,
  // OCTI
  objectOrganization,
  objectAssignee,
];

// Register
schemaTypesDefinition.register(
  ABSTRACT_STIX_REF_RELATIONSHIP,
  [...STIX_REF_RELATIONSHIPS, ...META_RELATIONS].map((arr) => arr.databaseName)
);

export const isStixRefRelationship = (type: string) => schemaTypesDefinition.isTypeIncludedIn(type, ABSTRACT_STIX_REF_RELATIONSHIP) || type === ABSTRACT_STIX_REF_RELATIONSHIP;

export const buildRelationRef = (relationRef: Omit<RelationRefDefinition, 'checker'>, checker: Checker): RelationRefDefinition => {
  return {
    ...relationRef,
    checker
  };
};

// retro-compatibility with cyber-observable-relationship
export const STIX_REF_RELATIONSHIP_TYPES = [ABSTRACT_STIX_META_RELATIONSHIP, ABSTRACT_STIX_CYBER_OBSERVABLE_RELATIONSHIP, ABSTRACT_STIX_REF_RELATIONSHIP];
