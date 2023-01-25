import { ABSTRACT_STIX_CYBER_OBSERVABLE_RELATIONSHIP } from './general';
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
  ENTITY_DIRECTORY,
  ENTITY_DOMAIN_NAME,
  ENTITY_EMAIL_MESSAGE,
  ENTITY_HASHED_OBSERVABLE_STIX_FILE,
  ENTITY_IPV4_ADDR,
  ENTITY_IPV6_ADDR,
  ENTITY_NETWORK_TRAFFIC,
  ENTITY_PROCESS,
  ENTITY_WINDOWS_REGISTRY_KEY,
  ENTITY_WINDOWS_REGISTRY_VALUE_TYPE
} from './stixCyberObservable';
import type { RelationRefDefinition } from './relationRef-definition';

// Inputs
export const INPUT_OPERATING_SYSTEM = 'operatingSystems';
export const INPUT_SAMPLE = 'sample';
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

// Not used ? TODO: remove

// const operatingSystems: RelationRefDefinition = {
//   name: INPUT_OPERATING_SYSTEM,
//   databaseName: RELATION_OPERATING_SYSTEM,
//   stixName: 'operating_system_refs',
//   multiple: true,
// };
// const sample: RelationRefDefinition = {
//   name: INPUT_SAMPLE,
//   databaseName: RELATION_SAMPLE,
//   stixName: 'sample_ref',
//   multiple: false,
// };

const contains: RelationRefDefinition = {
  inputName: INPUT_CONTAINS,
  databaseName: RELATION_CONTAINS,
  stixName: 'contains_refs',
  mandatoryType: 'no',
  multiple: true,
};
const resolvesTo: RelationRefDefinition = {
  inputName: INPUT_RESOLVES_TO,
  databaseName: RELATION_RESOLVES_TO,
  stixName: 'resolves_to_refs',
  mandatoryType: 'no',
  multiple: true,
};
const belongsTo: RelationRefDefinition = {
  inputName: INPUT_BELONGS_TO,
  databaseName: RELATION_BELONGS_TO,
  stixName: 'belongs_to_refs',
  mandatoryType: 'no',
  multiple: true,
};
const from: RelationRefDefinition = {
  inputName: INPUT_FROM,
  databaseName: RELATION_FROM,
  stixName: 'from_ref',
  mandatoryType: 'no',
  multiple: false,
};
const sender: RelationRefDefinition = {
  inputName: INPUT_SENDER,
  databaseName: RELATION_SENDER,
  stixName: 'sender_ref',
  mandatoryType: 'no',
  multiple: false,
};
const to: RelationRefDefinition = {
  inputName: INPUT_TO,
  databaseName: RELATION_TO,
  stixName: 'to_refs',
  mandatoryType: 'no',
  multiple: true,
};
const cc: RelationRefDefinition = {
  inputName: INPUT_CC,
  databaseName: RELATION_CC,
  stixName: 'cc_refs',
  mandatoryType: 'no',
  multiple: true,
};
const bcc: RelationRefDefinition = {
  inputName: INPUT_BCC,
  databaseName: RELATION_BCC,
  stixName: 'bcc_refs',
  mandatoryType: 'no',
  multiple: true,
};
const rawEmail: RelationRefDefinition = {
  inputName: INPUT_RAW_EMAIL,
  databaseName: RELATION_RAW_EMAIL,
  stixName: 'raw_email_ref',
  mandatoryType: 'no',
  multiple: false,
};
const bodyRaw: RelationRefDefinition = {
  inputName: INPUT_BODY_RAW,
  databaseName: RELATION_BODY_RAW,
  stixName: 'body_raw_ref',
  mandatoryType: 'no',
  multiple: false,
};
const parentDirectory: RelationRefDefinition = {
  inputName: INPUT_PARENT_DIRECTORY,
  databaseName: RELATION_PARENT_DIRECTORY,
  stixName: 'parent_directory_ref',
  mandatoryType: 'no',
  multiple: false,
};
const obsContent: RelationRefDefinition = {
  inputName: INPUT_CONTENT,
  databaseName: RELATION_CONTENT,
  stixName: 'content_ref',
  mandatoryType: 'no',
  multiple: false,
};
const src: RelationRefDefinition = {
  inputName: INPUT_SRC,
  databaseName: RELATION_SRC,
  stixName: 'src_ref',
  mandatoryType: 'no',
  multiple: false,
};
const dst: RelationRefDefinition = {
  inputName: INPUT_DST,
  databaseName: RELATION_DST,
  stixName: 'dst_ref',
  mandatoryType: 'no',
  multiple: false,
};
const srcPayload: RelationRefDefinition = {
  inputName: INPUT_SRC_PAYLOAD,
  databaseName: RELATION_SRC_PAYLOAD,
  stixName: 'src_payload_ref',
  mandatoryType: 'no',
  multiple: false,
};
const dstPayload: RelationRefDefinition = {
  inputName: INPUT_DST_PAYLOAD,
  databaseName: RELATION_DST_PAYLOAD,
  stixName: 'dst_payload_ref',
  mandatoryType: 'no',
  multiple: false,
};
const encapsulates: RelationRefDefinition = {
  inputName: INPUT_ENCAPSULATES,
  databaseName: RELATION_ENCAPSULATES,
  stixName: 'encapsulates_refs',
  mandatoryType: 'no',
  multiple: true,
};
const encapsulatedBy: RelationRefDefinition = {
  inputName: INPUT_ENCAPSULATED_BY,
  databaseName: RELATION_ENCAPSULATED_BY,
  stixName: 'encapsulated_by_ref',
  mandatoryType: 'no',
  multiple: false,
};
const openedConnections: RelationRefDefinition = {
  inputName: INPUT_OPENED_CONNECTION,
  databaseName: RELATION_OPENED_CONNECTION,
  stixName: 'opened_connection_refs',
  mandatoryType: 'no',
  multiple: true,
};
const creatorUser: RelationRefDefinition = {
  inputName: INPUT_CREATOR_USER,
  databaseName: RELATION_CREATOR_USER,
  stixName: 'creator_user_ref',
  mandatoryType: 'no',
  multiple: false,
};
const image: RelationRefDefinition = {
  inputName: INPUT_IMAGE,
  databaseName: RELATION_IMAGE,
  stixName: 'image_ref',
  mandatoryType: 'no',
  multiple: false,
};
const parent: RelationRefDefinition = {
  inputName: INPUT_PARENT,
  databaseName: RELATION_PARENT,
  stixName: 'parent_ref',
  mandatoryType: 'no',
  multiple: false,
};
const child: RelationRefDefinition = {
  inputName: INPUT_CHILD,
  databaseName: RELATION_CHILD,
  stixName: 'child_refs',
  mandatoryType: 'no',
  multiple: true,
};
const bodyMultipart: RelationRefDefinition = {
  inputName: INPUT_BODY_MULTIPART,
  databaseName: RELATION_BODY_MULTIPART,
  stixName: 'body_multipart',
  mandatoryType: 'no',
  multiple: true,
};
const values: RelationRefDefinition = { // Not in standard
  inputName: INPUT_VALUES,
  databaseName: RELATION_VALUES,
  stixName: 'values_refs',
  mandatoryType: 'no',
  multiple: true,
};
// Not used ? TODO: remove
// const xOpenctiLinkedTo: RelationRefDefinition = { // Not in standard
//   name: INPUT_LINKED,
//   databaseName: RELATION_LINKED,
//   stixName: 'x_opencti_linked_to_refs',
//   multiple: true,
// };
const serviceDlls: RelationRefDefinition = {
  inputName: INPUT_SERVICE_DLL,
  databaseName: RELATION_SERVICE_DLL,
  stixName: 'service_dll_refs',
  mandatoryType: 'no',
  multiple: true,
};

export const STIX_CYBER_OBSERVABLE_RELATIONSHIPS: RelationRefDefinition[] = [
  // operatingSystems,
  // sample,
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
  // xOpenctiLinkedTo,
  serviceDlls
];
// schemaRelationsRefDefinition.registerRelationsRef(ABSTRACT_STIX_CYBER_OBSERVABLE, STIX_CYBER_OBSERVABLE_RELATIONSHIPS);

schemaRelationsRefDefinition.registerRelationsRef(ENTITY_DIRECTORY, [contains]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_HASHED_OBSERVABLE_STIX_FILE, [contains, parentDirectory, obsContent]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_DOMAIN_NAME, [resolvesTo, to]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_IPV4_ADDR, [resolvesTo, belongsTo]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_IPV6_ADDR, [resolvesTo, belongsTo]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_EMAIL_MESSAGE, [from, sender, to, cc, bcc, rawEmail, bodyRaw, bodyMultipart]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_NETWORK_TRAFFIC, [src, dst, srcPayload, dstPayload, encapsulates, encapsulatedBy]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_PROCESS, [openedConnections, creatorUser, image, parent, child, serviceDlls]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_WINDOWS_REGISTRY_KEY, [creatorUser]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_WINDOWS_REGISTRY_VALUE_TYPE, [values]);

// -- TYPES --

schemaAttributesDefinition.register(ABSTRACT_STIX_CYBER_OBSERVABLE_RELATIONSHIP, STIX_CYBER_OBSERVABLE_RELATIONSHIPS.map((arr) => arr.databaseName));
export const isStixCyberObservableRelationship = (type: string) => schemaAttributesDefinition.get(ABSTRACT_STIX_CYBER_OBSERVABLE_RELATIONSHIP).includes(type)
  || type === ABSTRACT_STIX_CYBER_OBSERVABLE_RELATIONSHIP;

// -- ATTRIBUTES -

const stixCyberObservableRelationshipsAttributes: AttributeDefinition[] = [
  internalId,
  standardId,
  entityType,
  xOpenctiStixIds,
  specVersion,
  createdAt,
  updatedAt,
  { name: 'i_created_at_day', type: 'date', mandatoryType: 'no', multiple: false, upsert: false },
  { name: 'i_created_at_month', type: 'date', mandatoryType: 'no', multiple: false, upsert: false },
  { name: 'i_created_at_year', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },

  revoked,
  confidence,
  lang,
  created,
  modified,
  relationshipType,
  { name: 'start_time', type: 'date', mandatoryType: 'no', multiple: false, upsert: false },
  { name: 'i_start_time_day', type: 'date', mandatoryType: 'no', multiple: false, upsert: false },
  { name: 'i_start_time_month', type: 'date', mandatoryType: 'no', multiple: false, upsert: false },
  { name: 'i_start_time_year', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
  { name: 'stop_time', type: 'date', mandatoryType: 'no', multiple: false, upsert: false },
  { name: 'i_stop_time_day', type: 'date', mandatoryType: 'no', multiple: false, upsert: false },
  { name: 'i_stop_time_month', type: 'date', mandatoryType: 'no', multiple: false, upsert: false },
  { name: 'i_stop_time_year', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
];
schemaAttributesDefinition.get(ABSTRACT_STIX_CYBER_OBSERVABLE_RELATIONSHIP)
  .forEach((obsType) => schemaAttributesDefinition.registerAttributes(obsType, stixCyberObservableRelationshipsAttributes));
