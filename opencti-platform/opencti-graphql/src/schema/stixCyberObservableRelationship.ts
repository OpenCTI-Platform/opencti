import * as R from 'ramda';
import { ABSTRACT_STIX_CYBER_OBSERVABLE_RELATIONSHIP, schemaTypes } from './general';

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

export const FIELD_CYBER_RELATIONS_TO_STIX_ATTRIBUTE: { [k: string]: string } = {
  [RELATION_OPERATING_SYSTEM]: 'operating_system_refs',
  [RELATION_SAMPLE]: 'sample_ref',
  [RELATION_CONTAINS]: 'contains_refs',
  [RELATION_RESOLVES_TO]: 'resolves_to_refs',
  [RELATION_BELONGS_TO]: 'belongs_to_refs',
  [RELATION_FROM]: 'from_ref',
  [RELATION_SENDER]: 'sender_ref',
  [RELATION_TO]: 'to_refs',
  [RELATION_CC]: 'cc_refs',
  [RELATION_BCC]: 'bcc_refs',
  [RELATION_RAW_EMAIL]: 'raw_email_ref',
  [RELATION_BODY_RAW]: 'body_raw_ref',
  [RELATION_PARENT_DIRECTORY]: 'parent_directory_ref',
  [RELATION_CONTENT]: 'content_ref',
  [RELATION_SRC]: 'src_ref',
  [RELATION_DST]: 'dst_ref',
  [RELATION_SRC_PAYLOAD]: 'src_payload_ref',
  [RELATION_DST_PAYLOAD]: 'dst_payload_ref',
  [RELATION_ENCAPSULATES]: 'encapsulates_refs',
  [RELATION_ENCAPSULATED_BY]: 'encapsulated_by_ref',
  [RELATION_OPENED_CONNECTION]: 'opened_connection_refs',
  [RELATION_CREATOR_USER]: 'creator_user_ref',
  [RELATION_IMAGE]: 'image_ref',
  [RELATION_PARENT]: 'parent_ref',
  [RELATION_CHILD]: 'child_refs',
  [RELATION_BODY_MULTIPART]: 'body_multipart',
  [RELATION_VALUES]: 'values_refs',
  [RELATION_LINKED]: 'x_opencti_linked_to_refs',
};

export const STIX_ATTRIBUTE_TO_CYBER_RELATIONS = R.mergeAll(
  Object.keys(FIELD_CYBER_RELATIONS_TO_STIX_ATTRIBUTE).map((k) => ({
    [FIELD_CYBER_RELATIONS_TO_STIX_ATTRIBUTE[k]]: k,
  }))
);

export const STIX_ATTRIBUTE_TO_CYBER_OBSERVABLE_FIELD: { [k: string]: string } = {
  operating_system_refs: INPUT_OPERATING_SYSTEM,
  sample_ref: INPUT_SAMPLE,
  contains_refs: INPUT_CONTAINS,
  resolves_to_refs: INPUT_RESOLVES_TO,
  belongs_to_refs: INPUT_BELONGS_TO,
  from_ref: INPUT_FROM,
  sender_ref: INPUT_SENDER,
  to_refs: INPUT_TO,
  cc_refs: INPUT_CC,
  bcc_refs: INPUT_BCC,
  raw_email_ref: INPUT_RAW_EMAIL,
  body_raw_ref: INPUT_BODY_RAW,
  parent_directory_ref: INPUT_PARENT_DIRECTORY,
  content_ref: INPUT_CONTENT,
  src_ref: INPUT_SRC,
  dst_ref: INPUT_DST,
  src_payload_ref: INPUT_SRC_PAYLOAD,
  dst_payload_ref: INPUT_DST_PAYLOAD,
  encapsulates_refs: INPUT_ENCAPSULATES,
  encapsulated_by_ref: INPUT_ENCAPSULATED_BY,
  opened_connection_refs: INPUT_OPENED_CONNECTION,
  creator_user_ref: INPUT_CREATOR_USER,
  image_ref: INPUT_IMAGE,
  parent_ref: INPUT_PARENT,
  child_refs: INPUT_CHILD,
  body_multipart: INPUT_BODY_MULTIPART,
  values_refs: INPUT_VALUES,
  x_opencti_linked_to_refs: INPUT_LINKED,
};
export const STIX_CYBER_OBSERVABLE_FIELD_TO_STIX_ATTRIBUTE = R.mergeAll(
  Object.keys(STIX_ATTRIBUTE_TO_CYBER_OBSERVABLE_FIELD).map((k) => ({
    [STIX_ATTRIBUTE_TO_CYBER_OBSERVABLE_FIELD[k]]: k,
  }))
);

export const STIX_CYBER_OBSERVABLE_RELATION_TO_FIELD: { [k: string]: string } = {
  [RELATION_OPERATING_SYSTEM]: INPUT_OPERATING_SYSTEM,
  [RELATION_SAMPLE]: INPUT_SAMPLE,
  [RELATION_CONTAINS]: INPUT_CONTAINS,
  [RELATION_RESOLVES_TO]: INPUT_RESOLVES_TO,
  [RELATION_BELONGS_TO]: INPUT_BELONGS_TO,
  [RELATION_FROM]: INPUT_FROM,
  [RELATION_SENDER]: INPUT_SENDER,
  [RELATION_TO]: INPUT_TO,
  [RELATION_CC]: INPUT_CC,
  [RELATION_BCC]: INPUT_BCC,
  [RELATION_RAW_EMAIL]: INPUT_RAW_EMAIL,
  [RELATION_BODY_RAW]: INPUT_BODY_RAW,
  [RELATION_PARENT_DIRECTORY]: INPUT_PARENT_DIRECTORY,
  [RELATION_CONTENT]: INPUT_CONTENT,
  [RELATION_SRC]: INPUT_SRC,
  [RELATION_DST]: INPUT_DST,
  [RELATION_SRC_PAYLOAD]: INPUT_SRC_PAYLOAD,
  [RELATION_DST_PAYLOAD]: INPUT_DST_PAYLOAD,
  [RELATION_ENCAPSULATES]: INPUT_ENCAPSULATES,
  [RELATION_ENCAPSULATED_BY]: INPUT_ENCAPSULATED_BY,
  [RELATION_OPENED_CONNECTION]: INPUT_OPENED_CONNECTION,
  [RELATION_CREATOR_USER]: INPUT_CREATOR_USER,
  [RELATION_IMAGE]: INPUT_IMAGE,
  [RELATION_PARENT]: INPUT_PARENT,
  [RELATION_CHILD]: INPUT_CHILD,
  [RELATION_BODY_MULTIPART]: INPUT_BODY_MULTIPART,
  [RELATION_VALUES]: INPUT_VALUES,
  [RELATION_LINKED]: INPUT_LINKED,
};

export const CYBER_OBSERVABLE_FIELD_TO_META_RELATION = R.mergeAll(
  Object.keys(STIX_CYBER_OBSERVABLE_RELATION_TO_FIELD).map((k) => ({
    [STIX_CYBER_OBSERVABLE_RELATION_TO_FIELD[k]]: k,
  }))
);

const STIX_CYBER_OBSERVABLE_RELATIONSHIPS = [
  RELATION_OPERATING_SYSTEM,
  RELATION_SAMPLE,
  RELATION_CONTAINS,
  RELATION_RESOLVES_TO,
  RELATION_BELONGS_TO,
  RELATION_FROM,
  RELATION_SENDER,
  RELATION_TO,
  RELATION_CC,
  RELATION_BCC,
  RELATION_RAW_EMAIL,
  RELATION_BODY_RAW,
  RELATION_PARENT_DIRECTORY,
  RELATION_CONTENT,
  RELATION_SRC,
  RELATION_DST,
  RELATION_SRC_PAYLOAD,
  RELATION_DST_PAYLOAD,
  RELATION_ENCAPSULATES,
  RELATION_ENCAPSULATED_BY,
  RELATION_OPENED_CONNECTION,
  RELATION_CREATOR_USER,
  RELATION_IMAGE,
  RELATION_PARENT,
  RELATION_CHILD,
  RELATION_BODY_MULTIPART,
  RELATION_VALUES,
  RELATION_LINKED,
];
schemaTypes.register(ABSTRACT_STIX_CYBER_OBSERVABLE_RELATIONSHIP, STIX_CYBER_OBSERVABLE_RELATIONSHIPS);
export const SINGLE_STIX_CYBER_OBSERVABLE_RELATIONSHIPS_INPUTS = [
  INPUT_SAMPLE,
  INPUT_FROM,
  INPUT_SENDER,
  INPUT_RAW_EMAIL,
  INPUT_BODY_RAW,
  INPUT_PARENT_DIRECTORY,
  INPUT_CONTENT,
  INPUT_SRC,
  INPUT_DST,
  INPUT_SRC_PAYLOAD,
  INPUT_DST_PAYLOAD,
  INPUT_ENCAPSULATED_BY,
  INPUT_CREATOR_USER,
  INPUT_IMAGE,
  INPUT_PARENT,
  INPUT_BODY_MULTIPART,
];
export const MULTIPLE_STIX_CYBER_OBSERVABLE_RELATIONSHIPS_INPUTS = [
  INPUT_OPERATING_SYSTEM,
  INPUT_CONTAINS,
  INPUT_RESOLVES_TO,
  INPUT_BELONGS_TO,
  INPUT_TO,
  INPUT_CC,
  INPUT_BCC,
  INPUT_ENCAPSULATES,
  INPUT_OPENED_CONNECTION,
  INPUT_CHILD,
  INPUT_BODY_MULTIPART,
  INPUT_VALUES,
  INPUT_LINKED,
];
export const STIX_CYBER_OBSERVABLE_RELATIONSHIPS_INPUTS = [
  ...SINGLE_STIX_CYBER_OBSERVABLE_RELATIONSHIPS_INPUTS,
  ...MULTIPLE_STIX_CYBER_OBSERVABLE_RELATIONSHIPS_INPUTS,
];
export const isStixCyberObservableRelationship = (type: string): boolean => R.includes(type, STIX_CYBER_OBSERVABLE_RELATIONSHIPS);
export const singleStixCyberObservableRelationships = [
  RELATION_FROM,
  RELATION_SENDER,
  RELATION_RAW_EMAIL,
  RELATION_BODY_RAW,
  RELATION_PARENT_DIRECTORY,
  RELATION_CONTENT,
  RELATION_SRC,
  RELATION_DST,
  RELATION_SRC_PAYLOAD,
  RELATION_DST_PAYLOAD,
  RELATION_ENCAPSULATED_BY,
  RELATION_CREATOR_USER,
  RELATION_IMAGE,
  RELATION_PARENT,
  RELATION_BODY_MULTIPART,
];
export const isSingleStixCyberObservableRelationship = (type: string): boolean => R.includes(type, singleStixCyberObservableRelationships);
export const isSingleStixCyberObservableRelationshipInput = (input: string): boolean => R.includes(input, SINGLE_STIX_CYBER_OBSERVABLE_RELATIONSHIPS_INPUTS);

export const stixCyberObservableRelationshipsAttributes = [
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
  'start_time',
  'i_start_time_day',
  'i_start_time_month',
  'i_start_time_month',
  'stop_time',
  'i_stop_time_day',
  'i_stop_time_month',
  'i_stop_time_year',
];
R.map((obsType) => schemaTypes.registerAttributes(obsType, stixCyberObservableRelationshipsAttributes), STIX_CYBER_OBSERVABLE_RELATIONSHIPS);
