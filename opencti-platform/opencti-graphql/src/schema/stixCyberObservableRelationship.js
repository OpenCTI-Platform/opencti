import * as R from 'ramda';
import { ABSTRACT_STIX_CYBER_OBSERVABLE_RELATIONSHIP, schemaTypes } from './general';

export const RELATION_OPERATING_SYSTEM = 'operating-system';
export const RELATION_SAMPLE = 'sample';
export const RELATION_CONTAINS = 'contains';
export const RELATION_RESOLVES_TO = 'resolves-to';
export const RELATION_BELONGS_TO = 'belongs-to';
export const RELATION_FROM = 'from';
export const RELATION_SENDER = 'sender';
export const RELATION_TO = 'to';
export const RELATION_CC = 'cc';
export const RELATION_BCC = 'bcc';
export const RELATION_RAW_EMAIL = 'raw-email';
export const RELATION_BODY_RAW = 'body-raw';
export const RELATION_PARENT_DIRECTORY = 'parent-directory';
export const RELATION_RELATION_CONTENT = 'relation-content';
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
export const RELATION_X509_V3_EXTENSIONS = 'x509-v3-extensions';
export const RELATION_LINKED = 'x_opencti_linked-to';

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
  RELATION_RELATION_CONTENT,
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
  RELATION_X509_V3_EXTENSIONS,
  RELATION_LINKED,
];
schemaTypes.register(ABSTRACT_STIX_CYBER_OBSERVABLE_RELATIONSHIP, STIX_CYBER_OBSERVABLE_RELATIONSHIPS);
export const isStixCyberObservableRelationship = (type) => R.includes(type, STIX_CYBER_OBSERVABLE_RELATIONSHIPS);

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
R.map(
  (stixCyberObservableRelationshipType) =>
    schemaTypes.registerAttributes(stixCyberObservableRelationshipType, stixCyberObservableRelationshipsAttributes),
  STIX_CYBER_OBSERVABLE_RELATIONSHIPS
);
