import * as R from 'ramda';

// General
export const KNOWLEDGE_DELETE = 'KNDELETE';

export const ID_INTERNAL = 'internal_id';
export const ID_STANDARD = 'standard_id';
export const INTERNAL_IDS_ALIASES = 'i_aliases_ids';
export const IDS_STIX = 'x_opencti_stix_ids';
export const BASE_TYPE_RELATION = 'RELATION';
export const BASE_TYPE_ENTITY = 'ENTITY';

// Inputs
export const INPUT_EXTERNAL_REFS = 'externalReferences'; // external_references
export const INPUT_KILLCHAIN = 'killChainPhases'; // kill_chain_phases
export const INPUT_CREATED_BY = 'createdBy'; // created_by_ref
export const INPUT_LABELS = 'objectLabel'; // labels
export const INPUT_MARKINGS = 'objectMarking'; // object_marking_refs
export const INPUT_OBJECTS = 'objects'; // object_refs
export const INPUT_DOMAIN_FROM = 'from'; // source_ref
export const INPUT_DOMAIN_TO = 'to'; // target_ref

export const MULTIPLE_META_RELATIONSHIPS_INPUTS = [
  INPUT_MARKINGS,
  INPUT_LABELS,
  INPUT_EXTERNAL_REFS,
  INPUT_KILLCHAIN,
  INPUT_OBJECTS,
];
export const STIX_META_RELATIONSHIPS_INPUTS = [INPUT_CREATED_BY, ...MULTIPLE_META_RELATIONSHIPS_INPUTS];

// Specific prefix
export const REL_INDEX_PREFIX = 'rel_';
export const INTERNAL_PREFIX = 'i_';
export const RULE_PREFIX = 'i_rule_';
export const buildRefRelationKey = (type, field = ID_INTERNAL) => `${REL_INDEX_PREFIX}${type}.${field}`;
export const buildRefRelationSearchKey = (type) => `${buildRefRelationKey(type)}.keyword`;

// Connectors
export const CONNECTOR_INTERNAL_ENRICHMENT = 'INTERNAL_ENRICHMENT'; // Entity types to support (Report, Hash, ...) -> enrich-
export const CONNECTOR_INTERNAL_IMPORT_FILE = 'INTERNAL_IMPORT_FILE'; // Files mime types to support (application/json, ...) -> import-
export const CONNECTOR_INTERNAL_EXPORT_FILE = 'INTERNAL_EXPORT_FILE'; // Files mime types to generate (application/pdf, ...) -> export-

// General UUID
export const OASIS_NAMESPACE = '00abedb4-aa42-466c-9c01-fed23315a9b7';
export const OPENCTI_NAMESPACE = 'b639ff3b-00eb-42ed-aa36-a8dd6f8fb4cf';
export const OPENCTI_PLATFORM_UUID = 'd06053cb-7123-404b-b092-6606411702d2';
export const OPENCTI_ADMIN_UUID = '88ec0c6a-13ce-5e39-b486-354fe4a7084f';
export const OPENCTI_SYSTEM_UUID = '6a4b11e1-90ca-4e42-ba42-db7bc7f7d505';

// Relations
export const ABSTRACT_BASIC_RELATIONSHIP = 'basic-relationship';
export const ABSTRACT_INTERNAL_RELATIONSHIP = 'internal-relationship';
export const ABSTRACT_STIX_RELATIONSHIP = 'stix-relationship';
export const ABSTRACT_STIX_CORE_RELATIONSHIP = 'stix-core-relationship';
export const ABSTRACT_STIX_CYBER_OBSERVABLE_RELATIONSHIP = 'stix-cyber-observable-relationship';
export const ABSTRACT_STIX_META_RELATIONSHIP = 'stix-meta-relationship';

// Entities
export const ABSTRACT_BASIC_OBJECT = 'Basic-Object';
export const ABSTRACT_STIX_OBJECT = 'Stix-Object';
export const ABSTRACT_STIX_META_OBJECT = 'Stix-Meta-Object';
export const ABSTRACT_STIX_CORE_OBJECT = 'Stix-Core-Object';
export const ABSTRACT_STIX_DOMAIN_OBJECT = 'Stix-Domain-Object';
export const ABSTRACT_STIX_CYBER_OBSERVABLE = 'Stix-Cyber-Observable';
export const ABSTRACT_STIX_CYBER_OBSERVABLE_HASHED_OBSERVABLE = 'Hashed-Observable';
export const ABSTRACT_INTERNAL_OBJECT = 'Internal-Object';

// Internal
export const ENTITY_TYPE_CONTAINER = 'Container';
export const ENTITY_TYPE_IDENTITY = 'Identity';
export const ENTITY_TYPE_LOCATION = 'Location';

// Abstract
export const ABSTRACT_TYPES = [
  ABSTRACT_BASIC_OBJECT,
  ABSTRACT_INTERNAL_OBJECT,
  ABSTRACT_STIX_OBJECT,
  ABSTRACT_STIX_CORE_OBJECT,
  ABSTRACT_STIX_DOMAIN_OBJECT,
  ENTITY_TYPE_CONTAINER,
  ENTITY_TYPE_IDENTITY,
  ENTITY_TYPE_LOCATION,
  ABSTRACT_STIX_META_OBJECT,
  ABSTRACT_STIX_CYBER_OBSERVABLE,
  ABSTRACT_STIX_CYBER_OBSERVABLE_HASHED_OBSERVABLE,
  ABSTRACT_BASIC_RELATIONSHIP,
  ABSTRACT_INTERNAL_RELATIONSHIP,
  ABSTRACT_STIX_RELATIONSHIP,
  ABSTRACT_STIX_CORE_RELATIONSHIP,
  ABSTRACT_STIX_META_RELATIONSHIP,
  ABSTRACT_STIX_CYBER_OBSERVABLE_RELATIONSHIP,
];
export const isAbstract = (type) => R.includes(type, ABSTRACT_TYPES);
export const schemaTypes = {
  types: {},
  attributes: {},
  upsertAttributes: {},
  relationshipsMapping: {},
  // eslint-disable-next-line object-shorthand,func-names
  register: function (type, children) {
    this.types[type] = children;
  },
  // eslint-disable-next-line object-shorthand,func-names
  get: function (type) {
    return this.types[type] ?? [];
  },
  // eslint-disable-next-line object-shorthand,func-names
  registerUpsertAttributes: function (type, children) {
    this.upsertAttributes[type] = children;
  },
  // eslint-disable-next-line object-shorthand,func-names
  getUpsertAttributes: function (type) {
    return this.upsertAttributes[type] ?? [];
  },
  // eslint-disable-next-line object-shorthand,func-names
  registerAttributes: function (type, children) {
    this.attributes[type] = children;
  },
  // eslint-disable-next-line object-shorthand,func-names
  getAttributes: function (type) {
    return this.attributes[type] ?? [];
  },
};
// region utils
