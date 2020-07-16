import { v5 as uuidv5 } from 'uuid';
import validator from 'validator';
import { includes } from 'ramda';
import { DatabaseError } from '../config/errors';

export const OPENCTI_NAMESPACE = 'b639ff3b-00eb-42ed-aa36-a8dd6f8fb4cf';
export const OPENCTI_ADMIN_UUID = '88ec0c6a-13ce-5e39-b486-354fe4a7084f';
export const OPENCTI_PLATFORM_UUID = 'd06053cb-7123-404b-b092-6606411702d2';

export const BASE_TYPE_RELATION = 'RELATION';
export const BASE_TYPE_ENTITY = 'ENTITY';

// region ABSTRACT TYPES
// Relations
const ABSTRACT_BASIC_RELATIONSHIP = 'basic-relationship';
export const ABSTRACT_INTERNAL_RELATIONSHIP = 'internal-relationship';
export const ABSTRACT_STIX_RELATIONSHIP = 'stix-relationship';
export const ABSTRACT_STIX_KNOWLEDGE_RELATIONSHIP = 'stix-knowledge-relationship';
export const ABSTRACT_STIX_META_RELATIONSHIP = 'stix-meta-relationship';
// Entities
const ABSTRACT_BASIC_OBJECT = 'Basic-Object';
const ABSTRACT_STIX_OBJECT = 'Stix-Object';
export const ABSTRACT_STIX_META_OBJECT = 'Stix-Meta-Object';
export const ABSTRACT_STIX_CORE_OBJECT = 'Stix-Core-Object';
export const ABSTRACT_STIX_DOMAIN_OBJECT = 'Stix-Domain-Object';
export const ABSTRACT_CYBER_OBSERVABLE = 'Stix-Cyber-Observable';
export const ABSTRACT_INTERNAL_OBJECT = 'Internal-Object';
// endregion

// RELATIONS --------------------------------------------
// region STIX KNOWLEDGE RELATIONSHIP
export const RELATION_DELIVERS = 'delivers';
export const RELATION_TARGETS = 'targets';
export const RELATION_USES = 'uses';
export const RELATION_ATTRIBUTED_TO = 'attributed-to';
export const RELATION_COMPROMISES = 'compromises';
export const RELATION_ORIGINATES_FROM = 'originates-from';
export const RELATION_INVESTIGATES = 'investigates';
export const RELATION_MITIGATES = 'mitigates';
export const RELATION_LOCATED_AT = 'located-at';
export const RELATION_INDICATES = 'indicates';
export const RELATION_BASED_ON = 'based-on';
export const RELATION_COMMUNICATES_WITH = 'communicates-with';
export const RELATION_CONSISTS_OF = 'consists-of';
export const RELATION_CONTROLS = 'controls';
export const RELATION_HAS = 'has';
export const RELATION_HOSTS = 'hosts';
export const RELATION_OWNS = 'owns';
export const RELATION_AUTHORED_BY = 'authored-by';
export const RELATION_BEACONS_TO = 'beacons-to';
export const RELATION_EXFILTRATE_TO = 'exfiltrate-to';
export const RELATION_DOWNLOADS = 'downloads';
export const RELATION_DROPS = 'drops';
export const RELATION_EXPLOITS = 'exploits';
export const RELATION_VARIANT_OF = 'variant-of';
export const RELATION_CHARACTERIZES = 'characterizes';
export const RELATION_ANALYSIS_OF = 'analysis-of';
export const RELATION_STATIC_ANALYSIS_OF = 'static-analysis-of';
export const RELATION_DYNAMIC_ANALYSIS_OF = 'dynamic-analysis-of';
export const RELATION_IMPERSONATES = 'impersonates';
export const RELATION_REMEDIATES = 'remediates';
export const RELATION_RELATED_TO = 'related-to';
export const RELATION_DERIVED_FROM = 'derived-from';
export const RELATION_DUPLICATE_OF = 'duplicate-of';
export const RELATION_PART_OF = 'part-of'; // Extension
export const RELATION_SUBTECHNIQUE_OF = 'subtechnique-of'; // Extension
const STIX_CORE_RELATIONSHIPS = [
  RELATION_DELIVERS,
  RELATION_TARGETS,
  RELATION_USES,
  RELATION_BEACONS_TO,
  RELATION_ATTRIBUTED_TO,
  RELATION_EXFILTRATE_TO,
  RELATION_COMPROMISES,
  RELATION_DOWNLOADS,
  RELATION_EXPLOITS,
  RELATION_CHARACTERIZES,
  RELATION_ANALYSIS_OF,
  RELATION_STATIC_ANALYSIS_OF,
  RELATION_DYNAMIC_ANALYSIS_OF,
  RELATION_DERIVED_FROM,
  RELATION_DUPLICATE_OF,
  RELATION_ORIGINATES_FROM,
  RELATION_INVESTIGATES,
  RELATION_LOCATED_AT,
  RELATION_BASED_ON,
  RELATION_HOSTS,
  RELATION_OWNS,
  RELATION_COMMUNICATES_WITH,
  RELATION_MITIGATES,
  RELATION_CONTROLS,
  RELATION_HAS,
  RELATION_CONSISTS_OF,
  RELATION_INDICATES,
  RELATION_VARIANT_OF,
  RELATION_IMPERSONATES,
  RELATION_REMEDIATES,
  RELATION_RELATED_TO,
  RELATION_DROPS,
  RELATION_PART_OF,
  RELATION_SUBTECHNIQUE_OF,
];
export const isStixCoreRelationship = (type) => includes(type, STIX_CORE_RELATIONSHIPS);
// endregion

// region STIX SIGHTING RELATIONSHIP
export const STIX_SIGHTING_RELATIONSHIP = 'stix-sighting-relationship';
export const isStixSightingRelationship = (type) => type === STIX_SIGHTING_RELATIONSHIP;
// endregion

// region STIX META RELATIONSHIP
export const RELATION_CREATED_BY = 'created-by';
export const RELATION_OBJECT_MARKING = 'object-marking';
export const RELATION_OBJECT_LABEL = 'object-label';
export const RELATION_OBJECT = 'object';
export const RELATION_EXTERNAL_REFERENCE = 'external-reference';
export const RELATION_KILL_CHAIN_PHASE = 'kill-chain-phase';
const STIX_META_RELATIONSHIPS = [RELATION_CREATED_BY, RELATION_OBJECT_MARKING, RELATION_OBJECT];
const STIX_INTERNAL_META_RELATIONSHIPS = [
  RELATION_OBJECT_LABEL,
  RELATION_EXTERNAL_REFERENCE,
  RELATION_KILL_CHAIN_PHASE,
];
export const isStixMetaRelationship = (type) =>
  includes(type, STIX_META_RELATIONSHIPS) || includes(type, STIX_INTERNAL_META_RELATIONSHIPS);
export const isStixInternalMetaRelationship = (type) => includes(type, STIX_INTERNAL_META_RELATIONSHIPS);
// endregion

// region STIX CYBER OBSERVABLE RELATIONSHIP
export const RELATION_OPERATING_SYSTEM = 'operating-system';
export const RELATION_SAMPLE = 'sample';
export const RELATION_CONTAINS = 'contains';
export const RELATION_RESOLVES_TO = ' resolves-to';
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
];
export const isStixCyberObservableRelationship = (type) => includes(type, STIX_CYBER_OBSERVABLE_RELATIONSHIPS);
// endregion

// region INTERNAL RELATIONSHIP
export const RELATION_AUTHORIZED_BY = 'authorized-by';
export const RELATION_MIGRATES = 'migrates';
export const RELATION_MEMBER_OF = 'member-of';
export const RELATION_ALLOWED_BY = 'allowed-by';
export const RELATION_HAS_ROLE = 'has-role';
export const RELATION_HAS_CAPABILITY = 'has-capability';
const INTERNAL_RELATIONSHIPS = [
  RELATION_AUTHORIZED_BY,
  RELATION_MIGRATES,
  RELATION_MEMBER_OF,
  RELATION_ALLOWED_BY,
  RELATION_HAS_ROLE,
  RELATION_HAS_CAPABILITY,
];
export const isInternalRelationship = (type) => includes(type, INTERNAL_RELATIONSHIPS);
// endregion
export const isStixRelationship = (type) =>
  isStixCoreRelationship(type) ||
  isStixSightingRelationship(type) ||
  isStixCyberObservableRelationship ||
  isStixMetaRelationship;
// ------------------------------------------------------

// ENTITIES --------------------------------------------
// region INTERNAL OBJECT
export const ENTITY_TYPE_SETTINGS = 'Settings';
export const ENTITY_TYPE_MIGRATION_STATUS = 'MigrationStatus';
export const ENTITY_TYPE_MIGRATION_REFERENCE = 'MigrationReference';
export const ENTITY_TYPE_TOKEN = 'Token';
export const ENTITY_TYPE_GROUP = 'Group';
export const ENTITY_TYPE_USER = 'User';
export const ENTITY_TYPE_ROLE = 'Role';
export const ENTITY_TYPE_CAPABILITY = 'Capability';
export const ENTITY_TYPE_CONNECTOR = 'Connector';
export const ENTITY_TYPE_WORKSPACE = 'Workspace';

const INTERNAL_OBJECTS = [
  ENTITY_TYPE_SETTINGS,
  ENTITY_TYPE_MIGRATION_STATUS,
  ENTITY_TYPE_MIGRATION_REFERENCE,
  ENTITY_TYPE_TOKEN,
  ENTITY_TYPE_GROUP,
  ENTITY_TYPE_USER,
  ENTITY_TYPE_ROLE,
  ENTITY_TYPE_CAPABILITY,
  ENTITY_TYPE_CONNECTOR,
  ENTITY_TYPE_WORKSPACE,
];
export const isInternalObject = (type) => includes(type, INTERNAL_OBJECTS);
// endregion

// region STIX META OBJECT
export const ENTITY_TYPE_MARKING_DEFINITION = 'Marking-Definition';
export const ENTITY_TYPE_LABEL = 'Label';
export const ENTITY_TYPE_EXTERNAL_REFERENCE = 'External-Reference';
export const ENTITY_TYPE_KILL_CHAIN_PHASE = 'Kill-Chain-Phase';

const STIX_META_OBJECT = [
  ENTITY_TYPE_MARKING_DEFINITION,
  ENTITY_TYPE_LABEL,
  ENTITY_TYPE_EXTERNAL_REFERENCE,
  ENTITY_TYPE_KILL_CHAIN_PHASE,
];
export const isStixMetaObject = (type) => includes(type, STIX_META_OBJECT);
// endregion

// region STIX DOMAIN OBJECT
export const ENTITY_TYPE_ATTACK_PATTERN = 'Attack-Pattern';
export const ENTITY_TYPE_CAMPAIGN = 'Campaign';
export const ENTITY_TYPE_CONTAINER_NOTE = 'Note';
export const ENTITY_TYPE_CONTAINER_OBSERVED_DATA = 'Observed-Data';
export const ENTITY_TYPE_CONTAINER_OPINION = 'Opinion';
export const ENTITY_TYPE_CONTAINER_REPORT = 'Report';
export const ENTITY_TYPE_COURSE_OF_ACTION = 'Course-Of-Action';
export const ENTITY_TYPE_IDENTITY_INDIVIDUAL = 'Individual';
export const ENTITY_TYPE_IDENTITY_ORGANIZATION = 'Organization';
export const ENTITY_TYPE_IDENTITY_SECTOR = 'Sector';
export const ENTITY_TYPE_INDICATOR = 'Indicator';
export const ENTITY_TYPE_INFRASTRUCTURE = 'Infrastructure';
export const ENTITY_TYPE_INTRUSION_SET = 'Intrusion-Set';
export const ENTITY_TYPE_LOCATION_CITY = 'City';
export const ENTITY_TYPE_LOCATION_COUNTRY = 'Country';
export const ENTITY_TYPE_LOCATION_REGION = 'Region';
export const ENTITY_TYPE_LOCATION_POSITION = 'Position';
export const ENTITY_TYPE_MALWARE = 'Malware';
export const ENTITY_TYPE_THREAT_ACTOR = 'Threat-Actor';
export const ENTITY_TYPE_TOOL = 'Tool';
export const ENTITY_TYPE_VULNERABILITY = 'Vulnerability';
export const ENTITY_TYPE_X_OPENCTI_INCIDENT = 'X-OpenCTI-Incident';

const STIX_DOMAIN_OBJECT_CONTAINERS = [
  ENTITY_TYPE_CONTAINER_NOTE,
  ENTITY_TYPE_CONTAINER_OBSERVED_DATA,
  ENTITY_TYPE_CONTAINER_OPINION,
  ENTITY_TYPE_CONTAINER_REPORT,
];
export const isStixDomainObjectContainer = (type) => includes(type, STIX_DOMAIN_OBJECT_CONTAINERS);
const STIX_DOMAIN_OBJECT_IDENTITIES = [
  ENTITY_TYPE_IDENTITY_INDIVIDUAL,
  ENTITY_TYPE_IDENTITY_ORGANIZATION,
  ENTITY_TYPE_IDENTITY_SECTOR,
];
export const isStixDomainObjectIdentity = (type) => includes(type, STIX_DOMAIN_OBJECT_IDENTITIES);
const STIX_DOMAIN_OBJECT_LOCATIONS = [
  ENTITY_TYPE_LOCATION_CITY,
  ENTITY_TYPE_LOCATION_COUNTRY,
  ENTITY_TYPE_LOCATION_REGION,
  ENTITY_TYPE_LOCATION_POSITION,
];
export const isStixDomainObjectLocation = (type) => includes(type, STIX_DOMAIN_OBJECT_LOCATIONS);

const STIX_DOMAIN_OBJECTS = [
  ENTITY_TYPE_ATTACK_PATTERN,
  ENTITY_TYPE_CAMPAIGN,
  ENTITY_TYPE_CONTAINER_NOTE,
  ENTITY_TYPE_CONTAINER_OBSERVED_DATA,
  ENTITY_TYPE_CONTAINER_OPINION,
  ENTITY_TYPE_CONTAINER_REPORT,
  ENTITY_TYPE_COURSE_OF_ACTION,
  ENTITY_TYPE_IDENTITY_INDIVIDUAL,
  ENTITY_TYPE_IDENTITY_ORGANIZATION,
  ENTITY_TYPE_IDENTITY_SECTOR,
  ENTITY_TYPE_INDICATOR,
  ENTITY_TYPE_INFRASTRUCTURE,
  ENTITY_TYPE_INTRUSION_SET,
  ENTITY_TYPE_LOCATION_CITY,
  ENTITY_TYPE_LOCATION_COUNTRY,
  ENTITY_TYPE_LOCATION_REGION,
  ENTITY_TYPE_LOCATION_POSITION,
  ENTITY_TYPE_MALWARE,
  ENTITY_TYPE_THREAT_ACTOR,
  ENTITY_TYPE_TOOL,
  ENTITY_TYPE_VULNERABILITY,
  ENTITY_TYPE_X_OPENCTI_INCIDENT,
];
export const isStixDomainObject = (type) => includes(type, STIX_DOMAIN_OBJECTS);
// endregion

// region STIX CYBER OBSERVABLE
export const ENTITY_AUTONOMOUS_SYSTEM = 'Autonomous-System';
export const ENTITY_CRYPTOGRAPHIC_KEY = 'Cryptographic-Key';
export const ENTITY_CRYPTOGRAPHIC_WALLET = 'Cryptocurrency-Wallet';
export const ENTITY_DIRECTORY = 'Directory';
export const ENTITY_DOMAIN_NAME = 'Domain-Name';
export const ENTITY_EMAIL_ADDR = 'Email-Addr';
export const ENTITY_EMAIL_MESSAGE = 'Email-Message';
export const ENTITY_EMAIL_MIME_PART_TYPE = 'Email-Mime-Part-Type';
export const ENTITY_HASHED_OBSERVABLE_ARTIFACT = 'Artifact';
export const ENTITY_HASHED_OBSERVABLE_FILE = 'File';
export const ENTITY_HASHED_OBSERVABLE_X509_CERTIFICATE = 'X509-Certificate';
export const ENTITY_IPV4_ADDR = 'IPv4-Addr';
export const ENTITY_IPV6_ADDR = 'IPv6-Addr';
export const ENTITY_MAC_ADDR = 'Mac-Addr';
export const ENTITY_MUTEX = 'Mutex';
export const ENTITY_NETWORK_TRAFFIC = 'Network-Traffic';
export const ENTITY_PROCESS = 'Process';
export const ENTITY_SOFTWARE = 'Software';
export const ENTITY_URL = 'Url';
export const ENTITY_USER_ACCOUNT = 'User-Account';
export const ENTITY_USER_AGENT = 'User-Agent';
export const ENTITY_TEXT = 'text';
export const ENTITY_WINDOWS_REGISTRY_KEY = 'Windows-Registry-Key';
export const ENTITY_WINDOWS_REGISTRY_VALUE_TYPE = 'Windows-Registry-Value-Type';
export const ENTITY_X509_V3_EXTENSIONS_TYPE = 'X509-V3-Extensions-Type';
const STIX_CYBER_OBSERVABLES = [
  ENTITY_AUTONOMOUS_SYSTEM,
  ENTITY_CRYPTOGRAPHIC_KEY,
  ENTITY_CRYPTOGRAPHIC_WALLET,
  ENTITY_DIRECTORY,
  ENTITY_DOMAIN_NAME,
  ENTITY_EMAIL_ADDR,
  ENTITY_EMAIL_MESSAGE,
  ENTITY_EMAIL_MIME_PART_TYPE,
  ENTITY_HASHED_OBSERVABLE_ARTIFACT,
  ENTITY_HASHED_OBSERVABLE_FILE,
  ENTITY_HASHED_OBSERVABLE_X509_CERTIFICATE,
  ENTITY_IPV4_ADDR,
  ENTITY_IPV6_ADDR,
  ENTITY_MAC_ADDR,
  ENTITY_MUTEX,
  ENTITY_NETWORK_TRAFFIC,
  ENTITY_PROCESS,
  ENTITY_SOFTWARE,
  ENTITY_URL,
  ENTITY_USER_ACCOUNT,
  ENTITY_USER_AGENT,
  ENTITY_TEXT,
  ENTITY_WINDOWS_REGISTRY_KEY,
  ENTITY_WINDOWS_REGISTRY_VALUE_TYPE,
  ENTITY_X509_V3_EXTENSIONS_TYPE,
];
export const isStixCyberObservable = (type) => includes(type, STIX_CYBER_OBSERVABLES);
// endregion
export const isStixCoreObject = (type) => isStixDomainObject(type) || isStixCyberObservable(type);
export const isStixObject = (type) => isStixCoreObject(type) || isStixMetaObject(type);
// ------------------------------------------------------

// region utils
const uuid = (data) => {
  const dataHash = JSON.stringify(data).toLowerCase();
  return uuidv5(dataHash, OPENCTI_NAMESPACE);
};
export const isStixId = (id) => id.match(/[a-z-]+--[\w-]{36}/g);
export const isInternalId = (id) => validator.isUUID(id);
const convertEntityTypeToStixType = (type) => {
  switch (type) {
    case ENTITY_TYPE_IDENTITY_INDIVIDUAL:
    case ENTITY_TYPE_IDENTITY_ORGANIZATION:
    case ENTITY_TYPE_IDENTITY_SECTOR:
      return 'identity';
    case ENTITY_TYPE_LOCATION_CITY:
    case ENTITY_TYPE_LOCATION_COUNTRY:
    case ENTITY_TYPE_LOCATION_REGION:
    case ENTITY_TYPE_LOCATION_POSITION:
      return 'location';
    default:
      return type.toLowerCase();
  }
};
export const parents = (type) => {
  if (isStixDomainObject(type)) {
    return [ABSTRACT_STIX_DOMAIN_OBJECT, ABSTRACT_STIX_CORE_OBJECT, ABSTRACT_STIX_OBJECT, ABSTRACT_BASIC_OBJECT];
  }
  if (isStixCyberObservable(type)) {
    return [ABSTRACT_CYBER_OBSERVABLE, ABSTRACT_STIX_CORE_OBJECT, ABSTRACT_STIX_OBJECT, ABSTRACT_BASIC_OBJECT];
  }
  if (isInternalObject(type)) {
    return [ABSTRACT_INTERNAL_OBJECT, ABSTRACT_BASIC_OBJECT];
  }
  if (isStixMetaObject(type)) {
    return [ABSTRACT_STIX_META_OBJECT, ABSTRACT_STIX_OBJECT, ABSTRACT_BASIC_OBJECT];
  }
  throw DatabaseError(`Cant resolve nature of ${type}`);
};
// endregion

// region entities
const externalReferenceId = (type, data) => {
  let referenceKey = data;
  if (data.url) {
    referenceKey = { type, url: data.url };
  } else if (data.source_name && data.external_id) {
    referenceKey = { type, source_name: data.source_name, external_id: data.external_id };
  }
  // Return uuid generated from the full content
  return uuid(referenceKey);
};
const killChainId = (type, data) => {
  const phaseName = data.phase_name.toLowerCase();
  const killChainName = data.kill_chain_name.toLowerCase();
  return uuid({ type, phaseName, killChainName });
};
const markingDefinitionId = (type, data) => {
  // eslint-disable-next-line camelcase
  const { definition, definition_type } = data;
  return uuid({ type, definition_type, definition });
};
const attackPatternId = (type, data) => {
  const { name, killChainPhases } = data;
  return uuid({ type, name, phases: killChainPhases });
};
const reportId = (type, data) => {
  // eslint-disable-next-line camelcase
  const { name, created_by_ref, published } = data;
  return uuid({ type, name, created_by_ref, published });
};
const indicatorId = (type, data) => {
  return uuid({ type, pattern: data.indicator_pattern });
};
// endregion

// region relationship
const relationshipId = (prefix, data) => {
  // eslint-disable-next-line camelcase
  const { fromId, toId, relationship_type, first_seen, last_seen } = data;
  return uuid({ prefix, fromId, toId, relationship_type, first_seen, last_seen });
};
export const generateEmbeddedId = (data) => {
  const { fromId, toId } = data;
  return uuid({ from: fromId, to: toId });
};
// endregion

const generateInternalObjectId = (type, entity) => {
  switch (type) {
    case ENTITY_TYPE_CAPABILITY:
    case ENTITY_TYPE_CONNECTOR:
    case ENTITY_TYPE_ROLE:
    case ENTITY_TYPE_GROUP:
      return uuid({ type, name: entity.name });
    case ENTITY_TYPE_SETTINGS:
      return OPENCTI_PLATFORM_UUID;
    case ENTITY_TYPE_LABEL:
      return uuid({ type, value: entity.value });
    case ENTITY_TYPE_TOKEN:
      return uuid({ type, uuid: entity.uuid });
    case ENTITY_TYPE_WORKSPACE:
      return uuid({ type, name: entity.name, workspace: entity.workspace_type });
    default:
      throw DatabaseError(`Cant generate internal id for type ${type}`);
  }
};
const generateStixDomainObjectUUID = (type, data) => {
  switch (type) {
    case ENTITY_TYPE_EXTERNAL_REFERENCE:
      return externalReferenceId(type, data);
    case ENTITY_TYPE_KILL_CHAIN_PHASE:
      return killChainId(type, data);
    case ENTITY_TYPE_ATTACK_PATTERN:
      return attackPatternId(type, data);
    case ENTITY_TYPE_MARKING_DEFINITION:
      return markingDefinitionId(type, data);
    case ENTITY_TYPE_CONTAINER_REPORT:
      return reportId(type, data);
    case ENTITY_TYPE_INDICATOR:
      return indicatorId(type, data);
    default:
      return uuid({ type, name: data.name });
  }
};
const generateStixDomainObjectId = (type, data) => {
  const prefix = convertEntityTypeToStixType(type);
  const id = generateStixDomainObjectUUID(prefix, data);
  return `${prefix}--${id}`;
  // if (type === 'report') return `${type}--${}`;
  // if (type === 'observable') return `${type}--${observableId(type, data)}`;
  // if (type === 'indicator') return `${type}--${indicatorId(type, data)}`;
  // // Relations
  // if (type === 'sighting' || type === 'relationship') return `${type}--${relationshipId(type, data)}`;
  // // default - just the name
  // return `${type}--${uuid({ type, name: data.name })}`;
};
const generateStixObservableId = (type, data) => {
  switch (type) {
    case ENTITY_AUTONOMOUS_SYSTEM:
    case ENTITY_CRYPTOGRAPHIC_KEY:
    case ENTITY_CRYPTOGRAPHIC_WALLET:
    case ENTITY_DIRECTORY:
    case ENTITY_DOMAIN_NAME:
    case ENTITY_EMAIL_ADDR:
    case ENTITY_EMAIL_MESSAGE:
    case ENTITY_EMAIL_MIME_PART_TYPE:
    case ENTITY_HASHED_OBSERVABLE_ARTIFACT:
    case ENTITY_HASHED_OBSERVABLE_FILE:
    case ENTITY_HASHED_OBSERVABLE_X509_CERTIFICATE:
    case ENTITY_IPV4_ADDR:
    case ENTITY_IPV6_ADDR:
    case ENTITY_MAC_ADDR:
    case ENTITY_MUTEX:
    case ENTITY_NETWORK_TRAFFIC:
    case ENTITY_PROCESS:
    case ENTITY_SOFTWARE:
    case ENTITY_URL:
    case ENTITY_USER_ACCOUNT:
    case ENTITY_USER_AGENT:
    case ENTITY_TEXT:
    case ENTITY_WINDOWS_REGISTRY_KEY:
    case ENTITY_WINDOWS_REGISTRY_VALUE_TYPE:
    case ENTITY_X509_V3_EXTENSIONS_TYPE:
      return ' test';
    default:
      return 'test';
  }
};

export const generateId = (type, data) => {
  // Entities
  if (isStixDomainObject(type)) return generateStixDomainObjectId(type, data);
  if (isStixCyberObservable(type)) return generateStixObservableId(type, data);
  if (isInternalObject(type)) return generateInternalObjectId(type, data);
  // Relations
  if (isStixCoreRelationship(type)) return 'TODO';
  if (isInternalRelationship(type)) return 'TODO';
  throw DatabaseError(`Cant generate an id for ${type}`);
};
