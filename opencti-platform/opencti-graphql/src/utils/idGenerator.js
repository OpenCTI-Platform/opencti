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
const ABSTRACT_INTERNAL_RELATIONSHIP = 'internal-relationship';
const ABSTRACT_STIX_RELATIONSHIP = 'stix-relationship';
const ABSTRACT_STIX_KNOWLEDGE_RELATIONSHIP = 'stix-knowledge-relationship';
const ABSTRACT_STIX_META_RELATIONSHIP = 'stix-meta-relationship';
export const ABSTRACT_STIX_SIGHTING_RELATIONSHIP = 'stix-sighting-relationship';
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
export const RELATION_RELATED_TO = 'related-to';
export const RELATION_DERIVED_FROM = 'derived-from';
export const RELATION_DUPLICATE_OF = 'duplicate-of';
export const RELATION_GATHERING = 'gathering'; // Extension
const RELATIONS_KNOWLEDGE = [
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
  RELATION_RELATED_TO,
  RELATION_DROPS,
  RELATION_GATHERING,
];
export const isStixRelation = (type) => includes(type, RELATIONS_KNOWLEDGE);
// endregion

// region STIX SIGHTING RELATIONSHIP
export const RELATION_SIGHTING_POSITIVE = 'sighting-positive';
export const RELATION_SIGHTING_NEGATIVE = 'sighting-negative';
const RELATIONS_SIGHTING = [RELATION_SIGHTING_POSITIVE, RELATION_SIGHTING_NEGATIVE];
export const isStixSighting = (type) => includes(type, RELATIONS_SIGHTING);
// endregion

// region STIX META RELATIONSHIP
export const RELATION_CREATED_BY = 'created-by';
export const RELATION_OBJECT_MARKING = 'object-marking';
export const RELATION_OBJECT = 'object';
export const RELATION_EXTERNAL_REFERENCE = 'external-reference';
export const RELATION_KILL_CHAIN_PHASE = 'kill-chain-phase';
export const RELATION_OBJECT_LABEL = 'object-label';
const RELATIONS_META = [
  RELATION_CREATED_BY,
  RELATION_OBJECT_MARKING,
  RELATION_OBJECT,
  RELATION_EXTERNAL_REFERENCE,
  RELATION_KILL_CHAIN_PHASE,
  RELATION_OBJECT_LABEL,
];
export const isMetaStixRelationship = (type) => includes(type, RELATIONS_META);
// endregion

// region INTERNAL RELATIONSHIP
export const RELATION_AUTHORIZE = 'authorize';
export const RELATION_MIGRATE = 'migrate';
export const RELATION_MEMBERSHIP = 'membership';
export const RELATION_PERMISSION = 'permission';
export const RELATION_USER_ROLE = 'user-role';
export const RELATION_ROLE_CAPABILITY = 'role-capability';
const RELATIONS_INTERNAL = [
  RELATION_AUTHORIZE,
  RELATION_MIGRATE,
  RELATION_MEMBERSHIP,
  RELATION_PERMISSION,
  RELATION_USER_ROLE,
  RELATION_ROLE_CAPABILITY,
  RELATION_AUTHORED_BY,
];
export const isInternalRelationship = (type) => includes(type, RELATIONS_INTERNAL);
// endregion
// ------------------------------------------------------

// ENTITIES --------------------------------------------
// region INTERNAL OBJECT
export const ENTITY_TYPE_CONNECTOR = 'Connector';
export const ENTITY_TYPE_CAPABILITY = 'Capability';
export const ENTITY_TYPE_ROLE = 'Role';
export const ENTITY_TYPE_GROUP = 'Group';
export const ENTITY_TYPE_SETTINGS = 'Settings';
export const ENTITY_TYPE_TOKEN = 'Token';
export const ENTITY_TYPE_WORKSPACE = 'Workspace';
export const ENTITY_TYPE_MIGRATION_STATUS = 'MigrationStatus';
export const ENTITY_TYPE_MIGRATION_REF = 'MigrationReference';
const ENTITIES_INTERNAL = [
  ENTITY_TYPE_CONNECTOR,
  ENTITY_TYPE_CAPABILITY,
  ENTITY_TYPE_ROLE,
  ENTITY_TYPE_GROUP,
  ENTITY_TYPE_SETTINGS,
  ENTITY_TYPE_TOKEN,
  ENTITY_TYPE_WORKSPACE,
  ENTITY_TYPE_MIGRATION_STATUS,
  ENTITY_TYPE_MIGRATION_REF,
];
export const isInternalObject = (type) => includes(type, ENTITIES_INTERNAL);
// endregion

// region STIX CYBER OBSERVABLE OBJECT
export const OBS_AUTONOMOUS_SYSTEM = 'Autonomous-System';
export const OBS_DIRECTORY = 'Directory';
export const OBS_IPV4_ADDR = 'IPv4-Addr';
export const OBS_MAC_ADDR = 'Mac-Addr';
export const OBS_DOMAIN_NAME = 'Domain-Name';
export const OBS_IPV6_ADDR = 'IPv6-Addr';
export const OBS_URL = 'URL';
export const OBS_EMAIL = 'Email';
export const OBS_MUTEX = 'Mutex';
export const OBS_FILE = 'File';
export const OBS_REGISTRY_KEY = 'Registry-Key';
export const OBS_HOSTNAME = 'Hostname';
export const OBS_PDB_PATH = 'pdb-path';
export const OBS_TEXT = 'text';
export const OBS_PROCESS = 'Process';
export const OBS_USER_ACCOUNT = 'User-Account';
export const OBS_CRYPTOGRAPHIC_KEY = 'Cryptographic-Key';
export const OBS_CRYPTOCURRENCY_WALLET = 'Cryptocurrency-Wallet';
export const OBS_USER_AGENT = 'User-Agent';
export const OBS_WINDOWS_SERVICE = 'Windows-Service';
export const OBS_WINDOWS_SCHEDULED_TASK = 'Windows-Scheduled-Task';
export const OBS_X509_CERTIFICATE = 'X509-Certificate';
const ENTITIES_SCO = [
  OBS_IPV4_ADDR,
  OBS_AUTONOMOUS_SYSTEM,
  OBS_MAC_ADDR,
  OBS_DOMAIN_NAME,
  OBS_IPV6_ADDR,
  OBS_URL,
  OBS_EMAIL,
  OBS_MUTEX,
  OBS_FILE,
  OBS_DIRECTORY,
  OBS_REGISTRY_KEY,
  OBS_HOSTNAME,
  OBS_PDB_PATH,
  OBS_TEXT,
  OBS_PROCESS,
  OBS_USER_ACCOUNT,
  OBS_CRYPTOGRAPHIC_KEY,
  OBS_CRYPTOCURRENCY_WALLET,
  OBS_USER_AGENT,
  OBS_WINDOWS_SERVICE,
  OBS_WINDOWS_SCHEDULED_TASK,
  OBS_X509_CERTIFICATE,
];
export const isStixCyberObservable = (type) => includes(type, ENTITIES_SCO);
// endregion

// region STIX DOMAIN OBJECT
export const ENTITY_TYPE_ATTACK_PATTERN = 'Attack-Pattern';
export const ENTITY_TYPE_CAMPAIGN = 'Campaign';
export const ENTITY_TYPE_CITY = 'City';
export const ENTITY_TYPE_COUNTRY = 'Country';
export const ENTITY_TYPE_COURSE = 'Course-Of-Action';
export const ENTITY_TYPE_INCIDENT = 'Incident';
export const ENTITY_TYPE_INDICATOR = 'Indicator';
export const ENTITY_TYPE_INTRUSION = 'Intrusion-Set';
export const ENTITY_TYPE_MALWARE = 'Malware';
export const ENTITY_TYPE_USER = 'User';
export const ENTITY_TYPE_ORGA = 'Organization';
export const ENTITY_TYPE_REGION = 'Region';
export const ENTITY_TYPE_SECTOR = 'Sector';
export const ENTITY_TYPE_THREAT_ACTOR = 'Threat-Actor';
export const ENTITY_TYPE_TOOL = 'Tool';
export const ENTITY_TYPE_VULN = 'Vulnerability';
export const ENTITY_TYPE_INDIVIDUAL = 'Individual';
export const ENTITY_TYPE_NOTE = 'Note';
export const ENTITY_TYPE_REPORT = 'Report';
export const ENTITY_TYPE_OPINION = 'Opinion';

const ENTITIES_CONTAINER = [ENTITY_TYPE_REPORT, ENTITY_TYPE_NOTE, ENTITY_TYPE_OPINION];
export const isStixContainer = (type) => includes(type, ENTITIES_CONTAINER);
const ENTITIES_LOCATION = [ENTITY_TYPE_COUNTRY, ENTITY_TYPE_REGION, ENTITY_TYPE_CITY];
export const isStixLocation = (type) => includes(type, ENTITIES_LOCATION);
const ENTITIES_IDENTITY = [ENTITY_TYPE_ORGA, ENTITY_TYPE_SECTOR, ENTITY_TYPE_INDIVIDUAL];
export const isStixIdentity = (type) => includes(type, ENTITIES_IDENTITY);
const ENTITIES_SDO = [
  ENTITY_TYPE_ATTACK_PATTERN,
  ENTITY_TYPE_CAMPAIGN,
  ENTITY_TYPE_CITY,
  ENTITY_TYPE_COUNTRY,
  ENTITY_TYPE_COURSE,
  ENTITY_TYPE_INCIDENT,
  ENTITY_TYPE_INDICATOR,
  ENTITY_TYPE_INTRUSION,
  ENTITY_TYPE_MALWARE,
  ENTITY_TYPE_NOTE,
  ENTITY_TYPE_USER,
  ENTITY_TYPE_ORGA,
  ENTITY_TYPE_REGION,
  ENTITY_TYPE_SECTOR,
  ENTITY_TYPE_REPORT,
  ENTITY_TYPE_THREAT_ACTOR,
  ENTITY_TYPE_TOOL,
  ENTITY_TYPE_VULN,
  ENTITY_TYPE_OPINION,
];
export const isStixDomainObject = (type) => includes(type, ENTITIES_SDO);
// endregion

// region STIX META OBJECT
export const ENTITY_TYPE_EXT_REF = 'External-Reference';
export const ENTITY_TYPE_KILL_CHAIN = 'Kill-Chain-Phase';
export const ENTITY_TYPE_MARKING = 'Marking-Definition';
export const ENTITY_TYPE_LABEL = 'Label';
const ENTITIES_META = [ENTITY_TYPE_EXT_REF, ENTITY_TYPE_KILL_CHAIN, ENTITY_TYPE_MARKING, ENTITY_TYPE_LABEL];
export const isStixMetaObject = (type) => includes(type, ENTITIES_META);
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
    case ENTITY_TYPE_CITY:
    case ENTITY_TYPE_COUNTRY:
    case ENTITY_TYPE_ORGA:
    case ENTITY_TYPE_REGION:
    case ENTITY_TYPE_SECTOR:
    case ENTITY_TYPE_USER:
      return 'identity';
    case ENTITY_TYPE_INCIDENT:
      return 'x-opencti-incident';
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
    case ENTITY_TYPE_EXT_REF:
      return externalReferenceId(type, data);
    case ENTITY_TYPE_KILL_CHAIN:
      return killChainId(type, data);
    case ENTITY_TYPE_ATTACK_PATTERN:
      return attackPatternId(type, data);
    case ENTITY_TYPE_MARKING:
      return markingDefinitionId(type, data);
    case ENTITY_TYPE_REPORT:
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
    case OBS_IPV4_ADDR:
    case OBS_AUTONOMOUS_SYSTEM:
    case OBS_MAC_ADDR:
    case OBS_DOMAIN_NAME:
    case OBS_IPV6_ADDR:
    case OBS_URL:
    case OBS_EMAIL:
    case OBS_MUTEX:
    case OBS_FILE:
    case OBS_DIRECTORY:
    case OBS_REGISTRY_KEY:
    case OBS_HOSTNAME:
    case OBS_PDB_PATH:
    case OBS_TEXT:
    case OBS_PROCESS:
    case OBS_USER_ACCOUNT:
    case OBS_CRYPTOGRAPHIC_KEY:
    case OBS_CRYPTOCURRENCY_WALLET:
    case OBS_USER_AGENT:
    case OBS_WINDOWS_SERVICE:
    case OBS_WINDOWS_SCHEDULED_TASK:
    case OBS_X509_CERTIFICATE:
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
  if (isStixRelation(type)) return 'TODO';
  if (isInternalRelationship(type)) return 'TODO';
  throw DatabaseError(`Cant generate an id for ${type}`);
};
