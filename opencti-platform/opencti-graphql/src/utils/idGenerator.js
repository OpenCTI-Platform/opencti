import { v5 as uuidv5, v4 as uuidv4 } from 'uuid';
import validator from 'validator';
import { includes } from 'ramda';
import { DatabaseError } from '../config/errors';

export const OPENCTI_NAMESPACE = 'b639ff3b-00eb-42ed-aa36-a8dd6f8fb4cf';
export const OPENCTI_ADMIN_UUID = '88ec0c6a-13ce-5e39-b486-354fe4a7084f';
export const OPENCTI_PLATFORM_UUID = 'd06053cb-7123-404b-b092-6606411702d2';

export const BASE_TYPE_RELATION = 'RELATION';
export const BASE_TYPE_ENTITY = 'ENTITY';

// region STIX RELATIONS
export const RELATION_SIGHTING = 'stix_sighting';
export const RELATION_TARGETS = 'targets';
export const RELATION_USES = 'uses';
export const RELATION_ATTRIBUTED_TO = 'attributed-to';
export const RELATION_MITIGATES = 'mitigates';
export const RELATION_INDICATES = 'indicates';
export const RELATION_COMES_AFTER = 'comes-after';
export const RELATION_VARIANT_OF = 'variant-of';
export const RELATION_IMPERSONATES = 'impersonates';
export const RELATION_RELATED_TO = 'related-to';
export const RELATION_LOCALIZATION = 'localization';
export const RELATION_DROPS = 'drops';
export const RELATION_GATHERING = 'gathering';
export const isStixRelation = (type) =>
  includes(type, [
    RELATION_SIGHTING,
    RELATION_TARGETS,
    RELATION_USES,
    RELATION_ATTRIBUTED_TO,
    RELATION_MITIGATES,
    RELATION_INDICATES,
    RELATION_COMES_AFTER,
    RELATION_VARIANT_OF,
    RELATION_IMPERSONATES,
    RELATION_RELATED_TO,
    RELATION_LOCALIZATION,
    RELATION_DROPS,
    RELATION_GATHERING,
  ]);
// endregion

// region OBSERVABLE RELATIONS
export const RELATION_LINKED = 'linked';
export const RELATION_RESOLVES = 'resolves';
export const RELATION_BELONGS = 'belongs';
export const RELATION_CONTAINS = 'contains';
export const RELATION_CORRESPONDS = 'corresponds';
export const isObservableRelation = (type) =>
  includes(type, [RELATION_LINKED, RELATION_RESOLVES, RELATION_BELONGS, RELATION_CONTAINS, RELATION_CORRESPONDS]);
// endregion

// region INTERNAL RELATIONS
export const RELATION_AUTHORIZE = 'authorize';
export const RELATION_MIGRATE = 'migrate';
export const RELATION_MEMBERSHIP = 'membership';
export const RELATION_PERMISSION = 'permission';
export const RELATION_USER_ROLE = 'user_role';
export const RELATION_ROLE_CAPABILITY = 'role_capability';
export const RELATION_AUTHORED_BY = 'authored_by';
export const RELATION_OWNED_BY = 'owned_by';
export const RELATION_TAGGED = 'tagged';
export const isInternalRelation = (type) =>
  includes(type, [
    RELATION_AUTHORIZE,
    RELATION_MIGRATE,
    RELATION_MEMBERSHIP,
    RELATION_PERMISSION,
    RELATION_USER_ROLE,
    RELATION_ROLE_CAPABILITY,
    RELATION_AUTHORED_BY,
    RELATION_OWNED_BY,
    RELATION_TAGGED,
  ]);
// endregion

// region stix_relation_embedded
export const RELATION_CREATED_BY_REF = 'created_by_ref';
export const RELATION_OBJECT_MARKING_REFS = 'object_marking_refs';
export const RELATION_OBJECT_REFS = 'object_refs';
export const RELATION_EXTERNAL_REFERENCES = 'external_references';
export const RELATION_KILL_CHAIN_PHASES = 'kill_chain_phases';
export const RELATION_OBSERVABLE_REFS = 'observable_refs';
export const isExtendedStixRelation = (type) =>
  includes(type, [
    RELATION_CREATED_BY_REF,
    RELATION_OBJECT_MARKING_REFS,
    RELATION_OBJECT_REFS,
    RELATION_EXTERNAL_REFERENCES,
    RELATION_KILL_CHAIN_PHASES,
    RELATION_OBSERVABLE_REFS,
  ]);
// endregion

// region STIX_OBSERVABLE
export const OBS_IPV4_ADDR = 'IPv4-Addr';
export const OBS_AUTONOMOUS_SYSTEM = 'Autonomous-System';
export const OBS_MAC_ADDR = 'Mac-Addr';
export const OBS_DOMAIN = 'Domain';
export const OBS_IPV6_ADDR = 'IPv6-Addr';
export const OBS_URL = 'URL';
export const OBS_EMAIL = 'Email';
export const OBS_MUTEX = 'Mutex';
export const OBS_FILE = 'File';
export const OBS_DIRECTORY = 'Directory';
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
export const isStixObservable = (type) =>
  includes(type, [
    OBS_IPV4_ADDR,
    OBS_AUTONOMOUS_SYSTEM,
    OBS_MAC_ADDR,
    OBS_DOMAIN,
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
  ]);
// endregion

// region STIX_DOMAIN_ENTITY
export const ENTITY_TYPE_EXT_REF = 'External-Reference';
export const ENTITY_TYPE_KILL_CHAIN = 'Kill-Chain-Phase';
export const ENTITY_TYPE_MARKING = 'Marking-Definition';
export const ENTITY_TYPE_ATTACK_PATTERN = 'Attack-Pattern';
export const ENTITY_TYPE_CAMPAIGN = 'Campaign';
export const ENTITY_TYPE_CITY = 'City';
export const ENTITY_TYPE_COUNTRY = 'Country';
export const ENTITY_TYPE_COURSE = 'Course-Of-Action';
export const ENTITY_TYPE_INCIDENT = 'Incident';
export const ENTITY_TYPE_INDICATOR = 'Indicator';
export const ENTITY_TYPE_INTRUSION = 'Intrusion-Set';
export const ENTITY_TYPE_MALWARE = 'Malware';
export const ENTITY_TYPE_NOTE = 'Note';
export const ENTITY_TYPE_USER = 'User';
export const ENTITY_TYPE_ORGANIZATION = 'Organization';
export const ENTITY_TYPE_REGION = 'Region';
export const ENTITY_TYPE_SECTOR = 'Sector';
export const ENTITY_TYPE_REPORT = 'Report';
export const ENTITY_TYPE_THREAT_ACTOR = 'Threat-Actor';
export const ENTITY_TYPE_TOOL = 'Tool';
export const ENTITY_TYPE_VULN = 'Vulnerability';
export const ENTITY_TYPE_OPINION = 'Opinion';
export const isStixIdentity = (type) =>
  includes(type, [
    ENTITY_TYPE_CITY,
    ENTITY_TYPE_COUNTRY,
    ENTITY_TYPE_USER,
    ENTITY_TYPE_ORGANIZATION,
    ENTITY_TYPE_REGION,
    ENTITY_TYPE_SECTOR,
    ENTITY_TYPE_THREAT_ACTOR,
  ]);
export const isStixEntity = (type) =>
  includes(type, [
    ENTITY_TYPE_EXT_REF,
    ENTITY_TYPE_KILL_CHAIN,
    ENTITY_TYPE_MARKING,
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
    ENTITY_TYPE_ORGANIZATION,
    ENTITY_TYPE_REGION,
    ENTITY_TYPE_SECTOR,
    ENTITY_TYPE_REPORT,
    ENTITY_TYPE_THREAT_ACTOR,
    ENTITY_TYPE_TOOL,
    ENTITY_TYPE_VULN,
    ENTITY_TYPE_OPINION,
  ]);
// endregion

export const isStixElement = (type) => {
  return isStixEntity(type) || isStixObservable(type);
};

// region OPENCTI_INTERNAL
export const ENTITY_TYPE_CONNECTOR = 'Connector';
export const ENTITY_TYPE_CAPABILITY = 'Capability';
export const ENTITY_TYPE_ROLE = 'Role';
export const ENTITY_TYPE_GROUP = 'Group';
export const ENTITY_TYPE_SETTINGS = 'Settings';
export const ENTITY_TYPE_TAG = 'Tag';
export const ENTITY_TYPE_TOKEN = 'Token';
export const ENTITY_TYPE_WORKSPACE = 'Workspace';
export const ENTITY_TYPE_MIGRATION_STATUS = 'MigrationStatus';
export const ENTITY_TYPE_MIGRATION_REF = 'MigrationReference';
export const isInternalEntity = (type) =>
  includes(type, [
    ENTITY_TYPE_CONNECTOR,
    ENTITY_TYPE_CAPABILITY,
    ENTITY_TYPE_ROLE,
    ENTITY_TYPE_GROUP,
    ENTITY_TYPE_SETTINGS,
    ENTITY_TYPE_TAG,
    ENTITY_TYPE_TOKEN,
    ENTITY_TYPE_WORKSPACE,
    ENTITY_TYPE_MIGRATION_STATUS,
    ENTITY_TYPE_MIGRATION_REF,
  ]);
// endregion

// region utils
const uuid = (data) => {
  const dataHash = JSON.stringify(data).toLowerCase();
  return uuidv5(dataHash, OPENCTI_NAMESPACE);
};
export const isStixId = (id) => id.match(/[a-z-]+--[\w-]{36}/g);
export const isStandardId = (id) => validator.isUUID(id);
// endregion

// region entities
const externalReferenceId = (prefix, data) => {
  let referenceKey = data;
  if (data.url) {
    referenceKey = { url: data.url };
  } else if (data.source_name && data.external_id) {
    referenceKey = { source_name: data.source_name, external_id: data.external_id };
  }
  // Return uuid generated from the full content
  return uuid({ prefix, referenceKey });
};
const killChainId = (prefix, data) => {
  const phaseName = data.phase_name.toLowerCase();
  const killChainName = data.kill_chain_name.toLowerCase();
  return uuid({ prefix, phaseName, killChainName });
};
const markingDefinitionId = (prefix, data) => {
  const type = data.definition_type;
  const { definition } = data;
  return uuid({ prefix, type, definition });
};
const attackPatternId = (prefix, data) => {
  const { name, killChainPhases } = data;
  return uuid({ prefix, name, phases: killChainPhases });
};
const reportId = (prefix, data) => {
  // eslint-disable-next-line camelcase
  const { name, created_by_ref, published } = data;
  return uuid({ prefix, name, created_by_ref, published });
};
const observableId = (prefix, data) => {
  const key = { value: data.observable_value };
  return uuid({ prefix, key });
};
const indicatorId = (prefix, data) => {
  const key = { pattern: data.indicator_pattern };
  return uuid({ prefix, key });
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

export const generateRandomId = () => uuidv4();

export const generateInternalId = (type, entity) => {
  switch (type) {
    case ENTITY_TYPE_CAPABILITY:
    case ENTITY_TYPE_CONNECTOR:
    case ENTITY_TYPE_ROLE:
    case ENTITY_TYPE_GROUP:
      return uuid({ type, name: entity.name });
    case ENTITY_TYPE_SETTINGS:
      throw DatabaseError('Settings have a static internal_id');
    case ENTITY_TYPE_TAG:
      return uuid({ type, value: entity.value });
    case ENTITY_TYPE_TOKEN:
      return uuid({ type, uuid: entity.uuid });
    case ENTITY_TYPE_WORKSPACE:
      return uuid({ type, name: entity.name, workspace: entity.workspace_type });
    default:
      throw DatabaseError(`Cant generate internal id for type ${type}`);
  }
};

const convertEntityTypeToStixType = (type) => {
  if (isStixObservable(type)) return 'observable';
  if (isInternalEntity(type)) return 'internal';
  switch (type) {
    case ENTITY_TYPE_CITY:
    case ENTITY_TYPE_COUNTRY:
    case ENTITY_TYPE_ORGANIZATION:
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
export const generateStixId = (type, data) => {
  const prefix = convertEntityTypeToStixType(type);
  // Entities
  if (prefix === 'external-reference') return `${prefix}--${externalReferenceId(prefix, data)}`;
  if (prefix === 'kill-chain-phase') return `${prefix}--${killChainId(prefix, data)}`;
  if (prefix === 'attack-pattern') return `${prefix}--${attackPatternId(prefix, data)}`;
  if (prefix === 'marking-definition') return `${prefix}--${markingDefinitionId(prefix, data)}`;
  if (prefix === 'report') return `${prefix}--${reportId(prefix, data)}`;
  if (prefix === 'observable') return `${prefix}--${observableId(prefix, data)}`;
  if (prefix === 'indicator') return `${prefix}--${indicatorId(prefix, data)}`;
  // Relations
  if (prefix === 'sighting' || prefix === 'relationship') return `${prefix}--${relationshipId(prefix, data)}`;
  // default - just the name
  return `${prefix}--${uuid({ prefix, name: data.name })}`;
};
