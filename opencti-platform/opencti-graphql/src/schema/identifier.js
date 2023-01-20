/* eslint-disable camelcase,no-case-declarations */
import { v4 as uuidv4, v5 as uuidv5 } from 'uuid';
import * as R from 'ramda';
import * as jsonpatch from 'fast-json-patch';
import jsonCanonicalize from 'canonicalize';
import { DatabaseError, UnsupportedError } from '../config/errors';
import * as I from './internalObject';
import { isInternalObject } from './internalObject';
import * as D from './stixDomainObject';
import {
  ENTITY_TYPE_ATTACK_PATTERN,
  isStixDomainObject,
  isStixDomainObjectIdentity,
  isStixDomainObjectLocation,
  isStixObjectAliased,
} from './stixDomainObject';
import * as M from './stixMetaObject';
import { isStixMetaObject } from './stixMetaObject';
import * as C from './stixCyberObservable';
import { isStixCyberObservable, isStixCyberObservableHashedObservable } from './stixCyberObservable';
import {
  BASE_TYPE_RELATION,
  OASIS_NAMESPACE,
  OPENCTI_NAMESPACE,
  OPENCTI_PLATFORM_UUID
} from './general';
import { isInternalRelationship } from './internalRelationship';
import { isStixCoreRelationship } from './stixCoreRelationship';
import { isStixMetaRelationship } from './stixMetaRelationship';
import { isStixSightingRelationship } from './stixSightingRelationship';
import { isStixCyberObservableRelationship } from './stixCyberObservableRelationship';
import { isEmptyField, isNotEmptyField, UPDATE_OPERATION_ADD, UPDATE_OPERATION_REMOVE } from '../database/utils';
import { now } from '../utils/format';
import { ENTITY_TYPE_VOCABULARY } from '../modules/vocabulary/vocabulary-types';
import { isBasicRelationship } from './stixRelationship';
import { convertTypeToStixType } from '../database/stix-converter';

// region hashes
const MD5 = 'MD5';
const SHA_1 = 'SHA-1';
const SHA_256 = 'SHA-256';
const SHA_512 = 'SHA-512';
const SHA3_256 = 'SHA3-256';
const SHA3_512 = 'SHA3-512';
const SSDEEP = 'SSDEEP';
const transformObjectToUpperKeys = (data) => {
  return Object.fromEntries(Object.entries(data).map(([k, v]) => [k.toUpperCase(), v]));
};
export const INTERNAL_FROM_FIELD = 'i_relations_from';
export const INTERNAL_TO_FIELD = 'i_relations_to';
export const NAME_FIELD = 'name';
export const VALUE_FIELD = 'value';
export const FIRST_SEEN = 'first_seen';
export const LAST_SEEN = 'last_seen';
export const START_TIME = 'start_time';
export const STOP_TIME = 'stop_time';
export const VALID_FROM = 'valid_from';
export const FIRST_OBSERVED = 'first_observed';
export const LAST_OBSERVED = 'last_observed';
export const VALID_UNTIL = 'valid_until';
export const REVOKED = 'revoked';
export const X_MITRE_ID_FIELD = 'x_mitre_id';
export const X_DETECTION = 'x_opencti_detection';
export const X_WORKFLOW_ID = 'x_opencti_workflow_id';
// endregion

export const normalizeName = (name) => {
  return (name || '').toLowerCase().trim();
};

const MARKING_TLP_CLEAR_ID = '613f2e26-407d-48c7-9eca-b8e91df99dc9';
export const MARKING_TLP_CLEAR = `marking-definition--${MARKING_TLP_CLEAR_ID}`;
const MARKING_TLP_GREEN_ID = '34098fce-860f-48ae-8e50-ebd3cc5e41da';
export const MARKING_TLP_GREEN = `marking-definition--${MARKING_TLP_GREEN_ID}`;
const MARKING_TLP_AMBER_ID = 'f88d31f6-486f-44da-b317-01333bde0b82';
export const MARKING_TLP_AMBER = `marking-definition--${MARKING_TLP_AMBER_ID}`;
const MARKING_TLP_AMBER_STRICT_ID = '826578e1-40ad-459f-bc73-ede076f81f37';
export const MARKING_TLP_AMBER_STRICT = `marking-definition--${MARKING_TLP_AMBER_STRICT_ID}`;
const MARKING_TLP_RED_ID = '5e57c739-391a-4eb3-b6be-7d15ca92d5ed';
export const MARKING_TLP_RED = `marking-definition--${MARKING_TLP_RED_ID}`;
export const STATIC_MARKING_IDS = [
  MARKING_TLP_CLEAR,
  MARKING_TLP_GREEN,
  MARKING_TLP_AMBER,
  MARKING_TLP_AMBER_STRICT,
  MARKING_TLP_RED
];
export const STATIC_STANDARD_IDS = [
  { id: MARKING_TLP_CLEAR_ID, data: { definition_type: 'TLP', definition: 'TLP:WHITE' } },
  { id: MARKING_TLP_CLEAR_ID, data: { definition_type: 'TLP', definition: 'TLP:CLEAR' } },
  { id: MARKING_TLP_GREEN_ID, data: { definition_type: 'TLP', definition: 'TLP:GREEN' } },
  { id: MARKING_TLP_AMBER_ID, data: { definition_type: 'TLP', definition: 'TLP:AMBER' } },
  { id: MARKING_TLP_AMBER_STRICT_ID, data: { definition_type: 'TLP', definition: 'TLP:AMBER+STRICT' } },
  { id: MARKING_TLP_RED_ID, data: { definition_type: 'TLP', definition: 'TLP:RED' } }
];
const getStaticIdFromData = (data) => {
  const findStatic = R.find((s) => R.equals(s.data, data), STATIC_STANDARD_IDS);
  return findStatic?.id;
};

const stixBaseCyberObservableContribution = {
  definition: {
    // Observables
    [C.ENTITY_AUTONOMOUS_SYSTEM]: [{ src: 'number' }], // number
    [C.ENTITY_DIRECTORY]: [{ src: 'path' }], // path
    [C.ENTITY_DOMAIN_NAME]: [{ src: 'value' }], // value
    [C.ENTITY_EMAIL_ADDR]: [{ src: 'value' }], // value
    [C.ENTITY_EMAIL_MESSAGE]: [{ src: 'from', dest: 'from_ref' }, { src: 'subject' }, { src: 'body' }], // from_ref, subject, body
    [C.ENTITY_HASHED_OBSERVABLE_ARTIFACT]: [[{ src: 'hashes' }], [{ src: 'url' }]], // hashes, (!) payload_bin > Cause of volume
    [C.ENTITY_HASHED_OBSERVABLE_STIX_FILE]: [[{ src: 'hashes' }], [{ src: NAME_FIELD }]], // hashes, name, (!) extensions, parent_directory_ref
    [C.ENTITY_HASHED_OBSERVABLE_X509_CERTIFICATE]: [[{ src: 'hashes' }], [{ src: 'serial_number' }], [{ src: 'subject' }]], // hashes, serial_number
    [C.ENTITY_IPV4_ADDR]: [{ src: 'value' }], // value
    [C.ENTITY_IPV6_ADDR]: [{ src: 'value' }], // value
    [C.ENTITY_MAC_ADDR]: [{ src: 'value' }], // value
    [C.ENTITY_MUTEX]: [{ src: NAME_FIELD }], // name
    [C.ENTITY_NETWORK_TRAFFIC]: [ // start, (!) end, src_ref, dst_ref, src_port, dst_port, protocols, (!) extensions
      { src: 'start' },
      { src: 'end' },
      { src: 'src', dest: 'src_ref' },
      { src: 'dst', dest: 'dst_ref' },
      { src: 'src_port' },
      { src: 'dst_port' },
      { src: 'protocols' },
    ],
    [C.ENTITY_PROCESS]: [{ src: 'pid', dependencies: ['command_line'] }, { src: 'command_line' }], // v4
    [C.ENTITY_SOFTWARE]: [{ src: NAME_FIELD }, { src: 'cpe' }, { src: 'swid' }, { src: 'vendor' }, { src: 'version' }], // name, cpe, swid, vendor, version
    [C.ENTITY_URL]: [{ src: 'value' }], // value
    [C.ENTITY_USER_ACCOUNT]: [{ src: 'account_type' }, { src: 'user_id' }, { src: 'account_login' }], // account_type, user_id, account_login
    [C.ENTITY_WINDOWS_REGISTRY_KEY]: [{ src: 'attribute_key', dst: 'key' }, { src: 'values' }], // key, values
    // Added types
    [C.ENTITY_CRYPTOGRAPHIC_KEY]: [{ src: 'value' }],
    [C.ENTITY_CRYPTOGRAPHIC_WALLET]: [{ src: 'value' }],
    [C.ENTITY_HOSTNAME]: [{ src: 'value' }],
    [C.ENTITY_USER_AGENT]: [{ src: 'value' }],
    [C.ENTITY_TEXT]: [{ src: 'value' }],
    [C.ENTITY_BANK_ACCOUNT]: [{ src: 'iban' }],
    [C.ENTITY_PHONE_NUMBER]: [{ src: 'value' }],
    [C.ENTITY_PAYMENT_CARD]: [{ src: 'card_number' }],
    [C.ENTITY_MEDIA_CONTENT]: [{ src: 'url' }],
    // Types embedded
    [C.ENTITY_EMAIL_MIME_PART_TYPE]: [], // ALL
    [C.ENTITY_WINDOWS_REGISTRY_VALUE_TYPE]: [], // ALL
  },
  resolvers: {
    from(from) {
      return from?.standard_id;
    },
    src(src) {
      return src?.standard_id;
    },
    dst(dst) {
      return dst?.standard_id;
    },
    hashes(data) {
      // Uppercase the object keys (md5 == MD5)
      const hashes = transformObjectToUpperKeys(data);
      // Get the key from stix rules
      if (hashes[MD5]) return { [MD5]: hashes[MD5] };
      if (hashes[SHA_1]) return { [SHA_1]: hashes[SHA_1] };
      if (hashes[SHA_256]) return { [SHA_256]: hashes[SHA_256] };
      if (hashes[SHA_512]) return { [SHA_512]: hashes[SHA_512] };
      if (hashes[SHA3_256]) return { [SHA3_256]: hashes[SHA3_256] };
      if (hashes[SHA3_512]) return { [SHA3_512]: hashes[SHA3_512] };
      if (hashes[SSDEEP]) return { [SSDEEP]: hashes[SSDEEP] };
      return undefined;
    },
  },
};
const stixBaseEntityContribution = {
  definition: {
    // Internal
    [I.ENTITY_TYPE_SETTINGS]: () => OPENCTI_PLATFORM_UUID,
    [I.ENTITY_TYPE_MIGRATION_STATUS]: () => uuidv4(),
    [I.ENTITY_TYPE_MIGRATION_REFERENCE]: [{ src: 'title' }, { src: 'timestamp' }],
    [I.ENTITY_TYPE_GROUP]: [{ src: NAME_FIELD }],
    [I.ENTITY_TYPE_USER]: [{ src: 'user_email' }],
    [I.ENTITY_TYPE_ROLE]: [{ src: NAME_FIELD }],
    [I.ENTITY_TYPE_CAPABILITY]: [{ src: NAME_FIELD }],
    [I.ENTITY_TYPE_CONNECTOR]: () => uuidv4(),
    [I.ENTITY_TYPE_RULE_MANAGER]: () => uuidv4(),
    [I.ENTITY_TYPE_RULE]: () => uuidv4(),
    [I.ENTITY_TYPE_HISTORY]: () => uuidv4(),
    [I.ENTITY_TYPE_STATUS_TEMPLATE]: [{ src: NAME_FIELD }],
    [I.ENTITY_TYPE_STATUS]: [{ src: 'template_id' }, { src: 'type' }],
    [I.ENTITY_TYPE_WORKSPACE]: () => uuidv4(),
    [I.ENTITY_TYPE_FEED]: () => uuidv4(),
    [I.ENTITY_TYPE_TAXII_COLLECTION]: () => uuidv4(),
    [I.ENTITY_TYPE_TASK]: () => uuidv4(),
    [I.ENTITY_TYPE_RETENTION_RULE]: () => uuidv4(),
    [I.ENTITY_TYPE_SYNC]: () => uuidv4(),
    [I.ENTITY_TYPE_STREAM_COLLECTION]: () => uuidv4(),
    // Stix Domain
    // Entities
    [D.ENTITY_TYPE_ATTACK_PATTERN]: [[{ src: X_MITRE_ID_FIELD }], [{ src: NAME_FIELD }]],
    [D.ENTITY_TYPE_CAMPAIGN]: [{ src: NAME_FIELD }],
    [D.ENTITY_TYPE_CONTAINER_NOTE]: [{ src: 'created' }, { src: 'content' }],
    [D.ENTITY_TYPE_CONTAINER_OBSERVED_DATA]: [{ src: 'objects' }],
    [D.ENTITY_TYPE_CONTAINER_OPINION]: () => uuidv4(),
    [D.ENTITY_TYPE_CONTAINER_REPORT]: [{ src: NAME_FIELD }, { src: 'published' }],
    [D.ENTITY_TYPE_COURSE_OF_ACTION]: [[{ src: X_MITRE_ID_FIELD }], [{ src: NAME_FIELD }]],
    [D.ENTITY_TYPE_IDENTITY_INDIVIDUAL]: [{ src: NAME_FIELD }, { src: 'identity_class' }],
    [D.ENTITY_TYPE_IDENTITY_ORGANIZATION]: [{ src: NAME_FIELD }, { src: 'identity_class' }],
    [D.ENTITY_TYPE_IDENTITY_SECTOR]: [{ src: NAME_FIELD }, { src: 'identity_class' }],
    [D.ENTITY_TYPE_IDENTITY_SYSTEM]: [{ src: NAME_FIELD }, { src: 'identity_class' }],
    [D.ENTITY_TYPE_INDICATOR]: [{ src: 'pattern' }],
    [D.ENTITY_TYPE_INFRASTRUCTURE]: [{ src: NAME_FIELD }],
    [D.ENTITY_TYPE_INTRUSION_SET]: [{ src: NAME_FIELD }],
    [D.ENTITY_TYPE_LOCATION_CITY]: [{ src: NAME_FIELD }, { src: 'x_opencti_location_type' }],
    [D.ENTITY_TYPE_LOCATION_COUNTRY]: [{ src: NAME_FIELD }, { src: 'x_opencti_location_type' }],
    [D.ENTITY_TYPE_LOCATION_REGION]: [{ src: NAME_FIELD }, { src: 'x_opencti_location_type' }],
    [D.ENTITY_TYPE_LOCATION_POSITION]: [[{ src: 'latitude' }, { src: 'longitude' }], [{ src: NAME_FIELD }]],
    [D.ENTITY_TYPE_MALWARE]: [{ src: NAME_FIELD }],
    [D.ENTITY_TYPE_THREAT_ACTOR]: [{ src: NAME_FIELD }],
    [D.ENTITY_TYPE_TOOL]: [{ src: NAME_FIELD }],
    [D.ENTITY_TYPE_VULNERABILITY]: [{ src: NAME_FIELD }],
    [D.ENTITY_TYPE_INCIDENT]: [{ src: NAME_FIELD }],
    [D.ENTITY_TYPE_DATA_COMPONENT]: [[{ src: NAME_FIELD }]],
    [D.ENTITY_TYPE_DATA_SOURCE]: [[{ src: NAME_FIELD }]],
    [D.ENTITY_TYPE_DATA_SOURCE]: [[{ src: NAME_FIELD }]],
    // Stix Meta
    [M.ENTITY_TYPE_MARKING_DEFINITION]: [{ src: 'definition', dependencies: ['definition_type'] }, { src: 'definition_type' }],
    [M.ENTITY_TYPE_LABEL]: [{ src: 'value' }],
    [M.ENTITY_TYPE_KILL_CHAIN_PHASE]: [{ src: 'phase_name' }, { src: 'kill_chain_name' }],
    [M.ENTITY_TYPE_EXTERNAL_REFERENCE]: [[{ src: 'url' }], [{ src: 'source_name', dependencies: ['external_id'] }, { src: 'external_id' }]],
  },
  resolvers: {
    name(data) {
      return normalizeName(data);
    },
    value(data) {
      return normalizeName(data);
    },
    definition(data) {
      return data.toUpperCase();
    },
    definition_type(data) {
      return data.toUpperCase();
    },
    published(data) {
      return data instanceof Date ? data.toISOString() : data;
    },
    first_observed(data) {
      return data instanceof Date ? data.toISOString() : data;
    },
    last_observed(data) {
      return data instanceof Date ? data.toISOString() : data;
    },
    objects(data) {
      return data.map((o) => o.standard_id).sort();
    },
  },
};

const identifierContributions = [stixBaseCyberObservableContribution, stixBaseEntityContribution];
export const isSupportedStixType = (stixType) => [...identifierContributions.map((identifier) => Object.keys(identifier.definition)).flat()
  .map((type) => type.toLowerCase()), 'identity', 'location', 'file', 'relationship', 'sighting'].includes(stixType);
export const registerModelIdentifier = (identifier) => {
  identifierContributions.push(identifier);
};

const resolveContribution = (type) => {
  const finder = (c) => Object.keys(c.definition).includes(type);
  const ident = identifierContributions.find(finder);
  if (!ident) {
    throw UnsupportedError(`Type ${type} has not available resolution`);
  }
  return ident;
};
export const idGen = (type, raw, data, namespace) => {
  // If empty data, generate an error message
  if (isEmptyField(data)) {
    const contrib = resolveContribution(type);
    const properties = contrib.definition[type];
    const missingKeys = properties.map((p) => p.src).join(' - ');
    throw UnsupportedError(`Missing required elements for ${type} creation (${missingKeys})`, { data: raw, properties });
  }
  // In some cases like TLP, standard id are fixed by the community
  const findStaticId = getStaticIdFromData(data);
  if (findStaticId) {
    return findStaticId;
  }
  // If everything standard, generate the id from the data
  const dataCanonicalize = jsonCanonicalize(data);
  return uuidv5(dataCanonicalize, namespace);
};
export const idGenFromData = (type, data) => {
  const dataCanonicalize = jsonCanonicalize(data);
  const uuid = uuidv5(dataCanonicalize, OPENCTI_NAMESPACE);
  return `${convertTypeToStixType(type)}--${uuid}`;
};

export const fieldsContributingToStandardId = (instance, keys) => {
  const instanceType = instance.entity_type;
  const isRelation = instance.base_type === BASE_TYPE_RELATION;
  if (isRelation) return false;
  const contrib = resolveContribution(instanceType);
  const properties = contrib.definition[instanceType];
  if (!properties) {
    throw DatabaseError(`Unknown definition for type ${instanceType}`);
  }
  // Handle specific case of dedicated generation function
  if (!Array.isArray(properties)) {
    return [];
  }
  // Handle specific case of all
  if (properties.length === 0) {
    return keys;
  }
  const targetKeys = R.map((k) => (k.includes('.') ? R.head(k.split('.')) : k), keys);
  const propertiesToKeep = R.map((t) => t.src, R.flatten(properties));
  return R.filter((p) => R.includes(p, targetKeys), propertiesToKeep);
};
export const isFieldContributingToStandardId = (instance, keys) => {
  const keysIncluded = fieldsContributingToStandardId(instance, keys);
  return keysIncluded.length > 0;
};
const filteredIdContributions = (contrib, way, data) => {
  const propertiesToKeep = R.flatten(R.map((t) => t.src, way));
  const dataRelated = R.pick(propertiesToKeep, data);
  if (R.isEmpty(dataRelated)) {
    return {};
  }
  const objectData = {};
  const entries = Object.entries(dataRelated);
  for (let index = 0; index < entries.length; index += 1) {
    const entry = entries[index];
    const [key, value] = entry;
    const prop = R.find((e) => R.includes(key, e.src), way);
    const { src, dest, dependencies = [] } = prop;
    const dataDependencies = Object.values(R.pick(dependencies, data));
    const isEmptyValueInDependencies = dataDependencies.filter((n) => isEmptyField(n)).length !== 0;
    if (isEmptyValueInDependencies) {
      return {};
    }
    const destKey = dest || src;
    const resolver = contrib.resolvers[src];
    if (resolver) {
      objectData[destKey] = value ? resolver(value) : value;
    } else {
      objectData[destKey] = value;
    }
  }
  return R.filter((keyValue) => !R.isEmpty(keyValue) && !R.isNil(keyValue), objectData);
};

const generateDataUUID = (type, data) => {
  const contrib = resolveContribution(type);
  const properties = contrib.definition[type];
  if (!properties) {
    throw DatabaseError(`Unknown definition for type ${type}`);
  }
  // Handle specific case of dedicated generation function
  if (!Array.isArray(properties)) {
    return { data: properties(), way: properties };
  }
  if (properties.length === 0) {
    return { data, way: properties };
  }
  // In same case ID have multiple possibility for his generation.
  const dataWay = {};
  const haveDiffWays = Array.isArray(R.head(properties));
  if (haveDiffWays) {
    for (let index = 0; index < properties.length; index += 1) {
      const way = properties[index];
      const uuid = filteredIdContributions(contrib, way, data);
      if (!R.isEmpty(uuid)) {
        dataWay.way = way;
        dataWay.data = uuid;
        break; // Stop as soon as a correct id is found
      }
    }
  } else {
    dataWay.way = properties;
    dataWay.data = filteredIdContributions(contrib, properties, data);
  }
  return dataWay;
};

export const isStandardIdSameWay = (previousInstance, updatedInstance) => {
  const { way: previousWay } = generateDataUUID(previousInstance.entity_type, previousInstance);
  const { way: currentWay } = generateDataUUID(updatedInstance.entity_type, updatedInstance);
  return R.equals(previousWay, currentWay);
};

const isStandardIdChanged = (previous, updated, operation) => {
  // If the way change, is not an upgrade
  if (!isStandardIdSameWay(previous, updated)) {
    return false;
  }
  // If same way, test if only adding is part of operation
  const { way: previousWay } = generateDataUUID(previous.entity_type, previous);
  const dataPrevious = R.fromPairs(Object.entries(previous).filter(([k]) => previousWay.map((w) => w.src).includes(k)));
  const { way: currentWay } = generateDataUUID(updated.entity_type, updated);
  const dataUpdated = R.fromPairs(Object.entries(updated).filter(([k]) => currentWay.map((w) => w.src).includes(k)));
  const patch = jsonpatch.compare(dataPrevious, dataUpdated);
  const numberOfOperations = patch.length;
  // If no operations, standard id will not change
  if (numberOfOperations === 0) {
    return false;
  }
  const numberOfUpgrade = patch.filter((p) => p.op === operation).length;
  return numberOfOperations === numberOfUpgrade;
};
export const isStandardIdUpgraded = (previous, updated) => {
  return isStandardIdChanged(previous, updated, UPDATE_OPERATION_ADD);
};
export const isStandardIdDowngraded = (previous, updated) => {
  return isStandardIdChanged(previous, updated, UPDATE_OPERATION_REMOVE);
};

const generateStixUUID = (type, data) => {
  const { data: dataUUID } = generateDataUUID(type, data);
  return idGen(type, data, dataUUID, OASIS_NAMESPACE);
};
const generateObjectUUID = (type, data) => {
  const { data: dataUUID } = generateDataUUID(type, data);
  return idGen(type, data, dataUUID, OPENCTI_NAMESPACE);
};

const generateObjectId = (type, data) => {
  const uuid = generateObjectUUID(type, data);
  return `${convertTypeToStixType(type)}--${uuid}`;
};
const generateStixId = (type, data) => {
  const uuid = generateStixUUID(type, data);
  return `${convertTypeToStixType(type)}--${uuid}`;
};

export const generateInternalId = () => uuidv4();
export const generateWorkId = (connectorId) => {
  const timestamp = now();
  return { id: `work_${connectorId}_${timestamp}`, timestamp };
};
export const generateStandardId = (type, data) => {
  // Entities
  if (isStixMetaObject(type)) return generateStixId(type, data);
  if (isStixDomainObject(type)) return generateStixId(type, data);
  if (isStixCyberObservable(type)) return generateStixId(type, data);
  if (isInternalObject(type)) return generateObjectId(type, data);
  // Relations
  if (isInternalRelationship(type)) return `internal-relationship--${generateInternalId()}`;
  if (isStixCoreRelationship(type)) return `relationship--${generateInternalId()}`;
  if (isStixMetaRelationship(type)) return `relationship-meta--${generateInternalId()}`;
  if (isStixCyberObservableRelationship(type)) return `relationship-meta--${generateInternalId()}`;
  if (isStixSightingRelationship(type)) return `sighting--${generateInternalId()}`;
  // Unknown
  throw UnsupportedError(`${type} is not supported by the platform`);
};
export const generateAliasesId = (rawAliases, instance = {}) => {
  const aliases = R.uniq(rawAliases);
  const additionalFields = {};
  if (isStixDomainObjectIdentity(instance.entity_type)) {
    additionalFields.identity_class = instance.identity_class;
  }
  if (isStixDomainObjectLocation(instance.entity_type)) {
    additionalFields.x_opencti_location_type = instance.x_opencti_location_type;
  }
  if (instance.entity_type === ENTITY_TYPE_ATTACK_PATTERN && instance.x_mitre_id) {
    additionalFields.x_mitre_id = instance.x_mitre_id;
  }
  if (instance.entity_type === ENTITY_TYPE_VOCABULARY) {
    additionalFields.category = instance.category;
  }
  return R.uniq(aliases.map((alias) => {
    const dataUUID = { name: normalizeName(alias), ...additionalFields };
    const uuid = idGen('ALIAS', alias, dataUUID, OPENCTI_NAMESPACE);
    return `aliases--${uuid}`;
  }));
};

export const generateAliasesIdsForInstance = (instance) => {
  if (isEmptyField(instance.entity_type)) {
    throw UnsupportedError('Cant generate alias without entity type ', { instance });
  }
  if (isStixObjectAliased(instance.entity_type)) {
    const aliases = [instance.name, ...(instance.aliases || []), ...(instance.x_opencti_aliases || [])];
    return generateAliasesId(aliases, instance);
  }
  return [];
};
const getHashIds = (type, hashes) => {
  const ids = [];
  if (isStixCyberObservableHashedObservable(type) && isNotEmptyField(hashes)) {
    const hashIds = Object.entries(hashes)
      .map(([, s]) => s)
      .filter((s) => isNotEmptyField(s));
    ids.push(...hashIds);
  }
  return ids;
};
export const getInstanceIds = (instance, withoutInternal = false) => {
  const ids = [];
  if (!withoutInternal) {
    ids.push(instance.internal_id);
  }
  ids.push(instance.standard_id);
  if (instance.x_opencti_stix_ids) {
    ids.push(...instance.x_opencti_stix_ids);
  }
  ids.push(...generateAliasesIdsForInstance(instance));
  ids.push(...getHashIds(instance.entity_type, instance.hashes));
  return R.uniq(ids);
};
export const getInputIds = (type, input, fromRule) => {
  const ids = [input.standard_id || generateStandardId(type, input)];
  if (isNotEmptyField(input.internal_id)) {
    ids.push(input.internal_id);
  }
  if (isNotEmptyField(input.stix_id)) {
    ids.push(input.stix_id);
  }
  if (isNotEmptyField(input.x_opencti_stix_ids)) {
    ids.push(...input.x_opencti_stix_ids);
  }
  ids.push(...generateAliasesIdsForInstance(input));
  ids.push(...getHashIds(type, input.hashes));
  // Inference can only be created once, locking the combination
  if (fromRule && isBasicRelationship(type)) {
    ids.push(`${input.from.internal_id}-${type}-${input.to.internal_id}`);
    ids.push(`${input.to.internal_id}-${type}-${input.from.internal_id}`);
  }
  // Return list of unique ids to lock
  return R.uniq(ids);
};
