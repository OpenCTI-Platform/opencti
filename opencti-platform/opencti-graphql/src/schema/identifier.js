/* eslint-disable camelcase,no-case-declarations */
import { v4 as uuidv4, v5 as uuidv5 } from 'uuid';
import * as R from 'ramda';
import jsonCanonicalize from 'canonicalize';
import { DatabaseError, UnsupportedError } from '../config/errors';
import { convertEntityTypeToStixType } from './schemaUtils';
import * as I from './internalObject';
import * as D from './stixDomainObject';
import * as M from './stixMetaObject';
import * as C from './stixCyberObservable';
import { BASE_TYPE_RELATION, OASIS_NAMESPACE, OPENCTI_NAMESPACE, OPENCTI_PLATFORM_UUID } from './general';
import { isStixMetaObject } from './stixMetaObject';
import { isStixDomainObject, isStixDomainObjectIdentity, isStixDomainObjectLocation } from './stixDomainObject';
import { isStixCyberObservable } from './stixCyberObservable';
import { isInternalObject } from './internalObject';
import { isInternalRelationship } from './internalRelationship';
import { isStixCoreRelationship } from './stixCoreRelationship';
import { isStixMetaRelationship } from './stixMetaRelationship';
import { isStixSightingRelationship } from './stixSightingRelationship';
import { isStixCyberObservableRelationship } from './stixCyberObservableRelationship';
import { isBasicRelationship } from './stixRelationship';

// region hashes
const MD5 = 'MD5';
const SHA_1 = 'SHA-1';
const SHA_256 = 'SHA-256';
const SHA_512 = 'SHA-512';
const SHA3_256 = 'SHA3-256';
const SHA3_512 = 'SHA3-512';
const SSDEEP = 'SSDEEP';
export const STANDARD_HASHES = [MD5, SHA_1, SHA_256, SHA_512, SHA3_256, SHA3_512, SSDEEP];
const transformObjectToUpperKeys = (data) => {
  return Object.fromEntries(Object.entries(data).map(([k, v]) => [k.toUpperCase(), v]));
};
export const INTERNAL_FROM_FIELD = 'i_relations_from';
export const INTERNAL_TO_FIELD = 'i_relations_to';
export const NAME_FIELD = 'name';
export const VALID_UNTIL = 'valid_until';
export const REVOKED = 'revoked';
export const CONTENT_FIELD = 'content';
export const OPINION_FIELD = 'opinion';
export const PID_FIELD = 'pid';
export const X_MITRE_ID_FIELD = 'x_mitre_id';
// endregion

export const normalizeName = (name) => {
  return (name || '').toLowerCase().trim();
};
const stixCyberObservableContribution = {
  definition: {
    // Observables
    [C.ENTITY_AUTONOMOUS_SYSTEM]: [{ src: 'number' }],
    [C.ENTITY_DIRECTORY]: [{ src: 'path' }],
    [C.ENTITY_DOMAIN_NAME]: [{ src: 'value' }],
    [C.ENTITY_EMAIL_ADDR]: [{ src: 'value' }],
    [C.ENTITY_EMAIL_MESSAGE]: [{ src: 'from', dest: 'from_ref' }, { src: 'subject' }, { src: 'body' }],
    [C.ENTITY_HASHED_OBSERVABLE_ARTIFACT]: [{ src: 'hashes' }],
    [C.ENTITY_HASHED_OBSERVABLE_STIX_FILE]: [[{ src: 'hashes' }], [{ src: 'name' }]],
    [C.ENTITY_HASHED_OBSERVABLE_X509_CERTIFICATE]: [
      [{ src: 'hashes' }],
      [{ src: 'serial_number' }],
      [{ src: 'subject' }],
    ],
    [C.ENTITY_IPV4_ADDR]: [{ src: 'value' }],
    [C.ENTITY_IPV6_ADDR]: [{ src: 'value' }],
    [C.ENTITY_MAC_ADDR]: [{ src: 'value' }],
    [C.ENTITY_MUTEX]: [{ src: NAME_FIELD }],
    [C.ENTITY_NETWORK_TRAFFIC]: [
      { src: 'start' },
      { src: 'src', dest: 'src_ref' },
      { src: 'dst', dest: 'dst_ref' },
      { src: 'src_port' },
      { src: 'dst_port' },
      { src: 'protocols' },
    ],
    [C.ENTITY_PROCESS]: [{ src: PID_FIELD }, { src: 'command_line' }],
    [C.ENTITY_SOFTWARE]: [{ src: NAME_FIELD }, { src: 'cpe' }, { src: 'vendor' }, { src: 'version' }],
    [C.ENTITY_URL]: [{ src: 'value' }],
    [C.ENTITY_USER_ACCOUNT]: [{ src: 'account_type' }, { src: 'user_id' }, { src: 'account_login' }],
    [C.ENTITY_WINDOWS_REGISTRY_KEY]: [{ src: 'attribute_key' }, { src: 'values' }],
    [C.ENTITY_X_OPENCTI_CRYPTOGRAPHIC_KEY]: [{ src: 'value' }],
    [C.ENTITY_X_OPENCTI_CRYPTOGRAPHIC_WALLET]: [{ src: 'value' }],
    [C.ENTITY_X_OPENCTI_HOSTNAME]: [{ src: 'value' }],
    [C.ENTITY_X_OPENCTI_USER_AGENT]: [{ src: 'value' }],
    [C.ENTITY_X_OPENCTI_TEXT]: [{ src: 'value' }],
    // Types embedded
    [C.ENTITY_EMAIL_MIME_PART_TYPE]: [], // ALL
    [C.ENTITY_X509_V3_EXTENSIONS_TYPE]: [], // ALL
    [C.ENTITY_WINDOWS_REGISTRY_VALUE_TYPE]: [], // ALL
  },
  resolvers: {
    pid() {
      return uuidv4();
    },
    command_line() {
      return uuidv4();
    },
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
const stixEntityContribution = {
  definition: {
    // Internal
    [I.ENTITY_TYPE_SETTINGS]: OPENCTI_PLATFORM_UUID,
    [I.ENTITY_TYPE_MIGRATION_STATUS]: [], // ALL
    [I.ENTITY_TYPE_MIGRATION_REFERENCE]: [], // ALL
    [I.ENTITY_TYPE_TOKEN]: [{ src: 'uuid' }],
    [I.ENTITY_TYPE_GROUP]: [{ src: NAME_FIELD }],
    [I.ENTITY_TYPE_USER]: [{ src: 'user_email' }],
    [I.ENTITY_TYPE_ROLE]: [{ src: NAME_FIELD }],
    [I.ENTITY_TYPE_CAPABILITY]: [{ src: NAME_FIELD }],
    [I.ENTITY_TYPE_CONNECTOR]: [{ src: 'internal_id' }],
    [I.ENTITY_TYPE_ATTRIBUTE]: [], // ALL
    [I.ENTITY_TYPE_WORKSPACE]: [], // ALL
    [I.ENTITY_TYPE_TAXII_COLLECTION]: [], // ALL
    [I.ENTITY_TYPE_TASK]: [], // ALL
    // Stix Domain
    [D.ENTITY_TYPE_ATTACK_PATTERN]: [[{ src: X_MITRE_ID_FIELD }], [{ src: NAME_FIELD }]],
    [D.ENTITY_TYPE_CAMPAIGN]: [{ src: NAME_FIELD }],
    [D.ENTITY_TYPE_CONTAINER_NOTE]: [{ src: CONTENT_FIELD }],
    [D.ENTITY_TYPE_CONTAINER_OBSERVED_DATA]: [
      { src: 'first_observed' },
      { src: 'last_observed' },
      { src: 'number_observed' },
    ],
    [D.ENTITY_TYPE_CONTAINER_OPINION]: [{ src: OPINION_FIELD }],
    [D.ENTITY_TYPE_CONTAINER_REPORT]: [{ src: NAME_FIELD }, { src: 'published' }],
    [D.ENTITY_TYPE_COURSE_OF_ACTION]: [[{ src: X_MITRE_ID_FIELD }], [{ src: NAME_FIELD }]],
    [D.ENTITY_TYPE_IDENTITY_INDIVIDUAL]: [{ src: NAME_FIELD }, { src: 'identity_class' }],
    [D.ENTITY_TYPE_IDENTITY_ORGANIZATION]: [{ src: NAME_FIELD }, { src: 'identity_class' }],
    [D.ENTITY_TYPE_IDENTITY_SECTOR]: [{ src: NAME_FIELD }, { src: 'identity_class' }],
    [D.ENTITY_TYPE_INDICATOR]: [{ src: 'pattern' }],
    [D.ENTITY_TYPE_INFRASTRUCTURE]: [{ src: NAME_FIELD }],
    [D.ENTITY_TYPE_INTRUSION_SET]: [{ src: NAME_FIELD }],
    [D.ENTITY_TYPE_LOCATION_CITY]: [{ src: NAME_FIELD }, { src: 'x_opencti_location_type' }],
    [D.ENTITY_TYPE_LOCATION_COUNTRY]: [{ src: NAME_FIELD }, { src: 'x_opencti_location_type' }],
    [D.ENTITY_TYPE_LOCATION_REGION]: [{ src: NAME_FIELD }, { src: 'x_opencti_location_type' }],
    [D.ENTITY_TYPE_LOCATION_POSITION]: [{ src: NAME_FIELD }, { src: 'latitude' }, { src: 'longitude' }],
    [D.ENTITY_TYPE_MALWARE]: [{ src: NAME_FIELD }],
    [D.ENTITY_TYPE_THREAT_ACTOR]: [{ src: NAME_FIELD }],
    [D.ENTITY_TYPE_TOOL]: [{ src: NAME_FIELD }],
    [D.ENTITY_TYPE_VULNERABILITY]: [{ src: NAME_FIELD }],
    [D.ENTITY_TYPE_INCIDENT]: [{ src: NAME_FIELD }],
    // Stix Meta
    [M.ENTITY_TYPE_MARKING_DEFINITION]: [{ src: 'definition' }, { src: 'definition_type' }],
    [M.ENTITY_TYPE_LABEL]: [{ src: 'value' }],
    [M.ENTITY_TYPE_KILL_CHAIN_PHASE]: [{ src: 'phase_name' }, { src: 'kill_chain_name' }],
    [M.ENTITY_TYPE_EXTERNAL_REFERENCE]: [[{ src: 'url' }], [{ src: 'source_name' }, { src: 'external_id' }]],
  },
  resolvers: {
    content() {
      return uuidv4();
    },
    opinion() {
      return uuidv4();
    },
    name(data) {
      return normalizeName(data);
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
  },
};
const resolveContribution = (type) => {
  return isStixCyberObservable(type) ? stixCyberObservableContribution : stixEntityContribution;
};
const idGen = (type, raw, data, namespace) => {
  if (R.isEmpty(data)) {
    const contrib = resolveContribution(type);
    const properties = contrib.definition[type];
    throw UnsupportedError(`Cant create key for ${type} from empty data`, { data: raw, properties });
  }
  const dataCanonicalize = jsonCanonicalize(data);
  return uuidv5(dataCanonicalize, namespace);
};
export const isTypeHasAliasIDs = (entityType) => {
  if (isBasicRelationship(entityType)) return false;
  if (isStixDomainObjectIdentity(entityType) || isStixDomainObjectLocation(entityType)) return true;
  const contrib = resolveContribution(entityType);
  const properties = contrib.definition[entityType];
  if (!properties) {
    throw DatabaseError(`Unknown definition for type ${entityType}`);
  }
  if (properties.length === 0) return true;
  if (Array.isArray(R.head(properties))) {
    // eslint-disable-next-line no-restricted-syntax
    for (const property of properties) {
      if (property.length === 1 && R.head(property).src === NAME_FIELD) {
        return true;
      }
    }
    return false;
  }
  return properties.length === 1 && R.head(properties).src === NAME_FIELD;
};
export const isFieldContributingToStandardId = (instance, keys) => {
  const instanceType = instance.entity_type;
  const isRelation = instance.base_type === BASE_TYPE_RELATION;
  if (isRelation) return false;
  const contrib = resolveContribution(instanceType);
  const properties = contrib.definition[instanceType];
  if (!properties) {
    throw DatabaseError(`Unknown definition for type ${instanceType}`);
  }
  if (properties.length === 0) return true;
  const targetKeys = R.map((k) => (k.includes('.') ? R.head(k.split('.')) : k), keys);
  const propertiesToKeep = R.map((t) => t.src, R.flatten(properties));
  const keysIncluded = R.filter((p) => R.includes(p, targetKeys), propertiesToKeep);
  return keysIncluded.length > 0;
};
const filteredIdContributions = (contrib, way, data) => {
  const propertiesToKeep = R.flatten(R.map((t) => t.src, way));
  const dataRelated = R.pick(propertiesToKeep, data);
  if (R.isEmpty(dataRelated)) return {};
  const objectData = {};
  const entries = Object.entries(dataRelated);
  for (let index = 0; index < entries.length; index += 1) {
    const entry = entries[index];
    const [key, value] = entry;
    const prop = R.find((e) => R.includes(key, e.src), way);
    const { src, dest } = prop;
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
  if (properties.length === 0) return data;
  // Handle specific case of static uuid
  if (!Array.isArray(properties)) return properties;
  // In same case ID have multiple possibility for his generation.
  let uuidData;
  const haveDiffWays = Array.isArray(R.head(properties));
  if (haveDiffWays) {
    for (let index = 0; index < properties.length; index += 1) {
      const way = properties[index];
      uuidData = filteredIdContributions(contrib, way, data);
      if (!R.isEmpty(uuidData)) break; // Stop as soon as a correct id is find
    }
  } else {
    uuidData = filteredIdContributions(contrib, properties, data);
  }
  return uuidData;
};
const generateStixUUID = (type, data) => {
  const dataUUID = generateDataUUID(type, data);
  return idGen(type, data, dataUUID, OASIS_NAMESPACE);
};
const generateObjectUUID = (type, data) => {
  const dataUUID = generateDataUUID(type, data);
  return idGen(type, data, dataUUID, OPENCTI_NAMESPACE);
};

const generateObjectId = (type, data) => {
  const uuid = generateObjectUUID(type, data);
  return `${convertEntityTypeToStixType(type)}--${uuid}`;
};
const generateStixId = (type, data) => {
  const uuid = generateStixUUID(type, data);
  return `${convertEntityTypeToStixType(type)}--${uuid}`;
};

export const generateInternalId = () => uuidv4();
export const generateWorkId = () => `opencti-work--${generateInternalId()}`;
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
export const generateAliasesId = (aliases, additionalFields = {}) => {
  return R.map((a) => {
    const dataUUID = { name: normalizeName(a), ...additionalFields };
    const uuid = idGen('ALIAS', aliases, dataUUID, OPENCTI_NAMESPACE);
    return `aliases--${uuid}`;
  }, aliases);
};
