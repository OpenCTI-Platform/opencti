import * as R from 'ramda';
import dot from 'dot-object';
import { version as uuidVersion } from 'uuid';
import uuidTime from 'uuid-time';
import { FunctionalError, UnsupportedError } from '../config/errors';
import {
  CONTAINER_REFS_TO_FIELDS,
  ENTITY_TYPE_ATTACK_PATTERN,
  ENTITY_TYPE_CAMPAIGN,
  ENTITY_TYPE_CONTAINER_OBSERVED_DATA,
  ENTITY_TYPE_COURSE_OF_ACTION,
  ENTITY_TYPE_IDENTITY_INDIVIDUAL,
  ENTITY_TYPE_IDENTITY_ORGANIZATION,
  ENTITY_TYPE_IDENTITY_SECTOR,
  ENTITY_TYPE_IDENTITY_SYSTEM,
  ENTITY_TYPE_INCIDENT,
  ENTITY_TYPE_INDICATOR,
  ENTITY_TYPE_INFRASTRUCTURE,
  ENTITY_TYPE_INTRUSION_SET,
  ENTITY_TYPE_LOCATION_CITY,
  ENTITY_TYPE_LOCATION_COUNTRY,
  ENTITY_TYPE_LOCATION_POSITION,
  ENTITY_TYPE_LOCATION_REGION,
  ENTITY_TYPE_MALWARE,
  ENTITY_TYPE_THREAT_ACTOR,
  ENTITY_TYPE_TOOL,
  ENTITY_TYPE_VULNERABILITY,
  isStixDomainObjectIdentity,
  isStixDomainObjectLocation,
} from '../schema/stixDomainObject';
import {
  ENTITY_AUTONOMOUS_SYSTEM,
  ENTITY_DIRECTORY,
  ENTITY_DOMAIN_NAME,
  ENTITY_EMAIL_ADDR,
  ENTITY_EMAIL_MESSAGE,
  ENTITY_EMAIL_MIME_PART_TYPE,
  ENTITY_HASHED_OBSERVABLE_ARTIFACT,
  ENTITY_HASHED_OBSERVABLE_STIX_FILE,
  ENTITY_HASHED_OBSERVABLE_X509_CERTIFICATE,
  ENTITY_IPV4_ADDR,
  ENTITY_IPV6_ADDR,
  ENTITY_MAC_ADDR,
  ENTITY_NETWORK_TRAFFIC,
  ENTITY_PROCESS,
  ENTITY_SOFTWARE,
  ENTITY_URL,
  ENTITY_USER_ACCOUNT,
  ENTITY_WINDOWS_REGISTRY_KEY,
  ENTITY_WINDOWS_REGISTRY_VALUE_TYPE,
  ENTITY_X509_V3_EXTENSIONS_TYPE,
  ENTITY_X_OPENCTI_HOSTNAME,
  isStixCyberObservable,
} from '../schema/stixCyberObservable';
import {
  isStixInternalMetaRelationship,
  isStixMetaRelationship,
  STIX_ATTRIBUTE_TO_META_RELATIONS_FIELD,
} from '../schema/stixMetaRelationship';
import {
  isStixCoreRelationship,
  RELATION_ATTRIBUTED_TO,
  RELATION_AUTHORED_BY,
  RELATION_BASED_ON,
  RELATION_BEACONS_TO,
  RELATION_BELONGS_TO,
  RELATION_COMMUNICATES_WITH,
  RELATION_COMPROMISES,
  RELATION_CONSISTS_OF,
  RELATION_CONTROLS,
  RELATION_DELIVERS,
  RELATION_DERIVED_FROM,
  RELATION_DOWNLOADS,
  RELATION_DROPS,
  RELATION_EXFILTRATES_TO,
  RELATION_EXPLOITS,
  RELATION_HAS,
  RELATION_HOSTS,
  RELATION_IMPERSONATES,
  RELATION_INDICATES,
  RELATION_INVESTIGATES,
  RELATION_LOCATED_AT,
  RELATION_MITIGATES,
  RELATION_ORIGINATES_FROM,
  RELATION_OWNS,
  RELATION_PART_OF,
  RELATION_RELATED_TO,
  RELATION_RESOLVES_TO,
  RELATION_REMEDIATES,
  RELATION_REVOKED_BY,
  RELATION_SUBTECHNIQUE_OF,
  RELATION_TARGETS,
  RELATION_USES,
  RELATION_VARIANT_OF,
  RELATIONSHIP_CORE_REFS_TO_FIELDS,
} from '../schema/stixCoreRelationship';
import { isStixSightingRelationship, SIGHTING_RELATIONSHIP_REFS_TO_FIELDS } from '../schema/stixSightingRelationship';
import {
  isStixCyberObservableRelationship,
  RELATION_BCC,
  RELATION_BELONGS_TO as OBS_RELATION_BELONGS_TO,
  RELATION_BODY_MULTIPART,
  RELATION_BODY_RAW,
  RELATION_CC,
  RELATION_CHILD,
  RELATION_CONTAINS,
  RELATION_CONTENT as OBS_RELATION_CONTENT,
  RELATION_CREATOR_USER,
  RELATION_DST,
  RELATION_DST_PAYLOAD,
  RELATION_ENCAPSULATED_BY,
  RELATION_ENCAPSULATES,
  RELATION_FROM,
  RELATION_IMAGE,
  RELATION_LINKED,
  RELATION_OPENED_CONNECTION,
  RELATION_OPERATING_SYSTEM,
  RELATION_PARENT,
  RELATION_PARENT_DIRECTORY,
  RELATION_RAW_EMAIL,
  RELATION_RESOLVES_TO as OBS_RELATION_RESOLVES_TO,
  RELATION_SAMPLE,
  RELATION_SENDER,
  RELATION_SRC,
  RELATION_SRC_PAYLOAD,
  RELATION_TO,
  RELATION_VALUES,
  RELATION_X509_V3_EXTENSIONS,
  STIX_ATTRIBUTE_TO_CYBER_OBSERVABLE_FIELD,
  STIX_CYBER_OBSERVABLE_FIELD_TO_STIX_ATTRIBUTE,
  STIX_CYBER_OBSERVABLE_RELATION_TO_FIELD,
  STIX_CYBER_OBSERVABLE_RELATIONSHIPS_INPUTS
} from '../schema/stixCyberObservableRelationship';
import {
  ABSTRACT_STIX_CYBER_OBSERVABLE,
  INPUT_CREATED_BY,
  INPUT_EXTERNAL_REFS,
  INPUT_KILLCHAIN,
  INPUT_LABELS,
  INPUT_MARKINGS,
  INPUT_OBJECTS,
  INTERNAL_PREFIX,
  REL_INDEX_PREFIX,
} from '../schema/general';
import { isEmptyField, isInferredIndex, isNotEmptyField, pascalize, UPDATE_OPERATION_REPLACE } from './utils';
import { isStixRelationship, isStixRelationShipExceptMeta } from '../schema/stixRelationship';
import {
  ENTITY_TYPE_EXTERNAL_REFERENCE,
  ENTITY_TYPE_KILL_CHAIN_PHASE,
  ENTITY_TYPE_LABEL,
  ENTITY_TYPE_MARKING_DEFINITION,
} from '../schema/stixMetaObject';
import { complexAttributeToApiFormat, isMultipleAttribute } from '../schema/fieldDataAdapter';
import {
  isSingleStixEmbeddedRelationship,
  isSingleStixEmbeddedRelationshipInput,
} from '../schema/stixEmbeddedRelationship';
import { observableValue } from '../utils/format';
import { generateInternalType } from '../schema/schemaUtils';
import typeDefs from '../../config/schema/opencti.graphql';
import { generateStandardId, normalizeName } from '../schema/identifier';
import { isInternalRelationship } from '../schema/internalRelationship';
import { isInternalObject } from '../schema/internalObject';

const MAX_TRANSIENT_STIX_IDS = 200;
export const STIX_SPEC_VERSION = '2.1';
const EXCLUDED_FIELDS_FROM_STIX = [
  '_index',
  'standard_id',
  'internal_id',
  'fromId',
  'fromRole',
  'fromType',
  'toId',
  'toRole',
  'toType',
  'parent_types',
  'base_type',
  'entity_type',
  'update',
  'connections',
  'created_at',
  'updated_at',
  'sort',
  'x_opencti_inferences',
  'x_opencti_graph_data'
];
const STIX_BASIC_FIELDS = [
  'id',
  'x_opencti_id',
  'type',
  'spec_version',
  'source_ref',
  'x_opencti_source_ref',
  'target_ref',
  'x_opencti_target_ref',
  'start_time',
  'stop_time',
  'hashes',
];

export const convertTypeToStixType = (type) => {
  if (isStixDomainObjectIdentity(type)) {
    return 'identity';
  }
  if (isStixDomainObjectLocation(type)) {
    return 'location';
  }
  if (type === ENTITY_HASHED_OBSERVABLE_STIX_FILE) {
    return 'file';
  }
  if (isStixCoreRelationship(type)) {
    return 'relationship';
  }
  if (isStixSightingRelationship(type)) {
    return 'sighting';
  }
  return type.toLowerCase();
};

const isValidStix = (data) => {
  // TODO @JRI @SAM
  return !R.isEmpty(data);
};

const isDefinedValue = (element) => {
  if (element) {
    // If not in diff mode, we only take into account none empty element
    const isArray = Array.isArray(element);
    if (isArray) return element.length > 0;
    // If not array, check if empty
    return !R.isEmpty(element);
  }
  return false;
};

export const isTrustedStixId = (stixId) => {
  const segments = stixId.split('--');
  const [, uuid] = segments;
  return uuidVersion(uuid) !== 1;
};

const cleanObject = (data) => {
  return R.mergeAll(Object.entries(data).filter(([, v]) => isNotEmptyField(v)).map(([k, v]) => ({ [k]: v })));
};

const extractObjectExtensions = (data) => {
  return R.mergeAll(Object.entries(data).filter(([k, v]) => {
    return k.startsWith('x_') && isNotEmptyField(v);
  }).map(([k, v]) => ({ [k]: v })));
};

export const convertInstanceToStix = (instance, args = {}) => {
  const { patchGeneration = false, clearEmptyValues = false, onlyBase = false } = args;
  let finalData = instance;
  if (instance._index && isInferredIndex(instance._index)) {
    finalData.x_opencti_inference = true;
  }
  if (instance.internal_id) {
    finalData.x_opencti_id = instance.internal_id;
  }
  if (instance.standard_id) {
    finalData.id = instance.standard_id;
  }
  if (instance.entity_type) {
    finalData.type = convertTypeToStixType(instance.entity_type);
    finalData.x_opencti_type = instance.entity_type;
  }
  // region Relationships
  const isRelation = isStixRelationship(instance.type);
  if (isRelation && isEmptyField(finalData.from)) {
    throw UnsupportedError(`Cannot convert relation without a resolved from: ${finalData.fromId}`);
  }
  if (isRelation && isEmptyField(finalData.to)) {
    throw UnsupportedError(`Cannot convert relation without a resolved to: ${finalData.toId}`);
  }
  if (isDefinedValue(finalData.from)) {
    finalData = R.pipe(R.dissoc(RELATION_FROM), R.dissoc('fromId'))(finalData);
    if (instance.type === 'sighting') {
      finalData = R.pipe(
        R.dissoc('source_ref'),
        R.dissoc('relationship_type'),
        R.assoc('sighting_of_ref', instance.from.standard_id),
        R.assoc('x_opencti_sighting_of_ref', instance.from.internal_id),
        R.assoc('x_opencti_sighting_of_type', instance.from.entity_type)
      )(finalData);
    } else {
      finalData = R.pipe(
        R.assoc('source_ref', instance.from.standard_id),
        R.assoc('x_opencti_source_ref', instance.from.internal_id),
        R.assoc('x_opencti_source_type', instance.from.entity_type)
      )(finalData);
    }
  }
  if (isDefinedValue(finalData.to)) {
    finalData = R.pipe(R.dissoc(RELATION_TO))(finalData);
    if (instance.type === 'sighting') {
      finalData = R.pipe(
        R.dissoc('target_ref'),
        R.dissoc('relationship_type'),
        R.assoc('where_sighted_refs', [instance.to.standard_id]),
        R.assoc('x_opencti_where_sighted_refs', [instance.to.internal_id]),
        R.assoc('x_opencti_where_sighted_types', [instance.to.entity_type])
      )(finalData);
    } else {
      finalData = R.pipe(
        R.assoc('target_ref', instance.to.standard_id),
        R.assoc('x_opencti_target_ref', instance.to.internal_id),
        R.assoc('x_opencti_target_type', instance.to.entity_type)
      )(finalData);
    }
  }
  // endregion
  // region Specific input cases
  if (isDefinedValue(finalData.stix_id)) {
    finalData = R.pipe(R.dissoc('stix_id'), R.assoc('x_opencti_stix_ids', [finalData.stix_id]))(finalData);
  } else {
    finalData = R.dissoc('stix_id', finalData);
  }
  // endregion
  // region Inner relations
  if (isDefinedValue(finalData.objects)) {
    const objectSet = Array.isArray(finalData.objects) ? finalData.objects : [finalData.objects];
    const objects = R.map((m) => {
      const value = m.standard_id;
      return patchGeneration ? { value, reference: m.name, x_opencti_id: m.internal_id } : m.standard_id;
    }, objectSet);
    finalData = R.pipe(R.dissoc(INPUT_OBJECTS), R.assoc('object_refs', objects))(finalData);
  } else {
    finalData = R.pipe(R.dissoc(INPUT_OBJECTS), R.dissoc('object_refs'))(finalData);
  }
  // endregion
  // region Markings
  if (isDefinedValue(finalData.objectMarking)) {
    const markingSet = Array.isArray(finalData.objectMarking) ? finalData.objectMarking : [finalData.objectMarking];
    const markings = R.map((m) => {
      const value = m.standard_id;
      return patchGeneration ? { value, reference: m.definition, x_opencti_id: m.internal_id } : m.standard_id;
    }, markingSet);
    finalData = R.pipe(R.dissoc(INPUT_MARKINGS), R.assoc('object_marking_refs', markings))(finalData);
  } else {
    finalData = R.pipe(R.dissoc(INPUT_MARKINGS), R.dissoc('object_marking_refs'))(finalData);
  }
  // endregion
  // region created by
  if (isDefinedValue(finalData.createdBy)) {
    const creator = Array.isArray(finalData.createdBy) ? R.head(finalData.createdBy) : finalData.createdBy;
    const created = patchGeneration
      ? [{ value: creator.standard_id, reference: creator.name, x_opencti_id: creator.internal_id }]
      : creator.standard_id;
    finalData = R.pipe(R.dissoc(INPUT_CREATED_BY), R.assoc('created_by_ref', created))(finalData);
  } else {
    finalData = R.pipe(R.dissoc(INPUT_CREATED_BY), R.dissoc('created_by_ref'))(finalData);
  }
  // endregion
  // region Embedded relations
  if (isDefinedValue(finalData.objectLabel)) {
    const labelSet = Array.isArray(finalData.objectLabel) ? finalData.objectLabel : [finalData.objectLabel];
    const labels = R.map((m) => {
      const { value } = m;
      return patchGeneration ? { value: m.standard_id, reference: value, x_opencti_id: m.internal_id } : value;
    }, labelSet);
    finalData = R.pipe(R.dissoc(INPUT_LABELS), R.assoc('labels', labels))(finalData);
  } else {
    finalData = R.pipe(R.dissoc(INPUT_LABELS), R.dissoc('labels'))(finalData);
  }
  // endregion
  // region Kill chain phases
  if (isDefinedValue(finalData.killChainPhases)) {
    const killSet = Array.isArray(finalData.killChainPhases) ? finalData.killChainPhases : [finalData.killChainPhases];
    const kills = R.map((k) => {
      const extension = extractObjectExtensions(k);
      const attrs = ['kill_chain_name', 'phase_name'];
      const value = cleanObject({ ...R.pick(attrs, k), ...extension });
      return patchGeneration ? { value: k.standard_id, reference: k.kill_chain_name, x_opencti_id: k.internal_id } : value;
    }, killSet);
    finalData = R.pipe(R.dissoc(INPUT_KILLCHAIN), R.assoc('kill_chain_phases', kills))(finalData);
  } else {
    finalData = R.pipe(R.dissoc(INPUT_KILLCHAIN), R.dissoc('kill_chain_phases'))(finalData);
  }
  // endregion
  // region external references
  if (isDefinedValue(finalData.externalReferences)) {
    const refs = finalData.externalReferences;
    const externalSet = Array.isArray(refs) ? refs : [refs];
    const externals = R.map((e) => {
      const extension = extractObjectExtensions(e);
      const attrs = ['source_name', 'description', 'url', 'hashes', 'external_id'];
      const value = cleanObject({ ...R.pick(attrs, e), ...extension });
      return patchGeneration ? { value: e.standard_id, reference: e.source_name, x_opencti_id: e.internal_id } : value;
    }, externalSet);
    finalData = R.pipe(R.dissoc(INPUT_EXTERNAL_REFS), R.assoc('external_references', externals))(finalData);
  } else {
    finalData = R.pipe(R.dissoc(INPUT_EXTERNAL_REFS), R.dissoc('external_references'))(finalData);
  }
  // endregion
  // region cyber observable relationship
  // eslint-disable-next-line no-restricted-syntax
  for (const stixCyberObservableRelationshipInput of STIX_CYBER_OBSERVABLE_RELATIONSHIPS_INPUTS) {
    const cyberInput = finalData[stixCyberObservableRelationshipInput];
    const stixKey = STIX_CYBER_OBSERVABLE_FIELD_TO_STIX_ATTRIBUTE[stixCyberObservableRelationshipInput];
    if (isDefinedValue(cyberInput)) {
      if (isSingleStixEmbeddedRelationshipInput(stixCyberObservableRelationshipInput)) {
        const stixCyberObservable = Array.isArray(cyberInput) ? R.head(cyberInput) : cyberInput;
        const stixCyberObservableRef = patchGeneration
          ? [
            {
              value: stixCyberObservable.standard_id,
              reference: observableValue(stixCyberObservable),
              x_opencti_id: stixCyberObservable.internal_id,
            },
          ]
          : stixCyberObservable.standard_id;
        finalData = R.pipe(
          R.dissoc(stixCyberObservableRelationshipInput),
          R.assoc(stixKey, stixCyberObservableRef)
        )(finalData);
      } else {
        const stixCyberObservable = Array.isArray(cyberInput) ? cyberInput : [cyberInput];
        const stixCyberObservables = R.map(
          (m) => (patchGeneration
            ? { value: m.standard_id, reference: observableValue(m), x_opencti_id: m.internal_id }
            : m.standard_id),
          stixCyberObservable
        );
        finalData = R.pipe(
          R.dissoc(stixCyberObservableRelationshipInput),
          R.assoc(stixKey, stixCyberObservables)
        )(finalData);
      }
    } else {
      finalData = R.pipe(R.dissoc(stixCyberObservableRelationshipInput), R.dissoc(stixKey))(finalData);
    }
  }
  // endregion
  // region StixID V1 are transient and so not in data output
  if (isDefinedValue(finalData.x_opencti_stix_ids)) {
    finalData.x_opencti_stix_ids = finalData.x_opencti_stix_ids.filter((stixId) => isTrustedStixId(stixId));
  }
  // endregion
  // region Attributes filtering
  const filteredData = {};
  const entries = Object.entries(finalData);
  for (let index = 0; index < entries.length; index += 1) {
    const [key, val] = entries[index];
    const isEmpty = Array.isArray(val) ? val.length === 0 : isEmptyField(val);
    const clearEmptyKey = clearEmptyValues && isEmpty;
    const isInternal = key.startsWith(INTERNAL_PREFIX) || key.startsWith(REL_INDEX_PREFIX);
    const isInternalKey = isInternal || EXCLUDED_FIELDS_FROM_STIX.includes(key);
    if (isInternalKey || isStixRelationShipExceptMeta(key) || clearEmptyKey) {
      // Internal opencti attributes.
    } else if (key.startsWith('attribute_')) {
      // Stix but reserved keywords
      const targetKey = key.replace('attribute_', '');
      filteredData[targetKey] = val;
    } else {
      filteredData[key] = val;
    }
  }
  // endregion
  // region specific format for marking definition
  if (filteredData.type === convertTypeToStixType(ENTITY_TYPE_MARKING_DEFINITION) && filteredData.definition) {
    const key = filteredData.definition_type.toLowerCase();
    filteredData.x_opencti_name = filteredData.definition;
    filteredData.definition_type = key;
    filteredData.definition = { [key]: filteredData.definition.replace(/^(tlp|TLP):/g, '') };
  }
  // Add x_ in extension
  // https://docs.oasis-open.org/cti/stix/v2.1/cs01/stix-v2.1-cs01.html#_ct36xlv6obo7
  const createFromPath = (path, value) => {
    const row = { [path]: value };
    dot.object(row);
    return row;
  };
  const dataEntries = Object.entries(filteredData);
  let openctiExtension = {};
  for (let attr = 0; attr < dataEntries.length; attr += 1) {
    const [key, val] = dataEntries[attr];
    if (key.startsWith('x_')) {
      const isOpenCTIExtension = key.startsWith('x_opencti_');
      const path = isOpenCTIExtension ? key.replace('x_opencti_', 'opencti.') : key.substring(2);
      const obj = createFromPath(path, val);
      openctiExtension = R.mergeDeepRight(openctiExtension, obj);
    }
    if (!R.isEmpty(openctiExtension)) {
      filteredData.extensions = openctiExtension;
    }
  }
  // endregion
  if (!isValidStix(filteredData)) {
    throw FunctionalError('Invalid stix data conversion', { data: instance });
  }
  if (onlyBase) {
    return R.pick(STIX_BASIC_FIELDS, filteredData);
  }
  return filteredData;
};

export const extractFieldInputDefinition = (entityType) => {
  // Internal doesnt have any contract
  if (isInternalRelationship(entityType)) {
    return [];
  }
  if (isInternalObject(entityType)) {
    return [];
  }
  // Relations
  if (isStixMetaRelationship(entityType)) {
    const def = R.find((e) => e.name.value === 'StixMetaRelationshipsAddInput', typeDefs.definitions);
    return def.fields.map((f) => f.name.value);
  }
  if (isStixCoreRelationship(entityType)) {
    const def = R.find((e) => e.name.value === 'StixCoreRelationshipAddInput', typeDefs.definitions);
    return def.fields.map((f) => f.name.value);
  }
  if (isStixSightingRelationship(entityType)) {
    const def = R.find((e) => e.name.value === 'StixSightingRelationshipAddInput', typeDefs.definitions);
    return def.fields.map((f) => f.name.value);
  }
  if (isStixCyberObservableRelationship(entityType)) {
    const def = R.find((e) => e.name.value === 'StixCyberObservableRelationshipAddInput', typeDefs.definitions);
    return def.fields.map((f) => f.name.value);
  }
  // Entities
  if (isStixCyberObservable(entityType)) {
    const baseFields = [
      'stix_id',
      'x_opencti_score',
      'x_opencti_description',
      'createIndicator',
      'createdBy',
      'objectMarking',
      'objectLabel',
      'externalReferences',
      'clientMutationId',
      'update',
    ];
    const formattedType = `${entityType.split('-').join('')}AddInput`;
    const def = R.find((e) => e.name.value === formattedType, typeDefs.definitions);
    const schemaFields = def.fields.map((f) => f.name.value);
    return [...baseFields, ...schemaFields];
  }
  const formattedType = `${entityType.split('-').map((e) => pascalize(e)).join('')}AddInput`;
  const def = R.find((e) => e.name.value === formattedType, typeDefs.definitions);
  if (def) {
    return def.fields.map((f) => f.name.value);
  }
  throw UnsupportedError(`Cant extract fields definition ${entityType}`);
};

export const buildInputDataFromStix = (stix) => {
  const inputType = generateInternalType(stix);
  const inputData = { internal_id: stix.x_opencti_id, stix_id: stix.id, type: inputType, update: true };
  const compatibleTypes = extractFieldInputDefinition(inputType);
  const entries = Object.entries(stix);
  for (let index = 0; index < entries.length; index += 1) {
    const [key] = entries[index];
    let translatedKey = RELATIONSHIP_CORE_REFS_TO_FIELDS[key]
      || SIGHTING_RELATIONSHIP_REFS_TO_FIELDS[key]
      || STIX_ATTRIBUTE_TO_META_RELATIONS_FIELD[key]
      || STIX_ATTRIBUTE_TO_CYBER_OBSERVABLE_FIELD[key]
      || CONTAINER_REFS_TO_FIELDS[key]
      || key;
    if (!compatibleTypes.includes(translatedKey) && compatibleTypes.includes(`attribute_${translatedKey}`)) {
      translatedKey = `attribute_${translatedKey}`;
    }
    if (compatibleTypes.includes(translatedKey)) {
      if (inputType === ENTITY_TYPE_MARKING_DEFINITION && translatedKey === 'definition') {
        inputData.definition = stix.definition[stix.definition_type];
      } else if (translatedKey === 'hashes') {
        inputData[translatedKey] = complexAttributeToApiFormat(translatedKey, stix);
      } else if (isStixSightingRelationship(inputType) && translatedKey === 'toId') {
        inputData[translatedKey] = R.head(stix[key]);
      } else if (translatedKey === INPUT_LABELS) {
        inputData[translatedKey] = stix[key].map((v) => {
          const labelName = { value: normalizeName(v) };
          return generateStandardId(ENTITY_TYPE_LABEL, labelName);
        });
      } else if (translatedKey === INPUT_EXTERNAL_REFS) {
        inputData[translatedKey] = stix[key].map((v) => generateStandardId(ENTITY_TYPE_EXTERNAL_REFERENCE, v));
      } else if (translatedKey === INPUT_KILLCHAIN) {
        inputData[translatedKey] = stix[key].map((v) => generateStandardId(ENTITY_TYPE_KILL_CHAIN_PHASE, v));
      } else {
        inputData[translatedKey] = stix[key];
      }
    }
  }
  return { type: inputType, input: inputData };
};

export const mergeDeepRightAll = R.unapply(R.reduce(R.mergeDeepRight, {}));
export const updateInputsToPatch = (inputs) => {
  const convertedInputs = inputs.map((input) => {
    const { key, value, operation = UPDATE_OPERATION_REPLACE, previous = null } = input;
    if (isNotEmptyField(value) && !Array.isArray(value)) {
      throw UnsupportedError('value must be an array');
    }
    if (isNotEmptyField(previous) && !Array.isArray(previous)) {
      throw UnsupportedError('previous must be an array');
    }
    const opts = { patchGeneration: true };
    const keyConvert = R.head(Object.keys(convertInstanceToStix({ [key]: value || previous }, opts)));
    // Sometime the key will be empty because the patch include a none stix modification
    if (isEmptyField(keyConvert)) {
      return {};
    }
    const converter = (val) => {
      const converted = convertInstanceToStix({ [key]: val }, opts);
      return converted[keyConvert];
    };
    const convertedVal = value ? converter(value) : value;
    const convertedPrevious = previous ? converter(previous) : previous;
    if (isMultipleAttribute(key)) {
      if (operation === UPDATE_OPERATION_REPLACE) {
        return { [operation]: { [keyConvert]: { current: convertedVal, previous: convertedPrevious } } };
      }
      return { [operation]: { [keyConvert]: convertedVal } };
    }
    const onlyVal = convertedVal ? R.head(convertedVal) : convertedVal;
    if (operation === UPDATE_OPERATION_REPLACE) {
      const onlyPrevious = convertedPrevious ? R.head(convertedPrevious) : convertedPrevious;
      return { [operation]: { [keyConvert]: { current: onlyVal, previous: onlyPrevious } } };
    }
    return { [operation]: { [keyConvert]: onlyVal } };
  });
  return mergeDeepRightAll(...convertedInputs);
};

export const convertStixMetaRelationshipToStix = (data) => {
  const entityType = data.entity_type;
  let finalData = convertInstanceToStix(data.from, { onlyBase: true });
  if (isStixInternalMetaRelationship(entityType)) {
    finalData = R.assoc(entityType.replace('-', '_'), [convertInstanceToStix(data.to)], finalData);
  } else {
    finalData = R.assoc(
      `${entityType.replace('-', '_')}_ref${!isSingleStixEmbeddedRelationship(entityType) ? 's' : ''}`,
      !isSingleStixEmbeddedRelationship(entityType) ? [data.to.standard_id] : data.to.standard_id,
      finalData
    );
  }
  return finalData;
};

export const convertStixCyberObservableRelationshipToStix = (data) => {
  const entityType = data.entity_type;
  let finalData = convertInstanceToStix(data.from, { onlyBase: true });
  finalData = R.assoc(`${entityType.replace('-', '_')}_ref`, data.to.standard_id, finalData);
  return finalData;
};

export const onlyStableStixIds = (ids = []) => R.filter((n) => uuidVersion(R.split('--', n)[1]) !== 1, ids);

export const cleanStixIds = (ids, maxStixIds = MAX_TRANSIENT_STIX_IDS) => {
  const keptIds = [];
  const transientIds = [];
  const wIds = Array.isArray(ids) ? ids : [ids];
  for (let index = 0; index < wIds.length; index += 1) {
    const stixId = wIds[index];
    const segments = stixId.split('--');
    const [, uuid] = segments;
    const isTransient = uuidVersion(uuid) === 1;
    if (isTransient) {
      const timestamp = uuidTime.v1(uuid);
      transientIds.push({ id: stixId, uuid, timestamp });
    } else {
      keptIds.push({ id: stixId, uuid });
    }
  }
  const orderedTransient = R.sort((a, b) => b.timestamp - a.timestamp, transientIds);
  const keptTimedIds = orderedTransient.length > maxStixIds ? orderedTransient.slice(0, maxStixIds) : orderedTransient;
  // Return the new list
  return R.map((s) => s.id, [...keptIds, ...keptTimedIds]);
};

export const stixCoreRelationshipsMapping = {
  [`${ENTITY_IPV4_ADDR}_${ENTITY_TYPE_LOCATION_CITY}`]: [RELATION_LOCATED_AT],
  [`${ENTITY_IPV4_ADDR}_${ENTITY_TYPE_LOCATION_COUNTRY}`]: [RELATION_LOCATED_AT],
  [`${ENTITY_IPV4_ADDR}_${ENTITY_TYPE_LOCATION_POSITION}`]: [RELATION_LOCATED_AT],
  [`${ENTITY_IPV4_ADDR}_${ENTITY_TYPE_LOCATION_REGION}`]: [RELATION_LOCATED_AT],
  [`${ENTITY_IPV6_ADDR}_${ENTITY_TYPE_LOCATION_CITY}`]: [RELATION_LOCATED_AT],
  [`${ENTITY_IPV6_ADDR}_${ENTITY_TYPE_LOCATION_COUNTRY}`]: [RELATION_LOCATED_AT],
  [`${ENTITY_IPV6_ADDR}_${ENTITY_TYPE_LOCATION_POSITION}`]: [RELATION_LOCATED_AT],
  [`${ENTITY_IPV6_ADDR}_${ENTITY_TYPE_LOCATION_REGION}`]: [RELATION_LOCATED_AT],
  [`${ENTITY_TYPE_ATTACK_PATTERN}_${ENTITY_TYPE_ATTACK_PATTERN}`]: [RELATION_SUBTECHNIQUE_OF],
  [`${ENTITY_TYPE_ATTACK_PATTERN}_${ENTITY_TYPE_IDENTITY_INDIVIDUAL}`]: [RELATION_TARGETS],
  [`${ENTITY_TYPE_ATTACK_PATTERN}_${ENTITY_TYPE_IDENTITY_ORGANIZATION}`]: [RELATION_TARGETS],
  [`${ENTITY_TYPE_ATTACK_PATTERN}_${ENTITY_TYPE_IDENTITY_SECTOR}`]: [RELATION_TARGETS],
  [`${ENTITY_TYPE_ATTACK_PATTERN}_${ENTITY_TYPE_LOCATION_CITY}`]: [RELATION_TARGETS],
  [`${ENTITY_TYPE_ATTACK_PATTERN}_${ENTITY_TYPE_LOCATION_COUNTRY}`]: [RELATION_TARGETS],
  [`${ENTITY_TYPE_ATTACK_PATTERN}_${ENTITY_TYPE_LOCATION_POSITION}`]: [RELATION_TARGETS],
  [`${ENTITY_TYPE_ATTACK_PATTERN}_${ENTITY_TYPE_LOCATION_REGION}`]: [RELATION_TARGETS],
  [`${ENTITY_TYPE_ATTACK_PATTERN}_${ENTITY_TYPE_MALWARE}`]: [RELATION_DELIVERS, RELATION_USES],
  [`${ENTITY_TYPE_ATTACK_PATTERN}_${ENTITY_TYPE_TOOL}`]: [RELATION_USES],
  [`${ENTITY_TYPE_ATTACK_PATTERN}_${ENTITY_TYPE_VULNERABILITY}`]: [RELATION_TARGETS],
  [`${ENTITY_TYPE_CAMPAIGN}_${ENTITY_TYPE_ATTACK_PATTERN}`]: [RELATION_USES],
  [`${ENTITY_TYPE_CAMPAIGN}_${ENTITY_TYPE_IDENTITY_INDIVIDUAL}`]: [RELATION_TARGETS],
  [`${ENTITY_TYPE_CAMPAIGN}_${ENTITY_TYPE_IDENTITY_ORGANIZATION}`]: [RELATION_TARGETS],
  [`${ENTITY_TYPE_CAMPAIGN}_${ENTITY_TYPE_IDENTITY_SECTOR}`]: [RELATION_TARGETS],
  [`${ENTITY_TYPE_CAMPAIGN}_${ENTITY_TYPE_IDENTITY_SYSTEM}`]: [RELATION_TARGETS],
  [`${ENTITY_TYPE_CAMPAIGN}_${ENTITY_TYPE_INFRASTRUCTURE}`]: [RELATION_COMPROMISES, RELATION_USES],
  [`${ENTITY_TYPE_CAMPAIGN}_${ENTITY_TYPE_INTRUSION_SET}`]: [RELATION_ATTRIBUTED_TO],
  [`${ENTITY_TYPE_CAMPAIGN}_${ENTITY_TYPE_LOCATION_CITY}`]: [RELATION_ORIGINATES_FROM, RELATION_TARGETS],
  [`${ENTITY_TYPE_CAMPAIGN}_${ENTITY_TYPE_LOCATION_COUNTRY}`]: [RELATION_ORIGINATES_FROM, RELATION_TARGETS],
  [`${ENTITY_TYPE_CAMPAIGN}_${ENTITY_TYPE_LOCATION_POSITION}`]: [RELATION_ORIGINATES_FROM, RELATION_TARGETS],
  [`${ENTITY_TYPE_CAMPAIGN}_${ENTITY_TYPE_LOCATION_REGION}`]: [RELATION_ORIGINATES_FROM, RELATION_TARGETS],
  [`${ENTITY_TYPE_CAMPAIGN}_${ENTITY_TYPE_MALWARE}`]: [RELATION_USES],
  [`${ENTITY_TYPE_CAMPAIGN}_${ENTITY_TYPE_THREAT_ACTOR}`]: [RELATION_ATTRIBUTED_TO],
  [`${ENTITY_TYPE_CAMPAIGN}_${ENTITY_TYPE_TOOL}`]: [RELATION_USES],
  [`${ENTITY_TYPE_CAMPAIGN}_${ENTITY_TYPE_VULNERABILITY}`]: [RELATION_TARGETS],
  [`${ENTITY_TYPE_COURSE_OF_ACTION}_${ENTITY_TYPE_ATTACK_PATTERN}`]: [RELATION_MITIGATES],
  [`${ENTITY_TYPE_COURSE_OF_ACTION}_${ENTITY_TYPE_INDICATOR}`]: [RELATION_INVESTIGATES, RELATION_MITIGATES],
  [`${ENTITY_TYPE_COURSE_OF_ACTION}_${ENTITY_TYPE_MALWARE}`]: [RELATION_MITIGATES, RELATION_REMEDIATES],
  [`${ENTITY_TYPE_COURSE_OF_ACTION}_${ENTITY_TYPE_TOOL}`]: [RELATION_MITIGATES],
  [`${ENTITY_TYPE_COURSE_OF_ACTION}_${ENTITY_TYPE_VULNERABILITY}`]: [RELATION_MITIGATES, RELATION_REMEDIATES],
  [`${ENTITY_TYPE_IDENTITY_INDIVIDUAL}_${ENTITY_TYPE_IDENTITY_INDIVIDUAL}`]: [RELATION_PART_OF],
  [`${ENTITY_TYPE_IDENTITY_INDIVIDUAL}_${ENTITY_TYPE_IDENTITY_ORGANIZATION}`]: [RELATION_PART_OF],
  [`${ENTITY_TYPE_IDENTITY_INDIVIDUAL}_${ENTITY_TYPE_LOCATION_CITY}`]: [RELATION_LOCATED_AT],
  [`${ENTITY_TYPE_IDENTITY_INDIVIDUAL}_${ENTITY_TYPE_LOCATION_COUNTRY}`]: [RELATION_LOCATED_AT],
  [`${ENTITY_TYPE_IDENTITY_INDIVIDUAL}_${ENTITY_TYPE_LOCATION_POSITION}`]: [RELATION_LOCATED_AT],
  [`${ENTITY_TYPE_IDENTITY_INDIVIDUAL}_${ENTITY_TYPE_LOCATION_REGION}`]: [RELATION_LOCATED_AT],
  [`${ENTITY_TYPE_IDENTITY_ORGANIZATION}_${ENTITY_TYPE_IDENTITY_ORGANIZATION}`]: [RELATION_PART_OF],
  [`${ENTITY_TYPE_IDENTITY_ORGANIZATION}_${ENTITY_TYPE_IDENTITY_SECTOR}`]: [RELATION_PART_OF],
  [`${ENTITY_TYPE_IDENTITY_ORGANIZATION}_${ENTITY_TYPE_LOCATION_CITY}`]: [RELATION_LOCATED_AT],
  [`${ENTITY_TYPE_IDENTITY_ORGANIZATION}_${ENTITY_TYPE_LOCATION_COUNTRY}`]: [RELATION_LOCATED_AT],
  [`${ENTITY_TYPE_IDENTITY_ORGANIZATION}_${ENTITY_TYPE_LOCATION_POSITION}`]: [RELATION_LOCATED_AT],
  [`${ENTITY_TYPE_IDENTITY_ORGANIZATION}_${ENTITY_TYPE_LOCATION_REGION}`]: [RELATION_LOCATED_AT],
  [`${ENTITY_TYPE_IDENTITY_SECTOR}_${ENTITY_TYPE_IDENTITY_SECTOR}`]: [RELATION_PART_OF],
  [`${ENTITY_TYPE_IDENTITY_SECTOR}_${ENTITY_TYPE_LOCATION_CITY}`]: [RELATION_LOCATED_AT],
  [`${ENTITY_TYPE_IDENTITY_SECTOR}_${ENTITY_TYPE_LOCATION_COUNTRY}`]: [RELATION_LOCATED_AT],
  [`${ENTITY_TYPE_IDENTITY_SECTOR}_${ENTITY_TYPE_LOCATION_POSITION}`]: [RELATION_LOCATED_AT],
  [`${ENTITY_TYPE_IDENTITY_SECTOR}_${ENTITY_TYPE_LOCATION_REGION}`]: [RELATION_LOCATED_AT],
  [`${ENTITY_TYPE_IDENTITY_SYSTEM}_${ENTITY_TYPE_IDENTITY_ORGANIZATION}`]: [RELATION_BELONGS_TO],
  [`${ENTITY_TYPE_IDENTITY_SYSTEM}_${ENTITY_TYPE_LOCATION_REGION}`]: [RELATION_LOCATED_AT],
  [`${ENTITY_TYPE_INCIDENT}_${ENTITY_TYPE_ATTACK_PATTERN}`]: [RELATION_USES],
  [`${ENTITY_TYPE_INCIDENT}_${ENTITY_TYPE_CAMPAIGN}`]: [RELATION_ATTRIBUTED_TO],
  [`${ENTITY_TYPE_INCIDENT}_${ENTITY_TYPE_IDENTITY_INDIVIDUAL}`]: [RELATION_TARGETS],
  [`${ENTITY_TYPE_INCIDENT}_${ENTITY_TYPE_IDENTITY_ORGANIZATION}`]: [RELATION_TARGETS],
  [`${ENTITY_TYPE_INCIDENT}_${ENTITY_TYPE_IDENTITY_SECTOR}`]: [RELATION_TARGETS],
  [`${ENTITY_TYPE_INCIDENT}_${ENTITY_TYPE_IDENTITY_SYSTEM}`]: [RELATION_TARGETS],
  [`${ENTITY_TYPE_INCIDENT}_${ENTITY_TYPE_INFRASTRUCTURE}`]: [RELATION_COMPROMISES, RELATION_USES],
  [`${ENTITY_TYPE_INCIDENT}_${ENTITY_TYPE_INTRUSION_SET}`]: [RELATION_ATTRIBUTED_TO],
  [`${ENTITY_TYPE_INCIDENT}_${ENTITY_TYPE_LOCATION_CITY}`]: [RELATION_ORIGINATES_FROM, RELATION_TARGETS],
  [`${ENTITY_TYPE_INCIDENT}_${ENTITY_TYPE_LOCATION_COUNTRY}`]: [RELATION_ORIGINATES_FROM, RELATION_TARGETS],
  [`${ENTITY_TYPE_INCIDENT}_${ENTITY_TYPE_LOCATION_POSITION}`]: [RELATION_ORIGINATES_FROM, RELATION_TARGETS],
  [`${ENTITY_TYPE_INCIDENT}_${ENTITY_TYPE_LOCATION_REGION}`]: [RELATION_ORIGINATES_FROM, RELATION_TARGETS],
  [`${ENTITY_TYPE_INCIDENT}_${ENTITY_TYPE_MALWARE}`]: [RELATION_USES],
  [`${ENTITY_TYPE_INCIDENT}_${ENTITY_TYPE_THREAT_ACTOR}`]: [RELATION_ATTRIBUTED_TO],
  [`${ENTITY_TYPE_INCIDENT}_${ENTITY_TYPE_TOOL}`]: [RELATION_USES],
  [`${ENTITY_TYPE_INCIDENT}_${ENTITY_TYPE_VULNERABILITY}`]: [RELATION_TARGETS],
  [`${ENTITY_TYPE_INDICATOR}_${ENTITY_HASHED_OBSERVABLE_ARTIFACT}`]: [RELATION_BASED_ON],
  [`${ENTITY_TYPE_INDICATOR}_${ABSTRACT_STIX_CYBER_OBSERVABLE}`]: [RELATION_BASED_ON],
  [`${ENTITY_TYPE_INDICATOR}_${ENTITY_TYPE_ATTACK_PATTERN}`]: [RELATION_INDICATES],
  [`${ENTITY_TYPE_INDICATOR}_${ENTITY_TYPE_CAMPAIGN}`]: [RELATION_INDICATES],
  [`${ENTITY_TYPE_INDICATOR}_${ENTITY_TYPE_CONTAINER_OBSERVED_DATA}`]: [RELATION_BASED_ON],
  [`${ENTITY_TYPE_INDICATOR}_${ENTITY_TYPE_INCIDENT}`]: [RELATION_INDICATES],
  [`${ENTITY_TYPE_INDICATOR}_${ENTITY_TYPE_INDICATOR}`]: [RELATION_DERIVED_FROM],
  [`${ENTITY_TYPE_INDICATOR}_${ENTITY_TYPE_INFRASTRUCTURE}`]: [RELATION_INDICATES],
  [`${ENTITY_TYPE_INDICATOR}_${ENTITY_TYPE_INTRUSION_SET}`]: [RELATION_INDICATES],
  [`${ENTITY_TYPE_INDICATOR}_${ENTITY_TYPE_MALWARE}`]: [RELATION_INDICATES],
  [`${ENTITY_TYPE_INDICATOR}_${ENTITY_TYPE_THREAT_ACTOR}`]: [RELATION_INDICATES],
  [`${ENTITY_TYPE_INDICATOR}_${ENTITY_TYPE_TOOL}`]: [RELATION_INDICATES],
  [`${ENTITY_TYPE_INDICATOR}_${ENTITY_TYPE_VULNERABILITY}`]: [RELATION_INDICATES],
  [`${ENTITY_TYPE_INFRASTRUCTURE}_${ENTITY_HASHED_OBSERVABLE_ARTIFACT}`]: [RELATION_CONSISTS_OF],
  [`${ENTITY_TYPE_INFRASTRUCTURE}_${ABSTRACT_STIX_CYBER_OBSERVABLE}`]: [RELATION_CONSISTS_OF],
  [`${ENTITY_TYPE_INFRASTRUCTURE}_${ENTITY_DOMAIN_NAME}`]: [RELATION_COMMUNICATES_WITH],
  [`${ENTITY_TYPE_INFRASTRUCTURE}_${ENTITY_IPV4_ADDR}`]: [RELATION_COMMUNICATES_WITH],
  [`${ENTITY_TYPE_INFRASTRUCTURE}_${ENTITY_IPV6_ADDR}`]: [RELATION_COMMUNICATES_WITH],
  [`${ENTITY_TYPE_INFRASTRUCTURE}_${ENTITY_TYPE_CONTAINER_OBSERVED_DATA}`]: [RELATION_CONSISTS_OF],
  [`${ENTITY_TYPE_INFRASTRUCTURE}_${ENTITY_TYPE_INFRASTRUCTURE}`]: [
    RELATION_COMMUNICATES_WITH,
    RELATION_CONSISTS_OF,
    RELATION_CONTROLS,
    RELATION_USES,
  ],
  [`${ENTITY_TYPE_INFRASTRUCTURE}_${ENTITY_TYPE_LOCATION_CITY}`]: [RELATION_LOCATED_AT],
  [`${ENTITY_TYPE_INFRASTRUCTURE}_${ENTITY_TYPE_LOCATION_COUNTRY}`]: [RELATION_LOCATED_AT],
  [`${ENTITY_TYPE_INFRASTRUCTURE}_${ENTITY_TYPE_LOCATION_POSITION}`]: [RELATION_LOCATED_AT],
  [`${ENTITY_TYPE_INFRASTRUCTURE}_${ENTITY_TYPE_LOCATION_REGION}`]: [RELATION_LOCATED_AT],
  [`${ENTITY_TYPE_INFRASTRUCTURE}_${ENTITY_TYPE_MALWARE}`]: [RELATION_CONTROLS, RELATION_DELIVERS, RELATION_HOSTS],
  [`${ENTITY_TYPE_INFRASTRUCTURE}_${ENTITY_TYPE_TOOL}`]: [RELATION_HOSTS],
  [`${ENTITY_TYPE_INFRASTRUCTURE}_${ENTITY_TYPE_VULNERABILITY}`]: [RELATION_HAS],
  [`${ENTITY_TYPE_INFRASTRUCTURE}_${ENTITY_URL}`]: [RELATION_COMMUNICATES_WITH],
  [`${ENTITY_TYPE_INTRUSION_SET}_${ENTITY_TYPE_ATTACK_PATTERN}`]: [RELATION_USES],
  [`${ENTITY_TYPE_INTRUSION_SET}_${ENTITY_TYPE_IDENTITY_INDIVIDUAL}`]: [RELATION_TARGETS],
  [`${ENTITY_TYPE_INTRUSION_SET}_${ENTITY_TYPE_IDENTITY_ORGANIZATION}`]: [RELATION_TARGETS],
  [`${ENTITY_TYPE_INTRUSION_SET}_${ENTITY_TYPE_IDENTITY_SECTOR}`]: [RELATION_TARGETS],
  [`${ENTITY_TYPE_INTRUSION_SET}_${ENTITY_TYPE_IDENTITY_SYSTEM}`]: [RELATION_TARGETS],
  [`${ENTITY_TYPE_INTRUSION_SET}_${ENTITY_TYPE_INFRASTRUCTURE}`]: [
    RELATION_COMPROMISES,
    RELATION_HOSTS,
    RELATION_OWNS,
    RELATION_USES,
  ],
  [`${ENTITY_TYPE_INTRUSION_SET}_${ENTITY_TYPE_LOCATION_CITY}`]: [RELATION_ORIGINATES_FROM, RELATION_TARGETS],
  [`${ENTITY_TYPE_INTRUSION_SET}_${ENTITY_TYPE_LOCATION_COUNTRY}`]: [RELATION_ORIGINATES_FROM, RELATION_TARGETS],
  [`${ENTITY_TYPE_INTRUSION_SET}_${ENTITY_TYPE_LOCATION_POSITION}`]: [RELATION_ORIGINATES_FROM, RELATION_TARGETS],
  [`${ENTITY_TYPE_INTRUSION_SET}_${ENTITY_TYPE_LOCATION_REGION}`]: [RELATION_ORIGINATES_FROM, RELATION_TARGETS],
  [`${ENTITY_TYPE_INTRUSION_SET}_${ENTITY_TYPE_MALWARE}`]: [RELATION_USES],
  [`${ENTITY_TYPE_INTRUSION_SET}_${ENTITY_TYPE_THREAT_ACTOR}`]: [RELATION_ATTRIBUTED_TO],
  [`${ENTITY_TYPE_INTRUSION_SET}_${ENTITY_TYPE_TOOL}`]: [RELATION_USES],
  [`${ENTITY_TYPE_INTRUSION_SET}_${ENTITY_TYPE_VULNERABILITY}`]: [RELATION_TARGETS],
  [`${ENTITY_TYPE_LOCATION_CITY}_${ENTITY_TYPE_LOCATION_COUNTRY}`]: [RELATION_LOCATED_AT],
  [`${ENTITY_TYPE_LOCATION_CITY}_${ENTITY_TYPE_LOCATION_REGION}`]: [RELATION_LOCATED_AT],
  [`${ENTITY_TYPE_LOCATION_COUNTRY}_${ENTITY_TYPE_LOCATION_REGION}`]: [RELATION_LOCATED_AT],
  [`${ENTITY_TYPE_LOCATION_POSITION}_${ENTITY_TYPE_LOCATION_CITY}`]: [RELATION_LOCATED_AT],
  [`${ENTITY_TYPE_LOCATION_REGION}_${ENTITY_TYPE_LOCATION_REGION}`]: [RELATION_LOCATED_AT],
  [`${ENTITY_TYPE_MALWARE}_${ENTITY_DOMAIN_NAME}`]: [RELATION_COMMUNICATES_WITH],
  [`${ENTITY_TYPE_MALWARE}_${ENTITY_HASHED_OBSERVABLE_STIX_FILE}`]: [
    RELATION_DOWNLOADS,
    RELATION_DROPS,
  ],
  [`${ENTITY_TYPE_MALWARE}_${ENTITY_IPV4_ADDR}`]: [RELATION_COMMUNICATES_WITH],
  [`${ENTITY_TYPE_MALWARE}_${ENTITY_IPV6_ADDR}`]: [RELATION_COMMUNICATES_WITH],
  [`${ENTITY_TYPE_MALWARE}_${ENTITY_TYPE_ATTACK_PATTERN}`]: [RELATION_USES],
  [`${ENTITY_TYPE_MALWARE}_${ENTITY_TYPE_ATTACK_PATTERN}`]: [RELATION_USES],
  [`${ENTITY_TYPE_MALWARE}_${ENTITY_TYPE_IDENTITY_INDIVIDUAL}`]: [RELATION_TARGETS],
  [`${ENTITY_TYPE_MALWARE}_${ENTITY_TYPE_IDENTITY_ORGANIZATION}`]: [RELATION_TARGETS],
  [`${ENTITY_TYPE_MALWARE}_${ENTITY_TYPE_IDENTITY_SECTOR}`]: [RELATION_TARGETS],
  [`${ENTITY_TYPE_MALWARE}_${ENTITY_TYPE_IDENTITY_SYSTEM}`]: [RELATION_TARGETS],
  [`${ENTITY_TYPE_MALWARE}_${ENTITY_TYPE_INFRASTRUCTURE}`]: [
    RELATION_BEACONS_TO,
    RELATION_EXFILTRATES_TO,
    RELATION_TARGETS,
    RELATION_USES,
  ],
  [`${ENTITY_TYPE_MALWARE}_${ENTITY_TYPE_INTRUSION_SET}`]: [RELATION_AUTHORED_BY],
  [`${ENTITY_TYPE_MALWARE}_${ENTITY_TYPE_LOCATION_CITY}`]: [RELATION_ORIGINATES_FROM, RELATION_TARGETS],
  [`${ENTITY_TYPE_MALWARE}_${ENTITY_TYPE_LOCATION_COUNTRY}`]: [RELATION_ORIGINATES_FROM, RELATION_TARGETS],
  [`${ENTITY_TYPE_MALWARE}_${ENTITY_TYPE_LOCATION_POSITION}`]: [RELATION_ORIGINATES_FROM, RELATION_TARGETS],
  [`${ENTITY_TYPE_MALWARE}_${ENTITY_TYPE_LOCATION_REGION}`]: [RELATION_ORIGINATES_FROM, RELATION_TARGETS],
  [`${ENTITY_TYPE_MALWARE}_${ENTITY_TYPE_MALWARE}`]: [
    RELATION_CONTROLS,
    RELATION_DOWNLOADS,
    RELATION_DROPS,
    RELATION_USES,
    RELATION_VARIANT_OF,
  ],
  [`${ENTITY_TYPE_MALWARE}_${ENTITY_TYPE_THREAT_ACTOR}`]: [RELATION_AUTHORED_BY],
  [`${ENTITY_TYPE_MALWARE}_${ENTITY_TYPE_TOOL}`]: [RELATION_DOWNLOADS, RELATION_DROPS, RELATION_USES],
  [`${ENTITY_TYPE_MALWARE}_${ENTITY_TYPE_VULNERABILITY}`]: [RELATION_EXPLOITS, RELATION_TARGETS],
  [`${ENTITY_TYPE_MALWARE}_${ENTITY_URL}`]: [RELATION_COMMUNICATES_WITH],
  [`${ENTITY_TYPE_THREAT_ACTOR}_${ENTITY_TYPE_ATTACK_PATTERN}`]: [RELATION_USES],
  [`${ENTITY_TYPE_THREAT_ACTOR}_${ENTITY_TYPE_IDENTITY_INDIVIDUAL}`]: [
    RELATION_ATTRIBUTED_TO,
    RELATION_IMPERSONATES,
    RELATION_TARGETS,
  ],
  [`${ENTITY_TYPE_THREAT_ACTOR}_${ENTITY_TYPE_IDENTITY_ORGANIZATION}`]: [
    RELATION_ATTRIBUTED_TO,
    RELATION_IMPERSONATES,
    RELATION_TARGETS,
  ],
  [`${ENTITY_TYPE_THREAT_ACTOR}_${ENTITY_TYPE_IDENTITY_SECTOR}`]: [RELATION_TARGETS],
  [`${ENTITY_TYPE_THREAT_ACTOR}_${ENTITY_TYPE_INFRASTRUCTURE}`]: [
    RELATION_COMPROMISES,
    RELATION_HOSTS,
    RELATION_OWNS,
    RELATION_USES,
  ],
  [`${ENTITY_TYPE_THREAT_ACTOR}_${ENTITY_TYPE_LOCATION_CITY}`]: [RELATION_LOCATED_AT, RELATION_TARGETS],
  [`${ENTITY_TYPE_THREAT_ACTOR}_${ENTITY_TYPE_LOCATION_COUNTRY}`]: [RELATION_LOCATED_AT, RELATION_TARGETS],
  [`${ENTITY_TYPE_THREAT_ACTOR}_${ENTITY_TYPE_LOCATION_POSITION}`]: [RELATION_LOCATED_AT, RELATION_TARGETS],
  [`${ENTITY_TYPE_THREAT_ACTOR}_${ENTITY_TYPE_LOCATION_REGION}`]: [RELATION_LOCATED_AT, RELATION_TARGETS],
  [`${ENTITY_TYPE_THREAT_ACTOR}_${ENTITY_TYPE_MALWARE}`]: [RELATION_USES],
  [`${ENTITY_TYPE_THREAT_ACTOR}_${ENTITY_TYPE_THREAT_ACTOR}`]: [RELATION_PART_OF],
  [`${ENTITY_TYPE_THREAT_ACTOR}_${ENTITY_TYPE_TOOL}`]: [RELATION_USES],
  [`${ENTITY_TYPE_THREAT_ACTOR}_${ENTITY_TYPE_VULNERABILITY}`]: [RELATION_TARGETS],
  [`${ENTITY_TYPE_TOOL}_${ENTITY_TYPE_IDENTITY_INDIVIDUAL}`]: [RELATION_TARGETS],
  [`${ENTITY_TYPE_TOOL}_${ENTITY_TYPE_IDENTITY_ORGANIZATION}`]: [RELATION_TARGETS],
  [`${ENTITY_TYPE_TOOL}_${ENTITY_TYPE_IDENTITY_SECTOR}`]: [RELATION_TARGETS],
  [`${ENTITY_TYPE_TOOL}_${ENTITY_TYPE_ATTACK_PATTERN}`]: [RELATION_USES, RELATION_DELIVERS, RELATION_DROPS],
  [`${ENTITY_TYPE_TOOL}_${ENTITY_TYPE_INFRASTRUCTURE}`]: [RELATION_TARGETS, RELATION_USES],
  [`${ENTITY_TYPE_TOOL}_${ENTITY_TYPE_LOCATION_CITY}`]: [RELATION_TARGETS],
  [`${ENTITY_TYPE_TOOL}_${ENTITY_TYPE_LOCATION_COUNTRY}`]: [RELATION_TARGETS],
  [`${ENTITY_TYPE_TOOL}_${ENTITY_TYPE_LOCATION_POSITION}`]: [RELATION_TARGETS],
  [`${ENTITY_TYPE_TOOL}_${ENTITY_TYPE_LOCATION_REGION}`]: [RELATION_TARGETS],
  [`${ENTITY_TYPE_TOOL}_${ENTITY_TYPE_MALWARE}`]: [RELATION_DELIVERS, RELATION_DROPS],
  [`${ENTITY_TYPE_TOOL}_${ENTITY_TYPE_VULNERABILITY}`]: [RELATION_HAS, RELATION_TARGETS],
  [`${ENTITY_X_OPENCTI_HOSTNAME}_${ENTITY_HASHED_OBSERVABLE_ARTIFACT}`]: [RELATION_DROPS],
  [`${ENTITY_X_OPENCTI_HOSTNAME}_${ENTITY_TYPE_ATTACK_PATTERN}`]: [RELATION_USES],
  [`${ENTITY_X_OPENCTI_HOSTNAME}_${ENTITY_DOMAIN_NAME}`]: [RELATION_COMMUNICATES_WITH],
  [`${ENTITY_X_OPENCTI_HOSTNAME}_${ENTITY_IPV4_ADDR}`]: [RELATION_COMMUNICATES_WITH],
  [`${ENTITY_X_OPENCTI_HOSTNAME}_${ENTITY_IPV6_ADDR}`]: [RELATION_COMMUNICATES_WITH],
  [`${ENTITY_X_OPENCTI_HOSTNAME}_${ENTITY_HASHED_OBSERVABLE_STIX_FILE}`]: [RELATION_DROPS],
  // Observables / SDO Stix Core Relationships
  [`${ENTITY_IPV4_ADDR}_${ENTITY_MAC_ADDR}`]: [RELATION_RESOLVES_TO],
  [`${ENTITY_IPV6_ADDR}_${ENTITY_MAC_ADDR}`]: [RELATION_RESOLVES_TO],
  [`${ENTITY_DOMAIN_NAME}_${ENTITY_DOMAIN_NAME}`]: [RELATION_RESOLVES_TO],
  [`${ENTITY_DOMAIN_NAME}_${ENTITY_IPV4_ADDR}`]: [RELATION_RESOLVES_TO],
  [`${ENTITY_DOMAIN_NAME}_${ENTITY_IPV6_ADDR}`]: [RELATION_RESOLVES_TO],
  [`${ENTITY_IPV4_ADDR}_${ENTITY_AUTONOMOUS_SYSTEM}`]: [RELATION_BELONGS_TO],
  [`${ENTITY_IPV6_ADDR}_${ENTITY_AUTONOMOUS_SYSTEM}`]: [RELATION_BELONGS_TO],
  // CUSTOM OPENCTI RELATIONSHIPS
  // DISCUSS IMPLEMENTATION!!
  [`${ENTITY_TYPE_INDICATOR}_${RELATION_USES}`]: [RELATION_INDICATES],
  [`${RELATION_TARGETS}_${ENTITY_TYPE_LOCATION_REGION}`]: [RELATION_LOCATED_AT],
  [`${RELATION_TARGETS}_${ENTITY_TYPE_LOCATION_COUNTRY}`]: [RELATION_LOCATED_AT],
  [`${RELATION_TARGETS}_${ENTITY_TYPE_LOCATION_CITY}`]: [RELATION_LOCATED_AT],
  [`${RELATION_TARGETS}_${ENTITY_TYPE_LOCATION_POSITION}`]: [RELATION_LOCATED_AT],
};

export const checkStixCoreRelationshipMapping = (fromType, toType, relationshipType) => {
  if (relationshipType === RELATION_RELATED_TO || relationshipType === RELATION_REVOKED_BY) {
    return true;
  }
  if (isStixCyberObservable(toType)) {
    if (
      R.includes(`${fromType}_${ABSTRACT_STIX_CYBER_OBSERVABLE}`, R.keys(stixCoreRelationshipsMapping))
      && R.includes(relationshipType, stixCoreRelationshipsMapping[`${fromType}_${ABSTRACT_STIX_CYBER_OBSERVABLE}`])
    ) {
      return true;
    }
  }
  if (isStixCyberObservable(fromType)) {
    if (
      R.includes(`${ABSTRACT_STIX_CYBER_OBSERVABLE}_${toType}`, R.keys(stixCoreRelationshipsMapping))
      && R.includes(relationshipType, stixCoreRelationshipsMapping[`${ABSTRACT_STIX_CYBER_OBSERVABLE}_${toType}`])
    ) {
      return true;
    }
  }
  return !!R.includes(relationshipType, stixCoreRelationshipsMapping[`${fromType}_${toType}`] || []);
};

export const stixCyberObservableRelationshipsMapping = {
  [`${ENTITY_DIRECTORY}_${ENTITY_DIRECTORY}`]: [RELATION_CONTAINS],
  [`${ENTITY_DIRECTORY}_${ENTITY_HASHED_OBSERVABLE_STIX_FILE}`]: [RELATION_CONTAINS],
  [`${ENTITY_DOMAIN_NAME}_${ENTITY_DOMAIN_NAME}`]: [OBS_RELATION_RESOLVES_TO],
  [`${ENTITY_DOMAIN_NAME}_${ENTITY_IPV4_ADDR}`]: [OBS_RELATION_RESOLVES_TO],
  [`${ENTITY_DOMAIN_NAME}_${ENTITY_IPV6_ADDR}`]: [OBS_RELATION_RESOLVES_TO],
  [`${ENTITY_DOMAIN_NAME}_${ENTITY_NETWORK_TRAFFIC}`]: [RELATION_SRC, RELATION_DST],
  [`${ENTITY_EMAIL_ADDR}_${ENTITY_EMAIL_MESSAGE}`]: [RELATION_FROM, RELATION_SENDER, RELATION_TO, RELATION_CC, RELATION_BCC],
  [`${ENTITY_EMAIL_ADDR}_${ENTITY_USER_ACCOUNT}`]: [OBS_RELATION_BELONGS_TO],
  [`${ENTITY_EMAIL_MIME_PART_TYPE}_${ENTITY_EMAIL_MESSAGE}`]: [RELATION_BODY_MULTIPART],
  [`${ENTITY_HASHED_OBSERVABLE_ARTIFACT}_${ENTITY_EMAIL_MESSAGE}`]: [RELATION_RAW_EMAIL],
  [`${ENTITY_HASHED_OBSERVABLE_ARTIFACT}_${ENTITY_EMAIL_MIME_PART_TYPE}`]: [RELATION_BODY_RAW],
  [`${ENTITY_HASHED_OBSERVABLE_ARTIFACT}_${ENTITY_HASHED_OBSERVABLE_STIX_FILE}`]: [OBS_RELATION_CONTENT],
  [`${ENTITY_HASHED_OBSERVABLE_ARTIFACT}_${ENTITY_NETWORK_TRAFFIC}`]: [RELATION_SRC_PAYLOAD, RELATION_DST_PAYLOAD],
  [`${ENTITY_HASHED_OBSERVABLE_ARTIFACT}_${ENTITY_TYPE_MALWARE}`]: [RELATION_SAMPLE],
  [`${ENTITY_HASHED_OBSERVABLE_STIX_FILE}_${ABSTRACT_STIX_CYBER_OBSERVABLE}`]: [RELATION_CONTAINS],
  [`${ENTITY_HASHED_OBSERVABLE_STIX_FILE}_${ENTITY_DIRECTORY}`]: [RELATION_PARENT_DIRECTORY],
  [`${ENTITY_HASHED_OBSERVABLE_STIX_FILE}_${ENTITY_EMAIL_MIME_PART_TYPE}`]: [RELATION_BODY_RAW],
  [`${ENTITY_HASHED_OBSERVABLE_STIX_FILE}_${ENTITY_HASHED_OBSERVABLE_ARTIFACT}`]: [RELATION_CONTAINS],
  [`${ENTITY_HASHED_OBSERVABLE_STIX_FILE}_${ENTITY_PROCESS}`]: [RELATION_IMAGE],
  [`${ENTITY_HASHED_OBSERVABLE_STIX_FILE}_${ENTITY_TYPE_MALWARE}`]: [RELATION_SAMPLE],
  [`${ENTITY_IPV4_ADDR}_${ENTITY_AUTONOMOUS_SYSTEM}`]: [OBS_RELATION_BELONGS_TO],
  [`${ENTITY_IPV4_ADDR}_${ENTITY_MAC_ADDR}`]: [OBS_RELATION_RESOLVES_TO],
  [`${ENTITY_IPV4_ADDR}_${ENTITY_NETWORK_TRAFFIC}`]: [RELATION_SRC, RELATION_DST],
  [`${ENTITY_IPV6_ADDR}_${ENTITY_AUTONOMOUS_SYSTEM}`]: [OBS_RELATION_BELONGS_TO],
  [`${ENTITY_IPV6_ADDR}_${ENTITY_MAC_ADDR}`]: [OBS_RELATION_RESOLVES_TO],
  [`${ENTITY_IPV6_ADDR}_${ENTITY_NETWORK_TRAFFIC}`]: [RELATION_SRC, RELATION_DST],
  [`${ENTITY_MAC_ADDR}_${ENTITY_NETWORK_TRAFFIC}`]: [RELATION_SRC, RELATION_DST],
  [`${ENTITY_NETWORK_TRAFFIC}_${ENTITY_NETWORK_TRAFFIC}`]: [RELATION_ENCAPSULATES, RELATION_ENCAPSULATED_BY],
  [`${ENTITY_PROCESS}_${ENTITY_NETWORK_TRAFFIC}`]: [RELATION_OPENED_CONNECTION],
  [`${ENTITY_PROCESS}_${ENTITY_PROCESS}`]: [RELATION_PARENT, RELATION_CHILD],
  [`${ENTITY_SOFTWARE}_${ENTITY_TYPE_MALWARE}`]: [RELATION_OPERATING_SYSTEM],
  [`${ENTITY_TYPE_CONTAINER_OBSERVED_DATA}_${ENTITY_HASHED_OBSERVABLE_STIX_FILE}`]: [OBS_RELATION_CONTENT],
  [`${ENTITY_USER_ACCOUNT}_${ENTITY_PROCESS}`]: [RELATION_CREATOR_USER],
  [`${ENTITY_USER_ACCOUNT}_${ENTITY_WINDOWS_REGISTRY_KEY}`]: [RELATION_CREATOR_USER],
  [`${ENTITY_WINDOWS_REGISTRY_KEY}_${ENTITY_WINDOWS_REGISTRY_VALUE_TYPE}`]: [RELATION_VALUES],
  [`${ENTITY_X509_V3_EXTENSIONS_TYPE}_${ENTITY_HASHED_OBSERVABLE_X509_CERTIFICATE}`]: [RELATION_X509_V3_EXTENSIONS]
};

export const stixCyberObservableTypeFields = () => {
  const entries = Object.entries(stixCyberObservableRelationshipsMapping);
  const typeFields = {};
  for (let index = 0; index < entries.length; index += 1) {
    const [fromTo, fields] = entries[index];
    const [fromType] = fromTo.split('_');
    const inputFields = fields.map((f) => STIX_CYBER_OBSERVABLE_RELATION_TO_FIELD[f]);
    if (typeFields[fromType]) {
      typeFields[fromType].push(...inputFields);
    } else {
      typeFields[fromType] = inputFields;
    }
  }
  return typeFields;
};

export const checkStixCyberObservableRelationshipMapping = (fromType, toType, relationshipType) => {
  if (relationshipType === RELATION_LINKED || relationshipType === RELATION_LINKED) {
    return true;
  }
  return !!R.includes(relationshipType, stixCyberObservableRelationshipsMapping[`${fromType}_${toType}`] || []);
};
