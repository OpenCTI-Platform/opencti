import * as R from 'ramda';
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
  ENTITY_DOMAIN_NAME,
  ENTITY_HASHED_OBSERVABLE_STIX_FILE,
  ENTITY_IPV4_ADDR,
  ENTITY_IPV6_ADDR,
  ENTITY_URL,
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
  RELATION_BASED_ON,
  RELATION_BELONGS_TO,
  RELATION_COMMUNICATES_WITH,
  RELATION_COMPROMISES,
  RELATION_CONSISTS_OF,
  RELATION_CONTROLS,
  RELATION_DELIVERS,
  RELATION_DERIVED_FROM,
  RELATION_HAS,
  RELATION_HOSTS,
  RELATION_INDICATES,
  RELATION_INVESTIGATES,
  RELATION_LOCATED_AT,
  RELATION_MITIGATES,
  RELATION_ORIGINATES_FROM,
  RELATION_PART_OF,
  RELATION_RELATED_TO,
  RELATION_REMEDIATES,
  RELATION_REVOKED_BY,
  RELATION_SUBTECHNIQUE_OF,
  RELATION_TARGETS,
  RELATION_USES,
  RELATIONSHIP_CORE_REFS_TO_FIELDS,
} from '../schema/stixCoreRelationship';
import { isStixSightingRelationship, SIGHTING_RELATIONSHIP_REFS_TO_FIELDS } from '../schema/stixSightingRelationship';
import {
  isStixCyberObservableRelationship,
  RELATION_LINKED,
  STIX_ATTRIBUTE_TO_CYBER_OBSERVABLE_FIELD,
  STIX_CYBER_OBSERVABLE_FIELD_TO_STIX_ATTRIBUTE,
  STIX_CYBER_OBSERVABLE_RELATION_TO_FIELD,
  STIX_CYBER_OBSERVABLE_RELATIONSHIPS_INPUTS,
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
import { isEmptyField, isNotEmptyField, pascalize, UPDATE_OPERATION_REPLACE } from './utils';
import { isStixRelationShipExceptMeta } from '../schema/stixRelationship';
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

const BASIC_FIELDS = [
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
export const stixDataConverter = (data, args = {}) => {
  const { patchGeneration = false, clearEmptyValues = false } = args;
  let finalData = data;
  const isSighting = data.type === 'sighting';
  // region Relationships
  if (isDefinedValue(finalData.fromId)) {
    finalData = R.pipe(R.dissoc('fromId'), R.dissoc('fromRole'), R.dissoc('fromType'))(finalData);
    if (isSighting) {
      finalData = R.pipe(
        R.assoc(`x_opencti_sighting_of_ref`, data.fromId),
        R.assoc(`x_opencti_sighting_of_type`, data.fromType)
      )(finalData);
    } else {
      finalData = R.pipe(
        R.assoc(`x_opencti_source_ref`, data.fromId),
        R.assoc(`x_opencti_source_type`, data.fromType)
      )(finalData);
    }
  }
  if (isDefinedValue(finalData.from)) {
    finalData = R.pipe(R.dissoc('from'))(finalData);
    if (isSighting) {
      finalData = R.pipe(
        R.dissoc('source_ref'),
        R.assoc('sighting_of_ref', data.from.standard_id),
        R.assoc(`x_opencti_sighting_of_ref`, data.from.internal_id),
        R.assoc(`x_opencti_sighting_of_type`, data.from.entity_type)
      )(finalData);
    } else {
      finalData = R.pipe(
        R.assoc('source_ref', data.from.standard_id),
        R.assoc(`x_opencti_source_ref`, data.from.internal_id),
        R.assoc(`x_opencti_source_type`, data.from.entity_type)
      )(finalData);
    }
  }
  if (isDefinedValue(finalData.toId)) {
    finalData = R.pipe(R.dissoc('toId'), R.dissoc('toRole'), R.dissoc('toType'))(finalData);
    if (isSighting) {
      finalData = R.pipe(
        R.assoc(`x_opencti_where_sighted_refs`, [data.toId]),
        R.assoc(`x_opencti_where_sighted_types`, [data.toType])
      )(finalData);
    } else {
      finalData = R.pipe(
        R.assoc(`x_opencti_target_ref`, data.toId),
        R.assoc(`x_opencti_target_type`, data.toType)
      )(finalData);
    }
  }
  if (isDefinedValue(finalData.to)) {
    finalData = R.pipe(R.dissoc('to'))(finalData);
    if (isSighting) {
      finalData = R.pipe(
        R.dissoc('target_ref'),
        R.assoc('where_sighted_refs', [data.to.standard_id]),
        R.assoc(`x_opencti_where_sighted_refs`, [data.to.internal_id]),
        R.assoc(`x_opencti_where_sighted_types`, [data.to.entity_type])
      )(finalData);
    } else {
      finalData = R.pipe(
        R.assoc('target_ref', data.to.standard_id),
        R.assoc(`x_opencti_target_ref`, data.to.internal_id),
        R.assoc(`x_opencti_target_type`, data.to.entity_type)
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
      const value = { kill_chain_name: k.kill_chain_name, phase_name: k.phase_name };
      return patchGeneration
        ? { value: k.standard_id, reference: k.kill_chain_name, x_opencti_id: k.internal_id }
        : value;
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
      const value = R.pick(['source_name', 'description', 'url', 'hashes', 'external_id'], e);
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
          (m) =>
            patchGeneration
              ? { value: m.standard_id, reference: observableValue(m), x_opencti_id: m.internal_id }
              : m.standard_id,
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
    const isInternalKey = isInternal || key === 'x_opencti_graph_data'; // Specific case of graph
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
    filteredData.name = filteredData.definition;
    filteredData.definition_type = key;
    filteredData.definition = { [key]: filteredData.definition.replace(/^(tlp|TLP):/g, '') };
  }
  // endregion
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
  // eslint-disable-next-line prettier/prettier
  const formattedType = `${entityType
    .split('-')
    .map((e) => pascalize(e))
    .join('')}AddInput`;
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
    let translatedKey =
      RELATIONSHIP_CORE_REFS_TO_FIELDS[key] ||
      SIGHTING_RELATIONSHIP_REFS_TO_FIELDS[key] ||
      STIX_ATTRIBUTE_TO_META_RELATIONS_FIELD[key] ||
      STIX_ATTRIBUTE_TO_CYBER_OBSERVABLE_FIELD[key] ||
      CONTAINER_REFS_TO_FIELDS[key] ||
      key;
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
export const buildStixData = (data, args = {}) => {
  const { onlyBase = false } = args;
  const type = data.entity_type;
  // general
  const rawData = R.pipe(
    R.assoc('id', data.standard_id),
    R.assoc('x_opencti_id', data.internal_id),
    R.assoc('type', convertTypeToStixType(type)),
    R.assoc('x_opencti_type', type),
    R.dissoc('_index'),
    R.dissoc('standard_id'),
    R.dissoc('internal_id'),
    R.dissoc('parent_types'),
    R.dissoc('base_type'),
    R.dissoc('entity_type'),
    R.dissoc('update'),
    R.dissoc('connections'),
    R.dissoc('sort')
  )(data);
  const stixData = stixDataConverter(rawData, args);
  if (!isValidStix(stixData)) {
    throw FunctionalError('Invalid stix data conversion', { data: stixData });
  }
  if (onlyBase) {
    return R.pick(BASIC_FIELDS, stixData);
  }
  return stixData;
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
    const keyConvert = R.head(Object.keys(stixDataConverter({ [key]: value || previous }, opts)));
    // Sometime the key will be empty because the patch include a none stix modification
    if (isEmptyField(keyConvert)) {
      return {};
    }
    const converter = (val) => {
      const converted = stixDataConverter({ [key]: val }, opts);
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
  let finalData = buildStixData(data.from, { onlyBase: true });
  if (isStixInternalMetaRelationship(entityType)) {
    finalData = R.assoc(entityType.replace('-', '_'), [buildStixData(data.to)], finalData);
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
  let finalData = buildStixData(data.from, { onlyBase: true });
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
  [`${ENTITY_TYPE_ATTACK_PATTERN}_${ENTITY_TYPE_ATTACK_PATTERN}`]: [RELATION_SUBTECHNIQUE_OF],
  [`${ENTITY_TYPE_ATTACK_PATTERN}_${ENTITY_TYPE_MALWARE}`]: [RELATION_DELIVERS, RELATION_USES],
  [`${ENTITY_TYPE_ATTACK_PATTERN}_${ENTITY_TYPE_IDENTITY_SECTOR}`]: [RELATION_TARGETS],
  [`${ENTITY_TYPE_ATTACK_PATTERN}_${ENTITY_TYPE_IDENTITY_ORGANIZATION}`]: [RELATION_TARGETS],
  [`${ENTITY_TYPE_ATTACK_PATTERN}_${ENTITY_TYPE_IDENTITY_INDIVIDUAL}`]: [RELATION_TARGETS],
  [`${ENTITY_TYPE_ATTACK_PATTERN}_${ENTITY_TYPE_LOCATION_REGION}`]: [RELATION_TARGETS],
  [`${ENTITY_TYPE_ATTACK_PATTERN}_${ENTITY_TYPE_LOCATION_COUNTRY}`]: [RELATION_TARGETS],
  [`${ENTITY_TYPE_ATTACK_PATTERN}_${ENTITY_TYPE_LOCATION_CITY}`]: [RELATION_TARGETS],
  [`${ENTITY_TYPE_ATTACK_PATTERN}_${ENTITY_TYPE_LOCATION_POSITION}`]: [RELATION_TARGETS],
  [`${ENTITY_TYPE_ATTACK_PATTERN}_${ENTITY_TYPE_VULNERABILITY}`]: [RELATION_TARGETS],
  [`${ENTITY_TYPE_ATTACK_PATTERN}_${ENTITY_TYPE_TOOL}`]: [RELATION_USES],
  [`${ENTITY_TYPE_CAMPAIGN}_${ENTITY_TYPE_INTRUSION_SET}`]: [RELATION_ATTRIBUTED_TO],
  [`${ENTITY_TYPE_CAMPAIGN}_${ENTITY_TYPE_THREAT_ACTOR}`]: [RELATION_ATTRIBUTED_TO],
  [`${ENTITY_TYPE_CAMPAIGN}_${ENTITY_TYPE_INFRASTRUCTURE}`]: [RELATION_COMPROMISES, RELATION_USES],
  [`${ENTITY_TYPE_CAMPAIGN}_${ENTITY_TYPE_LOCATION_REGION}`]: [RELATION_ORIGINATES_FROM, RELATION_TARGETS],
  [`${ENTITY_TYPE_CAMPAIGN}_${ENTITY_TYPE_LOCATION_COUNTRY}`]: [RELATION_ORIGINATES_FROM, RELATION_TARGETS],
  [`${ENTITY_TYPE_CAMPAIGN}_${ENTITY_TYPE_LOCATION_CITY}`]: [RELATION_ORIGINATES_FROM, RELATION_TARGETS],
  [`${ENTITY_TYPE_CAMPAIGN}_${ENTITY_TYPE_LOCATION_POSITION}`]: [RELATION_ORIGINATES_FROM, RELATION_TARGETS],
  [`${ENTITY_TYPE_CAMPAIGN}_${ENTITY_TYPE_IDENTITY_SECTOR}`]: [RELATION_TARGETS],
  [`${ENTITY_TYPE_CAMPAIGN}_${ENTITY_TYPE_IDENTITY_ORGANIZATION}`]: [RELATION_TARGETS],
  [`${ENTITY_TYPE_CAMPAIGN}_${ENTITY_TYPE_IDENTITY_INDIVIDUAL}`]: [RELATION_TARGETS],
  [`${ENTITY_TYPE_CAMPAIGN}_${ENTITY_TYPE_IDENTITY_SYSTEM}`]: [RELATION_TARGETS],
  [`${ENTITY_TYPE_CAMPAIGN}_${ENTITY_TYPE_VULNERABILITY}`]: [RELATION_TARGETS],
  [`${ENTITY_TYPE_CAMPAIGN}_${ENTITY_TYPE_ATTACK_PATTERN}`]: [RELATION_USES],
  [`${ENTITY_TYPE_CAMPAIGN}_${ENTITY_TYPE_MALWARE}`]: [RELATION_USES],
  [`${ENTITY_TYPE_CAMPAIGN}_${ENTITY_TYPE_TOOL}`]: [RELATION_USES],
  [`${ENTITY_TYPE_COURSE_OF_ACTION}_${ENTITY_TYPE_INDICATOR}`]: [RELATION_INVESTIGATES, RELATION_MITIGATES],
  [`${ENTITY_TYPE_COURSE_OF_ACTION}_${ENTITY_TYPE_ATTACK_PATTERN}`]: [RELATION_MITIGATES],
  [`${ENTITY_TYPE_COURSE_OF_ACTION}_${ENTITY_TYPE_MALWARE}`]: [RELATION_MITIGATES, RELATION_REMEDIATES],
  [`${ENTITY_TYPE_COURSE_OF_ACTION}_${ENTITY_TYPE_TOOL}`]: [RELATION_MITIGATES],
  [`${ENTITY_TYPE_COURSE_OF_ACTION}_${ENTITY_TYPE_VULNERABILITY}`]: [RELATION_MITIGATES, RELATION_REMEDIATES],
  [`${ENTITY_TYPE_IDENTITY_SYSTEM}_${ENTITY_TYPE_LOCATION_REGION}`]: [RELATION_LOCATED_AT],
  [`${ENTITY_TYPE_IDENTITY_SYSTEM}_${ENTITY_TYPE_IDENTITY_ORGANIZATION}`]: [RELATION_BELONGS_TO],
  [`${ENTITY_TYPE_IDENTITY_SECTOR}_${ENTITY_TYPE_LOCATION_REGION}`]: [RELATION_LOCATED_AT],
  [`${ENTITY_TYPE_IDENTITY_SECTOR}_${ENTITY_TYPE_LOCATION_COUNTRY}`]: [RELATION_LOCATED_AT],
  [`${ENTITY_TYPE_IDENTITY_SECTOR}_${ENTITY_TYPE_LOCATION_CITY}`]: [RELATION_LOCATED_AT],
  [`${ENTITY_TYPE_IDENTITY_SECTOR}_${ENTITY_TYPE_LOCATION_POSITION}`]: [RELATION_LOCATED_AT],
  [`${ENTITY_TYPE_IDENTITY_SECTOR}_${ENTITY_TYPE_IDENTITY_SECTOR}`]: [RELATION_PART_OF],
  [`${ENTITY_TYPE_IDENTITY_ORGANIZATION}_${ENTITY_TYPE_IDENTITY_SECTOR}`]: [RELATION_PART_OF],
  [`${ENTITY_TYPE_IDENTITY_ORGANIZATION}_${ENTITY_TYPE_LOCATION_REGION}`]: [RELATION_LOCATED_AT],
  [`${ENTITY_TYPE_IDENTITY_ORGANIZATION}_${ENTITY_TYPE_LOCATION_COUNTRY}`]: [RELATION_LOCATED_AT],
  [`${ENTITY_TYPE_IDENTITY_ORGANIZATION}_${ENTITY_TYPE_LOCATION_CITY}`]: [RELATION_LOCATED_AT],
  [`${ENTITY_TYPE_IDENTITY_ORGANIZATION}_${ENTITY_TYPE_LOCATION_POSITION}`]: [RELATION_LOCATED_AT],
  [`${ENTITY_TYPE_IDENTITY_ORGANIZATION}_${ENTITY_TYPE_IDENTITY_ORGANIZATION}`]: [RELATION_PART_OF],
  [`${ENTITY_TYPE_IDENTITY_INDIVIDUAL}_${ENTITY_TYPE_IDENTITY_INDIVIDUAL}`]: [RELATION_PART_OF],
  [`${ENTITY_TYPE_IDENTITY_INDIVIDUAL}_${ENTITY_TYPE_IDENTITY_ORGANIZATION}`]: [RELATION_PART_OF],
  [`${ENTITY_TYPE_IDENTITY_INDIVIDUAL}_${ENTITY_TYPE_LOCATION_REGION}`]: [RELATION_LOCATED_AT],
  [`${ENTITY_TYPE_IDENTITY_INDIVIDUAL}_${ENTITY_TYPE_LOCATION_COUNTRY}`]: [RELATION_LOCATED_AT],
  [`${ENTITY_TYPE_IDENTITY_INDIVIDUAL}_${ENTITY_TYPE_LOCATION_CITY}`]: [RELATION_LOCATED_AT],
  [`${ENTITY_TYPE_IDENTITY_INDIVIDUAL}_${ENTITY_TYPE_LOCATION_POSITION}`]: [RELATION_LOCATED_AT],
  [`${ENTITY_TYPE_INDICATOR}_${ENTITY_TYPE_ATTACK_PATTERN}`]: [RELATION_INDICATES],
  [`${ENTITY_TYPE_INDICATOR}_${ENTITY_TYPE_CAMPAIGN}`]: [RELATION_INDICATES],
  [`${ENTITY_TYPE_INDICATOR}_${ENTITY_TYPE_INFRASTRUCTURE}`]: [RELATION_INDICATES],
  [`${ENTITY_TYPE_INDICATOR}_${ENTITY_TYPE_INTRUSION_SET}`]: [RELATION_INDICATES],
  [`${ENTITY_TYPE_INDICATOR}_${ENTITY_TYPE_MALWARE}`]: [RELATION_INDICATES],
  [`${ENTITY_TYPE_INDICATOR}_${ENTITY_TYPE_THREAT_ACTOR}`]: [RELATION_INDICATES],
  [`${ENTITY_TYPE_INDICATOR}_${ENTITY_TYPE_TOOL}`]: [RELATION_INDICATES],
  [`${ENTITY_TYPE_INDICATOR}_${ENTITY_TYPE_VULNERABILITY}`]: [RELATION_INDICATES],
  [`${ENTITY_TYPE_INDICATOR}_${ENTITY_TYPE_CONTAINER_OBSERVED_DATA}`]: [RELATION_BASED_ON],
  [`${ENTITY_TYPE_INDICATOR}_${ENTITY_TYPE_INDICATOR}`]: [RELATION_DERIVED_FROM],
  [`${ENTITY_TYPE_INDICATOR}_${ABSTRACT_STIX_CYBER_OBSERVABLE}`]: [RELATION_BASED_ON],
  [`${ENTITY_TYPE_INDICATOR}_${RELATION_USES}`]: [RELATION_INDICATES],
  [`${ENTITY_TYPE_INFRASTRUCTURE}_${ENTITY_TYPE_INFRASTRUCTURE}`]: [
    RELATION_COMMUNICATES_WITH,
    RELATION_CONSISTS_OF,
    RELATION_CONTROLS,
    RELATION_USES,
  ],
  [`${ENTITY_TYPE_INFRASTRUCTURE}_${ENTITY_IPV4_ADDR}`]: [RELATION_COMMUNICATES_WITH],
  [`${ENTITY_TYPE_INFRASTRUCTURE}_${ENTITY_IPV6_ADDR}`]: [RELATION_COMMUNICATES_WITH],
  [`${ENTITY_TYPE_INFRASTRUCTURE}_${ENTITY_DOMAIN_NAME}`]: [RELATION_COMMUNICATES_WITH],
  [`${ENTITY_TYPE_INFRASTRUCTURE}_${ENTITY_URL}`]: [RELATION_COMMUNICATES_WITH],
  [`${ENTITY_TYPE_INFRASTRUCTURE}_${ENTITY_TYPE_CONTAINER_OBSERVED_DATA}`]: [RELATION_CONSISTS_OF],
  [`${ENTITY_TYPE_INFRASTRUCTURE}_${ABSTRACT_STIX_CYBER_OBSERVABLE}`]: [RELATION_CONSISTS_OF, RELATION_BASED_ON],
  [`${ENTITY_TYPE_INFRASTRUCTURE}_${ENTITY_TYPE_MALWARE}`]: [RELATION_CONTROLS, RELATION_DELIVERS, RELATION_HOSTS],
  [`${ENTITY_TYPE_INFRASTRUCTURE}_${ENTITY_TYPE_VULNERABILITY}`]: [RELATION_HAS],
  [`${ENTITY_TYPE_INFRASTRUCTURE}_${ENTITY_TYPE_TOOL}`]: [RELATION_HOSTS],
  [`${ENTITY_TYPE_INFRASTRUCTURE}_${ENTITY_TYPE_LOCATION_REGION}`]: [RELATION_LOCATED_AT],
  Infrastructure_Country: ['located-at'],
  Infrastructure_City: ['located-at'],
  Infrastructure_Position: ['located-at'],
  'Intrusion-Set_Threat-Actor': ['attributed-to'],
  'Intrusion-Set_Infrastructure': ['compromises', 'hosts', 'owns', 'uses'],
  'Intrusion-Set_Region': ['originates-from', 'targets'],
  'Intrusion-Set_Country': ['originates-from', 'targets'],
  'Intrusion-Set_City': ['originates-from', 'targets'],
  'Intrusion-Set_Position': ['originates-from', 'targets'],
  'Intrusion-Set_Sector': ['targets'],
  'Intrusion-Set_Organization': ['targets'],
  'Intrusion-Set_Individual': ['targets'],
  'Intrusion-Set_System': ['targets'],
  'Intrusion-Set_Vulnerability': ['targets'],
  'Intrusion-Set_Attack-Pattern': ['uses'],
  'Intrusion-Set_Malware': ['uses'],
  'Intrusion-Set_Tool': ['uses'],
  'Malware_attack-pattern': ['uses'],
  'Malware_Threat-Actor': ['authored-by'],
  'Malware_Intrusion-Set': ['authored-by'],
  Malware_Infrastructure: ['beacons-to', 'exfiltrates-to', 'targets', 'uses'],
  'Malware_IPv4-Addr': ['communicates-with'],
  'Malware_IPv6-Addr': ['communicates-with'],
  'Malware_Domain-Name': ['communicates-with'],
  Malware_Url: ['communicates-with'],
  Malware_Malware: ['controls', 'downloads', 'drops', 'uses', 'variant-of'],
  Malware_Tool: ['downloads', 'drops', 'uses'],
  Malware_StixFile: ['downloads', 'drops'],
  Malware_Vulnerability: ['exploits', 'targets'],
  Malware_Region: ['originates-from', 'targets'],
  Malware_Country: ['originates-from', 'targets'],
  Malware_City: ['originates-from', 'targets'],
  Malware_Position: ['originates-from', 'targets'],
  Malware_Sector: ['targets'],
  Malware_Organization: ['targets'],
  Malware_Individual: ['targets'],
  Malware_System: ['targets'],
  'Malware_Attack-Pattern': ['uses'],
  'Threat-Actor_Organization': ['attributed-to', 'impersonates', 'targets'],
  'Threat-Actor_Individual': ['attributed-to', 'impersonates', 'targets'],
  'Threat-Actor_Sector': ['targets'],
  'Threat-Actor_Infrastructure': ['compromises', 'hosts', 'owns', 'uses'],
  'Threat-Actor_Region': ['located-at', 'targets'],
  'Threat-Actor_Country': ['located-at', 'targets'],
  'Threat-Actor_City': ['located-at', 'targets'],
  'Threat-Actor_Position': ['located-at', 'targets'],
  'Threat-Actor_Attack-Pattern': ['uses'],
  'Threat-Actor_Malware': ['uses'],
  'Threat-Actor_Threat-Actor': ['part-of'],
  'Threat-Actor_Tool': ['uses'],
  'Threat-Actor_Vulnerability': ['targets'],
  'Tool_Attack-Pattern': ['uses', 'drops', 'delivers'],
  Tool_Malware: ['delivers', 'drops'],
  Tool_Vulnerability: ['has', 'targets'],
  Tool_Sector: ['targets'],
  Tool_Organization: ['targets'],
  Tool_Individual: ['targets'],
  Tool_Infrastructure: ['targets', 'uses'],
  Tool_Region: ['targets'],
  Tool_Country: ['targets'],
  Tool_City: ['targets'],
  Tool_Position: ['targets'],
  'Incident_Intrusion-Set': ['attributed-to'],
  'Incident_Threat-Actor': ['attributed-to'],
  Incident_Campaign: ['attributed-to'],
  Incident_Infrastructure: ['compromises', 'uses'],
  Incident_Region: ['originates-from', 'targets'],
  Incident_Country: ['originates-from', 'targets'],
  Incident_City: ['originates-from', 'targets'],
  Incident_Position: ['originates-from', 'targets'],
  Incident_Sector: ['targets'],
  Incident_Organization: ['targets'],
  Incident_Individual: ['targets'],
  Incident_System: ['targets'],
  Incident_Vulnerability: ['targets'],
  'Incident_Attack-Pattern': ['uses'],
  Incident_Malware: ['uses'],
  Incident_Tool: ['uses'],
  Region_Region: ['located-at'],
  Country_Region: ['located-at'],
  City_Country: ['located-at'],
  City_Region: ['located-at'],
  Position_City: ['located-at'],
  'Domain-Name_IPv4-Addr': ['resolves-to'],
  'Domain-Name_IPv6-Addr': ['resolves-to'],
  'IPv4-Addr_Autonomous-System': ['belongs-to'],
  'IPv6-Addr_Autonomous-System': ['belongs-to'],
  'IPv4-Addr_Region': ['located-at'],
  'IPv4-Addr_Country': ['located-at'],
  'IPv4-Addr_City': ['located-at'],
  'IPv4-Addr_Position': ['located-at'],
  'IPv6-Addr_Region': ['located-at'],
  'IPv6-Addr_Country': ['located-at'],
  'IPv6-Addr_City': ['located-at'],
  'IPv6-Addr_Position': ['located-at'],
  'Artifact_IPv4-Addr': ['communicates-with'],
  'Artifact_IPv6-Addr': ['communicates-with'],
  'Artifact_Domain-Name': ['communicates-with'],
  'StixFile_IPv4-Addr': ['communicates-with'],
  'StixFile_IPv6-Addr': ['communicates-with'],
  'StixFile_Domain-Name': ['communicates-with'],
  'Url_IPv4-Addr': ['communicates-with'],
  'Url_IPv6-Addr': ['communicates-with'],
  'Url_Domain-Name': ['communicates-with'],
  'Domain-Name_Domain-Name': ['resolves-to'],
  'X-OpenCTI-Hostname_IPv4-Addr': ['communicates-with'],
  'X-OpenCTI-Hostname_IPv6-Addr': ['communicates-with'],
  'X-OpenCTI-Hostname_Domain-Name': ['communicates-with'],
  'Artifact_Attack-Pattern': ['uses'],
  'StixFile_Attack-Pattern': ['uses'],
  'Url_Attack-Pattern': ['uses'],
  'Domain-Name_Attack-Pattern': ['uses'],
  'X-OpenCTI-Hostname_Attack-Pattern': ['uses'],
  StixFile_StixFile: ['drops'],
  StixFile_Artifact: ['drops'],
  Artifact_StixFile: ['drops'],
  Artifact_Artifact: ['drops'],
  Url_StixFile: ['drops'],
  Url_Artifact: ['drops'],
  'X-OpenCTI-Hostname_StixFile': ['drops'],
  'X-OpenCTI-Hostname_Artifact': ['drops'],
  targets_Region: ['located-at'],
  targets_Country: ['located-at'],
  targets_City: ['located-at'],
  targets_Position: ['located-at'],
};

export const checkStixCoreRelationshipMapping = (fromType, toType, relationshipType) => {
  if (relationshipType === RELATION_RELATED_TO || relationshipType === RELATION_REVOKED_BY) {
    return true;
  }
  if (isStixCyberObservable(toType)) {
    if (
      R.includes(`${fromType}_${ABSTRACT_STIX_CYBER_OBSERVABLE}`, R.keys(stixCoreRelationshipsMapping)) &&
      R.includes(relationshipType, stixCoreRelationshipsMapping[`${fromType}_${ABSTRACT_STIX_CYBER_OBSERVABLE}`])
    ) {
      return true;
    }
  }
  if (isStixCyberObservable(fromType)) {
    if (
      R.includes(`${ABSTRACT_STIX_CYBER_OBSERVABLE}_${toType}`, R.keys(stixCoreRelationshipsMapping)) &&
      R.includes(relationshipType, stixCoreRelationshipsMapping[`${ABSTRACT_STIX_CYBER_OBSERVABLE}_${toType}`])
    ) {
      return true;
    }
  }
  return !!R.includes(relationshipType, stixCoreRelationshipsMapping[`${fromType}_${toType}`] || []);
};

export const stixCyberObservableRelationshipsMapping = {
  Directory_Directory: ['contains'],
  Directory_StixFile: ['contains'],
  Directory_Artifact: ['contains'],
  'Email-Addr_User-Account': ['belongs-to'],
  'Email-Message_Email-Addr': ['from', 'sender', 'to', 'bcc'],
  'Email-Message_Email-Mime-Part-Type': ['body-multipart'],
  'Email-Message_Artifact': ['raw-email'],
  'Email-Mime-Part-Type_Artifact': ['body-raw'],
  StixFile_Directory: ['parent-directory', 'contains'],
  StixFile_Artifact: ['relation-content'],
  'Domain-Name_IPv4-Addr': ['resolves-to'],
  'Domain-Name_IPv6-Addr': ['resolves-to'],
  'IPv4-Addr_Mac-Addr': ['resolves-to'],
  'IPv4-Addr_Autonomous-System': ['obs_belongs-to'],
  'IPv6-Addr_Mac-Addr': ['resolves-to'],
  'IPv6-Addr_Autonomous-System': ['obs_belongs-to'],
  'Network-Traffic_IPv4-Addr': ['src', 'dst'],
  'Network-Traffic_IPv6-Addr': ['src', 'dst'],
  'Network-Traffic_Network-Traffic': ['encapsulates'],
  'Network-Traffic_Artifact': ['src-payload', 'dst-payload'],
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
