import * as R from 'ramda';
import { version as uuidVersion } from 'uuid';
import uuidTime from 'uuid-time';
import { FunctionalError } from '../config/errors';
import {
  ENTITY_TYPE_ATTACK_PATTERN,
  ENTITY_TYPE_CAMPAIGN,
  ENTITY_TYPE_CONTAINER_OBSERVED_DATA,
  ENTITY_TYPE_COURSE_OF_ACTION,
  ENTITY_TYPE_IDENTITY_INDIVIDUAL,
  ENTITY_TYPE_IDENTITY_ORGANIZATION,
  ENTITY_TYPE_IDENTITY_SECTOR,
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
  RELATION_CREATED_BY,
} from '../schema/stixMetaRelationship';
import { isStixObject } from '../schema/stixCoreObject';
import {
  isStixCoreRelationship,
  RELATION_ATTRIBUTED_TO,
  RELATION_BASED_ON,
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
  RELATION_REVOKED_BY,
  RELATION_SUBTECHNIQUE_OF,
  RELATION_TARGETS,
  RELATION_USES,
} from '../schema/stixCoreRelationship';
import { isStixSightingRelationship } from '../schema/stixSightingRelationship';
import { isStixCyberObservableRelationship, RELATION_LINKED } from '../schema/stixCyberObservableRelationship';
import { isMultipleAttribute } from '../schema/fieldDataAdapter';
import { ABSTRACT_STIX_CYBER_OBSERVABLE } from '../schema/general';

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
  return type.toLowerCase();
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
const isDefinedValue = (element, diffMode) => {
  if (element) {
    // Element is defined, empty or not we need to add it in the result
    if (diffMode) return true;
    // If not in diff mode, we only take into account none empty element
    const isArray = Array.isArray(element);
    if (isArray) return element.length > 0;
    // If not array, check if empty
    return !R.isEmpty(element);
  }
  return false;
};
export const stixDataConverter = (data, args = {}) => {
  const { diffMode = true } = args;
  let finalData = data;
  // Relationships
  if (isDefinedValue(finalData.from, diffMode)) {
    finalData = R.pipe(
      R.dissoc('from'),
      R.assoc('source_ref', data.from.standard_id),
      R.assoc('x_opencti_source_ref', data.from.internal_id)
    )(finalData);
  }
  if (isDefinedValue(finalData.to, diffMode)) {
    finalData = R.pipe(
      R.dissoc('to'),
      R.assoc('target_ref', data.to.standard_id),
      R.assoc('x_opencti_target_ref', data.to.internal_id)
    )(finalData);
  }
  // Specific input cases
  if (isDefinedValue(finalData.stix_id, diffMode)) {
    finalData = R.pipe(R.dissoc('stix_id'), R.assoc('x_opencti_stix_ids', [data.stix_id]))(finalData);
  } else {
    finalData = R.dissoc('stix_id', finalData);
  }
  // Inner relations
  if (isDefinedValue(finalData.object, diffMode)) {
    const objectSet = Array.isArray(finalData.object) ? finalData.object : [finalData.object];
    const objects = R.map((m) => m.standard_id, objectSet);
    finalData = R.pipe(R.dissoc('object'), R.assoc('object_refs', objects))(finalData);
  } else {
    finalData = R.dissoc('object', finalData);
  }
  if (isDefinedValue(finalData.objectMarking, diffMode)) {
    const markingSet = Array.isArray(finalData.objectMarking) ? finalData.objectMarking : [finalData.objectMarking];
    const markings = R.map((m) => m.standard_id, markingSet);
    finalData = R.pipe(R.dissoc('objectMarking'), R.assoc('object_marking_refs', markings))(finalData);
  } else {
    finalData = R.dissoc('objectMarking', finalData);
  }
  if (isDefinedValue(finalData.createdBy, diffMode)) {
    const creator = Array.isArray(finalData.createdBy) ? R.head(finalData.createdBy) : finalData.createdBy;
    finalData = R.pipe(R.dissoc('createdBy'), R.assoc('created_by_ref', creator.standard_id))(finalData);
  } else {
    finalData = R.dissoc('createdBy', finalData);
  }
  // Embedded relations
  if (isDefinedValue(finalData.objectLabel, diffMode)) {
    const labelSet = Array.isArray(finalData.objectLabel) ? finalData.objectLabel : [finalData.objectLabel];
    const labels = R.map((m) => m.value, labelSet);
    finalData = R.pipe(R.dissoc('objectLabel'), R.assoc('labels', labels))(finalData);
  } else {
    finalData = R.dissoc('objectLabel', finalData);
  }
  if (isDefinedValue(finalData.killChainPhases, diffMode)) {
    const killSet = Array.isArray(finalData.killChainPhases) ? finalData.killChainPhases : [finalData.killChainPhases];
    const kills = R.map((k) => R.pick(['kill_chain_name', 'phase_name'], k), killSet);
    finalData = R.pipe(R.dissoc('killChainPhases'), R.assoc('kill_chain_phases', kills))(finalData);
  } else {
    finalData = R.dissoc('killChainPhases', finalData);
  }
  if (isDefinedValue(finalData.externalReferences, diffMode)) {
    const externalSet = Array.isArray(finalData.externalReferences)
      ? finalData.externalReferences
      : [finalData.externalReferences];
    const externals = R.map(
      (e) => R.pick(['source_name', 'description', 'url', 'hashes', 'external_id'], e),
      externalSet
    );
    finalData = R.pipe(R.dissoc('externalReferences'), R.assoc('external_references', externals))(finalData);
  } else {
    finalData = R.dissoc('externalReferences', finalData);
  }
  // Attributes filtering
  const filteredData = {};
  const entries = Object.entries(finalData);
  for (let index = 0; index < entries.length; index += 1) {
    const [key, val] = entries[index];
    if (key.startsWith('i_') || key === 'x_opencti_graph_data' || val === null) {
      // Internal opencti attributes.
    } else if (key.startsWith('attribute_')) {
      // Stix but reserved keywords
      const targetKey = key.replace('attribute_', '');
      filteredData[targetKey] = val;
    } else if (!isMultipleAttribute(key) && !key.endsWith('_refs')) {
      filteredData[key] = Array.isArray(val) ? R.head(val) : val;
    } else if (diffMode) {
      // In diff mode, empty values must be available
      filteredData[key] = val;
    } else if (!isMultipleAttribute(key) || val.length > 0) {
      filteredData[key] = val;
    }
  }
  // Add x_ in extension
  // https://docs.oasis-open.org/cti/stix/v2.1/cs01/stix-v2.1-cs01.html#_ct36xlv6obo7
  const dataEntries = Object.entries(filteredData);
  const opencti = {};
  for (let attr = 0; attr < dataEntries.length; attr += 1) {
    const [key, val] = dataEntries[attr];
    if (key.startsWith('x_opencti_')) {
      opencti[key.substring('x_opencti_'.length)] = val;
    }
  }
  if (diffMode) {
    return filteredData;
  }
  return { ...filteredData, extensions: { x_opencti: opencti } };
};
export const buildStixData = (data, args = {}) => {
  const { onlyBase = false } = args;
  const type = data.entity_type;
  // general
  const rawData = R.pipe(
    R.assoc('id', data.standard_id),
    R.assoc('x_opencti_id', data.internal_id),
    R.assoc('type', convertTypeToStixType(type)),
    R.dissoc('_index'),
    R.dissoc('standard_id'),
    R.dissoc('internal_id'),
    R.dissoc('parent_types'),
    R.dissoc('base_type'),
    R.dissoc('entity_type'),
    R.dissoc('update'),
    // Relations
    R.dissoc('fromId'),
    R.dissoc('fromRole'),
    R.dissoc('fromType'),
    R.dissoc('toId'),
    R.dissoc('toRole'),
    R.dissoc('toType'),
    R.dissoc('connections')
  )(data);
  const stixData = stixDataConverter(rawData, args);
  if (onlyBase) {
    return R.pick(BASIC_FIELDS, stixData);
  }
  return stixData;
};

export const convertStixMetaRelationshipToStix = (data) => {
  const entityType = data.entity_type;
  let finalData = buildStixData(data.from, { onlyBase: true });
  if (isStixInternalMetaRelationship(entityType)) {
    finalData = R.assoc(entityType.replace('-', '_'), [buildStixData(data.to)], finalData);
  } else {
    finalData = R.assoc(
      `${entityType.replace('-', '_')}_ref${entityType !== RELATION_CREATED_BY ? 's' : ''}`,
      entityType !== RELATION_CREATED_BY ? [data.to.standard_id] : data.to.standard_id,
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

export const convertDataToStix = (data, type) => {
  if (!data) {
    /* istanbul ignore next */
    throw FunctionalError('No data provided to STIX converter');
  }
  const entityType = data.entity_type;
  const onlyBase = type === 'delete';
  let finalData;
  if (isStixObject(entityType)) {
    finalData = buildStixData(data, { onlyBase });
  }
  if (isStixCoreRelationship(entityType)) {
    finalData = buildStixData(data, { onlyBase });
  }
  if (isStixSightingRelationship(entityType)) {
    finalData = buildStixData(data, { onlyBase });
  }
  if (isStixMetaRelationship(entityType)) {
    finalData = convertStixMetaRelationshipToStix(data);
  }
  if (isStixCyberObservableRelationship(entityType)) {
    finalData = convertStixCyberObservableRelationshipToStix(data);
  }
  if (!finalData) {
    throw FunctionalError(`The converter is not able to convert this type of entity: ${entityType}`);
  }
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
  [`${ENTITY_TYPE_CAMPAIGN}_${ENTITY_TYPE_VULNERABILITY}`]: [RELATION_TARGETS],
  [`${ENTITY_TYPE_CAMPAIGN}_${ENTITY_TYPE_ATTACK_PATTERN}`]: [RELATION_USES],
  [`${ENTITY_TYPE_CAMPAIGN}_${ENTITY_TYPE_MALWARE}`]: [RELATION_USES],
  [`${ENTITY_TYPE_CAMPAIGN}_${ENTITY_TYPE_TOOL}`]: [RELATION_USES],
  [`${ENTITY_TYPE_COURSE_OF_ACTION}_${ENTITY_TYPE_INDICATOR}`]: [RELATION_INVESTIGATES, RELATION_MITIGATES],
  [`${ENTITY_TYPE_COURSE_OF_ACTION}_${ENTITY_TYPE_ATTACK_PATTERN}`]: [RELATION_MITIGATES],
  [`${ENTITY_TYPE_COURSE_OF_ACTION}_${ENTITY_TYPE_MALWARE}`]: [RELATION_MITIGATES],
  [`${ENTITY_TYPE_COURSE_OF_ACTION}_${ENTITY_TYPE_TOOL}`]: [RELATION_MITIGATES],
  [`${ENTITY_TYPE_COURSE_OF_ACTION}_${ENTITY_TYPE_VULNERABILITY}`]: [RELATION_MITIGATES],
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
  'Intrusion-Set_Threat-Actor': ['attributed-to', 'targets'],
  'Intrusion-Set_Infrastructure': ['compromises', 'hosts', 'own', 'uses'],
  'Intrusion-Set_Region': ['originates-from', 'targets'],
  'Intrusion-Set_Country': ['originates-from', 'targets'],
  'Intrusion-Set_City': ['originates-from', 'targets'],
  'Intrusion-Set_Position': ['originates-from', 'targets'],
  'Intrusion-Set_Sector': ['targets'],
  'Intrusion-Set_Organization': ['targets'],
  'Intrusion-Set_Individual': ['targets'],
  'Intrusion-Set_Vulnerability': ['targets'],
  'Intrusion-Set_Attack-Pattern': ['uses'],
  'Intrusion-Set_Malware': ['uses'],
  'Intrusion-Set_Tool': ['uses'],
  'Malware_attack-pattern': ['uses'],
  'Malware_Threat-Actor': ['authored-by'],
  'Malware_Intrusion-Set': ['authored-by'],
  Malware_Infrastructure: ['beacons-to', 'exfiltrate-to', 'targets', 'uses'],
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
  'Threat-Actor_Tool': ['uses'],
  'Threat-Actor_Vulnerability': ['targets'],
  'Tool_Attack-Pattern': ['uses', 'drops', 'delivers'],
  Tool_Malware: ['uses', 'drops', 'delivers'],
  Tool_Vulnerability: ['has', 'targets'],
  Tool_Sector: ['targets'],
  Tool_Organization: ['targets'],
  Tool_Individual: ['targets'],
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
  Incident_Vulnerability: ['targets'],
  'Incident_Attack-Pattern': ['uses'],
  Incident_Malware: ['uses'],
  Incident_Tool: ['uses'],
  Region_Region: ['located-at'],
  Country_Region: ['located-at'],
  City_Country: ['located-at'],
  Position_City: ['located-at'],
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
  'Domain-Name_IPv4-Addr': ['communicates-with'],
  'Domain-Name_IPv6-Addr': ['communicates-with'],
  'Domain-Name_Domain-Name': ['communicates-with'],
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
  'IPv4-Addr_Autonomous-System': ['belongs-to'],
  'IPv6-Addr_Mac-Addr': ['resolves-to'],
  'IPv6-Addr_Autonomous-System': ['belongs-to'],
  'Network-Traffic_IPv4-Addr': ['src', 'dst'],
  'Network-Traffic_IPv6-Addr': ['src', 'dst'],
  'Network-Traffic_Network-Traffic': ['encapsulates'],
  'Network-Traffic_Artifact': ['src-payload', 'dst-payload'],
};

export const checkStixCyberObservableRelationshipMapping = (fromType, toType, relationshipType) => {
  if (relationshipType === RELATION_LINKED || relationshipType === RELATION_LINKED) {
    return true;
  }
  return !!R.includes(relationshipType, stixCyberObservableRelationshipsMapping[`${fromType}_${toType}`] || []);
};
