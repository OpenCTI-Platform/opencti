import * as R from 'ramda';
import { version as uuidVersion } from 'uuid';
import uuidTime from 'uuid-time';
import { UnsupportedError } from '../config/errors';
import {
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
  RELATION_REMEDIATES,
  RELATION_RESOLVES_TO,
  RELATION_REVOKED_BY,
  RELATION_SUBTECHNIQUE_OF,
  RELATION_TARGETS,
  RELATION_USES,
  RELATION_VARIANT_OF,
} from '../schema/stixCoreRelationship';
import { isStixSightingRelationship } from '../schema/stixSightingRelationship';
import {
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
  STIX_CYBER_OBSERVABLE_RELATION_TO_FIELD,
} from '../schema/stixCyberObservableRelationship';
import { ABSTRACT_STIX_CYBER_OBSERVABLE, INTERNAL_PREFIX, REL_INDEX_PREFIX, } from '../schema/general';
import { isNotEmptyField, UPDATE_OPERATION_REPLACE } from './utils';
import {
  ENTITY_TYPE_EXTERNAL_REFERENCE,
  ENTITY_TYPE_LABEL,
  ENTITY_TYPE_MARKING_DEFINITION,
} from '../schema/stixMetaObject';
import { isMultipleAttribute, stixHashesToInput } from '../schema/fieldDataAdapter';
import { generateInternalType } from '../schema/schemaUtils';
import { generateStandardId, normalizeName } from '../schema/identifier';
import { mergeDeepRightAll } from '../utils/format';
import type { StoreInput, StoreInputOperation, StorePartial } from '../types/store';
import type { StixCoreObject, StixExternalReference, StixObject } from '../types/stix-common';
import { STIX_EXT_OCTI, STIX_EXT_OCTI_SCO } from '../types/stix-extensions';
import type { StixMarkingDefinition } from '../types/stix-smo';
import type {
  ArtifactAddInput,
  AttackPatternAddInput,
  ExternalReferenceAddInput,
  MarkingDefinitionAddInput,
  StixCoreRelationshipAddInput,
  StixSightingRelationshipAddInput
} from '../generated/graphql';
import type { StixRelation, StixSighting } from '../types/stix-sro';
import type { StixAttackPattern } from '../types/stix-sdo';
import type { StixArtifact } from '../types/stix-sco';
import { convertPartialToStix } from './stix-converter';

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

const isStixFieldKey = (key: string): boolean => {
  const isInternal = key.startsWith(INTERNAL_PREFIX);
  const isSpecificRels = key.startsWith(REL_INDEX_PREFIX);
  return !(isInternal || isSpecificRels || EXCLUDED_FIELDS_FROM_STIX.includes(key));
};

const storeInputToStixPatch = (entityType: string, input: StoreInput): StixObject => {
  const { key, value } = input;
  const adaptedVal = !isMultipleAttribute(key) && Array.isArray(value) ? R.head(value) : value;
  const partialData = { [key]: adaptedVal } as StorePartial;
  return convertPartialToStix(partialData, entityType);
};

export const buildInputDataFromStix = (stix: StixCoreObject | StixMarkingDefinition | StixExternalReference): unknown => {
  const type = generateInternalType(stix);
  if (isStixCoreRelationship(type)) {
    const relationship = stix as StixRelation;
    const externalReferencesIds = (relationship.external_references ?? []).map((v) => generateStandardId(ENTITY_TYPE_EXTERNAL_REFERENCE, v));
    const labelIds = relationship.labels.map((v) => {
      const labelName = { value: normalizeName(v) };
      return generateStandardId(ENTITY_TYPE_LABEL, labelName);
    });
    // noinspection UnnecessaryLocalVariableJS
    const input:StixCoreRelationshipAddInput = {
      confidence: relationship.confidence,
      created: relationship.created,
      createdBy: relationship.created_by_ref,
      description: relationship.description,
      externalReferences: externalReferencesIds,
      fromId: relationship.source_ref,
      // killChainPhases: undefined,
      lang: relationship.lang,
      modified: relationship.modified,
      objectLabel: labelIds,
      objectMarking: relationship.object_marking_refs,
      relationship_type: relationship.relationship_type,
      revoked: relationship.revoked,
      start_time: relationship.start_time,
      stix_id: relationship.id,
      stop_time: relationship.stop_time,
      toId: relationship.target_ref,
      x_opencti_stix_ids: relationship.extensions[STIX_EXT_OCTI].stix_ids,
      update: true
    };
    return input;
  }
  if (isStixSightingRelationship(type)) {
    const sightingRelationship = stix as StixSighting;
    const externalReferencesIds = (sightingRelationship.external_references ?? []).map((v) => generateStandardId(ENTITY_TYPE_EXTERNAL_REFERENCE, v));
    const labelIds = sightingRelationship.labels.map((v) => {
      const labelName = { value: normalizeName(v) };
      return generateStandardId(ENTITY_TYPE_LABEL, labelName);
    });
    // noinspection UnnecessaryLocalVariableJS
    const input:StixSightingRelationshipAddInput = {
      attribute_count: sightingRelationship.count,
      confidence: sightingRelationship.confidence,
      created: sightingRelationship.created,
      createdBy: sightingRelationship.created_by_ref,
      description: sightingRelationship.description,
      externalReferences: externalReferencesIds,
      first_seen: sightingRelationship.first_seen,
      fromId: sightingRelationship.sighting_of_ref,
      toId: R.head(sightingRelationship.where_sighted_refs),
      last_seen: sightingRelationship.last_seen,
      modified: sightingRelationship.modified,
      objectLabel: labelIds,
      objectMarking: sightingRelationship.object_marking_refs,
      stix_id: sightingRelationship.id,
      x_opencti_negative: sightingRelationship.extensions[STIX_EXT_OCTI].negative,
      x_opencti_stix_ids: sightingRelationship.extensions[STIX_EXT_OCTI].stix_ids,
      update: true
    };
    return input;
  }
  if (type === ENTITY_TYPE_EXTERNAL_REFERENCE) {
    const ref = stix as StixExternalReference;
    // noinspection UnnecessaryLocalVariableJS
    const input:ExternalReferenceAddInput = {
      description: ref.description,
      external_id: ref.external_id,
      // file: undefined, - TODO File upload
      // hash: undefined - TODO remove?
      // modified: undefined, TODO what to do?
      source_name: ref.source_name,
      url: ref.url,
      x_opencti_stix_ids: ref.extensions[STIX_EXT_OCTI].stix_ids,
      update: true
    };
    return input;
  }
  if (type === ENTITY_TYPE_ATTACK_PATTERN) {
    const attack = stix as StixAttackPattern;
    // noinspection UnnecessaryLocalVariableJS
    const input:AttackPatternAddInput = {
      aliases: attack.aliases,
      confidence: attack.confidence,
      created: attack.created,
      createdBy: attack.created_by_ref,
      description: attack.description,
      externalReferences: undefined,
      killChainPhases: undefined,
      lang: attack.lang,
      modified: attack.modified,
      name: attack.name,
      objectLabel: undefined,
      objectMarking: attack.object_marking_refs,
      revoked: attack.revoked,
      stix_id: attack.id,
      x_mitre_detection: undefined,
      x_mitre_id: undefined,
      x_mitre_permissions_required: undefined,
      x_mitre_platforms: undefined,
      x_opencti_stix_ids: attack.extensions[STIX_EXT_OCTI].stix_ids,
      update: true,
    };
    return input;
  }
  if (type === ENTITY_TYPE_MARKING_DEFINITION) {
    const markingDef = stix as StixMarkingDefinition;
    // noinspection UnnecessaryLocalVariableJS
    const input:MarkingDefinitionAddInput = {
      created: markingDef.created,
      definition: markingDef.definition[markingDef.definition_type],
      definition_type: markingDef.definition_type,
      x_opencti_order: markingDef.extensions[STIX_EXT_OCTI].order,
      modified: markingDef.modified,
      stix_id: markingDef.id,
      x_opencti_color: markingDef.extensions[STIX_EXT_OCTI].color,
      x_opencti_stix_ids: markingDef.extensions[STIX_EXT_OCTI].stix_ids,
      update: true
    };
    return input;
  }
  if (type === ENTITY_HASHED_OBSERVABLE_ARTIFACT) {
    const artifact = stix as StixArtifact;
    // noinspection UnnecessaryLocalVariableJS
    const input:ArtifactAddInput = {
      decryption_key: artifact.decryption_key,
      encryption_algorithm: artifact.encryption_algorithm,
      hashes: stixHashesToInput(artifact),
      mime_type: artifact.mime_type,
      payload_bin: artifact.payload_bin,
      url: artifact.url,
      x_opencti_additional_names: artifact.extensions[STIX_EXT_OCTI_SCO].additional_names
    };
    return input;
  }
  // inputData[translatedKey] = stix[key].map((v) => generateStandardId(ENTITY_TYPE_EXTERNAL_REFERENCE, v));
  // inputData[translatedKey] = stix[key].map((v) => generateStandardId(ENTITY_TYPE_KILL_CHAIN_PHASE, v));
  // TODO JRI Generate all mapping types
  return {};
};

export const updateInputsToPatch = (entityType: string, inputs: Array<StoreInputOperation>) => {
  const convertedInputs = inputs.map((input) => {
    const { key, value, operation = UPDATE_OPERATION_REPLACE, previous = null } = input;
    if (isNotEmptyField(value) && !Array.isArray(value)) {
      throw UnsupportedError('value must be an array');
    }
    if (isNotEmptyField(previous) && !Array.isArray(previous)) {
      throw UnsupportedError('previous must be an array');
    }
    // Sometime the key will be empty because the patch include a none stix modification
    if (!isStixFieldKey(key)) {
      return undefined;
    }
    const stixPatchValue = storeInputToStixPatch(entityType, input);
    if (operation === UPDATE_OPERATION_REPLACE) {
      if (previous) {
        const prevStixPatchValue = storeInputToStixPatch(entityType, { key, value: previous });
        return { [operation]: prevStixPatchValue };
      }
      return { [operation]: null };
    }
    return { [operation]: stixPatchValue };
  });
  return mergeDeepRightAll(...convertedInputs);
};

export const onlyStableStixIds = (ids = []) => R.filter((n) => uuidVersion(R.split('--', n)[1]) !== 1, ids);

export const cleanStixIds = (ids: Array<string>, maxStixIds = MAX_TRANSIENT_STIX_IDS): Array<string> => {
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

export const checkStixCoreRelationshipMapping = (fromType: string, toType: string, relationshipType: string): boolean => {
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
  return R.includes(relationshipType, stixCoreRelationshipsMapping[`${fromType}_${toType}`] || []);
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
  const typeFields: { [k: string]: Array<string> } = {};
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

export const checkStixCyberObservableRelationshipMapping = (fromType: string, toType: string, relationshipType: string): boolean => {
  if (relationshipType === RELATION_LINKED || relationshipType === RELATION_LINKED) {
    return true;
  }
  return R.includes(relationshipType, stixCyberObservableRelationshipsMapping[`${fromType}_${toType}`] || []);
};
