import type { StoreCommon, StoreEntity, StoreFileWithRefs, StoreObject, StoreRelation } from '../types/store';
import type * as S from '../types/stix-2-0-common';
import type * as SDO from '../types/stix-2-0-sdo';
import type * as SMO from '../types/stix-2-0-smo';
import { INPUT_CREATED_BY, INPUT_EXTERNAL_REFS, INPUT_GRANTED_REFS, INPUT_KILLCHAIN, INPUT_LABELS, INPUT_MARKINGS } from '../schema/general';
import { INPUT_OPERATING_SYSTEM, INPUT_SAMPLE } from '../schema/stixRefRelationship';
import {
  ENTITY_TYPE_CONTAINER_NOTE,
  ENTITY_TYPE_CONTAINER_OBSERVED_DATA,
  ENTITY_TYPE_CONTAINER_OPINION,
  ENTITY_TYPE_CONTAINER_REPORT,
  ENTITY_TYPE_DATA_COMPONENT,
  ENTITY_TYPE_DATA_SOURCE,
  ENTITY_TYPE_MALWARE,
  isStixDomainObject,
  isStixDomainObjectIdentity,
  isStixDomainObjectLocation,
  isStixDomainObjectThreatActor
} from '../schema/stixDomainObject';
import { assertType, cleanObject, convertObjectReferences, convertToStixDate, isValidStix } from './stix-converter-utils';
import { ENTITY_HASHED_OBSERVABLE_STIX_FILE } from '../schema/stixCyberObservable';
import { isStixCoreRelationship } from '../schema/stixCoreRelationship';
import { isStixSightingRelationship } from '../schema/stixSightingRelationship';
import { ENTITY_TYPE_CONTAINER_TASK } from '../modules/task/task-types';
import { ENTITY_TYPE_CONTAINER_CASE_INCIDENT } from '../modules/case/case-incident/case-incident-types';
import { ENTITY_TYPE_CONTAINER_CASE_RFI } from '../modules/case/case-rfi/case-rfi-types';
import { ENTITY_TYPE_CONTAINER_CASE_RFT } from '../modules/case/case-rft/case-rft-types';
import { ENTITY_TYPE_CONTAINER_FEEDBACK } from '../modules/case/feedback/feedback-types';
import { isBasicObject } from '../schema/stixCoreObject';
import { isBasicRelationship } from '../schema/stixRelationship';
import { FunctionalError, UnsupportedError } from '../config/errors';
import { isEmptyField } from './utils';

const CUSTOM_ENTITY_TYPES = [
  ENTITY_TYPE_CONTAINER_TASK,
  ENTITY_TYPE_CONTAINER_FEEDBACK,
  ENTITY_TYPE_CONTAINER_CASE_INCIDENT,
  ENTITY_TYPE_CONTAINER_CASE_RFI,
  ENTITY_TYPE_CONTAINER_CASE_RFT
];

export const buildStixId = (instanceType: string, standard_id: S.StixId): S.StixId => {
  const isCustomContainer = CUSTOM_ENTITY_TYPES.includes(instanceType);
  return isCustomContainer ? `x-opencti-${standard_id}` : standard_id as S.StixId;
};

export const convertTypeToStix2Type = (type: string): string => {
  if (isStixDomainObjectIdentity(type)) {
    return 'identity';
  }
  if (isStixDomainObjectLocation(type)) {
    return 'location';
  }
  if (type.toLowerCase() === ENTITY_HASHED_OBSERVABLE_STIX_FILE.toLowerCase()) {
    return 'file';
  }
  if (isStixCoreRelationship(type)) {
    return 'relationship';
  }
  if (isStixSightingRelationship(type)) {
    return 'sighting';
  }
  if (isStixDomainObjectThreatActor(type)) {
    return 'threat-actor';
  }
  if (type === ENTITY_TYPE_CONTAINER_CASE_INCIDENT
    || type === ENTITY_TYPE_CONTAINER_CASE_RFI
    || type === ENTITY_TYPE_CONTAINER_CASE_RFT
    || type === ENTITY_TYPE_CONTAINER_FEEDBACK
    || type === ENTITY_TYPE_CONTAINER_TASK) {
    return `x-opencti-${type.toLowerCase()}`;
  }
  if (type === ENTITY_TYPE_DATA_COMPONENT || type === ENTITY_TYPE_DATA_SOURCE) {
    return `x-mitre-${type.toLowerCase()}`;
  }
  return type.toLowerCase();
};

// Meta
const buildKillChainPhases = (instance: StoreEntity | StoreRelation): Array<SMO.StixInternalKillChainPhase> => {
  return (instance[INPUT_KILLCHAIN] ?? []).map((k) => {
    const data: SMO.StixInternalKillChainPhase = {
      kill_chain_name: k.kill_chain_name,
      phase_name: k.phase_name,
      x_opencti_order: k.x_opencti_order,
    };
    return cleanObject(data);
  });
};

const buildExternalReferences = (instance: StoreObject): Array<SMO.StixInternalExternalReference> => {
  return (instance[INPUT_EXTERNAL_REFS] ?? []).map((e) => {
    const data: SMO.StixInternalExternalReference = {
      source_name: e.source_name,
      description: e.description,
      url: e.url,
      hash: e.hashes,
      external_id: e.external_id,
    };
    return cleanObject(data);
  });
};

// Builders
const buildStixObject = (instance: StoreObject): S.StixObject => {
  return {
    id: buildStixId(instance.entity_type, instance.standard_id),
    x_opencti_id: instance.id,
    spec_version: '2.0',
    x_opencti_type: instance.entity_type,
    type: convertTypeToStix2Type(instance.entity_type),
    x_opencti_granted_refs: (instance[INPUT_GRANTED_REFS] ?? []).map((m) => m.standard_id),
    x_opencti_workflow_id: instance.x_opencti_workflow_id,
    x_opencti_files: ((instance.x_opencti_files ?? []).map((file: StoreFileWithRefs) => ({
      name: file.name,
      uri: `/storage/get/${file.id}`,
      mime_type: file.mime_type,
      version: file.version,
      object_marking_refs: (file[INPUT_MARKINGS] ?? []).filter((f) => f).map((f) => f.standard_id),
    }))),
  };
};

// General
export const buildStixDomain = (instance: StoreEntity | StoreRelation): S.StixDomainObject => {
  return {
    ...buildStixObject(instance),
    created: convertToStixDate(instance.created),
    modified: convertToStixDate(instance.modified),
    revoked: instance.revoked,
    confidence: instance.confidence,
    // lang: instance.lang,
    labels: (instance[INPUT_LABELS] ?? []).map((m) => m.value),
    object_marking_refs: (instance[INPUT_MARKINGS] ?? []).map((m) => m.standard_id),
    created_by_ref: instance[INPUT_CREATED_BY]?.standard_id,
    external_references: buildExternalReferences(instance),
  };
};

export const convertMalwareToStix = (instance: StoreEntity): SDO.StixMalware => {
  assertType(ENTITY_TYPE_MALWARE, instance.entity_type);
  return {
    ...buildStixDomain(instance),
    name: instance.name,
    description: instance.description,
    malware_types: instance.malware_types,
    is_family: instance.is_family,
    aliases: instance.aliases,
    kill_chain_phases: buildKillChainPhases(instance),
    first_seen: convertToStixDate(instance.first_seen),
    last_seen: convertToStixDate(instance.last_seen),
    architecture_execution_envs: instance.architecture_execution_envs,
    implementation_languages: instance.implementation_languages,
    capabilities: instance.capabilities,
    operating_system_refs: (instance[INPUT_OPERATING_SYSTEM] ?? []).map((m) => m.standard_id),
    sample_refs: (instance[INPUT_SAMPLE] ?? []).map((m) => m.standard_id),
  };
};

export const convertReportToStix = (instance: StoreEntity): SDO.StixReport => {
  assertType(ENTITY_TYPE_CONTAINER_REPORT, instance.entity_type);
  const report = buildStixDomain(instance);
  return {
    ...report,
    name: instance.name,
    description: instance.description,
    report_types: instance.report_types,
    published: convertToStixDate(instance.published),
    object_refs: convertObjectReferences(instance),
    x_opencti_reliability: instance.x_opencti_reliability,
  };
};

export const convertNoteToStix = (instance: StoreEntity): SDO.StixNote => {
  assertType(ENTITY_TYPE_CONTAINER_NOTE, instance.entity_type);
  const note = buildStixDomain(instance);
  return {
    ...note,
    abstract: instance.attribute_abstract,
    content: instance.content,
    object_refs: convertObjectReferences(instance),
    note_types: instance.note_types,
    likelihood: instance.likelihood,
  };
};

export const convertObservedDataToStix = (instance: StoreEntity): SDO.StixObservedData => {
  assertType(ENTITY_TYPE_CONTAINER_OBSERVED_DATA, instance.entity_type);
  const observedData = buildStixDomain(instance);
  return {
    ...observedData,
    first_observed: convertToStixDate(instance.first_observed),
    last_observed: convertToStixDate(instance.last_observed),
    number_observed: instance.number_observed,
    object_refs: convertObjectReferences(instance),
  };
};

export const convertOpinionToStix = (instance: StoreEntity): SDO.StixOpinion => {
  assertType(ENTITY_TYPE_CONTAINER_OPINION, instance.entity_type);
  const opinion = buildStixDomain(instance);
  return {
    ...opinion,
    explanation: instance.explanation,
    opinion: instance.opinion,
    object_refs: convertObjectReferences(instance),
  };
};

// CONVERTERS
export type ConvertFn<T extends StoreEntity, Z extends S.StixObject> = (instance: T) => Z;
const stixDomainConverters = new Map<string, ConvertFn<any, any>>();
// TODO add registerConverters for module converters

const convertToStix_2_0 = (instance: StoreCommon): S.StixObject => {
  const type = instance.entity_type;
  if (!isBasicObject(type) && !isBasicRelationship(type)) {
    throw UnsupportedError('Type cannot be converted to Stix', { type });
  }
  if (isStixDomainObject(type)) {
    const basic = instance as StoreEntity;
    // First try in registered converters
    if (stixDomainConverters.has(type)) {
      const externalConverter = stixDomainConverters.get(type);
      if (!externalConverter) {
        throw UnsupportedError('Converter was declared without a conversion function', { type });
      }
      return externalConverter(basic);
    }
    // TODO add Location, Identity, all SDOs
    if (ENTITY_TYPE_MALWARE === type) {
      return convertMalwareToStix(basic);
    }
    // No converter_2_0 found
    throw UnsupportedError(`No entity stix 2.0 converter available for ${type}`);
  }
  // TODO add SRO (relations and sightings), InternalObject, MetaObject, StixCyberObservable :)
  throw UnsupportedError(`No entity stix 2.0 converter available for ${type}`);
};

export const convertStoreToStix_2_0 = (instance: StoreCommon): S.StixObject => {
  if (isEmptyField(instance.standard_id) || isEmptyField(instance.entity_type)) {
    throw UnsupportedError('convertInstanceToStix must be used with opencti fully loaded instance');
  }
  const converted = convertToStix_2_0(instance);
  const stix = cleanObject(converted);
  if (!isValidStix(stix)) {
    throw FunctionalError('Invalid stix data conversion', { id: instance.standard_id, type: instance.entity_type });
  }
  return stix;
};
