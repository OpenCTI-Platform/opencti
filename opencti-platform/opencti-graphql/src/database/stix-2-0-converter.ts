import type { StoreCommon, StoreEntity, StoreFileWithRefs, StoreObject, StoreRelation } from '../types/store';
import type * as S from '../types/stix-2-0-common';
import type * as SDO from '../types/stix-2-0-sdo';
import type * as SMO from '../types/stix-2-0-smo';
import { INPUT_CREATED_BY, INPUT_EXTERNAL_REFS, INPUT_GRANTED_REFS, INPUT_KILLCHAIN, INPUT_LABELS, INPUT_MARKINGS } from '../schema/general';
import { INPUT_OPERATING_SYSTEM, INPUT_SAMPLE } from '../schema/stixRefRelationship';
import {
  ENTITY_TYPE_DATA_COMPONENT,
  ENTITY_TYPE_DATA_SOURCE,
  ENTITY_TYPE_MALWARE,
  isStixDomainObject,
  isStixDomainObjectIdentity,
  isStixDomainObjectLocation,
  isStixDomainObjectThreatActor
} from '../schema/stixDomainObject';
import { assertType, cleanObject, convertToStixDate } from './stix-converter-utils';
import { ENTITY_HASHED_OBSERVABLE_STIX_FILE } from '../schema/stixCyberObservable';
import { isStixCoreRelationship } from '../schema/stixCoreRelationship';
import { isStixSightingRelationship } from '../schema/stixSightingRelationship';
import { ENTITY_TYPE_CONTAINER_FEEDBACK } from '../modules/case/feedback/feedback-types';
import { ENTITY_TYPE_CONTAINER_TASK } from '../modules/task/task-types';
import { ENTITY_TYPE_CONTAINER_CASE_INCIDENT } from '../modules/case/case-incident/case-incident-types';
import { ENTITY_TYPE_CONTAINER_CASE_RFI } from '../modules/case/case-rfi/case-rfi-types';
import { ENTITY_TYPE_CONTAINER_CASE_RFT } from '../modules/case/case-rft/case-rft-types';
import { isBasicObject } from '../schema/stixCoreObject';
import { isBasicRelationship } from '../schema/stixRelationship';
import { UnsupportedError } from '../config/errors';

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
    id: instance.standard_id,
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
const buildStixDomain = (instance: StoreEntity | StoreRelation): S.StixDomainObject => {
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

export const convertMalwareToStix = (instance: StoreEntity, type: string): SDO.StixMalware => {
  assertType(ENTITY_TYPE_MALWARE, type);
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

// CONVERTERS
export type ConvertFn<T extends StoreEntity, Z extends S.StixObject> = (instance: T) => Z;
const stixDomainConverters = new Map<string, ConvertFn<any, any>>();
// TODO add registerConverters for module converters

export const convertToStix_2_0 = (instance: StoreCommon): S.StixObject => {
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
      return convertMalwareToStix(basic, type);
    }
    // No converter_2_0 found
    throw UnsupportedError(`No entity stix 2.0 converter available for ${type}`);
  }
  // TODO add SRO (relations and sightings), InternalObject, MetaObject, StixCyberObservable :)
  throw UnsupportedError(`No entity stix 2.0 converter available for ${type}`);
};
