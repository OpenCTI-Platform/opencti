import type { StoreEntity, StoreObject, StoreRelation } from '../types/store';
import type * as S from '../types/stix-2-0-common';
import type * as SDO from '../types/stix-2-0-sdo';
import { buildKillChainPhases, assertType, convertTypeToStixType, convertToStixDate, buildExternalReferences } from './stix-converter';
import { INPUT_CREATED_BY, INPUT_GRANTED_REFS, INPUT_LABELS, INPUT_MARKINGS } from '../schema/general';
import { INPUT_OPERATING_SYSTEM, INPUT_SAMPLE } from '../schema/stixRefRelationship';
import { ENTITY_TYPE_MALWARE } from '../schema/stixDomainObject';

// Builders
const buildStixObject = (instance: StoreObject): S.StixObject2 => {
  return {
    id: instance.standard_id,
    spec_version: '2.0',
    x_opencti_type: convertTypeToStixType(instance.entity_type),
    x_opencti_granted_refs: (instance[INPUT_GRANTED_REFS] ?? []).map((m) => m.internal_id)
  };
};

// General
const buildStixDomain = (instance: StoreEntity | StoreRelation): S.StixDomainObject2 => {
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

export const convertMalwareToStix2 = (instance: StoreEntity, type: string): SDO.StixMalware2 => {
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
