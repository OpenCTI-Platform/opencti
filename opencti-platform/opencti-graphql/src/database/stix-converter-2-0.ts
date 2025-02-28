import type { StoreEntity, StoreObject, StoreRelation } from '../types/store';
import type * as S from '../types/stix-2-0/stix-2-0-common';
import type * as SDO from '../types/stix-2-0/stix-2-0-sdo';
import { convertToStixDate } from '../types/utils';
import { buildKillChainPhases, cleanObject, convertTypeToStixType } from './stix-converter-2-1';
import { INPUT_CREATED_BY, INPUT_EXTERNAL_REFS, INPUT_LABELS, INPUT_MARKINGS } from '../schema/general';
import type * as SMO from '../types/stix-2-0/stix-2-0-smo';
import { INPUT_OPERATING_SYSTEM, INPUT_SAMPLE } from '../schema/stixRefRelationship';

// Builders
export const buildStixObject = (instance: StoreObject): S.StixObject => {
  return {
    id: instance.standard_id,
    spec_version: '2.0',
    // x_opencti_type: convertTypeToStixType(instance.entity_type), // TODO should be in utils file as it is common to stix 2.0 and 2.1 ?
    // x_opencti_granted_refs: // TODO where should I put custom attributes?
  };
};

// Meta // TODO not sure about this method seems to be same as in stix-converter-2-1.ts but with no  hashes: e.hashes,
const buildExternalReferences = (instance: StoreObject): Array<SMO.StixInternalExternalReference> => {
  return (instance[INPUT_EXTERNAL_REFS] ?? []).map((e) => {
    const data: SMO.StixInternalExternalReference = {
      source_name: e.source_name,
      description: e.description,
      url: e.url,
      external_id: e.external_id,
      hashes: e.hashes, // TODO if this, no need to copy this method
    };
    return cleanObject(data); // TODO should be in utils file as it is common to stix 2.0 and 2.1 ?
  });
};

// General
export const buildStixDomain = (instance: StoreEntity | StoreRelation): S.StixDomainObject2 => {
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

const convertMalwareToStix2 = (instance: StoreEntity, type: string): SDO.StixMalware2 => {
  // TODO should we  assertType(ENTITY_TYPE_MALWARE, type); as it is done in convertMalwareToStix
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
