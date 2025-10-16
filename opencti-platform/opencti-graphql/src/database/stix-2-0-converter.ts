import type { StoreEntity, StoreFileWithRefs, StoreObject, StoreRelation } from '../types/store';
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
  ENTITY_TYPE_TOOL,
  ENTITY_TYPE_VULNERABILITY,
  isStixDomainObjectIdentity,
  isStixDomainObjectLocation,
  isStixDomainObjectThreatActor
} from '../schema/stixDomainObject';
import { assertType, cleanObject, convertObjectReferences, convertToStixDate } from './stix-converter-utils';
import { ENTITY_HASHED_OBSERVABLE_STIX_FILE } from '../schema/stixCyberObservable';
import { isStixCoreRelationship } from '../schema/stixCoreRelationship';
import { isStixSightingRelationship } from '../schema/stixSightingRelationship';
import { ENTITY_TYPE_CONTAINER_TASK } from '../modules/task/task-types';
import { ENTITY_TYPE_CONTAINER_CASE_INCIDENT } from '../modules/case/case-incident/case-incident-types';
import { ENTITY_TYPE_CONTAINER_CASE_RFI } from '../modules/case/case-rfi/case-rfi-types';
import { ENTITY_TYPE_CONTAINER_CASE_RFT } from '../modules/case/case-rft/case-rft-types';
import { ENTITY_TYPE_CONTAINER_FEEDBACK } from '../modules/case/feedback/feedback-types';

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

export const convertToolToStix = (instance: StoreEntity, type: string): SDO.StixTool => {
  assertType(ENTITY_TYPE_TOOL, type);
  return {
    ...buildStixDomain(instance),
    name: instance.name,
    description: instance.description,
    tool_types: instance.tool_types,
    aliases: instance.aliases,
    kill_chain_phases: buildKillChainPhases(instance),
    tool_version: instance.tool_version
  };
};

export const convertVulnerabilityToStix = (instance: StoreEntity, type: string): SDO.StixVulnerability => {
  assertType(ENTITY_TYPE_VULNERABILITY, type);
  const vulnerability = buildStixDomain(instance);
  return {
    ...vulnerability,
    name: instance.name,
    description: instance.description,
    x_opencti_cisa_kev: instance.x_opencti_cisa_kev,
    x_opencti_first_seen_active: instance.x_opencti_first_seen_active,
    // CVSS3
    x_opencti_cvss_vector_string: instance.x_opencti_cvss_vector_string,
    x_opencti_cvss_base_score: instance.x_opencti_cvss_base_score,
    x_opencti_cvss_base_severity: instance.x_opencti_cvss_base_severity,
    x_opencti_cvss_attack_vector: instance.x_opencti_cvss_attack_vector,
    x_opencti_cvss_attack_complexity: instance.x_opencti_cvss_attack_complexity,
    x_opencti_cvss_privileges_required: instance.x_opencti_cvss_privileges_required,
    x_opencti_cvss_user_interaction: instance.x_opencti_cvss_user_interaction,
    x_opencti_cvss_scope: instance.x_opencti_cvss_scope,
    x_opencti_cvss_confidentiality_impact: instance.x_opencti_cvss_confidentiality_impact,
    x_opencti_cvss_integrity_impact: instance.x_opencti_cvss_integrity_impact,
    x_opencti_cvss_availability_impact: instance.x_opencti_cvss_availability_impact,
    x_opencti_cvss_exploit_code_maturity: instance.x_opencti_cvss_exploit_code_maturity,
    x_opencti_cvss_remediation_level: instance.x_opencti_cvss_remediation_level,
    x_opencti_cvss_report_confidence: instance.x_opencti_cvss_report_confidence,
    x_opencti_cvss_temporal_score: instance.x_opencti_cvss_temporal_score,
    // CVSS2
    x_opencti_cvss_v2_vector_string: instance.x_opencti_cvss_v2_vector_string,
    x_opencti_cvss_v2_base_score: instance.x_opencti_cvss_v2_base_score,
    x_opencti_cvss_v2_access_vector: instance.x_opencti_cvss_v2_access_vector,
    x_opencti_cvss_v2_access_complexity: instance.x_opencti_cvss_v2_access_complexity,
    x_opencti_cvss_v2_authentication: instance.x_opencti_cvss_v2_authentication,
    x_opencti_cvss_v2_confidentiality_impact: instance.x_opencti_cvss_v2_confidentiality_impact,
    x_opencti_cvss_v2_integrity_impact: instance.x_opencti_cvss_v2_integrity_impact,
    x_opencti_cvss_v2_availability_impact: instance.x_opencti_cvss_v2_availability_impact,
    x_opencti_cvss_v2_exploitability: instance.x_opencti_cvss_v2_exploitability,
    x_opencti_cvss_v2_remediation_level: instance.x_opencti_cvss_v2_remediation_level,
    x_opencti_cvss_v2_report_confidence: instance.x_opencti_cvss_v2_report_confidence,
    x_opencti_cvss_v2_temporal_score: instance.x_opencti_cvss_v2_temporal_score,
    // CVSS4
    x_opencti_cvss_v4_vector_string: instance.x_opencti_cvss_v4_vector_string,
    x_opencti_cvss_v4_base_score: instance.x_opencti_cvss_v4_base_score,
    x_opencti_cvss_v4_base_severity: instance.x_opencti_cvss_v4_base_severity,
    x_opencti_cvss_v4_attack_vector: instance.x_opencti_cvss_v4_attack_vector,
    x_opencti_cvss_v4_attack_complexity: instance.x_opencti_cvss_v4_attack_complexity,
    x_opencti_cvss_v4_attack_requirements: instance.x_opencti_cvss_v4_attack_requirements,
    x_opencti_cvss_v4_privileges_required: instance.x_opencti_cvss_v4_privileges_required,
    x_opencti_cvss_v4_user_interaction: instance.x_opencti_cvss_v4_user_interaction,
    x_opencti_cvss_v4_confidentiality_impact_v: instance.x_opencti_cvss_v4_confidentiality_impact_v,
    x_opencti_cvss_v4_confidentiality_impact_s: instance.x_opencti_cvss_v4_confidentiality_impact_s,
    x_opencti_cvss_v4_integrity_impact_v: instance.x_opencti_cvss_v4_integrity_impact_v,
    x_opencti_cvss_v4_integrity_impact_s: instance.x_opencti_cvss_v4_integrity_impact_s,
    x_opencti_cvss_v4_availability_impact_v: instance.x_opencti_cvss_v4_availability_impact_v,
    x_opencti_cvss_v4_availability_impact_s: instance.x_opencti_cvss_v4_availability_impact_s,
    x_opencti_cvss_v4_exploit_maturity: instance.x_opencti_cvss_v4_exploit_maturity,
    // Others
    x_opencti_score: instance.x_opencti_score,
    x_opencti_epss_score: instance.x_opencti_epss_score,
    x_opencti_epss_percentile: instance.x_opencti_epss_percentile,
  };
};

export const convertReportToStix = (instance: StoreEntity, type: string): SDO.StixReport => {
  assertType(ENTITY_TYPE_CONTAINER_REPORT, type);
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

export const convertNoteToStix = (instance: StoreEntity, type: string): SDO.StixNote => {
  assertType(ENTITY_TYPE_CONTAINER_NOTE, type);
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

export const convertObservedDataToStix = (instance: StoreEntity, type: string): SDO.StixObservedData => {
  assertType(ENTITY_TYPE_CONTAINER_OBSERVED_DATA, type);
  const observedData = buildStixDomain(instance);
  return {
    ...observedData,
    first_observed: convertToStixDate(instance.first_observed),
    last_observed: convertToStixDate(instance.last_observed),
    number_observed: instance.number_observed,
    object_refs: convertObjectReferences(instance),
  };
};

export const convertOpinionToStix = (instance: StoreEntity, type: string): SDO.StixOpinion => {
  assertType(ENTITY_TYPE_CONTAINER_OPINION, type);
  const opinion = buildStixDomain(instance);
  return {
    ...opinion,
    explanation: instance.explanation,
    opinion: instance.opinion,
    object_refs: convertObjectReferences(instance),
  };
};
