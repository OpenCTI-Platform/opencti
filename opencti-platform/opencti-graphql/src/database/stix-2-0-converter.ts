import type { BasicStoreCommon, StoreCommon, StoreEntity, StoreFileWithRefs, StoreObject, StoreRelation } from '../types/store';
import type * as S from '../types/stix-2-0-common';
import type * as SDO from '../types/stix-2-0-sdo';
import type * as SMO from '../types/stix-2-0-smo';
import { INPUT_CREATED_BY, INPUT_EXTERNAL_REFS, INPUT_GRANTED_REFS, INPUT_KILLCHAIN, INPUT_LABELS, INPUT_MARKINGS } from '../schema/general';
import { INPUT_OPERATING_SYSTEM, INPUT_SAMPLE } from '../schema/stixRefRelationship';
import {
  ENTITY_TYPE_ATTACK_PATTERN,
  ENTITY_TYPE_CAMPAIGN,
  ENTITY_TYPE_CONTAINER_NOTE,
  ENTITY_TYPE_CONTAINER_OBSERVED_DATA,
  ENTITY_TYPE_CONTAINER_OPINION,
  ENTITY_TYPE_CONTAINER_REPORT,
  ENTITY_TYPE_COURSE_OF_ACTION,
  ENTITY_TYPE_DATA_COMPONENT,
  ENTITY_TYPE_DATA_SOURCE,
  ENTITY_TYPE_INCIDENT,
  ENTITY_TYPE_INTRUSION_SET,
  ENTITY_TYPE_MALWARE,
  ENTITY_TYPE_THREAT_ACTOR_GROUP,
  isStixDomainObject,
  ENTITY_TYPE_TOOL,
  ENTITY_TYPE_VULNERABILITY,
  isStixDomainObjectIdentity,
  isStixDomainObjectLocation,
  isStixDomainObjectThreatActor,
} from '../schema/stixDomainObject';
import { assertType, checkInstanceCompletion, cleanObject, convertObjectReferences, convertToStixDate, isValidStix } from './stix-converter-utils';
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
import type * as SRO from '../types/stix-2-0-sro';

const CUSTOM_ENTITY_TYPES = [
  ENTITY_TYPE_CONTAINER_TASK,
  ENTITY_TYPE_CONTAINER_FEEDBACK,
  ENTITY_TYPE_CONTAINER_CASE_INCIDENT,
  ENTITY_TYPE_CONTAINER_CASE_RFI,
  ENTITY_TYPE_CONTAINER_CASE_RFT,
];

export const buildStixId = (instanceType: string, standard_id: S.StixId): S.StixId => {
  if (CUSTOM_ENTITY_TYPES.includes(instanceType)) {
    return `x-opencti-${standard_id}` as S.StixId;
  }
  if (instanceType === ENTITY_TYPE_DATA_COMPONENT || instanceType === ENTITY_TYPE_DATA_SOURCE) {
    return `x-mitre-${standard_id}` as S.StixId;
  }
  return standard_id as S.StixId;
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
    type: convertTypeToStix2Type(instance.entity_type),
    spec_version: '2.0',
    // extensions
    x_opencti_id: instance.id,
    x_opencti_type: instance.entity_type,
    x_opencti_modified_at: convertToStixDate(instance.x_opencti_modified_at),
    x_opencti_granted_refs: (instance[INPUT_GRANTED_REFS] ?? []).map((m) => m.standard_id),
    x_opencti_workflow_id: instance.x_opencti_workflow_id,
    x_opencti_files: ((instance.x_opencti_files ?? []).map((file: StoreFileWithRefs) => ({
      name: file.name,
      uri: `/storage/get/${file.id}`,
      mime_type: file.mime_type,
      version: file.version,
      object_marking_refs: (file[INPUT_MARKINGS] ?? []).filter((f) => f).map((f) => f.standard_id),
    }))),
    // TODO Add missing attribute 2.1 extension
    // x_created_by_ref_id: instance[INPUT_CREATED_BY]?.internal_id,
    // x_created_by_ref_type: instance[INPUT_CREATED_BY]?.entity_type,
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
const buildStixRelationship = (instance: StoreRelation): S.StixRelationshipObject => {
  // As 14/03/2022, relationship share same common information with domain
  return buildStixDomain(instance);
};

export const convertIdentityToStix = (instance: StoreEntity, type: string): SDO.StixIdentity => {
  if (!isStixDomainObjectIdentity(type)) {
    throw UnsupportedError('Type not compatible with identity', { entity_type: type });
  }
  const identity = buildStixDomain(instance);
  return {
    ...identity,
    name: instance.name,
    description: instance.description,
    contact_information: instance.contact_information,
    identity_class: instance.identity_class,
    roles: instance.roles,
    sectors: instance.sectors,
    x_opencti_aliases: instance.x_opencti_aliases ?? [],
    x_opencti_firstname: instance.x_opencti_firstname,
    x_opencti_lastname: instance.x_opencti_lastname,
    x_opencti_organization_type: instance.x_opencti_organization_type,
    x_opencti_reliability: instance.x_opencti_reliability,
    x_opencti_score: instance.x_opencti_score,
  };
};

export const convertIncidentToStix = (instance: StoreEntity): SDO.StixIncident => {
  assertType(ENTITY_TYPE_INCIDENT, instance.entity_type);
  const incident = buildStixDomain(instance);
  return {
    ...incident,
    name: instance.name,
    description: instance.description,
    first_seen: convertToStixDate(instance.first_seen),
    last_seen: convertToStixDate(instance.last_seen),
    aliases: instance.aliases,
    objective: instance.objective,
    incident_type: instance.incident_type,
    severity: instance.severity,
    source: instance.source,
  };
};

export const convertCampaignToStix = (instance: StoreEntity): SDO.StixCampaign => {
  assertType(ENTITY_TYPE_CAMPAIGN, instance.entity_type);
  return {
    ...buildStixDomain(instance),
    name: instance.name,
    description: instance.description,
    aliases: instance.aliases ?? instance.x_opencti_aliases ?? [],
    first_seen: convertToStixDate(instance.first_seen),
    last_seen: convertToStixDate(instance.last_seen),
    objective: instance.objective,
  };
};

export const convertAttackPatternToStix = (instance: StoreEntity): SDO.StixAttackPattern => {
  assertType(ENTITY_TYPE_ATTACK_PATTERN, instance.entity_type);
  return {
    ...buildStixDomain(instance),
    name: instance.name,
    description: instance.description,
    aliases: instance.aliases ?? [],
    kill_chain_phases: buildKillChainPhases(instance),
    x_mitre_id: instance.x_mitre_id,
    x_mitre_platforms: instance.x_mitre_platforms,
    x_mitre_permissions_required: instance.x_mitre_permissions_required,
    x_mitre_detection: instance.x_mitre_detection,
  };
};

export const convertCourseOfActionToStix = (instance: StoreEntity): SDO.StixCourseOfAction => {
  assertType(ENTITY_TYPE_COURSE_OF_ACTION, instance.entity_type);
  return {
    ...buildStixDomain(instance),
    name: instance.name,
    description: instance.description,
    x_opencti_aliases: instance.x_opencti_aliases ?? [],
    x_mitre_id: instance.x_mitre_id,
    x_opencti_threat_hunting: instance.x_opencti_threat_hunting,
    x_opencti_log_sources: instance.x_opencti_log_sources,
  };
};

export const convertIntrusionSetToStix = (instance: StoreEntity): SDO.StixIntrusionSet => {
  assertType(ENTITY_TYPE_INTRUSION_SET, instance.entity_type);
  return {
    ...buildStixDomain(instance),
    name: instance.name,
    description: instance.description,
    aliases: instance.aliases ?? instance.x_opencti_aliases ?? [],
    first_seen: convertToStixDate(instance.first_seen),
    last_seen: convertToStixDate(instance.last_seen),
    goals: instance.goals,
    resource_level: instance.resource_level,
    primary_motivation: instance.primary_motivation,
    secondary_motivations: instance.secondary_motivations,
  };
};

export const convertThreatActorGroupToStix = (instance: StoreEntity): SDO.StixThreatActor & { threat_actor_group: string } => {
  assertType(ENTITY_TYPE_THREAT_ACTOR_GROUP, instance.entity_type);
  return {
    ...buildStixDomain(instance),
    name: instance.name,
    description: instance.description,
    threat_actor_types: instance.threat_actor_types,
    aliases: instance.aliases ?? instance.x_opencti_aliases ?? [],
    first_seen: convertToStixDate(instance.first_seen),
    last_seen: convertToStixDate(instance.last_seen),
    roles: instance.roles,
    goals: instance.goals,
    sophistication: instance.sophistication,
    resource_level: instance.resource_level,
    primary_motivation: instance.primary_motivation,
    secondary_motivations: instance.secondary_motivations,
    personal_motivations: instance.personal_motivations,
    threat_actor_group: instance.name,
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

export const convertToolToStix = (instance: StoreEntity): SDO.StixTool => {
  assertType(ENTITY_TYPE_TOOL, instance.entity_type);
  return {
    ...buildStixDomain(instance),
    name: instance.name,
    description: instance.description,
    tool_types: instance.tool_types,
    aliases: instance.aliases,
    kill_chain_phases: buildKillChainPhases(instance),
    tool_version: instance.tool_version,
  };
};

export const convertVulnerabilityToStix = (instance: StoreEntity): SDO.StixVulnerability => {
  assertType(ENTITY_TYPE_VULNERABILITY, instance.entity_type);
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
    if (ENTITY_TYPE_INCIDENT === type) {
      return convertIncidentToStix(basic);
    }
    if (ENTITY_TYPE_MALWARE === type) {
      return convertMalwareToStix(basic);
    }
    if (ENTITY_TYPE_ATTACK_PATTERN === type) {
      return convertAttackPatternToStix(basic);
    }
    if (ENTITY_TYPE_COURSE_OF_ACTION === type) {
      return convertCourseOfActionToStix(basic);
    }
    if (ENTITY_TYPE_CAMPAIGN === type) {
      return convertCampaignToStix(basic);
    }
    if (ENTITY_TYPE_INTRUSION_SET === type) {
      return convertIntrusionSetToStix(basic);
    }
    if (ENTITY_TYPE_THREAT_ACTOR_GROUP === type) {
      return convertThreatActorGroupToStix(basic);
    }
    if (isStixDomainObjectIdentity(type)) {
      return convertIdentityToStix(basic, type);
    }
    if (ENTITY_TYPE_TOOL === type) {
      return convertToolToStix(basic);
    }
    if (ENTITY_TYPE_VULNERABILITY === type) {
      return convertVulnerabilityToStix(basic);
    }
    if (ENTITY_TYPE_CONTAINER_REPORT === type) {
      return convertReportToStix(basic);
    }
    if (ENTITY_TYPE_CONTAINER_NOTE === type) {
      return convertNoteToStix(basic);
    }
    if (ENTITY_TYPE_CONTAINER_OBSERVED_DATA === type) {
      return convertObservedDataToStix(basic);
    }
    if (ENTITY_TYPE_CONTAINER_OPINION === type) {
      return convertOpinionToStix(basic);
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

// SRO
export const convertSightingToStix = (instance: StoreRelation): SRO.StixSighting => {
  checkInstanceCompletion(instance);
  const stixRelationship = buildStixRelationship(instance);
  const resolvedFrom = instance.from as BasicStoreCommon;
  const resolvedTo = instance.to as BasicStoreCommon;
  return {
    ...stixRelationship,
    description: instance.description,
    first_seen: convertToStixDate(instance.first_seen),
    last_seen: convertToStixDate(instance.last_seen),
    count: instance.attribute_count,
    sighting_of_ref: resolvedFrom.standard_id,
    where_sighted_refs: [resolvedTo.standard_id],
    x_opencti_negative: instance.x_opencti_negative,
  };
};
