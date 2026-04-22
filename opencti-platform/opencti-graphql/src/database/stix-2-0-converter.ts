import type { BasicStoreCommon, StoreCyberObservable, StoreCommon, StoreEntity, StoreFileWithRefs, StoreObject, StoreRelation } from '../types/store';
import type * as S from '../types/stix-2-0-common';
import type * as SDO from '../types/stix-2-0-sdo';
import type * as SCO from '../types/stix-2-0-sco';
import type * as SMO from '../types/stix-2-0-smo';
import { INPUT_CREATED_BY, INPUT_EXTERNAL_REFS, INPUT_GRANTED_REFS, INPUT_KILLCHAIN, INPUT_LABELS, INPUT_MARKINGS } from '../schema/general';
import {
  INPUT_OPERATING_SYSTEM,
  INPUT_SAMPLE,
  INPUT_CONTAINS,
  INPUT_RESOLVES_TO,
  INPUT_BELONGS_TO,
  INPUT_SENDER,
  INPUT_EMAIL_FROM,
  INPUT_EMAIL_TO,
  INPUT_CC,
  INPUT_BCC,
  INPUT_RAW_EMAIL,
  INPUT_BODY_RAW,
  INPUT_PARENT_DIRECTORY,
  INPUT_CONTENT,
  INPUT_SRC,
  INPUT_DST,
  INPUT_SRC_PAYLOAD,
  INPUT_DST_PAYLOAD,
  INPUT_ENCAPSULATES,
  INPUT_ENCAPSULATED_BY,
  INPUT_OPENED_CONNECTION,
  INPUT_CREATOR_USER,
  INPUT_IMAGE,
  INPUT_PARENT,
  INPUT_CHILD,
  INPUT_BODY_MULTIPART,
  INPUT_VALUES,
  INPUT_SERVICE_DLL,
} from '../schema/stixRefRelationship';
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
  ENTITY_TYPE_INFRASTRUCTURE,
  ENTITY_TYPE_INTRUSION_SET,
  ENTITY_TYPE_LOCATION_CITY,
  ENTITY_TYPE_LOCATION_COUNTRY,
  ENTITY_TYPE_LOCATION_REGION,
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
import {
  ENTITY_AUTONOMOUS_SYSTEM,
  ENTITY_DIRECTORY,
  ENTITY_DOMAIN_NAME,
  ENTITY_EMAIL_ADDR,
  ENTITY_EMAIL_MESSAGE,
  ENTITY_EMAIL_MIME_PART_TYPE,
  ENTITY_HASHED_OBSERVABLE_ARTIFACT,
  ENTITY_HASHED_OBSERVABLE_X509_CERTIFICATE,
  ENTITY_IPV4_ADDR,
  ENTITY_IPV6_ADDR,
  ENTITY_MAC_ADDR,
  ENTITY_MUTEX,
  ENTITY_NETWORK_TRAFFIC,
  ENTITY_PROCESS,
  ENTITY_SOFTWARE,
  ENTITY_URL,
  ENTITY_USER_ACCOUNT,
  ENTITY_WINDOWS_REGISTRY_KEY,
  ENTITY_WINDOWS_REGISTRY_VALUE_TYPE,
  ENTITY_CRYPTOGRAPHIC_KEY,
  ENTITY_CRYPTOGRAPHIC_WALLET,
  ENTITY_HOSTNAME,
  ENTITY_TEXT,
  ENTITY_CREDENTIAL,
  ENTITY_USER_AGENT,
  ENTITY_BANK_ACCOUNT,
  ENTITY_TRACKING_NUMBER,
  ENTITY_PHONE_NUMBER,
  ENTITY_PAYMENT_CARD,
  ENTITY_MEDIA_CONTENT,
  ENTITY_PERSONA,
  ENTITY_SSH_KEY,
  ENTITY_AI_PROMPT,
  ENTITY_IMEI,
  ENTITY_ICCID,
  ENTITY_IMSI,
  isStixCyberObservable,
} from '../schema/stixCyberObservable';
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

export const convertLocationToStix = (instance: StoreEntity, type: string): SDO.StixLocation => {
  if (!isStixDomainObjectLocation(type)) {
    throw UnsupportedError('Type not compatible with location', { entity_type: type });
  }
  const location = buildStixDomain(instance);
  return {
    ...location,
    name: instance.name,
    description: instance.description,
    latitude: instance.latitude ? parseFloat(instance.latitude) : undefined,
    longitude: instance.longitude ? parseFloat(instance.longitude) : undefined,
    precision: instance.precision,
    region: instance.entity_type === ENTITY_TYPE_LOCATION_REGION ? instance.name : undefined,
    country: instance.entity_type === ENTITY_TYPE_LOCATION_COUNTRY ? instance.name : undefined,
    city: instance.entity_type === ENTITY_TYPE_LOCATION_CITY ? instance.name : undefined,
    street_address: instance.street_address,
    postal_code: instance.postal_code,
    x_opencti_location_type: instance.entity_type,
    x_opencti_aliases: instance.x_opencti_aliases ?? [],
  };
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

export const convertInfrastructureToStix = (instance: StoreEntity): SDO.StixInfrastructure => {
  assertType(ENTITY_TYPE_INFRASTRUCTURE, instance.entity_type);
  return {
    ...buildStixDomain(instance),
    name: instance.name,
    description: instance.description,
    infrastructure_types: instance.infrastructure_types,
    aliases: instance.aliases ?? [],
    kill_chain_phases: buildKillChainPhases(instance),
    first_seen: convertToStixDate(instance.first_seen),
    last_seen: convertToStixDate(instance.last_seen),
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
    // TODO add Identity, all SDOs
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
    if (isStixDomainObjectLocation(type)) {
      return convertLocationToStix(basic, type);
    }
    if (ENTITY_TYPE_TOOL === type) {
      return convertToolToStix(basic);
    }
    if (ENTITY_TYPE_VULNERABILITY === type) {
      return convertVulnerabilityToStix(basic);
    }
    if (ENTITY_TYPE_INFRASTRUCTURE === type) {
      return convertInfrastructureToStix(basic);
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
  // TODO add SRO (relations and sightings), InternalObject, MetaObject :)
  if (isStixCyberObservable(type)) {
    const cyber = instance as StoreCyberObservable;
    if (ENTITY_WINDOWS_REGISTRY_VALUE_TYPE === type) return convertWindowsRegistryValueToStix(cyber);
    if (ENTITY_EMAIL_MIME_PART_TYPE === type) return convertEmailMimePartToStix(cyber);
    if (ENTITY_HASHED_OBSERVABLE_ARTIFACT === type) return convertArtifactToStix(cyber);
    if (ENTITY_AUTONOMOUS_SYSTEM === type) return convertAutonomousSystemToStix(cyber);
    if (ENTITY_BANK_ACCOUNT === type) return convertBankAccountToStix(cyber);
    if (ENTITY_CREDENTIAL === type) return convertCredentialToStix(cyber);
    if (ENTITY_TRACKING_NUMBER === type) return convertTrackingNumberToStix(cyber);
    if (ENTITY_CRYPTOGRAPHIC_WALLET === type) return convertCryptocurrencyWalletToStix(cyber);
    if (ENTITY_CRYPTOGRAPHIC_KEY === type) return convertCryptographicKeyToStix(cyber);
    if (ENTITY_DIRECTORY === type) return convertDirectoryToStix(cyber);
    if (ENTITY_DOMAIN_NAME === type) return convertDomainNameToStix(cyber);
    if (ENTITY_EMAIL_ADDR === type) return convertEmailAddressToStix(cyber);
    if (ENTITY_EMAIL_MESSAGE === type) return convertEmailMessageToStix(cyber);
    if (ENTITY_HASHED_OBSERVABLE_STIX_FILE === type) return convertFileToStix(cyber);
    if (ENTITY_HOSTNAME === type) return convertHostnameToStix(cyber);
    if (ENTITY_ICCID === type) return convertICCIDToStix(cyber);
    if (ENTITY_IMEI === type) return convertIMEIToStix(cyber);
    if (ENTITY_IMSI === type) return convertIMSIToStix(cyber);
    if (ENTITY_IPV4_ADDR === type) return convertIPv4AddressToStix(cyber);
    if (ENTITY_IPV6_ADDR === type) return convertIPv6AddressToStix(cyber);
    if (ENTITY_MAC_ADDR === type) return convertMacAddressToStix(cyber);
    if (ENTITY_MEDIA_CONTENT === type) return convertMediaContentToStix(cyber);
    if (ENTITY_PERSONA === type) return convertPersonaToStix(cyber);
    if (ENTITY_MUTEX === type) return convertMutexToStix(cyber);
    if (ENTITY_NETWORK_TRAFFIC === type) return convertNetworkTrafficToStix(cyber);
    if (ENTITY_PROCESS === type) return convertProcessToStix(cyber);
    if (ENTITY_SOFTWARE === type) return convertSoftwareToStix(cyber);
    if (ENTITY_TEXT === type) return convertTextToStix(cyber);
    if (ENTITY_PHONE_NUMBER === type) return convertPhoneNumberToStix(cyber);
    if (ENTITY_PAYMENT_CARD === type) return convertPaymentCardToStix(cyber);
    if (ENTITY_URL === type) return convertURLToStix(cyber);
    if (ENTITY_USER_ACCOUNT === type) return convertUserAccountToStix(cyber);
    if (ENTITY_USER_AGENT === type) return convertUserAgentToStix(cyber);
    if (ENTITY_WINDOWS_REGISTRY_KEY === type) return convertWindowsRegistryKeyToStix(cyber);
    if (ENTITY_HASHED_OBSERVABLE_X509_CERTIFICATE === type) return convertX509CertificateToStix(cyber);
    if (ENTITY_SSH_KEY === type) return convertSSHKeyToStix(cyber);
    if (ENTITY_AI_PROMPT === type) return convertAIPromptToStix(cyber);
    throw UnsupportedError(`No SCO stix 2.0 converter available for ${type}`);
  }
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

// SCO
const buildStixCyberObservable = (instance: StoreCyberObservable): S.StixCyberObject => {
  const stixObject = buildStixObject(instance);
  return {
    ...stixObject,
    defanged: instance.defanged,
    object_marking_refs: (instance[INPUT_MARKINGS] ?? []).map((m) => m.standard_id),
    x_opencti_score: instance.x_opencti_score,
    x_opencti_description: instance.x_opencti_description,
    x_opencti_labels: (instance[INPUT_LABELS] ?? []).map((m) => m.value),
    x_opencti_created_by_ref: instance[INPUT_CREATED_BY]?.standard_id,
    x_opencti_external_references: buildExternalReferences(instance),
  };
};

const buildWindowsRegistryValueType = (instance: StoreCyberObservable): Array<SCO.StixInternalWindowsRegistryValueType> => {
  return (instance[INPUT_VALUES] ?? []).map((k) => {
    const data: SCO.StixInternalWindowsRegistryValueType = {
      name: k.name,
      data: k.data,
      data_type: k.data_type,
    };
    return cleanObject(data);
  });
};

const buildEmailBodyMultipart = (instance: StoreCyberObservable): Array<SCO.StixInternalEmailBodyMultipart> => {
  return (instance[INPUT_BODY_MULTIPART] ?? []).map((k) => {
    const data: SCO.StixInternalEmailBodyMultipart = {
      content_type: k.content_type,
      content_disposition: k.content_disposition,
      body: k.body,
      body_raw_ref: instance[INPUT_BODY_RAW]?.standard_id,
    };
    return cleanObject(data);
  });
};

export const convertArtifactToStix = (instance: StoreCyberObservable): SCO.StixArtifact => {
  assertType(ENTITY_HASHED_OBSERVABLE_ARTIFACT, instance.entity_type);
  return {
    ...buildStixCyberObservable(instance),
    mime_type: instance.mime_type,
    payload_bin: instance.payload_bin,
    url: instance.url,
    hashes: instance.hashes ?? {},
    encryption_algorithm: instance.encryption_algorithm,
    decryption_key: instance.decryption_key,
    x_opencti_additional_names: instance.x_opencti_additional_names ?? [],
  };
};

export const convertAutonomousSystemToStix = (instance: StoreCyberObservable): SCO.StixAutonomousSystem => {
  assertType(ENTITY_AUTONOMOUS_SYSTEM, instance.entity_type);
  return {
    ...buildStixCyberObservable(instance),
    number: instance.number,
    name: instance.name,
    rir: instance.rir,
  };
};

export const convertCryptocurrencyWalletToStix = (instance: StoreCyberObservable): SCO.StixCryptocurrencyWallet => {
  assertType(ENTITY_CRYPTOGRAPHIC_WALLET, instance.entity_type);
  return {
    ...buildStixCyberObservable(instance),
    value: instance.value,
    labels: (instance[INPUT_LABELS] ?? []).map((m) => m.value),
    description: instance.x_opencti_description,
    score: instance.x_opencti_score,
    created_by_ref: instance[INPUT_CREATED_BY]?.standard_id,
    external_references: buildExternalReferences(instance),
  };
};

export const convertCryptographicKeyToStix = (instance: StoreCyberObservable): SCO.StixCryptographicKey => {
  assertType(ENTITY_CRYPTOGRAPHIC_KEY, instance.entity_type);
  return {
    ...buildStixCyberObservable(instance),
    value: instance.value,
    labels: (instance[INPUT_LABELS] ?? []).map((m) => m.value),
    description: instance.x_opencti_description,
    score: instance.x_opencti_score,
    created_by_ref: instance[INPUT_CREATED_BY]?.standard_id,
    external_references: buildExternalReferences(instance),
  };
};

export const convertDirectoryToStix = (instance: StoreCyberObservable): SCO.StixDirectory => {
  assertType(ENTITY_DIRECTORY, instance.entity_type);
  return {
    ...buildStixCyberObservable(instance),
    path: instance.path,
    path_enc: instance.path_enc,
    ctime: convertToStixDate(instance.ctime),
    mtime: convertToStixDate(instance.mtime),
    atime: convertToStixDate(instance.atime),
    contains_refs: (instance[INPUT_CONTAINS] ?? []).map((m) => m.standard_id),
  };
};

export const convertDomainNameToStix = (instance: StoreCyberObservable): SCO.StixDomainName => {
  assertType(ENTITY_DOMAIN_NAME, instance.entity_type);
  return {
    ...buildStixCyberObservable(instance),
    value: instance.value,
    resolves_to_refs: (instance[INPUT_RESOLVES_TO] ?? []).map((m) => m.standard_id),
  };
};

export const convertEmailAddressToStix = (instance: StoreCyberObservable): SCO.StixEmailAddress => {
  assertType(ENTITY_EMAIL_ADDR, instance.entity_type);
  return {
    ...buildStixCyberObservable(instance),
    value: instance.value,
    display_name: instance.display_name,
    belongs_to_ref: (instance[INPUT_BELONGS_TO] ?? [])[0]?.standard_id,
  };
};

export const convertEmailMessageToStix = (instance: StoreCyberObservable): SCO.StixEmailMessage => {
  assertType(ENTITY_EMAIL_MESSAGE, instance.entity_type);
  return {
    ...buildStixCyberObservable(instance),
    is_multipart: instance.is_multipart,
    date: convertToStixDate(instance.attribute_date),
    content_type: instance.content_type,
    from_ref: instance[INPUT_EMAIL_FROM]?.standard_id,
    sender_ref: instance[INPUT_SENDER]?.standard_id,
    to_refs: (instance[INPUT_EMAIL_TO] ?? []).map((m) => m.standard_id),
    cc_refs: (instance[INPUT_CC] ?? []).map((m) => m.standard_id),
    bcc_refs: (instance[INPUT_BCC] ?? []).map((m) => m.standard_id),
    message_id: instance.message_id,
    subject: instance.subject,
    received_lines: instance.received_lines,
    additional_header_fields: {},
    body: instance.body,
    body_multipart: buildEmailBodyMultipart(instance),
    raw_email_ref: instance[INPUT_RAW_EMAIL]?.standard_id,
    x_opencti_contains_refs: (instance[INPUT_CONTAINS] ?? []).map((m) => m.standard_id),
  };
};

export const convertEmailMimePartToStix = (instance: StoreCyberObservable): SCO.StixEmailBodyMultipart => {
  assertType(ENTITY_EMAIL_MIME_PART_TYPE, instance.entity_type);
  return {
    ...buildStixCyberObservable(instance),
    content_type: instance.content_type,
    content_disposition: instance.content_disposition,
    body: instance.body,
    body_raw_ref: instance[INPUT_BODY_RAW]?.standard_id,
    labels: (instance[INPUT_LABELS] ?? []).map((m) => m.value),
    description: instance.x_opencti_description,
    score: instance.x_opencti_score,
    created_by_ref: instance[INPUT_CREATED_BY]?.standard_id,
    external_references: buildExternalReferences(instance),
  };
};

export const convertFileToStix = (instance: StoreCyberObservable): SCO.StixFile => {
  assertType(ENTITY_HASHED_OBSERVABLE_STIX_FILE, instance.entity_type);
  return {
    ...buildStixCyberObservable(instance),
    hashes: instance.hashes ?? {},
    size: instance.size,
    name: instance.name,
    name_enc: instance.name_enc,
    magic_number_hex: instance.magic_number_hex,
    mime_type: instance.mime_type,
    ctime: convertToStixDate(instance.ctime),
    mtime: convertToStixDate(instance.mtime),
    atime: convertToStixDate(instance.atime),
    parent_directory_ref: instance[INPUT_PARENT_DIRECTORY]?.standard_id,
    contains_refs: (instance[INPUT_CONTAINS] ?? []).map((m) => m.standard_id),
    content_ref: instance[INPUT_CONTENT]?.standard_id,
    x_opencti_additional_names: instance.x_opencti_additional_names ?? [],
  };
};

export const convertHostnameToStix = (instance: StoreCyberObservable): SCO.StixHostname => {
  assertType(ENTITY_HOSTNAME, instance.entity_type);
  return {
    ...buildStixCyberObservable(instance),
    value: instance.value,
    labels: (instance[INPUT_LABELS] ?? []).map((m) => m.value),
    description: instance.x_opencti_description,
    score: instance.x_opencti_score,
    created_by_ref: instance[INPUT_CREATED_BY]?.standard_id,
    external_references: buildExternalReferences(instance),
  };
};

export const convertIPv4AddressToStix = (instance: StoreCyberObservable): SCO.StixIPv4Address => {
  assertType(ENTITY_IPV4_ADDR, instance.entity_type);
  return {
    ...buildStixCyberObservable(instance),
    value: instance.value,
    resolves_to_refs: (instance[INPUT_RESOLVES_TO] ?? []).map((m) => m.standard_id),
    belongs_to_refs: (instance[INPUT_BELONGS_TO] ?? []).map((m) => m.standard_id),
  };
};

export const convertIPv6AddressToStix = (instance: StoreCyberObservable): SCO.StixIPv6Address => {
  assertType(ENTITY_IPV6_ADDR, instance.entity_type);
  return {
    ...buildStixCyberObservable(instance),
    value: instance.value,
    resolves_to_refs: (instance[INPUT_RESOLVES_TO] ?? []).map((m) => m.standard_id),
    belongs_to_refs: (instance[INPUT_BELONGS_TO] ?? []).map((m) => m.standard_id),
  };
};

export const convertMacAddressToStix = (instance: StoreCyberObservable): SCO.StixMacAddress => {
  assertType(ENTITY_MAC_ADDR, instance.entity_type);
  return {
    ...buildStixCyberObservable(instance),
    value: instance.value,
  };
};

export const convertMutexToStix = (instance: StoreCyberObservable): SCO.StixMutex => {
  assertType(ENTITY_MUTEX, instance.entity_type);
  return {
    ...buildStixCyberObservable(instance),
    name: instance.name,
  };
};

export const convertNetworkTrafficToStix = (instance: StoreCyberObservable): SCO.StixNetworkTraffic => {
  assertType(ENTITY_NETWORK_TRAFFIC, instance.entity_type);
  return {
    ...buildStixCyberObservable(instance),
    start: convertToStixDate(instance.start),
    end: convertToStixDate(instance.end),
    is_active: instance.is_active,
    src_ref: instance[INPUT_SRC]?.standard_id,
    dst_ref: instance[INPUT_DST]?.standard_id,
    src_port: instance.src_port,
    dst_port: instance.dst_port,
    protocols: instance.protocols,
    src_byte_count: instance.src_byte_count,
    dst_byte_count: instance.dst_byte_count,
    src_packets: instance.src_packets,
    dst_packets: instance.dst_packets,
    ipfix: instance.ipfix,
    src_payload_ref: instance[INPUT_SRC_PAYLOAD]?.standard_id,
    dst_payload_ref: instance[INPUT_DST_PAYLOAD]?.standard_id,
    encapsulates_refs: (instance[INPUT_ENCAPSULATES] ?? []).map((m) => m.standard_id),
    encapsulated_by_ref: instance[INPUT_ENCAPSULATED_BY]?.standard_id,
  };
};

export const convertProcessToStix = (instance: StoreCyberObservable): SCO.StixProcess => {
  assertType(ENTITY_PROCESS, instance.entity_type);
  return {
    ...buildStixCyberObservable(instance),
    is_hidden: instance.is_hidden,
    pid: instance.pid,
    created_time: convertToStixDate(instance.created_time),
    cwd: instance.cwd,
    command_line: instance.command_line,
    environment_variables: instance.environment_variables,
    opened_connection_refs: (instance[INPUT_OPENED_CONNECTION] ?? []).map((m) => m.standard_id),
    creator_user_ref: instance[INPUT_CREATOR_USER]?.standard_id,
    image_ref: instance[INPUT_IMAGE]?.standard_id,
    parent_ref: instance[INPUT_PARENT]?.standard_id,
    child_refs: (instance[INPUT_CHILD] ?? []).map((m) => m.standard_id),
    aslr_enabled: instance.aslr_enabled,
    dep_enabled: instance.dep_enabled,
    priority: instance.priority,
    owner_sid: instance.owner_sid,
    window_title: instance.window_title,
    startup_info: instance.startup_info,
    integrity_level: instance.integrity_level,
    service_name: instance.service_name,
    descriptions: instance.descriptions,
    display_name: instance.display_name,
    group_name: instance.group_name,
    start_type: instance.start_type,
    service_dll_refs: (instance[INPUT_SERVICE_DLL] ?? []).map((m) => m.standard_id),
    service_type: instance.service_type,
    service_status: instance.service_status,
  };
};

export const convertSoftwareToStix = (instance: StoreCyberObservable): SCO.StixSoftware => {
  assertType(ENTITY_SOFTWARE, instance.entity_type);
  return {
    ...buildStixCyberObservable(instance),
    name: instance.name,
    cpe: instance.cpe,
    swid: instance.swid,
    languages: instance.languages,
    vendor: instance.vendor,
    version: instance.version,
    x_opencti_product: instance.x_opencti_product,
  };
};

export const convertURLToStix = (instance: StoreCyberObservable): SCO.StixURL => {
  assertType(ENTITY_URL, instance.entity_type);
  return {
    ...buildStixCyberObservable(instance),
    value: instance.value,
    score: instance.x_opencti_score,
  };
};

export const convertTextToStix = (instance: StoreCyberObservable): SCO.StixText => {
  assertType(ENTITY_TEXT, instance.entity_type);
  return {
    ...buildStixCyberObservable(instance),
    value: instance.value,
    labels: (instance[INPUT_LABELS] ?? []).map((m) => m.value),
    description: instance.x_opencti_description,
    score: instance.x_opencti_score,
    created_by_ref: instance[INPUT_CREATED_BY]?.standard_id,
    external_references: buildExternalReferences(instance),
  };
};

export const convertBankAccountToStix = (instance: StoreCyberObservable): SCO.StixBankAccount => {
  assertType(ENTITY_BANK_ACCOUNT, instance.entity_type);
  return {
    ...buildStixCyberObservable(instance),
    iban: instance.iban,
    bic: instance.bic,
    account_number: instance.account_number,
    labels: (instance[INPUT_LABELS] ?? []).map((m) => m.value),
    description: instance.x_opencti_description,
    score: instance.x_opencti_score,
    created_by_ref: instance[INPUT_CREATED_BY]?.standard_id,
    external_references: buildExternalReferences(instance),
  };
};

export const convertCredentialToStix = (instance: StoreCyberObservable): SCO.StixCredential => {
  assertType(ENTITY_CREDENTIAL, instance.entity_type);
  return {
    ...buildStixCyberObservable(instance),
    value: instance.value,
    labels: (instance[INPUT_LABELS] ?? []).map((m) => m.value),
    description: instance.x_opencti_description,
    score: instance.x_opencti_score,
    created_by_ref: instance[INPUT_CREATED_BY]?.standard_id,
    external_references: buildExternalReferences(instance),
  };
};

export const convertTrackingNumberToStix = (instance: StoreCyberObservable): SCO.StixTrackingNumber => {
  assertType(ENTITY_TRACKING_NUMBER, instance.entity_type);
  return {
    ...buildStixCyberObservable(instance),
    value: instance.value,
    labels: (instance[INPUT_LABELS] ?? []).map((m) => m.value),
    description: instance.x_opencti_description,
    score: instance.x_opencti_score,
    created_by_ref: instance[INPUT_CREATED_BY]?.standard_id,
    external_references: buildExternalReferences(instance),
  };
};

export const convertPhoneNumberToStix = (instance: StoreCyberObservable): SCO.StixPhoneNumber => {
  assertType(ENTITY_PHONE_NUMBER, instance.entity_type);
  return {
    ...buildStixCyberObservable(instance),
    value: instance.value,
    labels: (instance[INPUT_LABELS] ?? []).map((m) => m.value),
    description: instance.x_opencti_description,
    score: instance.x_opencti_score,
    created_by_ref: instance[INPUT_CREATED_BY]?.standard_id,
    external_references: buildExternalReferences(instance),
  };
};

export const convertPaymentCardToStix = (instance: StoreCyberObservable): SCO.StixPaymentCard => {
  assertType(ENTITY_PAYMENT_CARD, instance.entity_type);
  return {
    ...buildStixCyberObservable(instance),
    card_number: instance.card_number,
    expiration_date: convertToStixDate(instance.expiration_date),
    cvv: instance.cvv,
    holder_name: instance.holder_name,
    labels: (instance[INPUT_LABELS] ?? []).map((m) => m.value),
    description: instance.x_opencti_description,
    score: instance.x_opencti_score,
    created_by_ref: instance[INPUT_CREATED_BY]?.standard_id,
    external_references: buildExternalReferences(instance),
  };
};

export const convertMediaContentToStix = (instance: StoreCyberObservable): SCO.StixMediaContent => {
  assertType(ENTITY_MEDIA_CONTENT, instance.entity_type);
  return {
    ...buildStixCyberObservable(instance),
    title: instance.title,
    description: instance.x_opencti_description,
    content: instance.content,
    media_category: instance.media_category,
    url: instance.url,
    publication_date: convertToStixDate(instance.publication_date),
    labels: (instance[INPUT_LABELS] ?? []).map((m) => m.value),
    score: instance.x_opencti_score,
    created_by_ref: instance[INPUT_CREATED_BY]?.standard_id,
    external_references: buildExternalReferences(instance),
  };
};

export const convertUserAgentToStix = (instance: StoreCyberObservable): SCO.StixUserAgent => {
  assertType(ENTITY_USER_AGENT, instance.entity_type);
  return {
    ...buildStixCyberObservable(instance),
    value: instance.value,
    labels: (instance[INPUT_LABELS] ?? []).map((m) => m.value),
    description: instance.x_opencti_description,
    score: instance.x_opencti_score,
    created_by_ref: instance[INPUT_CREATED_BY]?.standard_id,
    external_references: buildExternalReferences(instance),
  };
};

export const convertUserAccountToStix = (instance: StoreCyberObservable): SCO.StixUserAccount => {
  assertType(ENTITY_USER_ACCOUNT, instance.entity_type);
  return {
    ...buildStixCyberObservable(instance),
    user_id: instance.user_id,
    credential: instance.credential,
    account_login: instance.account_login,
    account_type: instance.account_type,
    display_name: instance.display_name,
    is_service_account: instance.is_service_account,
    is_privileged: instance.is_privileged,
    can_escalate_privs: instance.can_escalate_privs,
    is_disabled: instance.is_disabled,
    account_created: convertToStixDate(instance.account_created),
    account_expires: convertToStixDate(instance.account_expires),
    credential_last_changed: convertToStixDate(instance.credential_last_changed),
    account_first_login: convertToStixDate(instance.account_first_login),
    account_last_login: convertToStixDate(instance.account_last_login),
  };
};

export const convertWindowsRegistryKeyToStix = (instance: StoreCyberObservable): SCO.StixWindowsRegistryKey => {
  assertType(ENTITY_WINDOWS_REGISTRY_KEY, instance.entity_type);
  return {
    ...buildStixCyberObservable(instance),
    key: instance.attribute_key,
    values: buildWindowsRegistryValueType(instance),
    modified_time: convertToStixDate(instance.modified_time),
    creator_user_ref: instance[INPUT_CREATOR_USER]?.standard_id,
    number_of_subkeys: instance.number_of_subkeys,
  };
};

export const convertWindowsRegistryValueToStix = (instance: StoreCyberObservable): SCO.StixWindowsRegistryValueType => {
  assertType(ENTITY_WINDOWS_REGISTRY_VALUE_TYPE, instance.entity_type);
  return {
    ...buildStixCyberObservable(instance),
    name: instance.name,
    data: instance.data,
    data_type: instance.data_type,
  };
};

export const convertX509CertificateToStix = (instance: StoreCyberObservable): SCO.StixX509Certificate => {
  assertType(ENTITY_HASHED_OBSERVABLE_X509_CERTIFICATE, instance.entity_type);
  return {
    ...buildStixCyberObservable(instance),
    is_self_signed: instance.is_self_signed,
    hashes: instance.hashes ?? {},
    version: instance.version,
    serial_number: instance.serial_number,
    signature_algorithm: instance.signature_algorithm,
    issuer: instance.issuer,
    validity_not_before: convertToStixDate(instance.validity_not_before),
    validity_not_after: convertToStixDate(instance.validity_not_after),
    subject: instance.subject,
    subject_public_key_algorithm: instance.subject_public_key_algorithm,
    subject_public_key_modulus: instance.subject_public_key_modulus,
    subject_public_key_exponent: instance.subject_public_key_exponent,
    x509_v3_extensions: cleanObject({
      basic_constraints: instance.basic_constraints,
      name_constraints: instance.name_constraints,
      policy_constraints: instance.policy_constraints,
      key_usage: instance.key_usage,
      extended_key_usage: instance.extended_key_usage,
      subject_key_identifier: instance.subject_key_identifier,
      authority_key_identifier: instance.authority_key_identifier,
      subject_alternative_name: instance.subject_alternative_name,
      issuer_alternative_name: instance.issuer_alternative_name,
      subject_directory_attributes: instance.subject_directory_attributes,
      crl_distribution_points: instance.crl_distribution_points,
      inhibit_any_policy: instance.inhibit_any_policy,
      private_key_usage_period_not_before: convertToStixDate(instance.private_key_usage_period_not_before),
      private_key_usage_period_not_after: convertToStixDate(instance.private_key_usage_period_not_after),
      certificate_policies: instance.certificate_policies,
      policy_mappings: instance.policy_mappings,
    }),
  };
};

export const convertPersonaToStix = (instance: StoreCyberObservable): SCO.StixPersona => {
  assertType(ENTITY_PERSONA, instance.entity_type);
  return {
    ...buildStixCyberObservable(instance),
    persona_name: instance.persona_name,
    persona_type: instance.persona_type,
    labels: (instance[INPUT_LABELS] ?? []).map((m) => m.value),
    score: instance.x_opencti_score,
    created_by_ref: instance[INPUT_CREATED_BY]?.standard_id,
    external_references: buildExternalReferences(instance),
  };
};

export const convertSSHKeyToStix = (instance: StoreCyberObservable): SCO.StixSSHKey => {
  assertType(ENTITY_SSH_KEY, instance.entity_type);
  return {
    ...buildStixCyberObservable(instance),
    key_type: instance.key_type,
    public_key: instance.public_key,
    fingerprint_sha256: instance.fingerprint_sha256,
    fingerprint_md5: instance.fingerprint_md5,
    key_length: instance.key_length,
    comment: instance.comment,
    created: convertToStixDate(instance.created),
    expiration_date: convertToStixDate(instance.expiration_date),
    external_references: buildExternalReferences(instance),
  };
};

export const convertAIPromptToStix = (instance: StoreCyberObservable): SCO.StixAIPrompt => {
  assertType(ENTITY_AI_PROMPT, instance.entity_type);
  return {
    ...buildStixCyberObservable(instance),
    value: instance.value,
    labels: (instance[INPUT_LABELS] ?? []).map((m) => m.value),
    description: instance.x_opencti_description,
    score: instance.x_opencti_score,
    created_by_ref: instance[INPUT_CREATED_BY]?.standard_id,
    external_references: buildExternalReferences(instance),
  };
};

export const convertIMEIToStix = (instance: StoreCyberObservable): SCO.StixIMEI => {
  assertType(ENTITY_IMEI, instance.entity_type);
  return {
    ...buildStixCyberObservable(instance),
    value: instance.value,
    labels: (instance[INPUT_LABELS] ?? []).map((m) => m.value),
    description: instance.x_opencti_description,
    score: instance.x_opencti_score,
    created_by_ref: instance[INPUT_CREATED_BY]?.standard_id,
    external_references: buildExternalReferences(instance),
  };
};

export const convertICCIDToStix = (instance: StoreCyberObservable): SCO.StixICCID => {
  assertType(ENTITY_ICCID, instance.entity_type);
  return {
    ...buildStixCyberObservable(instance),
    value: instance.value,
    labels: (instance[INPUT_LABELS] ?? []).map((m) => m.value),
    description: instance.x_opencti_description,
    score: instance.x_opencti_score,
    created_by_ref: instance[INPUT_CREATED_BY]?.standard_id,
    external_references: buildExternalReferences(instance),
  };
};

export const convertIMSIToStix = (instance: StoreCyberObservable): SCO.StixIMSI => {
  assertType(ENTITY_IMSI, instance.entity_type);
  return {
    ...buildStixCyberObservable(instance),
    value: instance.value,
    labels: (instance[INPUT_LABELS] ?? []).map((m) => m.value),
    description: instance.x_opencti_description,
    score: instance.x_opencti_score,
    created_by_ref: instance[INPUT_CREATED_BY]?.standard_id,
    external_references: buildExternalReferences(instance),
  };
};
