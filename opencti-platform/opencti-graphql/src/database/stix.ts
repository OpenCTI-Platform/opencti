import * as R from 'ramda';
import { version as uuidVersion } from 'uuid';
import uuidTime from 'uuid-time';
import {
  ENTITY_TYPE_ATTACK_PATTERN,
  ENTITY_TYPE_CAMPAIGN,
  ENTITY_TYPE_CONTAINER_NOTE,
  ENTITY_TYPE_CONTAINER_OBSERVED_DATA,
  ENTITY_TYPE_CONTAINER_OPINION,
  ENTITY_TYPE_CONTAINER_REPORT,
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
  ENTITY_MUTEX,
  ENTITY_NETWORK_TRAFFIC,
  ENTITY_PROCESS,
  ENTITY_SOFTWARE,
  ENTITY_URL,
  ENTITY_USER_ACCOUNT,
  ENTITY_WINDOWS_REGISTRY_KEY,
  ENTITY_WINDOWS_REGISTRY_VALUE_TYPE,
  ENTITY_X509_V3_EXTENSIONS_TYPE,
  ENTITY_CRYPTOGRAPHIC_KEY,
  ENTITY_CRYPTOGRAPHIC_WALLET,
  ENTITY_HOSTNAME,
  ENTITY_TEXT,
  ENTITY_USER_AGENT,
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
  RELATION_COOPERATES_WITH,
  RELATION_RELATED_TO,
  RELATION_REMEDIATES,
  RELATION_RESOLVES_TO,
  RELATION_REVOKED_BY,
  RELATION_SUBTECHNIQUE_OF,
  RELATION_TARGETS,
  RELATION_USES,
  RELATION_VARIANT_OF, RELATION_PARTICIPATES_IN
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
import { ABSTRACT_STIX_CYBER_OBSERVABLE } from '../schema/general';
import {
  ENTITY_TYPE_EXTERNAL_REFERENCE,
  ENTITY_TYPE_KILL_CHAIN_PHASE,
  ENTITY_TYPE_LABEL,
  ENTITY_TYPE_MARKING_DEFINITION,
} from '../schema/stixMetaObject';
import { stixHashesToInput } from '../schema/fieldDataAdapter';
import { generateStandardId, normalizeName } from '../schema/identifier';
import type { StixCyberObject, StixDomainObject, StixObject } from '../types/stix-common';
import { STIX_EXT_MITRE, STIX_EXT_OCTI, STIX_EXT_OCTI_SCO } from '../types/stix-extensions';
import type {
  StixExternalReference,
  StixInternalExternalReference,
  StixKillChainPhase, StixLabel,
  StixMarkingDefinition
} from '../types/stix-smo';
import type {
  ArtifactAddInput,
  AttackPatternAddInput,
  AutonomousSystemAddInput,
  CampaignAddInput,
  CityAddInput,
  CountryAddInput,
  CourseOfActionAddInput,
  DirectoryAddInput,
  DomainNameAddInput,
  EmailAddrAddInput,
  EmailMessageAddInput,
  ExternalReferenceAddInput,
  IncidentAddInput,
  IndicatorAddInput,
  IndividualAddInput,
  InfrastructureAddInput,
  IntrusionSetAddInput,
  IPv4AddrAddInput,
  IPv6AddrAddInput,
  KillChainPhaseAddInput,
  LabelAddInput,
  MacAddrAddInput,
  MalwareAddInput,
  MarkingDefinitionAddInput,
  MutationStixCyberObservableAddArgs,
  MutexAddInput,
  NetworkTrafficAddInput,
  NoteAddInput,
  ObservedDataAddInput,
  OpinionAddInput,
  OrganizationAddInput,
  PositionAddInput,
  ProcessAddInput,
  RegionAddInput,
  ReportAddInput,
  SectorAddInput,
  SoftwareAddInput,
  StixCoreRelationshipAddInput,
  StixFileAddInput,
  StixSightingRelationshipAddInput,
  SystemAddInput,
  ThreatActorAddInput,
  ToolAddInput,
  UrlAddInput,
  UserAccountAddInput,
  VulnerabilityAddInput,
  WindowsRegistryKeyAddInput,
  X509CertificateAddInput,
  CryptographicKeyAddInput,
  CryptocurrencyWalletAddInput,
  HostnameAddInput,
  TextAddInput,
  UserAgentAddInput,
  EmailMimePartTypeAddInput,
  WindowsRegistryValueTypeAddInput,
} from '../generated/graphql';
import type { StixRelation, StixSighting } from '../types/stix-sro';
import type {
  StixAttackPattern,
  StixCampaign,
  StixCourseOfAction,
  StixIdentity,
  StixIncident,
  StixIndicator,
  StixInfrastructure,
  StixIntrusionSet,
  StixLocation,
  StixMalware,
  StixNote,
  StixObservedData,
  StixOpinion,
  StixReport,
  StixThreatActor,
  StixTool,
  StixVulnerability
} from '../types/stix-sdo';
import type {
  StixArtifact,
  StixAutonomousSystem, StixCryptocurrencyWallet, StixCryptographicKey,
  StixDirectory,
  StixDomainName,
  StixEmailAddress,
  StixEmailMessage,
  StixFile, StixHostname,
  StixIPv4Address,
  StixIPv6Address,
  StixMacAddress,
  StixMutex,
  StixNetworkTraffic,
  StixProcess, StixSoftware, StixText, StixURL, StixUserAccount, StixUserAgent, StixWindowsRegistryKey,
  StixX509Certificate,
  StixExtendedObservable, StixEmailBodyMultipart, StixWindowsRegistryValueType
} from '../types/stix-sco';
import { UnsupportedError } from '../config/errors';

const MAX_TRANSIENT_STIX_IDS = 200;
export const STIX_SPEC_VERSION = '2.1';

const buildExternalRefs = (element: StixDomainObject | { external_references: Array<StixInternalExternalReference> }) => {
  return (element.external_references ?? []).map((v) => generateStandardId(ENTITY_TYPE_EXTERNAL_REFERENCE, v));
};

const buildKillChainRefs = (element: StixAttackPattern | StixIndicator | StixInfrastructure | StixMalware | StixTool) => {
  return (element.kill_chain_phases ?? []).map((v) => generateStandardId(ENTITY_TYPE_KILL_CHAIN_PHASE, v));
};

const buildLabelRefs = (element: StixDomainObject) => {
  return (element.labels ?? []).map((v) => generateStandardId(ENTITY_TYPE_LABEL, { value: normalizeName(v) }));
};

const buildObservableInputFromExtension = (stix: StixCyberObject): MutationStixCyberObservableAddArgs => {
  return {
    stix_id: stix.id,
    // createIndicator - Indicator will be created through stream if needed.
    type: stix.extensions[STIX_EXT_OCTI].type,
    objectMarking: stix.object_marking_refs,
    createdBy: stix.extensions[STIX_EXT_OCTI_SCO]?.created_by_ref,
    objectLabel: stix.extensions[STIX_EXT_OCTI_SCO]?.labels,
    x_opencti_score: stix.extensions[STIX_EXT_OCTI_SCO]?.score,
    x_opencti_description: stix.extensions[STIX_EXT_OCTI_SCO]?.description,
    externalReferences: buildExternalRefs(stix.extensions[STIX_EXT_OCTI_SCO] ?? {}),
    update: true
  };
};

const buildObservableInputFromStix = (stix: StixExtendedObservable): MutationStixCyberObservableAddArgs => {
  return {
    stix_id: stix.id,
    // createIndicator - Indicator will be created through stream if needed.
    type: stix.extensions[STIX_EXT_OCTI].type,
    createdBy: stix.created_by_ref,
    externalReferences: buildExternalRefs(stix),
    objectLabel: stix.labels,
    objectMarking: stix.object_marking_refs,
    x_opencti_description: stix.description,
    x_opencti_score: stix.score,
    update: true
  };
};

export const buildInputDataFromStix = (stix: StixObject): unknown => {
  const { type } = stix.extensions[STIX_EXT_OCTI];
  if (isStixCoreRelationship(type)) {
    const relationship = stix as StixRelation;
    // noinspection UnnecessaryLocalVariableJS
    const input:StixCoreRelationshipAddInput = {
      confidence: relationship.confidence,
      created: relationship.created,
      createdBy: relationship.created_by_ref,
      description: relationship.description,
      externalReferences: buildExternalRefs(relationship),
      fromId: relationship.source_ref,
      // killChainPhases: undefined, // TODO JRI What about killChainPhases?
      lang: relationship.lang,
      modified: relationship.modified,
      objectLabel: buildLabelRefs(relationship),
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
    // noinspection UnnecessaryLocalVariableJS
    const input:StixSightingRelationshipAddInput = {
      attribute_count: sightingRelationship.count,
      confidence: sightingRelationship.confidence,
      created: sightingRelationship.created,
      createdBy: sightingRelationship.created_by_ref,
      description: sightingRelationship.description,
      externalReferences: buildExternalRefs(sightingRelationship),
      first_seen: sightingRelationship.first_seen,
      fromId: sightingRelationship.sighting_of_ref,
      toId: R.head(sightingRelationship.where_sighted_refs),
      last_seen: sightingRelationship.last_seen,
      modified: sightingRelationship.modified,
      objectLabel: buildLabelRefs(sightingRelationship),
      objectMarking: sightingRelationship.object_marking_refs,
      stix_id: sightingRelationship.id,
      x_opencti_negative: sightingRelationship.extensions[STIX_EXT_OCTI].negative,
      x_opencti_stix_ids: sightingRelationship.extensions[STIX_EXT_OCTI].stix_ids,
      update: true
    };
    return input;
  }
  // region Meta
  if (type === ENTITY_TYPE_LABEL) {
    const label = stix as StixLabel;
    // noinspection UnnecessaryLocalVariableJS
    const input:LabelAddInput = {
      stix_id: label.id,
      value: label.value,
      color: label.color,
      x_opencti_stix_ids: label.extensions[STIX_EXT_OCTI].stix_ids,
      update: true
    };
    return input;
  }
  if (type === ENTITY_TYPE_KILL_CHAIN_PHASE) {
    const kill = stix as StixKillChainPhase;
    // noinspection UnnecessaryLocalVariableJS
    const input:KillChainPhaseAddInput = {
      stix_id: kill.id,
      kill_chain_name: kill.kill_chain_name,
      phase_name: kill.phase_name,
      x_opencti_order: kill.order,
      x_opencti_stix_ids: kill.extensions[STIX_EXT_OCTI].stix_ids,
      update: true,
    };
    return input;
  }
  if (type === ENTITY_TYPE_EXTERNAL_REFERENCE) {
    const ref = stix as StixExternalReference;
    // noinspection UnnecessaryLocalVariableJS
    const input:ExternalReferenceAddInput = {
      stix_id: ref.id,
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
  if (type === ENTITY_TYPE_MARKING_DEFINITION) {
    const markingDef = stix as StixMarkingDefinition;
    // noinspection UnnecessaryLocalVariableJS
    const input:MarkingDefinitionAddInput = {
      stix_id: markingDef.id,
      created: markingDef.created,
      definition: markingDef.name,
      definition_type: markingDef.definition_type,
      modified: markingDef.modified,
      x_opencti_order: markingDef.extensions[STIX_EXT_OCTI].order,
      x_opencti_color: markingDef.extensions[STIX_EXT_OCTI].color,
      x_opencti_stix_ids: markingDef.extensions[STIX_EXT_OCTI].stix_ids,
      update: true
    };
    return input;
  }
  // endregion
  // region Entities
  if (type === ENTITY_TYPE_ATTACK_PATTERN) {
    const attack = stix as StixAttackPattern;
    // noinspection UnnecessaryLocalVariableJS
    const input:AttackPatternAddInput = {
      stix_id: attack.id,
      aliases: attack.aliases,
      confidence: attack.confidence,
      created: attack.created,
      createdBy: attack.created_by_ref,
      description: attack.description,
      externalReferences: buildExternalRefs(attack),
      killChainPhases: buildKillChainRefs(attack),
      lang: attack.lang,
      modified: attack.modified,
      name: attack.name,
      objectLabel: buildLabelRefs(attack),
      objectMarking: attack.object_marking_refs,
      revoked: attack.revoked,
      x_mitre_id: attack.extensions[STIX_EXT_MITRE]?.id,
      x_mitre_detection: attack.extensions[STIX_EXT_MITRE]?.detection,
      x_mitre_permissions_required: attack.extensions[STIX_EXT_MITRE]?.permissions_required,
      x_mitre_platforms: attack.extensions[STIX_EXT_MITRE]?.platforms,
      x_opencti_stix_ids: attack.extensions[STIX_EXT_OCTI].stix_ids,
      update: true,
    };
    return input;
  }
  if (type === ENTITY_TYPE_CAMPAIGN) {
    const campaign = stix as StixCampaign;
    // noinspection UnnecessaryLocalVariableJS
    const input:CampaignAddInput = {
      stix_id: campaign.id,
      aliases: campaign.aliases,
      confidence: campaign.confidence,
      created: campaign.created,
      createdBy: campaign.created_by_ref,
      description: campaign.description,
      externalReferences: buildExternalRefs(campaign),
      first_seen: campaign.first_seen,
      lang: campaign.lang,
      last_seen: campaign.last_seen,
      modified: campaign.modified,
      name: campaign.name,
      objectLabel: buildLabelRefs(campaign),
      objectMarking: campaign.object_marking_refs,
      objective: campaign.objective,
      revoked: campaign.revoked,
      x_opencti_stix_ids: campaign.extensions[STIX_EXT_OCTI].stix_ids,
      update: true
    };
    return input;
  }
  if (type === ENTITY_TYPE_CONTAINER_NOTE) {
    const note = stix as StixNote;
    // noinspection UnnecessaryLocalVariableJS
    const input:NoteAddInput = {
      stix_id: note.id,
      attribute_abstract: note.abstract,
      authors: note.authors,
      confidence: note.confidence,
      content: note.content,
      created: note.created,
      createdBy: note.created_by_ref,
      externalReferences: buildExternalRefs(note),
      lang: note.lang,
      modified: note.modified,
      objectLabel: buildLabelRefs(note),
      objectMarking: note.object_marking_refs,
      objects: note.object_refs,
      revoked: note.revoked,
      x_opencti_stix_ids: note.extensions[STIX_EXT_OCTI].stix_ids,
      update: true
    };
    return input;
  }
  if (type === ENTITY_TYPE_CONTAINER_OBSERVED_DATA) {
    const observed = stix as StixObservedData;
    // noinspection UnnecessaryLocalVariableJS
    const input:ObservedDataAddInput = {
      stix_id: observed.id,
      confidence: observed.confidence,
      created: observed.created,
      createdBy: observed.created_by_ref,
      externalReferences: buildExternalRefs(observed),
      first_observed: observed.first_observed,
      lang: observed.lang,
      last_observed: observed.last_observed,
      modified: observed.modified,
      number_observed: observed.number_observed,
      objectLabel: buildLabelRefs(observed),
      objectMarking: observed.object_marking_refs,
      objects: observed.object_refs,
      revoked: observed.revoked,
      x_opencti_stix_ids: observed.extensions[STIX_EXT_OCTI].stix_ids,
      update: true
    };
    return input;
  }
  if (type === ENTITY_TYPE_CONTAINER_OPINION) {
    const opinion = stix as StixOpinion;
    // noinspection UnnecessaryLocalVariableJS
    const input:OpinionAddInput = {
      stix_id: opinion.id,
      authors: opinion.authors,
      confidence: opinion.confidence,
      created: opinion.created,
      createdBy: opinion.created_by_ref,
      explanation: opinion.explanation,
      externalReferences: buildExternalRefs(opinion),
      lang: opinion.lang,
      modified: opinion.modified,
      objectLabel: buildLabelRefs(opinion),
      objectMarking: opinion.object_marking_refs,
      objects: opinion.object_refs,
      opinion: opinion.opinion,
      revoked: opinion.revoked,
      x_opencti_stix_ids: opinion.extensions[STIX_EXT_OCTI].stix_ids,
      update: true
    };
    return input;
  }
  if (type === ENTITY_TYPE_CONTAINER_REPORT) {
    const report = stix as StixReport;
    // noinspection UnnecessaryLocalVariableJS
    const input:ReportAddInput = {
      stix_id: report.id,
      confidence: report.confidence,
      created: report.created,
      createdBy: report.created_by_ref,
      description: report.description,
      externalReferences: buildExternalRefs(report),
      lang: report.lang,
      modified: report.modified,
      name: report.name,
      objectLabel: buildLabelRefs(report),
      objectMarking: report.object_marking_refs,
      objects: report.object_refs,
      published: report.published,
      report_types: report.report_types,
      revoked: report.revoked,
      x_opencti_stix_ids: report.extensions[STIX_EXT_OCTI].stix_ids,
      update: true
    };
    return input;
  }
  if (type === ENTITY_TYPE_COURSE_OF_ACTION) {
    const action = stix as StixCourseOfAction;
    // noinspection UnnecessaryLocalVariableJS
    const input:CourseOfActionAddInput = {
      stix_id: action.id,
      confidence: action.confidence,
      created: action.created,
      createdBy: action.created_by_ref,
      description: action.description,
      externalReferences: buildExternalRefs(action),
      lang: action.lang,
      modified: action.modified,
      name: action.name,
      objectLabel: buildLabelRefs(action),
      objectMarking: action.object_marking_refs,
      revoked: action.revoked,
      x_mitre_id: action.extensions[STIX_EXT_MITRE]?.id,
      x_opencti_aliases: action.extensions[STIX_EXT_OCTI].aliases,
      x_opencti_stix_ids: action.extensions[STIX_EXT_OCTI].stix_ids,
      update: true,
    };
    return input;
  }
  if (type === ENTITY_TYPE_IDENTITY_INDIVIDUAL) {
    const individual = stix as StixIdentity;
    // noinspection UnnecessaryLocalVariableJS
    const input:IndividualAddInput = {
      stix_id: individual.id,
      confidence: individual.confidence,
      contact_information: individual.contact_information,
      created: individual.created,
      createdBy: individual.created_by_ref,
      description: individual.description,
      externalReferences: buildExternalRefs(individual),
      lang: individual.lang,
      modified: individual.modified,
      name: individual.name,
      objectLabel: buildLabelRefs(individual),
      objectMarking: individual.object_marking_refs,
      revoked: individual.revoked,
      roles: individual.roles,
      x_opencti_aliases: individual.extensions[STIX_EXT_OCTI].aliases,
      x_opencti_firstname: individual.extensions[STIX_EXT_OCTI].firstname,
      x_opencti_lastname: individual.extensions[STIX_EXT_OCTI].lastname,
      x_opencti_stix_ids: individual.extensions[STIX_EXT_OCTI].stix_ids,
      update: true
    };
    return input;
  }
  if (type === ENTITY_TYPE_IDENTITY_ORGANIZATION) {
    const organization = stix as StixIdentity;
    // noinspection UnnecessaryLocalVariableJS
    const input:OrganizationAddInput = {
      stix_id: organization.id,
      confidence: organization.confidence,
      contact_information: organization.contact_information,
      created: organization.created,
      createdBy: organization.created_by_ref,
      description: organization.description,
      externalReferences: buildExternalRefs(organization),
      lang: organization.lang,
      modified: organization.modified,
      name: organization.name,
      objectLabel: buildLabelRefs(organization),
      objectMarking: organization.object_marking_refs,
      revoked: organization.revoked,
      roles: organization.roles,
      x_opencti_aliases: organization.extensions[STIX_EXT_OCTI].aliases,
      x_opencti_organization_type: organization.extensions[STIX_EXT_OCTI].organization_type,
      x_opencti_reliability: organization.extensions[STIX_EXT_OCTI].reliability,
      x_opencti_stix_ids: organization.extensions[STIX_EXT_OCTI].stix_ids,
      update: true
    };
    return input;
  }
  if (type === ENTITY_TYPE_IDENTITY_SECTOR) {
    const sector = stix as StixIdentity;
    // noinspection UnnecessaryLocalVariableJS
    const input:SectorAddInput = {
      stix_id: sector.id,
      confidence: sector.confidence,
      contact_information: sector.contact_information,
      created: sector.created,
      createdBy: sector.created_by_ref,
      description: sector.description,
      externalReferences: buildExternalRefs(sector),
      lang: sector.lang,
      modified: sector.modified,
      name: sector.name,
      objectLabel: buildLabelRefs(sector),
      objectMarking: sector.object_marking_refs,
      revoked: sector.revoked,
      roles: sector.roles,
      x_opencti_aliases: sector.extensions[STIX_EXT_OCTI].aliases,
      x_opencti_stix_ids: sector.extensions[STIX_EXT_OCTI].stix_ids,
      update: true
    };
    return input;
  }
  if (type === ENTITY_TYPE_IDENTITY_SYSTEM) {
    const system = stix as StixIdentity;
    // noinspection UnnecessaryLocalVariableJS
    const input:SystemAddInput = {
      stix_id: system.id,
      confidence: system.confidence,
      contact_information: system.contact_information,
      created: system.created,
      createdBy: system.created_by_ref,
      description: system.description,
      externalReferences: buildExternalRefs(system),
      lang: system.lang,
      modified: system.modified,
      name: system.name,
      objectLabel: buildLabelRefs(system),
      objectMarking: system.object_marking_refs,
      revoked: system.revoked,
      roles: system.roles,
      x_opencti_aliases: system.extensions[STIX_EXT_OCTI].aliases,
      x_opencti_firstname: system.extensions[STIX_EXT_OCTI].firstname,
      x_opencti_lastname: system.extensions[STIX_EXT_OCTI].lastname,
      x_opencti_stix_ids: system.extensions[STIX_EXT_OCTI].stix_ids,
      update: true
    };
    return input;
  }
  if (type === ENTITY_TYPE_INDICATOR) {
    const indicator = stix as StixIndicator;
    // noinspection UnnecessaryLocalVariableJS
    const input:IndicatorAddInput = {
      stix_id: indicator.id,
      confidence: indicator.confidence,
      createObservables: false, // Indicator will be created by the stream if needed
      created: indicator.created,
      createdBy: indicator.created_by_ref,
      description: indicator.description,
      externalReferences: buildExternalRefs(indicator),
      indicator_types: indicator.indicator_types,
      killChainPhases: buildKillChainRefs(indicator),
      lang: indicator.lang,
      modified: indicator.modified,
      name: indicator.name,
      objectLabel: buildLabelRefs(indicator),
      objectMarking: indicator.object_marking_refs,
      pattern: indicator.pattern,
      pattern_type: indicator.pattern_type,
      pattern_version: indicator.pattern_version,
      revoked: indicator.revoked,
      valid_from: indicator.valid_from,
      valid_until: indicator.valid_until,
      x_mitre_platforms: indicator.extensions[STIX_EXT_MITRE]?.platforms,
      x_opencti_detection: indicator.extensions[STIX_EXT_OCTI].detection,
      x_opencti_main_observable_type: indicator.extensions[STIX_EXT_OCTI].main_observable_type,
      x_opencti_score: indicator.extensions[STIX_EXT_OCTI].score,
      x_opencti_stix_ids: indicator.extensions[STIX_EXT_OCTI].stix_ids,
      update: true
    };
    return input;
  }
  if (type === ENTITY_TYPE_INFRASTRUCTURE) {
    const infra = stix as StixInfrastructure;
    // noinspection UnnecessaryLocalVariableJS
    const input:InfrastructureAddInput = {
      stix_id: infra.id,
      aliases: infra.aliases,
      confidence: infra.confidence,
      created: infra.created,
      createdBy: infra.created_by_ref,
      description: infra.description,
      externalReferences: buildExternalRefs(infra),
      first_seen: infra.first_seen,
      infrastructure_types: infra.infrastructure_types,
      killChainPhases: buildKillChainRefs(infra),
      lang: infra.lang,
      last_seen: infra.last_seen,
      modified: infra.modified,
      name: infra.name,
      objectLabel: buildLabelRefs(infra),
      objectMarking: infra.object_marking_refs,
      revoked: infra.revoked,
      x_opencti_stix_ids: infra.extensions[STIX_EXT_OCTI].stix_ids,
      update: true
    };
    return input;
  }
  if (type === ENTITY_TYPE_INTRUSION_SET) {
    const intrusion = stix as StixIntrusionSet;
    // noinspection UnnecessaryLocalVariableJS
    const input:IntrusionSetAddInput = {
      stix_id: intrusion.id,
      aliases: intrusion.aliases,
      confidence: intrusion.confidence,
      created: intrusion.created,
      createdBy: intrusion.created_by_ref,
      description: intrusion.description,
      externalReferences: buildExternalRefs(intrusion),
      first_seen: intrusion.first_seen,
      goals: intrusion.goals,
      lang: intrusion.lang,
      last_seen: intrusion.last_seen,
      modified: intrusion.modified,
      name: intrusion.name,
      objectLabel: buildLabelRefs(intrusion),
      objectMarking: intrusion.object_marking_refs,
      primary_motivation: intrusion.primary_motivation,
      resource_level: intrusion.resource_level,
      revoked: intrusion.revoked,
      secondary_motivations: intrusion.secondary_motivations,
      x_opencti_stix_ids: intrusion.extensions[STIX_EXT_OCTI].stix_ids,
      update: true
    };
    return input;
  }
  if (type === ENTITY_TYPE_LOCATION_CITY) {
    const location = stix as StixLocation;
    // noinspection UnnecessaryLocalVariableJS
    const input:CityAddInput = {
      stix_id: location.id,
      confidence: location.confidence,
      created: location.created,
      createdBy: location.created_by_ref,
      description: location.description,
      externalReferences: buildExternalRefs(location),
      lang: location.lang,
      latitude: location.latitude,
      longitude: location.longitude,
      modified: location.modified,
      name: location.name,
      objectLabel: buildLabelRefs(location),
      objectMarking: location.object_marking_refs,
      precision: location.precision,
      revoked: location.revoked,
      x_opencti_aliases: location.extensions[STIX_EXT_OCTI].aliases,
      x_opencti_stix_ids: location.extensions[STIX_EXT_OCTI].stix_ids,
      update: true
    };
    return input;
  }
  if (type === ENTITY_TYPE_LOCATION_COUNTRY) {
    const location = stix as StixLocation;
    // noinspection UnnecessaryLocalVariableJS
    const input:CountryAddInput = {
      stix_id: location.id,
      confidence: location.confidence,
      created: location.created,
      createdBy: location.created_by_ref,
      description: location.description,
      externalReferences: buildExternalRefs(location),
      lang: location.lang,
      latitude: location.latitude,
      longitude: location.longitude,
      modified: location.modified,
      name: location.name,
      objectLabel: buildLabelRefs(location),
      objectMarking: location.object_marking_refs,
      precision: location.precision,
      revoked: location.revoked,
      x_opencti_aliases: location.extensions[STIX_EXT_OCTI].aliases,
      x_opencti_stix_ids: location.extensions[STIX_EXT_OCTI].stix_ids,
      update: true
    };
    return input;
  }
  if (type === ENTITY_TYPE_LOCATION_REGION) {
    const location = stix as StixLocation;
    // noinspection UnnecessaryLocalVariableJS
    const input:RegionAddInput = {
      stix_id: location.id,
      confidence: location.confidence,
      created: location.created,
      createdBy: location.created_by_ref,
      description: location.description,
      externalReferences: buildExternalRefs(location),
      lang: location.lang,
      latitude: location.latitude,
      longitude: location.longitude,
      modified: location.modified,
      name: location.name,
      objectLabel: buildLabelRefs(location),
      objectMarking: location.object_marking_refs,
      precision: location.precision,
      revoked: location.revoked,
      x_opencti_aliases: location.extensions[STIX_EXT_OCTI].aliases,
      x_opencti_stix_ids: location.extensions[STIX_EXT_OCTI].stix_ids,
      update: true
    };
    return input;
  }
  if (type === ENTITY_TYPE_LOCATION_POSITION) {
    const location = stix as StixLocation;
    // noinspection UnnecessaryLocalVariableJS
    const input:PositionAddInput = {
      stix_id: location.id,
      confidence: location.confidence,
      created: location.created,
      createdBy: location.created_by_ref,
      description: location.description,
      externalReferences: buildExternalRefs(location),
      lang: location.lang,
      latitude: location.latitude,
      longitude: location.longitude,
      modified: location.modified,
      name: location.name,
      objectLabel: buildLabelRefs(location),
      objectMarking: location.object_marking_refs,
      precision: location.precision,
      revoked: location.revoked,
      x_opencti_aliases: location.extensions[STIX_EXT_OCTI].aliases,
      x_opencti_stix_ids: location.extensions[STIX_EXT_OCTI].stix_ids,
      update: true
    };
    return input;
  }
  if (type === ENTITY_TYPE_MALWARE) {
    const malware = stix as StixMalware;
    // noinspection UnnecessaryLocalVariableJS
    const input:MalwareAddInput = {
      stix_id: malware.id,
      aliases: malware.aliases,
      architecture_execution_envs: malware.architecture_execution_envs,
      capabilities: malware.capabilities,
      confidence: malware.confidence,
      created: malware.created,
      createdBy: malware.created_by_ref,
      description: malware.description,
      externalReferences: buildExternalRefs(malware),
      first_seen: malware.first_seen,
      implementation_languages: malware.implementation_languages,
      is_family: malware.is_family,
      killChainPhases: buildKillChainRefs(malware),
      lang: malware.lang,
      last_seen: malware.last_seen,
      malware_types: malware.malware_types,
      modified: malware.modified,
      name: malware.name,
      objectLabel: buildLabelRefs(malware),
      objectMarking: malware.object_marking_refs,
      revoked: malware.revoked,
      x_opencti_stix_ids: malware.extensions[STIX_EXT_OCTI].stix_ids,
      update: true
    };
    return input;
  }
  if (type === ENTITY_TYPE_THREAT_ACTOR) {
    const threat = stix as StixThreatActor;
    // noinspection UnnecessaryLocalVariableJS
    const input:ThreatActorAddInput = {
      stix_id: threat.id,
      aliases: threat.aliases,
      confidence: threat.confidence,
      created: threat.created,
      createdBy: threat.created_by_ref,
      description: threat.description,
      externalReferences: buildExternalRefs(threat),
      first_seen: threat.first_seen,
      goals: threat.goals,
      lang: threat.lang,
      last_seen: threat.last_seen,
      modified: threat.modified,
      name: threat.name,
      objectLabel: buildLabelRefs(threat),
      objectMarking: threat.object_marking_refs,
      personal_motivations: threat.personal_motivations,
      primary_motivation: threat.primary_motivation,
      resource_level: threat.resource_level,
      revoked: threat.revoked,
      secondary_motivations: threat.secondary_motivations,
      sophistication: threat.sophistication,
      threat_actor_types: threat.threat_actor_types,
      x_opencti_stix_ids: threat.extensions[STIX_EXT_OCTI].stix_ids,
      update: true
    };
    return input;
  }
  if (type === ENTITY_TYPE_TOOL) {
    const tool = stix as StixTool;
    // noinspection UnnecessaryLocalVariableJS
    const input:ToolAddInput = {
      stix_id: tool.id,
      aliases: tool.aliases,
      confidence: tool.confidence,
      created: tool.created,
      createdBy: tool.created_by_ref,
      description: tool.description,
      externalReferences: buildExternalRefs(tool),
      killChainPhases: buildKillChainRefs(tool),
      lang: tool.lang,
      modified: tool.modified,
      name: tool.name,
      objectLabel: buildLabelRefs(tool),
      objectMarking: tool.object_marking_refs,
      revoked: tool.revoked,
      tool_types: tool.tool_types,
      tool_version: tool.tool_version,
      x_opencti_stix_ids: tool.extensions[STIX_EXT_OCTI].stix_ids,
      update: true
    };
    return input;
  }
  if (type === ENTITY_TYPE_VULNERABILITY) {
    const vulnerability = stix as StixVulnerability;
    // noinspection UnnecessaryLocalVariableJS
    const input:VulnerabilityAddInput = {
      stix_id: vulnerability.id,
      confidence: vulnerability.confidence,
      created: vulnerability.created,
      createdBy: vulnerability.created_by_ref,
      description: vulnerability.description,
      externalReferences: buildExternalRefs(vulnerability),
      lang: vulnerability.lang,
      modified: vulnerability.modified,
      name: vulnerability.name,
      objectLabel: buildLabelRefs(vulnerability),
      objectMarking: vulnerability.object_marking_refs,
      revoked: vulnerability.revoked,
      x_opencti_attack_vector: vulnerability.extensions[STIX_EXT_OCTI].attack_vector,
      x_opencti_availability_impact: vulnerability.extensions[STIX_EXT_OCTI].availability_impact,
      x_opencti_base_score: vulnerability.extensions[STIX_EXT_OCTI].base_score,
      x_opencti_base_severity: vulnerability.extensions[STIX_EXT_OCTI].base_severity,
      x_opencti_confidentiality_impact: vulnerability.extensions[STIX_EXT_OCTI].confidentiality_impact,
      x_opencti_integrity_impact: vulnerability.extensions[STIX_EXT_OCTI].integrity_impact,
      x_opencti_stix_ids: vulnerability.extensions[STIX_EXT_OCTI].stix_ids,
      update: true
    };
    return input;
  }
  if (type === ENTITY_TYPE_INCIDENT) {
    const incident = stix as StixIncident;
    // noinspection UnnecessaryLocalVariableJS
    const input:IncidentAddInput = {
      stix_id: incident.id,
      aliases: incident.aliases,
      confidence: incident.confidence,
      created: incident.created,
      createdBy: incident.created_by_ref,
      description: incident.description,
      externalReferences: buildExternalRefs(incident),
      first_seen: incident.first_seen,
      lang: incident.lang,
      last_seen: incident.last_seen,
      modified: incident.modified,
      name: incident.name,
      objectLabel: buildLabelRefs(incident),
      objectMarking: incident.object_marking_refs,
      objective: incident.objective,
      revoked: incident.revoked,
      x_opencti_stix_ids: incident.extensions[STIX_EXT_OCTI].stix_ids,
      update: true
    };
    return input;
  }
  // endregion
  // region Observables
  if (type === ENTITY_AUTONOMOUS_SYSTEM) {
    const auto = stix as StixAutonomousSystem;
    const input:AutonomousSystemAddInput = { name: auto.name, number: auto.number, rir: auto.rir };
    return { ...buildObservableInputFromExtension(auto), AutonomousSystem: input } as MutationStixCyberObservableAddArgs;
  }
  if (type === ENTITY_DIRECTORY) {
    const directory = stix as StixDirectory;
    const input:DirectoryAddInput = {
      atime: directory.atime,
      ctime: directory.ctime,
      mtime: directory.mtime,
      path: directory.path,
      path_enc: directory.path_enc
    };
    return { ...buildObservableInputFromExtension(directory), Directory: input } as MutationStixCyberObservableAddArgs;
  }
  if (type === ENTITY_DOMAIN_NAME) {
    const domain = stix as StixDomainName;
    const input:DomainNameAddInput = { value: domain.value };
    return { ...buildObservableInputFromExtension(domain), DomainName: input } as MutationStixCyberObservableAddArgs;
  }
  if (type === ENTITY_EMAIL_ADDR) {
    const email = stix as StixEmailAddress;
    const input:EmailAddrAddInput = {
      display_name: email.display_name,
      value: email.value
    };
    return { ...buildObservableInputFromExtension(email), EmailAddr: input } as MutationStixCyberObservableAddArgs;
  }
  if (type === ENTITY_EMAIL_MESSAGE) {
    const message = stix as StixEmailMessage;
    const input:EmailMessageAddInput = {
      attribute_date: message.date,
      body: message.body,
      content_type: message.content_type,
      is_multipart: message.is_multipart,
      message_id: message.message_id,
      received_lines: message.received_lines,
      subject: message.subject
    };
    return { ...buildObservableInputFromExtension(message), EmailMessage: input } as MutationStixCyberObservableAddArgs;
  }
  if (type === ENTITY_EMAIL_MIME_PART_TYPE) {
    const part = stix as StixEmailBodyMultipart;
    const input:EmailMimePartTypeAddInput = {
      body: part.body,
      content_disposition: part.content_disposition,
      content_type: part.content_type
    };
    return { ...buildObservableInputFromStix(part), EmailMimePartType: input } as MutationStixCyberObservableAddArgs;
  }
  if (type === ENTITY_HASHED_OBSERVABLE_ARTIFACT) {
    const artifact = stix as StixArtifact;
    const input:ArtifactAddInput = {
      decryption_key: artifact.decryption_key,
      encryption_algorithm: artifact.encryption_algorithm,
      hashes: stixHashesToInput(artifact),
      mime_type: artifact.mime_type,
      payload_bin: artifact.payload_bin,
      url: artifact.url,
      x_opencti_additional_names: artifact.extensions[STIX_EXT_OCTI_SCO]?.additional_names
    };
    return { ...buildObservableInputFromExtension(artifact), Artifact: input } as MutationStixCyberObservableAddArgs;
  }
  if (type === ENTITY_HASHED_OBSERVABLE_STIX_FILE) {
    const file = stix as StixFile;
    const input:StixFileAddInput = {
      atime: file.atime,
      ctime: file.ctime,
      hashes: stixHashesToInput(file),
      magic_number_hex: file.magic_number_hex,
      mime_type: file.mime_type,
      mtime: file.mtime,
      name: file.name,
      name_enc: file.name_enc,
      size: file.size,
      x_opencti_additional_names: file.extensions[STIX_EXT_OCTI_SCO]?.additional_names
    };
    return { ...buildObservableInputFromExtension(file), StixFile: input } as MutationStixCyberObservableAddArgs;
  }
  if (type === ENTITY_HASHED_OBSERVABLE_X509_CERTIFICATE) {
    const x509 = stix as StixX509Certificate;
    const input:X509CertificateAddInput = {
      hashes: stixHashesToInput(x509),
      is_self_signed: x509.is_self_signed,
      issuer: x509.issuer,
      serial_number: x509.serial_number,
      signature_algorithm: x509.signature_algorithm,
      subject: x509.subject,
      subject_public_key_algorithm: x509.subject_public_key_algorithm,
      subject_public_key_exponent: x509.subject_public_key_exponent,
      subject_public_key_modulus: x509.subject_public_key_modulus,
      validity_not_after: x509.validity_not_after,
      validity_not_before: x509.validity_not_before,
      version: x509.version
    };
    return { ...buildObservableInputFromExtension(x509), X509Certificate: input } as MutationStixCyberObservableAddArgs;
  }
  if (type === ENTITY_IPV4_ADDR) {
    const ipv4 = stix as StixIPv4Address;
    const input:IPv4AddrAddInput = {
      belongsTo: ipv4.belongs_to_refs,
      resolvesTo: ipv4.resolves_to_refs,
      value: ipv4.value
    };
    return { ...buildObservableInputFromExtension(ipv4), IPv4Addr: input } as MutationStixCyberObservableAddArgs;
  }
  if (type === ENTITY_IPV6_ADDR) {
    const ipv6 = stix as StixIPv6Address;
    const input:IPv6AddrAddInput = { value: ipv6.value };
    return { ...buildObservableInputFromExtension(ipv6), IPv6Addr: input } as MutationStixCyberObservableAddArgs;
  }
  if (type === ENTITY_MAC_ADDR) {
    const mac = stix as StixMacAddress;
    const input:MacAddrAddInput = { value: mac.value };
    return { ...buildObservableInputFromExtension(mac), MacAddr: input } as MutationStixCyberObservableAddArgs;
  }
  if (type === ENTITY_MUTEX) {
    const mutex = stix as StixMutex;
    const input:MutexAddInput = { name: mutex.name };
    return { ...buildObservableInputFromExtension(mutex), Mutex: input } as MutationStixCyberObservableAddArgs;
  }
  if (type === ENTITY_NETWORK_TRAFFIC) {
    const traffic = stix as StixNetworkTraffic;
    const input:NetworkTrafficAddInput = {
      dst_byte_count: traffic.dst_byte_count,
      dst_packets: traffic.dst_packets,
      dst_port: traffic.dst_port,
      end: traffic.end,
      is_active: traffic.is_active,
      protocols: traffic.protocols,
      src_byte_count: traffic.src_byte_count,
      src_packets: traffic.src_packets,
      src_port: traffic.src_port,
      start: traffic.start
    };
    return { ...buildObservableInputFromExtension(traffic), NetworkTraffic: input } as MutationStixCyberObservableAddArgs;
  }
  if (type === ENTITY_PROCESS) {
    const process = stix as StixProcess;
    const input:ProcessAddInput = {
      command_line: process.command_line,
      created_time: process.created_time,
      cwd: process.cwd,
      // environment_variables: process.environment_variables,
      is_hidden: process.is_hidden,
      pid: process.pid
    };
    return { ...buildObservableInputFromExtension(process), Process: input } as MutationStixCyberObservableAddArgs;
  }
  if (type === ENTITY_SOFTWARE) {
    const software = stix as StixSoftware;
    const input:SoftwareAddInput = {
      cpe: software.cpe,
      languages: software.languages,
      name: software.name,
      swid: software.swid,
      vendor: software.vendor,
      version: software.version,
    };
    return { ...buildObservableInputFromExtension(software), Software: input } as MutationStixCyberObservableAddArgs;
  }
  if (type === ENTITY_URL) {
    const url = stix as StixURL;
    const input:UrlAddInput = { value: url.value };
    return { ...buildObservableInputFromExtension(url), Url: input } as MutationStixCyberObservableAddArgs;
  }
  if (type === ENTITY_USER_ACCOUNT) {
    const account = stix as StixUserAccount;
    const input:UserAccountAddInput = {
      account_created: account.account_created,
      account_expires: account.account_expires,
      account_first_login: account.account_first_login,
      account_last_login: account.account_last_login,
      account_login: account.account_login,
      account_type: account.account_type,
      can_escalate_privs: account.can_escalate_privs,
      credential: account.credential,
      credential_last_changed: account.credential_last_changed,
      display_name: account.display_name,
      is_disabled: account.is_disabled,
      is_privileged: account.is_privileged,
      is_service_account: account.is_service_account,
      user_id: account.user_id
    };
    return { ...buildObservableInputFromExtension(account), UserAccount: input } as MutationStixCyberObservableAddArgs;
  }
  if (type === ENTITY_WINDOWS_REGISTRY_KEY) {
    const key = stix as StixWindowsRegistryKey;
    const input:WindowsRegistryKeyAddInput = {
      attribute_key: key.key,
      modified_time: key.modified_time,
      number_of_subkeys: key.number_of_subkeys
    };
    return { ...buildObservableInputFromExtension(key), WindowsRegistryKey: input } as MutationStixCyberObservableAddArgs;
  }
  if (type === ENTITY_WINDOWS_REGISTRY_VALUE_TYPE) {
    const valueType = stix as StixWindowsRegistryValueType;
    const input:WindowsRegistryValueTypeAddInput = {
      data: valueType.data,
      data_type: valueType.data_type,
      name: valueType.name
    };
    return { ...buildObservableInputFromStix(valueType), WindowsRegistryValueType: input } as MutationStixCyberObservableAddArgs;
  }
  if (type === ENTITY_X509_V3_EXTENSIONS_TYPE) {
    // TODO JRI x509 v3 extension need to be remove? Sam?
  }
  if (type === ENTITY_CRYPTOGRAPHIC_KEY) {
    const cryptoKey = stix as StixCryptographicKey;
    const input:CryptographicKeyAddInput = { value: cryptoKey.value };
    return { ...buildObservableInputFromStix(cryptoKey), CryptographicKey: input } as MutationStixCyberObservableAddArgs;
  }
  if (type === ENTITY_CRYPTOGRAPHIC_WALLET) {
    const wallet = stix as StixCryptocurrencyWallet;
    const input:CryptocurrencyWalletAddInput = { value: wallet.value };
    return { ...buildObservableInputFromStix(wallet), CryptocurrencyWallet: input } as MutationStixCyberObservableAddArgs;
  }
  if (type === ENTITY_HOSTNAME) {
    const hostname = stix as StixHostname;
    const input:HostnameAddInput = { value: hostname.value };
    return { ...buildObservableInputFromStix(hostname), Hostname: input } as MutationStixCyberObservableAddArgs;
  }
  if (type === ENTITY_TEXT) {
    const text = stix as StixText;
    const input:TextAddInput = { value: text.value };
    return { ...buildObservableInputFromStix(text), Text: input } as MutationStixCyberObservableAddArgs;
  }
  if (type === ENTITY_USER_AGENT) {
    const agent = stix as StixUserAgent;
    const input:UserAgentAddInput = { value: agent.value };
    return { ...buildObservableInputFromStix(agent), UserAgent: input } as MutationStixCyberObservableAddArgs;
  }
  // endregion
  throw UnsupportedError(`Sync of type ${type} is not supported`);
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
  [`${ENTITY_TYPE_THREAT_ACTOR}_${ENTITY_TYPE_CAMPAIGN}`]: [RELATION_PARTICIPATES_IN],
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
  [`${ENTITY_TYPE_THREAT_ACTOR}_${ENTITY_TYPE_THREAT_ACTOR}`]: [RELATION_PART_OF, RELATION_COOPERATES_WITH],
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
  [`${ENTITY_HOSTNAME}_${ENTITY_HASHED_OBSERVABLE_ARTIFACT}`]: [RELATION_DROPS],
  [`${ENTITY_HOSTNAME}_${ENTITY_TYPE_ATTACK_PATTERN}`]: [RELATION_USES],
  [`${ENTITY_HOSTNAME}_${ENTITY_DOMAIN_NAME}`]: [RELATION_COMMUNICATES_WITH],
  [`${ENTITY_HOSTNAME}_${ENTITY_IPV4_ADDR}`]: [RELATION_COMMUNICATES_WITH],
  [`${ENTITY_HOSTNAME}_${ENTITY_IPV6_ADDR}`]: [RELATION_COMMUNICATES_WITH],
  [`${ENTITY_HOSTNAME}_${ENTITY_HASHED_OBSERVABLE_STIX_FILE}`]: [RELATION_DROPS],
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
  [`${ENTITY_EMAIL_ADDR}_${ENTITY_EMAIL_MESSAGE}`]: [RELATION_FROM, RELATION_SENDER, RELATION_TO, RELATION_CC, RELATION_BCC],
  [`${ENTITY_EMAIL_ADDR}_${ENTITY_USER_ACCOUNT}`]: [OBS_RELATION_BELONGS_TO],
  [`${ENTITY_EMAIL_MIME_PART_TYPE}_${ENTITY_EMAIL_MESSAGE}`]: [RELATION_BODY_MULTIPART],
  [`${ENTITY_HASHED_OBSERVABLE_ARTIFACT}_${ENTITY_EMAIL_MESSAGE}`]: [RELATION_RAW_EMAIL],
  [`${ENTITY_HASHED_OBSERVABLE_ARTIFACT}_${ENTITY_EMAIL_MIME_PART_TYPE}`]: [RELATION_BODY_RAW],
  [`${ENTITY_HASHED_OBSERVABLE_ARTIFACT}_${ENTITY_HASHED_OBSERVABLE_STIX_FILE}`]: [OBS_RELATION_CONTENT],
  [`${ENTITY_TYPE_MALWARE}_${ENTITY_HASHED_OBSERVABLE_ARTIFACT}`]: [RELATION_SAMPLE],
  [`${ENTITY_TYPE_MALWARE}_${ENTITY_HASHED_OBSERVABLE_STIX_FILE}`]: [RELATION_SAMPLE],
  [`${ENTITY_HASHED_OBSERVABLE_STIX_FILE}_${ABSTRACT_STIX_CYBER_OBSERVABLE}`]: [RELATION_CONTAINS],
  [`${ENTITY_HASHED_OBSERVABLE_STIX_FILE}_${ENTITY_DIRECTORY}`]: [RELATION_PARENT_DIRECTORY],
  [`${ENTITY_HASHED_OBSERVABLE_STIX_FILE}_${ENTITY_EMAIL_MIME_PART_TYPE}`]: [RELATION_BODY_RAW],
  [`${ENTITY_HASHED_OBSERVABLE_STIX_FILE}_${ENTITY_HASHED_OBSERVABLE_ARTIFACT}`]: [RELATION_CONTAINS],
  [`${ENTITY_HASHED_OBSERVABLE_STIX_FILE}_${ENTITY_PROCESS}`]: [RELATION_IMAGE],
  [`${ENTITY_IPV4_ADDR}_${ENTITY_AUTONOMOUS_SYSTEM}`]: [OBS_RELATION_BELONGS_TO],
  [`${ENTITY_IPV4_ADDR}_${ENTITY_MAC_ADDR}`]: [OBS_RELATION_RESOLVES_TO],
  [`${ENTITY_IPV6_ADDR}_${ENTITY_AUTONOMOUS_SYSTEM}`]: [OBS_RELATION_BELONGS_TO],
  [`${ENTITY_IPV6_ADDR}_${ENTITY_MAC_ADDR}`]: [OBS_RELATION_RESOLVES_TO],
  [`${ENTITY_NETWORK_TRAFFIC}_${ENTITY_HASHED_OBSERVABLE_ARTIFACT}`]: [RELATION_SRC_PAYLOAD, RELATION_DST_PAYLOAD],
  [`${ENTITY_NETWORK_TRAFFIC}_${ENTITY_DOMAIN_NAME}`]: [RELATION_SRC, RELATION_DST],
  [`${ENTITY_NETWORK_TRAFFIC}_${ENTITY_IPV4_ADDR}`]: [RELATION_SRC, RELATION_DST],
  [`${ENTITY_NETWORK_TRAFFIC}_${ENTITY_IPV6_ADDR}`]: [RELATION_SRC, RELATION_DST],
  [`${ENTITY_NETWORK_TRAFFIC}_${ENTITY_MAC_ADDR}`]: [RELATION_SRC, RELATION_DST],
  [`${ENTITY_NETWORK_TRAFFIC}_${ENTITY_NETWORK_TRAFFIC}`]: [RELATION_ENCAPSULATES, RELATION_ENCAPSULATED_BY],
  [`${ENTITY_NETWORK_TRAFFIC}_${ENTITY_NETWORK_TRAFFIC}`]: [RELATION_ENCAPSULATES, RELATION_ENCAPSULATED_BY],
  [`${ENTITY_NETWORK_TRAFFIC}_${ENTITY_NETWORK_TRAFFIC}`]: [RELATION_ENCAPSULATES, RELATION_ENCAPSULATED_BY],
  [`${ENTITY_NETWORK_TRAFFIC}_${ENTITY_NETWORK_TRAFFIC}`]: [RELATION_ENCAPSULATES, RELATION_ENCAPSULATED_BY],
  [`${ENTITY_PROCESS}_${ENTITY_NETWORK_TRAFFIC}`]: [RELATION_OPENED_CONNECTION],
  [`${ENTITY_PROCESS}_${ENTITY_PROCESS}`]: [RELATION_PARENT, RELATION_CHILD],
  [`${ENTITY_TYPE_MALWARE}_${ENTITY_SOFTWARE}`]: [RELATION_OPERATING_SYSTEM],
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
