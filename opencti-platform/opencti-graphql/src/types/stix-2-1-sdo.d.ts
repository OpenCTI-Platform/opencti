import type {
  StixDomainObject,
  StixId,
  StixOpenctiExtensionSDO,
  StixDate,
  StixKillChainPhase,
  StixOpenctiExtension,
  StixMitreExtension,
  StixContainerExtension
} from './stix-2-1-common';
import { STIX_EXT_MITRE, STIX_EXT_OCTI } from './stix-2-1-extensions';

// Attack Pattern Specific Properties
// name, description, aliases, kill_chain_phases
export interface StixAttackPattern extends StixDomainObject {
  name: string; // optional
  description: string; // optional
  aliases: Array<string>; // optional
  kill_chain_phases: Array<StixKillChainPhase>; // optional
  extensions: {
    [STIX_EXT_OCTI] : StixOpenctiExtension
    [STIX_EXT_MITRE] : StixMitreExtension
  };
}

// Campaign Specific Properties
// name, description, aliases, first_seen, last_seen, objective
export interface StixCampaign extends StixDomainObject {
  name: string;
  description: string; // optional
  aliases: Array<string>; // optional
  first_seen: StixDate; // optional
  last_seen: StixDate; // optional
  objective: string; // optional
}

// Course of Action Specific Properties
// name, description, action
export interface StixCourseOfAction extends StixDomainObject {
  name: string; // optional
  description: string; // optional
  // action - RESERVED
  extensions: {
    [STIX_EXT_OCTI] : StixOpenctiExtension
    [STIX_EXT_MITRE] : StixMitreExtension
  };
}

// Identity Specific Properties
export interface StixIdentityExtension extends StixOpenctiExtension {
  firstname: string;
  lastname: string;
  organization_type: string;
  reliability: string;
}
// name, description, roles, identity_class, sectors, contact_information
export interface StixIdentity extends StixDomainObject {
  name: string; // optional
  description: string; // optional
  roles: Array<string>; // optional
  identity_class: string; // 'individual' | 'group' | 'system' | 'organization' | 'class' | 'unknown'; // optional
  sectors: Array<string>; // optional
  contact_information: string; // optional
  extensions: {
    [STIX_EXT_OCTI]: StixIdentityExtension;
  };
}

// Incident Specific Properties
// name, description
// Not in https://docs.oasis-open.org/cti/stix/v2.1
interface StixIncident extends StixDomainObject {
  name: string;
  incident_type: string; // optional
  description: string; // optional
  first_seen: StixDate;
  last_seen: StixDate;
  objective: string;
  aliases: Array<string>;
  source: string;
  severity: string;
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtensionSDO;
  };
}

// infrastructure Specific Properties
// name, description, infrastructure_types, aliases, kill_chain_phases, first_seen, last_seen
export interface StixInfrastructure extends StixDomainObject {
  name: string;
  description: string; // optional
  infrastructure_types: Array<string>; // infrastructure-type-ov - optional
  aliases : Array<string>; // optional
  kill_chain_phases: Array<StixKillChainPhase>; // optional
  first_seen: StixDate; // optional
  last_seen: StixDate; // optional
}

// Intrusion Set Specific Properties
// name, description, aliases, first_seen, last_seen, goals, resource_level, primary_motivation, secondary_motivations
export interface StixIntrusionSet extends StixDomainObject {
  name: string;
  description: string; // optional
  aliases: Array<string>; // optional
  first_seen : StixDate; // optional
  last_seen : StixDate; // optional
  goals: Array<string>; // optional
  resource_level: string; // optional
  primary_motivation: string; // optional
  secondary_motivations: Array<string>; // optional
}

// Location Specific Properties
// name, description, latitude, longitude, precision, region, country, administrative_area, city, street_address, postal_code
export interface StixLocation extends StixDomainObject {
  name: string; // optional
  description: string; // optional
  latitude: number | undefined; // optional
  longitude: number | undefined; // optional
  precision: number | undefined; // optional
  region: string | undefined; // optional
  country: string | undefined; // optional
  city: string | undefined; // optional
  street_address: string; // optional
  postal_code: string; // optional
}

// Malware Specific Properties
// name, description, malware_types, is_family, aliases, kill_chain_phases, first_seen, last_seen,
// operating_system_refs, architecture_execution_envs, implementation_languages, capabilities, sample_refs
export interface StixMalware extends StixDomainObject {
  name: string; // optional
  description: string; // optional
  malware_types: Array<string>; // optional
  is_family: boolean;
  aliases: Array<string>; // optional
  kill_chain_phases: Array<StixKillChainPhase>; // optional
  first_seen: StixDate; // optional
  last_seen: StixDate; // optional
  architecture_execution_envs: Array<string>; // optional
  implementation_languages: Array<string>; // optional
  capabilities: Array<string>; // optional
  operating_system_refs: Array<StixId>; // optional
  sample_refs: Array<StixId>; // optional
}

// TODO Add support for Malware analysis
// Malware Analysis Specific Properties
// product, version, host_vm_ref, operating_system_ref, installed_software_refs, configuration_version,
// modules, analysis_engine_version, analysis_definition_version, submitted, analysis_started,
// analysis_ended, result_name, result, analysis_sco_refs, sample_ref
export interface StixMalwareAnalysis extends StixDomainObject {
  product: string;
  version: string; // optional
  host_vm_ref: StixId; // optional
  operating_system_ref: StixId; // optional
  installed_software_refs: Array<StixId>; // optional
  configuration_version: string; // optional
  modules: Array<string>; // optional
  analysis_engine_version: string; // optional
  analysis_definition_version: string; // optional
  submitted: StixDate; // optional
  analysis_started: StixDate; // optional
  analysis_ended: StixDate; // optional
  result_name: string; // optional
  result: string; // malware-result-ov - optional
  analysis_sco_refs: Array<StixId>; // optional
  sample_ref: StixId; // optional
}

// Container specific Properties
export interface StixContainer extends StixDomainObject {
  object_refs: Array<StixId>;
  extensions: {
    [STIX_EXT_OCTI]: StixContainerExtension;
  };
}

// Note Specific Properties
// abstract, content, authors, object_refs
export interface StixNoteExtension extends StixOpenctiExtension {
  content_mapping: string;
  object_refs_inferred?: Array<StixId>; // optional
}

export interface StixNote extends StixContainer {
  abstract: string
  content: string
  authors: Array<string>
  note_types: Array<string>
  likelihood: number
  extensions: {
    [STIX_EXT_OCTI]: StixNoteExtension;
  };
}

// Observed Data Specific Properties
// first_observed, last_observed, number_observed, objects, object_refs
export interface StixObservedDataExtension extends StixOpenctiExtension {
  content: string;
  content_mapping: string;
  object_refs_inferred?: Array<StixId>; // optional
}

export interface StixObservedData extends StixContainer {
  first_observed: StixDate
  last_observed: StixDate
  number_observed: number
  extensions: {
    [STIX_EXT_OCTI]: StixObservedDataExtension;
  };
}

// Opinion Specific Properties
// explanation, authors, opinion, object_refs
export interface StixOpinionExtension extends StixOpenctiExtension {
  content: string;
  content_mapping: string;
  object_refs_inferred?: Array<StixId>; // optional
}

export interface StixOpinion extends StixContainer {
  explanation: string // optional
  authors: Array<string> // optional
  opinion: 'strongly-disagree' | 'disagree' | 'neutral' | 'agree' | 'strongly-agree'
  extensions: {
    [STIX_EXT_OCTI]: StixOpinionExtension;
  };
}

// Report Specific Properties
// name, description, report_types, published, object_refs
export interface StixReportExtension extends StixOpenctiExtension {
  content: string;
  content_mapping: string;
  object_refs_inferred?: Array<StixId>; // optional
  reliability: string;
}

export interface StixReport extends StixContainer {
  name: string
  description: string
  report_types: Array<string>
  published: StixDate
  extensions: {
    [STIX_EXT_OCTI]: StixReportExtension;
  };
}

// Threat Actor Specific Properties
// name, description, threat_actor_types, aliases, first_seen, last_seen, roles, goals,
// sophistication, resource_level, primary_motivation, secondary_motivations, personal_motivations
export interface StixThreatActor extends StixDomainObject {
  name: string;
  description: string; // optional
  threat_actor_types : Array<string>; // threat-actor-type-ov - optional
  aliases: Array<string>; // optional
  first_seen: StixDate; // optional
  last_seen: StixDate; // optional
  roles: Array<string>; // threat-actor-role-ov - optional
  goals: Array<string>; // optional
  sophistication: string; // threat-actor-sophistication-ov - optional
  resource_level: string; // attack-resource-level-ov - optional
  primary_motivation: string; // attack-motivation-ov - optional
  secondary_motivations: Array<string>; // attack-motivation-ov - optional
  personal_motivations: Array<string>; // attack-motivation-ov - optional
}

// Tool Specific Properties
// name, description, tool_types, aliases, kill_chain_phases, tool_version
export interface StixTool extends StixDomainObject {
  name: string;
  description: string; // optional
  tool_types : Array<string>; // tool-type-ov - optional
  aliases: Array<string>; // optional
  kill_chain_phases: Array<StixKillChainPhase>; // optional
  tool_version: string;
}

// Vulnerability Specific Properties
export interface StixVulnerabilityExtension extends StixOpenctiExtension {
  attack_vector: string;
  availability_impact: string;
  base_score: number;
  base_severity: string;
  confidentiality_impact: string;
  integrity_impact: string;
}
// name, description
export interface StixVulnerability extends StixDomainObject {
  name: string;
  description: string; // optional
  extensions: {
    [STIX_EXT_OCTI]: StixVulnerabilityExtension;
  };
}
