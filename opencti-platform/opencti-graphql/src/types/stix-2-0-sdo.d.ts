import type { StixDomainObject } from './stix-2-0-common';
import type { StixId, StixDate, StixKillChainPhase } from './stix-2-1-common';

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

export interface StixTool extends StixDomainObject {
  name: string;
  description: string; // optional
  tool_types : Array<string>; // tool-type-ov - optional
  aliases: Array<string>; // optional
  kill_chain_phases: Array<StixKillChainPhase>; // optional
  tool_version: string;
}

export interface StixVulnerability extends StixDomainObject {
  name: string;
  description: string; // optional
  x_opencti_cisa_kev: instance.x_opencti_cisa_kev,
  x_opencti_first_seen_active: instance.x_opencti_first_seen_active,
  // CVSS3
  x_opencti_cvss_vector_string: string;
  x_opencti_cvss_base_score: number;
  x_opencti_cvss_base_severity: string;
  x_opencti_cvss_attack_vector: string;
  x_opencti_cvss_attack_complexity: string;
  x_opencti_cvss_privileges_required: string;
  x_opencti_cvss_user_interaction: string;
  x_opencti_cvss_scope: string;
  x_opencti_cvss_confidentiality_impact: string;
  x_opencti_cvss_integrity_impact: string;
  x_opencti_cvss_availability_impact: string;
  x_opencti_cvss_exploit_code_maturity: string;
  x_opencti_cvss_remediation_level: string;
  x_opencti_cvss_report_confidence: string;
  x_opencti_cvss_temporal_score: number;
  // CVSS2
  x_opencti_cvss_v2_vector_string: string;
  x_opencti_cvss_v2_base_score: number;
  x_opencti_cvss_v2_access_vector: string;
  x_opencti_cvss_v2_access_complexity: string;
  x_opencti_cvss_v2_authentication: string;
  x_opencti_cvss_v2_confidentiality_impact: string;
  x_opencti_cvss_v2_integrity_impact: string;
  x_opencti_cvss_v2_availability_impact: string;
  x_opencti_cvss_v2_exploitability: string;
  x_opencti_cvss_v2_remediation_level: string;
  x_opencti_cvss_v2_report_confidence: string;
  x_opencti_cvss_v2_temporal_score: number;
  // CVSS4
  x_opencti_cvss_v4_vector_string: string;
  x_opencti_cvss_v4_base_score: number;
  x_opencti_cvss_v4_base_severity: string;
  x_opencti_cvss_v4_attack_vector: string;
  x_opencti_cvss_v4_attack_complexity: string;
  x_opencti_cvss_v4_attack_requirements: string;
  x_opencti_cvss_v4_privileges_required: string;
  x_opencti_cvss_v4_user_interaction: string;
  x_opencti_cvss_v4_confidentiality_impact_v: string;
  x_opencti_cvss_v4_confidentiality_impact_s: string;
  x_opencti_cvss_v4_integrity_impact_v: string;
  x_opencti_cvss_v4_integrity_impact_s: string;
  x_opencti_cvss_v4_availability_impact_v: string;
  x_opencti_cvss_v4_availability_impact_s: string;
  x_opencti_cvss_v4_exploit_maturity: string;
  // Others
  x_opencti_score: number;
  x_opencti_epss_score: number;
  x_opencti_epss_percentile: number;
}

// Container specific Properties
export interface StixContainer extends StixDomainObject {
  object_refs: Array<StixId>;
}

export interface StixReport extends StixContainer {
  name: string;
  description: string;
  report_types: Array<string>;
  published: StixDate;
  x_opencti_reliability: string;
}

export interface StixNote extends StixContainer {
  abstract: string;
  content: string;
  note_types: Array<string>;
  likelihood: number;
}

export interface StixObservedData extends StixContainer {
  first_observed: StixDate;
  last_observed: StixDate;
  number_observed: number;
}

export interface StixOpinion extends StixContainer {
  explanation: string; // optional
  opinion: 'strongly-disagree' | 'disagree' | 'neutral' | 'agree' | 'strongly-agree';
}
