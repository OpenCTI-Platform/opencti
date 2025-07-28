import type { StixDate, StixDomainObject } from './stix-2-0-common';

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

interface StixIncident extends StixDomainObject {
  name: string;
  description: string; // optional
  incident_type: string; // optional
  first_seen: StixDate;
  last_seen: StixDate;
  objective: string;
  aliases: Array<string>;
  source: string;
  severity: string;
}

// Container specific Properties
export interface StixContainer extends StixDomainObject {
  object_refs: Array<StixId>;
}

export interface StixReport extends StixContainer {
  name: string
  description: string
  report_types: Array<string>
  published: StixDate
  x_opencti_reliability: string;
}

export interface StixNote extends StixContainer {
  abstract: string
  content: string
  note_types: Array<string>
  likelihood: number
}

export interface StixObservedData extends StixContainer {
  first_observed: StixDate
  last_observed: StixDate
  number_observed: number
}

export interface StixOpinion extends StixContainer {
  explanation: string // optional
  opinion: 'strongly-disagree' | 'disagree' | 'neutral' | 'agree' | 'strongly-agree'
}
