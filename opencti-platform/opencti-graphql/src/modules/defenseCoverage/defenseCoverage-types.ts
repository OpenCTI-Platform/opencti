import { ENTITY_TYPE_CAMPAIGN, ENTITY_TYPE_INTRUSION_SET, ENTITY_TYPE_MALWARE, ENTITY_TYPE_THREAT_ACTOR_GROUP } from '../../schema/stixDomainObject';
import { ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL } from '../threatActorIndividual/threatActorIndividual-types';

// region levels
// The defense level of a technique, for one security platform or aggregated over all of them.
// Every level is explained by the evidences stored next to it (see DefenseCoverage below).
export const DEFENSE_LEVEL_NONE = 0; // Nothing known
export const DEFENSE_LEVEL_TELEMETRY = 1; // A provided data component detects the technique
export const DEFENSE_LEVEL_DETECTION_AVAILABLE = 2; // A detection rule indicating the technique is known in OpenCTI
export const DEFENSE_LEVEL_DETECTION_DEPLOYED = 3; // The rule is deployed (or active) on the security platform
export const DEFENSE_LEVEL_VALIDATED = 4; // OpenAEV proved the detection or the prevention
export const DEFENSE_LEVEL_MAX = DEFENSE_LEVEL_VALIDATED;

export const DEFENSE_AGGREGATE_PLATFORM = 'all';

export type DefenseDetectionStatus = 'none' | 'available' | 'deployed' | 'active';
export type DefenseValidationStatus = 'none' | 'prevented' | 'detected' | 'failed';
export type DefenseRecommendedAction = 'add_telemetry' | 'import_rule' | 'deploy_rule' | 'activate_rule' | 'validate' | 'fix_detection' | 'none';

export const DEFENSE_DETECTION_ORDER: Record<DefenseDetectionStatus, number> = { none: 0, available: 1, deployed: 2, active: 3 };
export const DEFENSE_VALIDATION_ORDER: Record<DefenseValidationStatus, number> = { none: 0, failed: 1, detected: 2, prevented: 3 };
// endregion

// region rules
// Pattern types considered as detection rules (the others are IOC patterns).
export const DEFENSE_RULE_PATTERN_TYPES = [
  'sigma',
  'yara',
  'snort',
  'suricata',
  'spl',
  'eql',
  'esql',
  'kuery',
  'lucene',
  'kql',
  'yara-l',
  'crowdstrike-ioa',
  // Rules whose logic is not their query alone: canonical JSON of the query and its conditions
  'elastic-rule',
  'sentinel-rule',
  'splunk-rule',
  'tanium-signal',
  'nova',
];
// endregion

// region threats
export const DEFENSE_THREAT_TYPES = [
  ENTITY_TYPE_INTRUSION_SET,
  ENTITY_TYPE_THREAT_ACTOR_GROUP,
  ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL,
  ENTITY_TYPE_CAMPAIGN,
  ENTITY_TYPE_MALWARE,
];
// endregion

// region stored coverage
// Every evidence carries the id of the element and the id of the relationship that links it,
// so that a reader only gets the evidences he is allowed to see (markings, organizations).
export interface DefenseEvidence {
  id: string; // element id (data component, indicator, course of action, security coverage result)
  rel: string; // relationship id (detects, indicates, mitigates, has-covered)
}

export interface DefenseTelemetryEvidence extends DefenseEvidence {
  detects: string; // detects relationship id (data component -> attack pattern)
  inferred_from?: string; // indicator id when the telemetry is inferred from a deployed rule log source
  indicates?: string; // indicates relationship id (indicator -> attack pattern) of an inferred telemetry
}

export interface DefenseDeploymentEvidence extends DefenseEvidence {
  status: string; // deployment status of the deployed-on relationship (rel)
  indicates: string; // indicates relationship id (indicator -> attack pattern)
}

export interface DefenseScore {
  name: string;
  score: number;
}

export interface DefenseValidationEvidence extends DefenseEvidence {
  coverage_id?: string; // security coverage id
  status: DefenseValidationStatus;
  last_result_at?: string;
  scores: DefenseScore[];
  attributed?: boolean; // technique-wide list only: the result is attributed to a security platform (absent from older stored coverages)
}

export interface DefensePlatformVector {
  platform_id: string;
  telemetry: DefenseTelemetryEvidence[];
  deployments: DefenseDeploymentEvidence[];
  validations: DefenseValidationEvidence[];
  level: number;
}

export interface DefenseCoverage {
  computed_at: string;
  data_components: DefenseEvidence[]; // data components detecting the technique
  rules: DefenseEvidence[]; // rule indicators indicating the technique
  mitigations: DefenseEvidence[]; // courses of action mitigating the technique
  validations: DefenseValidationEvidence[]; // every validation result, attributed or not to a platform
  platforms: DefensePlatformVector[];
  level: number;
}
// endregion

// region evaluated (per reader) coverage
export interface DefenseCellPlatform {
  platform_id: string;
  telemetry: boolean;
  detection: DefenseDetectionStatus;
  validated: DefenseValidationStatus;
  last_result_at?: string;
  level: number;
  data_component_ids: string[];
  inferred_data_component_ids: string[];
  rule_ids: string[];
  coverage_result_ids: string[];
  recommended_action: DefenseRecommendedAction;
}

export interface DefenseCell {
  attack_pattern_id: string;
  level: number;
  telemetry: boolean;
  detection: DefenseDetectionStatus;
  validated: DefenseValidationStatus;
  last_result_at?: string;
  mitigated: boolean;
  data_component_ids: string[];
  rule_ids: string[];
  mitigation_ids: string[];
  coverage_result_ids: string[];
  platforms: DefenseCellPlatform[];
  recommended_action: DefenseRecommendedAction;
  computed_at?: string;
}
// endregion

// region threat overlay
export interface DefenseThreatUsage {
  threat_id: string;
  relationship_id: string;
  confidence: number;
}

export interface DefenseThreatOverlay {
  computed_at: string;
  threats_count: number;
  // attack pattern id -> usages by threats visible to the reader
  usages: Map<string, DefenseThreatUsage[]>;
}
// endregion
