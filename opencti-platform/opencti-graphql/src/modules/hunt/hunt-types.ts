import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import type { StixDomainObject, StixOpenctiExtensionSDO } from '../../types/stix-2-1-common';
import { STIX_EXT_OCTI, STIX_EXT_OCTI_HUNT } from '../../types/stix-2-1-extensions';

export const ENTITY_TYPE_HUNT = 'Hunt';

// region refs
export const INPUT_HUNT_TARGETS = 'huntTargets';
export const RELATION_HUNT_TARGETS = 'hunt-target';
export const ATTRIBUTE_HUNT_TARGETS = 'target_refs';

export const INPUT_HUNT_TECHNIQUES = 'huntTechniques';
export const RELATION_HUNT_TECHNIQUES = 'hunt-technique';
export const ATTRIBUTE_HUNT_TECHNIQUES = 'technique_refs';

export const INPUT_HUNT_SOURCES = 'huntSources';
export const RELATION_HUNT_SOURCES = 'hunt-source';
export const ATTRIBUTE_HUNT_SOURCES = 'source_refs';
// endregion

// region enumerations
export const HUNT_TYPE_TELEMETRY = 'telemetry';
export const HUNT_TYPE_INDICATORS = 'indicators';
export const HUNT_TYPE_INFRASTRUCTURE = 'infrastructure';
export const HUNT_TYPES = [HUNT_TYPE_TELEMETRY, HUNT_TYPE_INDICATORS, HUNT_TYPE_INFRASTRUCTURE];

export const HUNT_STATUS_DRAFT = 'draft';
export const HUNT_STATUS_ACTIVE = 'active';
export const HUNT_STATUS_PAUSED = 'paused';
export const HUNT_STATUS_RETIRED = 'retired';
export const HUNT_STATUSES = [HUNT_STATUS_DRAFT, HUNT_STATUS_ACTIVE, HUNT_STATUS_PAUSED, HUNT_STATUS_RETIRED];

export const HUNT_SOURCE_ANALYST = 'analyst';
export const HUNT_SOURCE_AGENT = 'agent';
export const HUNT_SOURCE_HUB = 'hub';
export const HUNT_SOURCE_KINDS = [HUNT_SOURCE_ANALYST, HUNT_SOURCE_AGENT, HUNT_SOURCE_HUB];

export const HUNT_SCHEDULE_MANUAL = 'manual';
export const HUNT_SCHEDULE_STANDING = 'standing';

export const HUNT_PLATFORM_INTERNET = 'internet';
export const HUNT_PLATFORMS = [
  'splunk',
  'microsoft-sentinel',
  'elastic-security',
  'crowdstrike-logscale',
  'google-secops',
  'opensearch',
  'clickhouse',
  's3-ocsf',
  HUNT_PLATFORM_INTERNET,
];
// endregion

export interface HuntNativeQuery {
  platform: string;
  language: string;
  query: string;
  pipeline?: string | null;
}

/** A value pasted in an indicator hunt, typed as an observable. */
export interface HuntIocValue {
  observable_type: string;
  value: string;
}

interface HuntAttributes {
  hypothesis?: string;
  hunt_type: string;
  hunt_status: string;
  hunt_source_kind: string;
  sigma_rule?: string;
  native_queries?: HuntNativeQuery[];
  hunt_ioc_filters?: string;
  hunt_ioc_values?: HuntIocValue[];
  hunt_scope?: string;
  hunt_schedule: string;
  trigger_filters?: string;
  hunt_pir_activation?: boolean;
  time_window_hours: number;
  expected_observables?: string[];
  benign_patterns?: string[];
  escalation_threshold: number;
  // Manual runs open an incident draft above the escalation threshold like autonomous ones; off, it is offered at verdict time
  escalate_manual_runs?: boolean;
  hunt_max_results?: number;
  last_run_at?: string;
  last_run_status?: string;
  last_hits_count?: number;
  last_new_hits_count?: number;
  next_run_at?: string;
  hunt_pir_armed?: boolean;
  hunt_pir_armed_at?: string;
}

export interface BasicStoreEntityHunt extends BasicStoreEntity, HuntAttributes {
  [RELATION_HUNT_TARGETS]?: string[];
  [RELATION_HUNT_TECHNIQUES]?: string[];
  [RELATION_HUNT_SOURCES]?: string[];
}

export interface StoreEntityHunt extends StoreEntity, HuntAttributes {
  [INPUT_HUNT_TARGETS]?: BasicStoreEntity[];
  [INPUT_HUNT_TECHNIQUES]?: BasicStoreEntity[];
  [INPUT_HUNT_SOURCES]?: BasicStoreEntity[];
}

export interface StixHunt extends StixDomainObject {
  name: string;
  description: string;
  hypothesis: string;
  hunt_type: string;
  hunt_status: string;
  hunt_source_kind: string;
  sigma_rule: string;
  native_queries: HuntNativeQuery[];
  hunt_ioc_filters?: string;
  hunt_ioc_values?: HuntIocValue[];
  hunt_scope: string;
  hunt_schedule: string;
  trigger_filters: string;
  hunt_pir_activation: boolean;
  time_window_hours: number;
  expected_observables: string[];
  benign_patterns: string[];
  escalation_threshold: number;
  escalate_manual_runs?: boolean;
  hunt_max_results?: number;
  [ATTRIBUTE_HUNT_TARGETS]: string[];
  [ATTRIBUTE_HUNT_TECHNIQUES]: string[];
  [ATTRIBUTE_HUNT_SOURCES]: string[];
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtensionSDO;
    [STIX_EXT_OCTI_HUNT]?: { extension_type: 'new-sdo' };
  };
}
