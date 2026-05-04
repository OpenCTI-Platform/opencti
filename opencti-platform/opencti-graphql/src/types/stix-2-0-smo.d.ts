import type { StixDate, StixObject } from './stix-2-0-common';

// External reference (embedded)
export interface StixInternalExternalReference {
  source_name: string;
  description: string;
  url: string;
  hash: object;
  external_id: string;
}

export interface StixInternalKillChainPhase {
  kill_chain_name: string;
  phase_name: string;
  x_opencti_order: number;
}

// --- Top-level STIX 2.0 Meta Objects ---

// Marking Definition
export interface StixMarkingDefinition extends StixObject {
  created: StixDate;
  name: string;
  definition_type: string;
  definition: Record<string, string>;
  x_opencti_order?: number;
  x_opencti_color?: string;
  created_by_ref?: string;
  object_marking_refs?: string[];
  external_references?: Array<StixInternalExternalReference>;
}

// Label
export interface StixLabel extends StixObject {
  value: string;
  color: string;
}

// Kill Chain Phase
export interface StixKillChainPhase extends StixObject {
  kill_chain_name: string;
  phase_name: string;
  x_opencti_order: number;
}

// External Reference
export interface StixExternalReference extends StixObject {
  source_name: string;
  description?: string;
  url?: string;
  hashes?: object;
  external_id?: string;
}
