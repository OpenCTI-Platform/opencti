import type { StixId } from './stix';
import type { StixRelationshipObject, StixOpenctiExtension, StixDate, StixKillChainPhase } from './stix-2-1-common';
import { STIX_EXT_OCTI } from './stix-2-1-extensions';

// Relationship Specific Properties
// relationship_type, description, source_ref, target_ref, start_time, stop_time
export interface RelationExtension extends StixOpenctiExtension {
  extension_type : 'property-extension' | 'new-sro';
  source_value: string;
  source_ref: string;
  source_type: string;
  source_ref_object_marking_refs: Array<string>;
  source_ref_granted_refs: Array<string>;
  target_value: string;
  target_ref: string;
  target_type: string;
  target_ref_object_marking_refs: Array<string>;
  target_ref_granted_refs: Array<string>;
  kill_chain_phases: Array<StixKillChainPhase>;
}
export interface StixRelation extends StixRelationshipObject {
  relationship_type: string;
  description: string;
  source_ref: StixId;
  target_ref: StixId;
  start_time: StixDate;
  stop_time: StixDate;
  extensions: {
    [STIX_EXT_OCTI] : RelationExtension
  };
}

// Sighting Specific Properties
// description, first_seen, last_seen, count, sighting_of_ref, observed_data_refs, where_sighted_refs, summary
export interface SightingExtension extends StixOpenctiExtension {
  sighting_of_value: string;
  sighting_of_ref: StixId;
  sighting_of_type: string;
  sighting_of_ref_object_marking_refs: Array<string>;
  sighting_of_ref_granted_refs: Array<string>;
  where_sighted_values: Array<string>;
  where_sighted_refs: Array<StixId>;
  where_sighted_types: Array<string>;
  where_sighted_refs_object_marking_refs: Array<string>;
  where_sighted_refs_granted_refs: Array<string>;
  negative: boolean;
}
export interface StixSighting extends StixRelationshipObject {
  description: string;
  first_seen: StixDate;
  last_seen: StixDate;
  count: number;
  sighting_of_ref: StixId;
  observed_data_refs: Array<StixId>;
  where_sighted_refs: Array<StixId>;
  summary: string;
  extensions: {
    [STIX_EXT_OCTI] : SightingExtension
  };
}
