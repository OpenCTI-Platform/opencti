import type { StixId } from './stix';
import type { StixRelationshipObject, StixOpenctiExtension } from './stix-common';
import { STIX_EXT_OCTI } from './stix-extensions';
import { StixKillChainPhase } from './stix-common';

// Relationship Specific Properties
// relationship_type, description, source_ref, target_ref, start_time, stop_time
export interface RelationExtension extends StixOpenctiExtension {
  source_ref: string;
  source_type: string;
  target_ref: string;
  target_type: string;
  kill_chain_phases: Array<StixKillChainPhase>;
}
interface StixRelation extends StixRelationshipObject {
  relationship_type: string;
  description: string;
  source_ref: string;
  target_ref: string;
  start_time: Date;
  stop_time: Date;
  extensions: {
    [STIX_EXT_OCTI] : RelationExtension
  };
}

// Sighting Specific Properties
// description, first_seen, last_seen, count, sighting_of_ref, observed_data_refs, where_sighted_refs, summary
interface SightingExtension extends StixOpenctiExtension {
  sighting_of_ref: StixId;
  sighting_of_type: string;
  where_sighted_refs: Array<StixId>;
  where_sighted_types: Array<string>;
  negative: boolean;
}
interface StixSighting extends StixRelationshipObject {
  description: string;
  first_seen: Date;
  last_seen: Date;
  count: number;
  sighting_of_ref: StixId;
  observed_data_refs: Array<StixId>;
  where_sighted_refs: Array<StixId>;
  summary: string;
  extensions: {
    [STIX_EXT_OCTI] : SightingExtension
  };
}
