import type { StixDate, StixId, StixRelationshipObject } from './stix-2-0-common';

export interface StixRelation extends StixRelationshipObject {
  relationship_type: string;
  description: string;
  source_ref: StixId;
  target_ref: StixId;
  start_time: StixDate;
  stop_time: StixDate;
}

export interface StixSighting extends StixRelationshipObject {
  description: string;
  first_seen: StixDate;
  last_seen: StixDate;
  count: number;
  sighting_of_ref: StixId;
  where_sighted_refs: Array<StixId>;
  x_opencti_negative: boolean;
}
