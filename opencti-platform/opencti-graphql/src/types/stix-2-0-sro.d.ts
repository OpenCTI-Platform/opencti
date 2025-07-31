import type { StixDate, StixId, StixRelationshipObject } from './stix-2-0-common';

export interface StixSighting extends StixRelationshipObject {
  description: string;
  first_seen: StixDate;
  last_seen: StixDate;
  count: number;
  sighting_of_ref: StixId;
  where_sighted_refs: Array<StixId>;
  x_opencti_negative: boolean;
}
