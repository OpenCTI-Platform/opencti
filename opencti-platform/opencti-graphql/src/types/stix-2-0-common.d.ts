import type { StixDate, StixId } from './stix-common';
import type { StixInternalExternalReference } from './stix-smo';

export interface StixObject2 {
  id: StixId;
  spec_version: string;
  x_opencti_granted_refs?: string[]
  x_opencti_type: string;
}

// --- STIX Core Objects
// SDO
export interface StixDomainObject2 extends StixObject2 {
  created: StixDate;
  modified: StixDate;
  revoked: boolean; // optional
  confidence: number; // optional
  // lang: string; // optional
  labels: Array<string>; // optional
  object_marking_refs?: Array<StixId>; // optional
  created_by_ref: StixId | undefined; // optional
  external_references?: Array<StixInternalExternalReference>;
}
