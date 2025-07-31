import { v4, v5 } from 'uuid';
import type { StixInternalExternalReference } from './stix-2-0-smo';

export type StixDate = string | undefined;
export type StixId = `${string}--${v4 | v5}`;

interface StixFile {
  name: string;
  uri: string;
  version: string;
  mime_type: string;
  object_marking_refs: string[];
}

export interface StixObject {
  id: StixId;
  x_opencti_id: string;
  spec_version: string;
  x_opencti_granted_refs?: string[]
  x_opencti_type: string;
  type: string;
  x_opencti_workflow_id?: string;
  x_opencti_files: Array<StixFile>;
}

// --- STIX Core Objects
// SDO
export interface StixDomainObject extends StixObject {
  created: StixDate;
  modified: StixDate;
  revoked?: boolean; // optional
  confidence: number; // optional
  // lang: string; // optional
  labels: Array<string>; // optional
  object_marking_refs?: Array<StixId>; // optional
  created_by_ref: StixId | undefined; // optional
  external_references?: Array<StixInternalExternalReference>;
}

// SRO
interface StixRelationshipObject extends StixObject {
  created_by_ref: StixId | undefined; // optional
  created: StixDate;
  modified: StixDate;
  revoked?: boolean; // optional
  labels: Array<string>; // optional
  confidence: number; // optional
  lang?: string; // optional
  external_references?: Array<StixInternalExternalReference>; // optional
  object_marking_refs?: Array<StixId>; // optional
}
