import { v4, v5 } from 'uuid';
import type { StixInternalExternalReference } from './stix-2-0-smo';

export type StixDate = string | undefined;
export type StixId = `${string}--${v4 | v5}`;

interface StixFile {
  name: string;
  uri: string;
  version?: string;
  mime_type?: string;
  object_marking_refs: string[];
  data?: string | undefined;
  no_trigger_import?: boolean;
}

export interface StixObject {
  id: StixId;
  spec_version: string;
  type: string;
  // custom
  x_opencti_id: string;
  x_opencti_granted_refs?: string[];
  x_opencti_type: string;
  x_opencti_workflow_id?: string;
  x_opencti_files: Array<StixFile>;
  x_opencti_modified_at?: string;
  x_created_by_ref_id?: StixDate;
  x_created_by_ref_type?: StixDate;
}

// --- STIX Core Objects
// SDO
export interface StixDomainObject extends StixObject {
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
