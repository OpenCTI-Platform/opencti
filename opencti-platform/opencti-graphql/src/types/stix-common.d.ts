import { v4, v5 } from 'uuid';
import { STIX_EXT_OCTI, STIX_EXT_OCTI_SCO } from './stix-extensions';
import type { StixRelation, StixSighting } from './stix-sro';

type StixId = `${string}--${v4 | v5}`;
type StixFieldExtension = `${string}--${string}`;

// Common
interface StixPatch {
  add?: StixCoreObject
  replace?: StixCoreObject
  remove?: StixCoreObject
}

interface StixContext {
  sources: Array<StixCoreObject>;
  deletions: Array<StixCoreObject>;
  shifts: Array<StixCoreObject>;
}

interface StixMitreExtension {
  'extension_type': 'property-extension',
  mitre_id: string;
}

interface StixOpenctiExtension {
  extension_type : 'property-extension';
  id: v4 | undefined;
  stix_ids: Array<StixId>;
  type: string;
  created_at: Date;
  is_inferred: boolean;
  patch: StixPatch | undefined;
  context: StixContext | undefined;
}

interface StixObject {
  type: string | undefined;
  spec_version: string | undefined;
  id: StixId;
  // TODO Implement granular_markings
  extensions: {
    [STIX_EXT_OCTI] : StixOpenctiExtension;
  };
}

// --- STIX Core Objects
// SDO
interface StixDomainObject extends StixObject {
  created_by_ref: StixId; // optional
  created: Date;
  modified: Date;
  revoked: boolean; // optional
  labels: Array<string>; // optional
  confidence: number; // optional
  lang: string; // optional
  external_references?: Array<StixExternalReference>;
  object_marking_refs: Array<StixId>; // optional
}

// SRO
interface StixRelationshipObject extends StixObject {
  created_by_ref: StixId; // optional
  created: Date;
  modified: Date;
  revoked: boolean; // optional
  labels: Array<string>; // optional
  confidence: number; // optional
  lang: string; // optional
  external_references?: Array<StixExternalReference>; // optional
  object_marking_refs: Array<StixId>; // optional
}

// SCO
interface StixCyberObject extends StixObject {
  object_marking_refs: Array<StixId>; // optional
  defanged: boolean; // optional
  extensions: {
    [STIX_EXT_OCTI] : StixOpenctiExtension;
    [STIX_EXT_OCTI_SCO] : {
      extension_type : 'property-extension',
      labels: Array<string>; // optional
      description: string; // optional
    }
  };
}

// --- STIX Meta Objects

// Extension
interface StixExtension extends StixObject {
  type: 'extension-definition';
  created_by_ref: StixId;
  created: Date;
  modified: Date;
  revoked: boolean;
  labels: Array<string>; // optional
  external_references?: Array<StixExternalReference>; // optional
  object_marking_refs: Array<StixId>; // optional
  // Extension Definition Specific Properties
  // name, description, schema, version, extension_types, extension_properties
  name: string;
  description: string;
  schema: string;
  version: string;
  extension_types: Array<'new-sdo' | 'new-sco' | 'property-extension'>;
  extension_properties?: Array<string>;
}

// Language
// TODO Add support for Language

// SEO (Stix embedded)
interface StixExternalReference {
  source_name: string;
  description: string;
  url: string;
  hashes: object;
  external_id: string;
  // [k: StixFieldExtension]: unknown
  extensions: {
    [STIX_EXT_OCTI] : StixOpenctiExtension;
  }
}

interface StixKillChainPhase {
  kill_chain_name: string;
  phase_name: string;
  // x_opencti_order: number;
  // [k: StixFieldExtension]: unknown
  // extensions?: object;
}

// Markings
interface StixMarkingsObject extends StixObject {
  created_by_ref: StixId; // optional
  created: Date;
  modified: Date;
  external_references?: Array<StixExternalReference>; // optional
  object_marking_refs: Array<StixId>; // optional
}

// Stix core definition
export type StixCoreObject = StixDomainObject | StixRelation | StixSighting | StixCyberObject;
// | StixMarkingsObject | StixExternalReference | StixKillChainPhase;
