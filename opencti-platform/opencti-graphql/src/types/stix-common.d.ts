import { v4, v5 } from 'uuid';
import { STIX_EXT_OCTI, STIX_EXT_OCTI_SCO } from './stix-extensions';
import type { StixRelation, StixSighting } from './stix-sro';
import type { StixInternalExternalReference } from './stix-smo';

type StixId = `${string}--${v4 | v5}`;
type StixFieldExtension = `${string}--${string}`;

export enum OrganizationReliability {
  A = 'A',
  B = 'B',
  C = 'C',
  D = 'D',
  E = 'E',
  F = 'F'
}

interface StixMitreExtension {
  'extension_type': 'property-extension',
  id: string;
  detection: string;
  permissions_required: Array<string>;
  platforms: Array<string>;
}

interface StixFileExtension {
  name: string;
  uri: string;
  version: string;
  mime_type: string;
}

interface StixOpenctiExtension {
  extension_type : 'property-extension' | 'new-sdo' | 'new-sro';
  id: v4 | undefined;
  files: Array<StixFileExtension>;
  aliases: Array<string>;
  linked_to_refs: Array<StixId>;
  stix_ids: Array<StixId>;
  type: string;
  created_at: Date;
  updated_at: Date;
  is_inferred: boolean;
  workflow_id: string | undefined;
}

interface StixOpenctiExtensionSDO extends StixOpenctiExtension {
  extension_type : 'new-sdo';
}

interface StixObject {
  id: StixId;
  type: string;
  spec_version: string;
  // TODO Implement granular_markings
  extensions: {
    [STIX_EXT_OCTI] : StixOpenctiExtension;
  };
}

// --- STIX Core Objects
// SDO
interface StixDomainObject extends StixObject {
  created_by_ref: StixId | undefined; // optional
  created: Date;
  modified: Date;
  revoked: boolean; // optional
  labels: Array<string>; // optional
  confidence: number; // optional
  lang: string; // optional
  external_references?: Array<StixInternalExternalReference>;
  object_marking_refs: Array<StixId>; // optional
}

// SRO
interface StixRelationshipObject extends StixObject {
  created_by_ref: StixId | undefined; // optional
  created: Date;
  modified: Date;
  revoked: boolean; // optional
  labels: Array<string>; // optional
  confidence: number; // optional
  lang: string; // optional
  external_references?: Array<StixInternalExternalReference>; // optional
  object_marking_refs: Array<StixId>; // optional
}

// SCO
interface CyberObjectExtension {
  extension_type : 'property-extension',
  labels: Array<string>;
  description: string;
  score: number;
  created_by_ref: StixId | undefined;
  external_references: Array<StixInternalExternalReference>;
}

interface StixCyberObject extends StixObject {
  object_marking_refs: Array<StixId>; // optional
  defanged: boolean; // optional
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtension;
    [STIX_EXT_OCTI_SCO]: CyberObjectExtension
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
  external_references?: Array<StixInternalExternalReference>; // optional
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

// Markings
interface StixMarkingsObject extends StixObject {
  created_by_ref: StixId | undefined; // optional
  created: Date;
  modified: Date;
  external_references?: Array<StixInternalExternalReference>; // optional
  object_marking_refs: Array<StixId>; // optional
}

// Stix core definition
export type StixCoreObject = StixDomainObject | StixRelation | StixSighting | StixCyberObject;
// | StixMarkingsObject | StixExternalReference | StixKillChainPhase;
