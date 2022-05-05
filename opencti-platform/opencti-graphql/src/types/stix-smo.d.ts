import { StixId, StixMarkingsObject, StixObject, StixOpenctiExtension, StixOpenctiExtensionSDO } from './stix-common';
import { STIX_EXT_OCTI } from './stix-extensions';

// Extensions
interface StixExtension {
  id: StixId;
  type: 'extension-definition';
  spec_version: string;
  name: string;
  description: string;
  created: Date;
  modified: Date;
  created_by_ref: StixId;
  version: string;
  extension_types: Array<'new-sdo' | 'property-extension'>;
  extension_properties?: Array<string>;
}

// Marking Definition Specific Properties
// name, definition_type, definition
interface MarkingDefinitionExtension extends StixOpenctiExtension {
  color: string;
  order: number;
}
interface StixMarkingDefinition extends StixMarkingsObject {
  name: string;
  definition_type: string;
  extensions: {
    [STIX_EXT_OCTI] : MarkingDefinitionExtension
  };
}

// Label
// interface StixInternalLabel = string
interface StixLabel extends StixObject {
  value: string;
  color: string;
  extensions: {
    [STIX_EXT_OCTI] : StixOpenctiExtensionSDO
  };
}

// Kill chain
interface StixInternalKillChainPhase {
  kill_chain_name: string;
  phase_name: string;
}
interface StixKillChainPhase extends StixInternalKillChainPhase, StixObject {
  order: number;
  extensions: {
    [STIX_EXT_OCTI] : StixOpenctiExtensionSDO
  };
}

// External reference
interface StixInternalExternalReference {
  source_name: string;
  description: string;
  url: string;
  hashes: object;
  external_id: string;
}
interface StixExternalReference extends StixInternalExternalReference, StixObject {
  extensions: {
    [STIX_EXT_OCTI] : StixOpenctiExtensionSDO
  };
}
