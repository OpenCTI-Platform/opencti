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
  definition: { [x: string]: string; };
  extensions: {
    [STIX_EXT_OCTI] : MarkingDefinitionExtension
  };
}

// Label
interface StixLabel extends StixObject {
  value: string;
  color: string;
  extensions: {
    [STIX_EXT_OCTI] : StixOpenctiExtensionSDO
  };
}

// Kill chain
interface StixKillChainPhase extends StixObject {
  kill_chain_name: string;
  phase_name: string;
  order: number;
  extensions: {
    [STIX_EXT_OCTI] : StixOpenctiExtensionSDO
  };
}

// External reference
interface StixExternalReference extends StixObject {
  url: string;
  source_name: string;
  description: string;
  external_id: string;
  extensions: {
    [STIX_EXT_OCTI] : StixOpenctiExtensionSDO
  };
}
