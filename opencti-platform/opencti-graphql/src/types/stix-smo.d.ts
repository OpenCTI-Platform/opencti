import { StixId, StixMarkingsObject, StixOpenctiExtension } from './stix-common';
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

interface MarkingDefinitionExtension extends StixOpenctiExtension {
  color: string;
  order: number;
}

// Marking Definition Specific Properties
// name, definition_type, definition
interface StixMarkingDefinition extends StixMarkingsObject {
  name: string;
  definition_type: string;
  definition: { [x: string]: string; };
  extensions: {
    [STIX_EXT_OCTI] : MarkingDefinitionExtension
  };
}
