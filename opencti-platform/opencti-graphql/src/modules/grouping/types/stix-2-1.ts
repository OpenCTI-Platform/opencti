// region Stix type
import type { StixContainer } from '../../../types/stix-2-1-sdo';
import { STIX_EXT_OCTI } from '../../../types/stix-2-1-extensions';
import type { StixOpenctiExtension } from '../../../types/stix-2-1-common';

export interface StixGroupingExtension extends StixOpenctiExtension {
  content: string;
  content_mapping: string;
}

export interface StixGrouping extends StixContainer {
  name: string;
  description: string;
  extensions: {
    [STIX_EXT_OCTI]: StixGroupingExtension;
  };
  context: string;
}

export interface GroupingNumberResult {
  count: number;
  total: number;
}
