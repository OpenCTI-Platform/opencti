import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import type { StixContainer } from '../../types/stix-sdo';
import type { StixOpenctiExtension } from '../../types/stix-common';
import { STIX_EXT_OCTI } from '../../types/stix-extensions';

export const ENTITY_TYPE_CONTAINER_GROUPING = 'Grouping';

// region Database types
export interface BasicStoreEntityGrouping extends BasicStoreEntity {
  name: string;
  description: string;
  content: string;
  content_mapping: string;
  context: string;
  object_refs: Array<string>;
}

export interface StoreEntityGrouping extends StoreEntity {
  name: string;
  description: string;
  content: string;
  content_mapping: string;
  context: string;
  object_refs: Array<string>;
}
// endregion

// region Stix type
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
// endregion

export interface GroupingNumberResult {
  count: number;
  total: number;
}
