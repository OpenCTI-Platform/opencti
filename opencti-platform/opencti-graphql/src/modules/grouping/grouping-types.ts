import type { StixOpenctiExtension } from '../../types/stix-2-1-common';
import type { StixContainer } from '../../types/stix-2-1-sdo';
import type { StixContainer as Stix2Container } from '../../types/stix-2-0-sdo';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import type { BasicStoreEntity, StoreEntity } from '../../types/store';

export const ENTITY_TYPE_CONTAINER_GROUPING = 'Grouping';

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

// region Stix 2.1 type
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

// region Stix 2.0 type
export interface Stix2Grouping extends Stix2Container {
  name: string;
  description: string;
  context: string;
}

export interface StoreEntityGrouping2 extends StoreEntity {
  name: string;
  description: string;
  context: string;
  object_refs: Array<string>;
}
