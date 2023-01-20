import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import type { StixContainer } from '../../types/stix-sdo';

export const ENTITY_TYPE_CONTAINER_GROUPING = 'Grouping';

// region Database types
export interface BasicStoreEntityGrouping extends BasicStoreEntity {
  name: string;
  description: string;
  context: string;
  object_refs: Array<string>;
}

export interface StoreEntityGrouping extends StoreEntity {
  name: string;
  description: string;
  context: string;
  object_refs: Array<string>;
}
// endregion

// region Stix type
export interface StixGrouping extends StixContainer {
  name: string;
  description: string;
  context: string;
}
// endregion

export interface GroupingNumberResult {
  count: number;
  total: number;
}
