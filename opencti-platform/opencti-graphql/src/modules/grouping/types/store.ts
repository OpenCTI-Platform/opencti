// region Database types
import type { BasicStoreEntity, StoreEntity } from '../../../types/store';

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

export const ENTITY_TYPE_CONTAINER_GROUPING = 'Grouping';
