import type { BasicStoreEntity, StoreEntity } from '../../../../types/store';

export const ENTITY_TYPE_CONTAINER_FEEDBACK = 'Feedback';

export interface BasicStoreEntityFeedback extends BasicStoreEntity {
  name: string,
  description: string,
  content: string,
  content_mapping: string,
  rating: number,
  object_refs: Array<string>,
}

export interface StoreEntityFeedback extends StoreEntity {
  name: string,
  description: string,
  content: string,
  content_mapping: string,
  rating: number,
  object_refs: Array<string>,
}

export interface StoreEntityStix2Feedback extends StoreEntity {
  name: string,
  description: string,
  rating: number,
  object_refs: Array<string>,
}
