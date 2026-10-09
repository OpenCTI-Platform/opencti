import type { BasicStoreEntity, StoreEntity } from '../../../types/store';

export const ENTITY_TYPE_DECAY_EXCLUSION_RULE = 'DecayExclusionRule';

export interface BasicStoreEntityDecayExclusionRule extends BasicStoreEntity {
  name: string;
  description: string;
  decay_exclusion_filters: string;
  active: boolean;
}

export interface StoreEntityDecayExclusionRule extends StoreEntity {
  name: string;
  description: string;
  decay_exclusion_filters: string;
  active: boolean;
}
