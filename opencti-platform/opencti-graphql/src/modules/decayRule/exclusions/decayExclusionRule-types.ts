import type { StixObject } from '../../../types/stix-2-1-common';
import type { BasicStoreEntity, StoreEntity } from '../../../types/store';

export const ENTITY_TYPE_DECAY_EXCLUSION_RULE = 'DecayExclusionRule';

export interface BasicStoreEntityDecayExclusionRule extends BasicStoreEntity {
  name: string
  description: string
  decay_exclusion_observable_types: string[]
  active: boolean
}

export interface StoreEntityDecayExclusionRule extends StoreEntity {
  name: string
  description: string
  decay_exclusion_observable_types: string[]
  active: boolean
}

export interface StixDecayExclusionRule extends StixObject {
  name: string
  description: string
  decay_exclusion_observable_types: string[]
}
