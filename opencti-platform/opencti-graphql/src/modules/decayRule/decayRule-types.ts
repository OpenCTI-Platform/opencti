import type { StixObject, StixOpenctiExtensionSDO } from '../../types/stix-common';
import { STIX_EXT_OCTI } from '../../types/stix-extensions';
import type { BasicStoreEntity, StoreEntity } from '../../types/store';

export const ENTITY_TYPE_DECAY_RULE = 'DecayRule';

export interface BasicStoreEntityDecayRule extends BasicStoreEntity {
  name: string
  built_in: boolean
  decay_lifetime: number // in days
  decay_pound: number // can be changed in other model when feature is ready.
  decay_points: number[] // reactions points
  decay_revoke_score: number // revoked when score is <= 20
  decay_observable_types: string[] // indicator x_opencti_main_observable_type
  order: number // low priority = 0
  active: boolean
}

export interface StoreEntityDecayRule extends StoreEntity {
  name: string
  built_in: boolean
  decay_lifetime: number
  decay_pound: number
  decay_points: number[]
  decay_revoke_score: number
  decay_observable_types: string[]
  order: number
  active: boolean
}

export interface StixDecayRule extends StixObject {
  name: string
  description: string
  decay_lifetime: number
  decay_pound: number
  decay_points: number[]
  decay_revoke_score: number
  decay_observable_types: string[]
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtensionSDO
  }
}
