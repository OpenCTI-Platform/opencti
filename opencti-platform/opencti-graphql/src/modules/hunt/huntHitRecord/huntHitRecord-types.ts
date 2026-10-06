import type { BasicStoreEntity, StoreEntity } from '../../../types/store';
import type { StixInternal } from '../../../types/stix-2-1-common';

export const ENTITY_TYPE_HUNT_HIT_RECORD = 'Hunt-Hit-Record';

interface HuntHitRecordAttributes {
  hunt_id: string;
  // Null for a hunt on the internet (no security platform)
  security_platform_id?: string | null;
  hit_key: string;
  // first_seen and last_seen (base attributes): when a run first found the hit, and when a run last found it
  // Runs that found the hit
  times_seen: number;
  first_run_id: string;
  last_run_id: string;
  // The latest runs that found the hit, so that a run processed again is not counted twice
  counted_run_ids?: string[];
  // Indicator hunts: the keys of the values the hit holds (huntRun-iocs iocKey)
  ioc_keys?: string[];
}

/** A hit a hunt already found on a security platform: the known hits ledger tells new hits from recurring ones. */
export interface BasicStoreEntityHuntHitRecord extends BasicStoreEntity, HuntHitRecordAttributes {}

export interface StoreEntityHuntHitRecord extends StoreEntity, HuntHitRecordAttributes {}

export interface StixHuntHitRecord extends StixInternal {
  hunt_id: string;
  security_platform_id?: string | null;
  hit_key: string;
}
