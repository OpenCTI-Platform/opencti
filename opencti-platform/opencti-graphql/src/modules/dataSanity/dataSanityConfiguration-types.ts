import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import type { StixObject, StixOpenctiExtensionSDO } from '../../types/stix-2-1-common';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';

export const ENTITY_TYPE_DATA_SANITY_CONFIGURATION = 'DataSanityConfiguration';

export type DayOfWeek = 'monday' | 'tuesday' | 'wednesday' | 'thursday' | 'friday' | 'saturday' | 'sunday';

export interface MaintenanceWindow {
  day: DayOfWeek;
  start_time: string; // "HH:mm" format (e.g., "22:30")
  end_time: string; // "HH:mm" format (e.g., "04:15")
}

export type MaintenancePlanning = MaintenanceWindow[];

export interface BasicStoreEntityDataSanityConfiguration extends BasicStoreEntity {
  maintenance_planning: string; // JSON-serialized MaintenancePlanning
}

export interface StoreEntityDataSanityConfiguration extends StoreEntity {
  maintenance_planning: string; // JSON-serialized MaintenancePlanning
}

export interface StixDataSanityConfiguration extends StixObject {
  maintenance_planning: string;
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtensionSDO;
  };
}
