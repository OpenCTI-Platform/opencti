import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import type { StixDomainObject, StixOpenctiExtensionSDO, StixDate } from '../../types/stix-2-1-common';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';

export const ENTITY_TYPE_EVENT = 'Event';

// region Database types
export interface BasicStoreEntityEvent extends BasicStoreEntity {
  name: string;
  description: string;
  event_types: Array<string>;
  start_time: Date;
  stop_time: Date;
}

export interface StoreEntityEvent extends StoreEntity {
  name: string;
  description: string;
  event_types: Array<string>;
  start_time: Date;
  stop_time: Date;
}
// endregion

// region Stix type
export interface StixEvent extends StixDomainObject {
  name: string;
  description: string;
  event_types: Array<string>;
  aliases: Array<string>;
  start_time: StixDate;
  stop_time: StixDate;
  extensions: {
    [STIX_EXT_OCTI] : StixOpenctiExtensionSDO
  };
}
// endregion
