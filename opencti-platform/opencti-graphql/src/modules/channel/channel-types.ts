import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import type { StixDomainObject, StixOpenctiExtensionSDO } from '../../types/stix-2-1-common';
import type { StixDomainObject as StixDomainObject2 } from '../../types/stix-2-0-common';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';

export const ENTITY_TYPE_CHANNEL = 'Channel';
// region Database types
export interface BasicStoreEntityChannel extends BasicStoreEntity {
  name: string;
  description: string;
  channel_types: Array<string>;
}

export interface StoreEntityChannel extends StoreEntity {
  name: string;
  description: string;
  channel_types: Array<string>;
}
// endregion

// region Stix 2.1 type
export interface StixChannel extends StixDomainObject {
  name: string;
  description: string;
  channel_types: Array<string>;
  aliases: Array<string>;
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtensionSDO;
  };
}
// endregion

// region Stix 2.0 type
export interface Stix2Channel extends StixDomainObject2 {
  name: string;
  description: string;
  channel_types: Array<string>;
  aliases: Array<string>;
}
// endregion
