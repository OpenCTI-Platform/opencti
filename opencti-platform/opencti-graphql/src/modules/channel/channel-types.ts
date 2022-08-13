import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import type {StixId, StixObject, StixOpenctiExtensionSDO} from '../../types/stix-common';
import { STIX_EXT_OCTI } from '../../types/stix-extensions';

export const ENTITY_TYPE_CHANNEL = 'Channel';

// region Database types
export interface BasicStoreEntityChannel extends BasicStoreEntity {
  name: string;
  description: string;
  channel_type: string;
  channel_languages: Array<string>;
}

export interface StoreEntityChannel extends StoreEntity {
  name: string;
  description: string;
  channel_type: string;
  channel_languages: Array<string>;
}
// endregion

// region Stix type
export interface StixChannel extends StixObject {
  name: string;
  description: string;
  category: string;
  labels: Array<string>; // optional
  aliases: Array<string>;
  // languages: Array<string>;
  created_by_ref: StixId | undefined; // optional
  object_marking_refs: Array<StixId>; // optional
  extensions: {
    [STIX_EXT_OCTI] : StixOpenctiExtensionSDO
  };
}
// endregion
