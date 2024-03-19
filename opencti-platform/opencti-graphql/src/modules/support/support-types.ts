import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import type { StixObject, StixOpenctiExtensionSDO } from '../../types/stix-common';
import { STIX_EXT_OCTI } from '../../types/stix-extensions';

export const ENTITY_TYPE_SUPPORT_PACKAGE = 'SupportPackage';

export interface BasicStoreEntitySupportPackage extends BasicStoreEntity {
  name: string
}

export interface StoreEntitySupportPackage extends StoreEntity {
  name: string
}

export interface StixSupportPackage extends StixObject {
  name: string
  extensions: {
    [STIX_EXT_OCTI] : StixOpenctiExtensionSDO
  }
}
