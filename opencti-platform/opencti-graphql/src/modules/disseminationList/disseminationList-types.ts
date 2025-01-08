import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import type { StixObject, StixOpenctiExtensionSDO } from '../../types/stix-common';
import { STIX_EXT_OCTI } from '../../types/stix-extensions';

export const ENTITY_TYPE_DISSEMINATION_LIST = 'DisseminationList';

export interface BasicStoreEntityDisseminationList extends BasicStoreEntity {
  name: string;
  emails: string[];
}

export interface StoreEntityDisseminationList extends StoreEntity {
  name: string;
  emails: string[];
}

export interface StixDisseminationList extends StixObject {
  name: string;
  emails: string[];
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtensionSDO
  };
}
